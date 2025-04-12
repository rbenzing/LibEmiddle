using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using LibEmiddle.Abstractions;
using LibEmiddle.Core;
using LibEmiddle.Domain;

namespace LibEmiddle.Messaging.Transport
{
    /// <summary>
    /// Implements the mailbox transport using HTTP requests to a mailbox server
    /// with enhanced security features and WebSocket support for real-time messaging.
    /// </summary>
    public class HttpMailboxTransport : IMailboxTransport, IDisposable
    {
        private readonly HttpClient _httpClient;
        private readonly string _baseUrl;
        private readonly JsonSerializerOptions _jsonOptions;
        private readonly bool _useWebSockets;
        private SecureWebSocketClient? _webSocketClient;
        private bool _isWebSocketConnected;
        private readonly SemaphoreSlim _webSocketLock = new SemaphoreSlim(1, 1);
        private bool _disposed;

        /// <summary>
        /// Creates a new HTTP-based mailbox transport.
        /// </summary>
        /// <param name="baseUrl">Base URL of the mailbox server (must use HTTPS in production)</param>
        /// <param name="useWebSockets">Whether to use WebSockets for real-time communication when available</param>
        /// <param name="httpClientHandler">Optional HTTP client handler for custom configuration</param>
        /// <exception cref="ArgumentException">Thrown when the URL scheme is not HTTPS in production environments</exception>
        public HttpMailboxTransport(string baseUrl, bool useWebSockets = true, HttpClientHandler? httpClientHandler = null)
        {
            // Validate URL and ensure it uses HTTPS in production
            if (string.IsNullOrWhiteSpace(baseUrl))
                throw new ArgumentException("Base URL cannot be null or empty", nameof(baseUrl));

            Uri uri = new Uri(baseUrl);

            // Check for HTTPS in production environments
#if !DEBUG
            if (uri.Scheme != "https")
                throw new ArgumentException("HTTPS is required for production environments", nameof(baseUrl));
#endif

            _baseUrl = baseUrl.TrimEnd('/');
            _useWebSockets = useWebSockets;

            // Setup HTTP client with enhanced security
            var handler = httpClientHandler ?? CreateSecureHttpClientHandler();
            _httpClient = new HttpClient(handler);

            // Set default headers
            _httpClient.DefaultRequestHeaders.Add("User-Agent", $"LibEmiddle/{ProtocolVersion.FULL_VERSION}");
            _httpClient.DefaultRequestHeaders.Add("X-Client-Version", ProtocolVersion.FULL_VERSION);

            // Set JSON serialization options
            _jsonOptions = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                WriteIndented = false,
                DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
            };

            // Initialize WebSocket client if enabled
            if (_useWebSockets)
            {
                string wsBaseUrl = _baseUrl.Replace("http://", "ws://").Replace("https://", "wss://");
                _webSocketClient = new SecureWebSocketClient($"{wsBaseUrl}/ws");
            }
        }

        /// <summary>
        /// Creates a secure HTTP client handler with appropriate security settings
        /// </summary>
        private static HttpClientHandler CreateSecureHttpClientHandler()
        {
            var handler = new HttpClientHandler
            {
                // Always validate server certificate
                ServerCertificateCustomValidationCallback = ValidateServerCertificate,

                // Use TLS 1.2 or higher
                SslProtocols = System.Security.Authentication.SslProtocols.Tls12 |
                              System.Security.Authentication.SslProtocols.Tls13,

                // Prevent redirects to insecure endpoints
                AllowAutoRedirect = false
            };

            return handler;
        }

        /// <summary>
        /// Validates the server's SSL certificate
        /// </summary>
        private static bool ValidateServerCertificate(
            HttpRequestMessage request,
            X509Certificate2? certificate,
            X509Chain? chain,
            SslPolicyErrors errors)
        {
            // In production, enforce strict certificate validation
#if !DEBUG
            return errors == SslPolicyErrors.None;
#else
            // In debug mode, we may be more lenient for testing with self-signed certs
            return true;
#endif
        }

        /// <summary>
        /// Sends a message to the mailbox server.
        /// </summary>
        /// <param name="message">The message to send</param>
        /// <returns>True if the send operation was successful</returns>
        public async Task<bool> SendMessageAsync(MailboxMessage message)
        {
            ThrowIfDisposed();
            ArgumentNullException.ThrowIfNull(message, nameof(message));

            try
            {
                // Try to use WebSocket if connected and enabled
                if (_useWebSockets && _isWebSocketConnected && _webSocketClient != null)
                {
                    try
                    {
                        await _webSocketLock.WaitAsync();
                        if (_isWebSocketConnected)
                        {
                            // Serialize message to JSON with a message type indicator
                            var wrapper = new
                            {
                                Type = "SendMailboxMessage",
                                Payload = message
                            };
                            string json = JsonSerializer.Serialize(wrapper, _jsonOptions);

                            await _webSocketClient.SendEncryptedMessageAsync(json);
                            return true;
                        }
                    }
                    catch (Exception ex)
                    {
                        // Log WebSocket error but try HTTP fallback
                        LoggingManager.LogError(nameof(HttpMailboxTransport), $"WebSocket send error, falling back to HTTP: {ex.Message}");
                        _isWebSocketConnected = false;
                    }
                    finally
                    {
                        _webSocketLock.Release();
                    }
                }

                // Use HTTP as primary or fallback method
                string messageJson = JsonSerializer.Serialize(message, _jsonOptions);
                var content = new StringContent(messageJson, Encoding.UTF8, "application/json");

                // Include idempotency key for retries
                string idempotencyKey = message.MessageId;
                using var request = new HttpRequestMessage(HttpMethod.Post, $"{_baseUrl}/messages")
                {
                    Content = content,
                };
                request.Headers.Add("X-Idempotency-Key", idempotencyKey);

                // Make the request with timeout
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                using var response = await _httpClient.SendAsync(request, cts.Token);

                // Consider retrying on specific status codes like 429 (Too Many Requests)
                if (response.StatusCode == HttpStatusCode.TooManyRequests &&
                    response.Headers.TryGetValues("Retry-After", out var retryValues) &&
                    int.TryParse(retryValues.FirstOrDefault(), out int retrySeconds))
                {
                    // Wait the suggested time and try once more
                    await Task.Delay(TimeSpan.FromSeconds(retrySeconds));
                    using var retryResponse = await _httpClient.SendAsync(request);
                    return retryResponse.IsSuccessStatusCode;
                }

                return response.IsSuccessStatusCode;
            }
            catch (TaskCanceledException)
            {
                // Request timeout
                LoggingManager.LogError(nameof(HttpMailboxTransport), $"Request timeout when sending message {message.MessageId}");
                return false;
            }
            catch (Exception ex)
            {
                // Log the error - in production this would use a proper logging framework
                LoggingManager.LogError(nameof(HttpMailboxTransport), $"Error sending message {message.MessageId}: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Fetches messages from the mailbox server.
        /// </summary>
        /// <param name="recipientKey">The recipient's public key</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>List of mailbox messages for the recipient</returns>
        public async Task<List<MailboxMessage>> FetchMessagesAsync(byte[] recipientKey, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();
            ArgumentNullException.ThrowIfNull(recipientKey, nameof(recipientKey));

            // Establish WebSocket connection if enabled but not connected
            if (_useWebSockets && !_isWebSocketConnected && _webSocketClient != null)
            {
                await TryConnectWebSocketAsync();
            }

            try
            {
                // Convert recipient key to base64 for use in URL with proper URL escaping
                string recipientKeyBase64 = Convert.ToBase64String(recipientKey);
                string encodedKey = Uri.EscapeDataString(recipientKeyBase64);

                // Use conditional requests with ETag/If-None-Match for caching
                using var request = new HttpRequestMessage(HttpMethod.Get,
                    $"{_baseUrl}/messages?recipient={encodedKey}");

                using var response = await _httpClient.SendAsync(request, cancellationToken);

                // Handle rate limiting
                if (response.StatusCode == HttpStatusCode.TooManyRequests &&
                    response.Headers.TryGetValues("Retry-After", out var retryValues) &&
                    int.TryParse(retryValues.FirstOrDefault(), out int retrySeconds))
                {
                    // Wait and retry once
                    await Task.Delay(TimeSpan.FromSeconds(retrySeconds), cancellationToken);
                    using var retryRequest = new HttpRequestMessage(HttpMethod.Get,
                        $"{_baseUrl}/messages?recipient={encodedKey}");
                    using var retryResponse = await _httpClient.SendAsync(retryRequest, cancellationToken);

                    if (!retryResponse.IsSuccessStatusCode)
                        return new List<MailboxMessage>();

                    string json = await retryResponse.Content.ReadAsStringAsync(cancellationToken);
                    var messages = JsonSerializer.Deserialize<List<MailboxMessage>>(json, _jsonOptions);
                    return messages ?? new List<MailboxMessage>();
                }

                if (!response.IsSuccessStatusCode)
                {
                    return new List<MailboxMessage>();
                }

                string responseJson = await response.Content.ReadAsStringAsync(cancellationToken);
                var responseMessages = JsonSerializer.Deserialize<List<MailboxMessage>>(responseJson, _jsonOptions);

                return responseMessages ?? new List<MailboxMessage>();
            }
            catch (OperationCanceledException)
            {
                // Rethrow cancellation exceptions
                throw;
            }
            catch (Exception ex)
            {
                // Log the error - in production this would use a proper logging framework
                LoggingManager.LogError(nameof(HttpMailboxTransport), $"Error fetching messages: {ex.Message}");
                return new List<MailboxMessage>();
            }
        }

        /// <summary>
        /// Attempts to establish a WebSocket connection
        /// </summary>
        private async Task TryConnectWebSocketAsync()
        {
            if (_webSocketClient == null || _isWebSocketConnected)
                return;

            try
            {
                await _webSocketLock.WaitAsync();
                if (!_isWebSocketConnected)
                {
                    await _webSocketClient.ConnectAsync();

                    // TODO: In a real implementation, we would establish the Double Ratchet session
                    // and set it on the WebSocket client using:
                    // _webSocketClient.SetSession(doubleRatchetSession);

                    _isWebSocketConnected = true;
                }
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(HttpMailboxTransport), $"Failed to connect WebSocket: {ex.Message}");
                _isWebSocketConnected = false;
            }
            finally
            {
                _webSocketLock.Release();
            }
        }

        /// <summary>
        /// Deletes a message from the server.
        /// </summary>
        /// <param name="messageId">The message ID to delete</param>
        /// <returns>True if the deletion was successful</returns>
        public async Task<bool> DeleteMessageAsync(string messageId)
        {
            ThrowIfDisposed();
            if (string.IsNullOrEmpty(messageId))
                throw new ArgumentException("Message ID cannot be null or empty", nameof(messageId));

            try
            {
                // Try to use WebSocket if connected
                if (_useWebSockets && _isWebSocketConnected && _webSocketClient != null)
                {
                    try
                    {
                        await _webSocketLock.WaitAsync();
                        if (_isWebSocketConnected)
                        {
                            // Serialize delete command
                            var deleteCommand = new
                            {
                                Type = "DeleteMessage",
                                MessageId = messageId
                            };
                            string json = JsonSerializer.Serialize(deleteCommand, _jsonOptions);

                            await _webSocketClient.SendEncryptedMessageAsync(json);
                            return true;
                        }
                    }
                    catch (Exception ex)
                    {
                        // Log WebSocket error but try HTTP fallback
                        LoggingManager.LogError(nameof(HttpMailboxTransport), $"WebSocket delete error, falling back to HTTP: {ex.Message}");
                        _isWebSocketConnected = false;
                    }
                    finally
                    {
                        _webSocketLock.Release();
                    }
                }

                // HTTP fallback
                string escapedId = Uri.EscapeDataString(messageId);
                using var response = await _httpClient.DeleteAsync($"{_baseUrl}/messages/{escapedId}");

                // For 404, we consider it a successful deletion (already gone)
                return response.IsSuccessStatusCode || response.StatusCode == HttpStatusCode.NotFound;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(HttpMailboxTransport), $"Error deleting message {messageId}: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Marks a message as read on the server.
        /// </summary>
        /// <param name="messageId">The message ID to mark as read</param>
        /// <returns>True if the operation was successful</returns>
        public async Task<bool> MarkMessageAsReadAsync(string messageId)
        {
            ThrowIfDisposed();
            if (string.IsNullOrEmpty(messageId))
                throw new ArgumentException("Message ID cannot be null or empty", nameof(messageId));

            try
            {
                // Try to use WebSocket if connected
                if (_useWebSockets && _isWebSocketConnected && _webSocketClient != null)
                {
                    try
                    {
                        await _webSocketLock.WaitAsync();
                        if (_isWebSocketConnected)
                        {
                            // Serialize mark read command
                            var readCommand = new
                            {
                                Type = "MarkAsRead",
                                MessageId = messageId
                            };
                            string json = JsonSerializer.Serialize(readCommand, _jsonOptions);

                            await _webSocketClient.SendEncryptedMessageAsync(json);
                            return true;
                        }
                    }
                    catch (Exception ex)
                    {
                        // Log WebSocket error but try HTTP fallback
                        LoggingManager.LogError(nameof(HttpMailboxTransport), $"WebSocket mark read error, falling back to HTTP: {ex.Message}");
                        _isWebSocketConnected = false;
                    }
                    finally
                    {
                        _webSocketLock.Release();
                    }
                }

                // HTTP fallback using PATCH
                string escapedId = Uri.EscapeDataString(messageId);
                var content = new StringContent("{\"read\": true}", Encoding.UTF8, "application/json");

                using var request = new HttpRequestMessage(HttpMethod.Patch,
                    $"{_baseUrl}/messages/{escapedId}")
                {
                    Content = content
                };

                using var response = await _httpClient.SendAsync(request);
                return response.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(HttpMailboxTransport), $"Error marking message as read: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Closes the WebSocket connection and disposes resources.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Disposes managed and unmanaged resources.
        /// </summary>
        /// <param name="disposing">True if called from Dispose(), false if called from finalizer</param>
        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                // Dispose managed resources
                _webSocketLock.Dispose();

                // Close WebSocket if connected
                if (_isWebSocketConnected && _webSocketClient != null)
                {
                    try
                    {
                        // Close gracefully
                        _webSocketClient.CloseAsync().Wait(TimeSpan.FromSeconds(5));
                    }
                    catch (Exception ex)
                    {
                        LoggingManager.LogError(nameof(HttpMailboxTransport), $"Error closing WebSocket: {ex.Message}");
                    }
                }

                // Dispose the HTTP client
                _httpClient.Dispose();
            }

            _disposed = true;
        }

        /// <summary>
        /// Throws if this instance has been disposed.
        /// </summary>
        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(HttpMailboxTransport));
            }
        }
    }
}