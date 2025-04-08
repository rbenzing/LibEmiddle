using System.Net.WebSockets;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using E2EELibrary.Models;
using E2EELibrary.Encryption;
using E2EELibrary.Core;
using E2EELibrary.Communication.Abstract;
using System.Buffers;

namespace E2EELibrary.Communication
{
    /// <summary>
    /// Secure WebSocket client for encrypted communications that properly manages resources
    /// </summary>
    public class SecureWebSocketClient : IDisposable
    {
        private readonly IWebSocketClient _webSocket;
        private readonly Uri _serverUri;
        private DoubleRatchetSession? _session = null;
        private bool _disposed = false;
        private readonly SemaphoreSlim _connectionLock = new SemaphoreSlim(1, 1);

        /// <summary>
        /// Creates a new secure WebSocket client
        /// </summary>
        /// <param name="serverUrl">Server URL</param>
        public SecureWebSocketClient(string serverUrl)
            : this(serverUrl, new StandardWebSocketClient())
        {
        }

        /// <summary>
        /// Creates a new secure WebSocket client with a provided WebSocket instance
        /// </summary>
        /// <param name="serverUrl">Server URL</param>
        /// <param name="webSocket">WebSocket client to use</param>
        public SecureWebSocketClient(string serverUrl, IWebSocketClient webSocket)
        {
            _serverUri = new Uri(serverUrl);
            _webSocket = webSocket ?? throw new ArgumentNullException(nameof(webSocket));
        }

        /// <summary>
        /// Gets the current connection state
        /// </summary>
        public WebSocketState State => _webSocket.State;

        /// <summary>
        /// Connects to the server and establishes encrypted session
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        public async Task ConnectAsync(CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();

            await _connectionLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                // Check if already connected
                if (_webSocket.State == WebSocketState.Open)
                    return;

                if (_webSocket.State != WebSocketState.None && _webSocket.State != WebSocketState.Closed)
                    throw new InvalidOperationException($"Cannot connect when WebSocket is in state {_webSocket.State}");

                await _webSocket.ConnectAsync(_serverUri, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _connectionLock.Release();
            }
        }

        /// <summary>
        /// Sets the Double Ratchet session for encrypted communication
        /// </summary>
        /// <param name="session">Double Ratchet session</param>
        public void SetSession(DoubleRatchetSession session)
        {
            ThrowIfDisposed();
            _session = session ?? throw new ArgumentNullException(nameof(session));
        }

        /// <summary>
        /// Sends an encrypted message to the server
        /// </summary>
        /// <param name="message">Plain text message</param>
        /// <param name="cancellationToken">The cancel token</param>
        public async Task SendEncryptedMessageAsync(string message, CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();

            // Validate input parameters
            ArgumentNullException.ThrowIfNull(message, nameof(message));

            // Validate session state
            if (_session is null)
            {
                throw new InvalidOperationException("Session not established. Call SetSession first.");
            }

            // Validate WebSocket connection
            if (_webSocket.State != WebSocketState.Open)
            {
                throw new InvalidOperationException($"WebSocket connection is not open. Current state: {_webSocket.State}");
            }

            try
            {
                // Encrypt the message
                var (updatedSession, encryptedMessage) = DoubleRatchet.DoubleRatchetEncrypt(_session, message);

                // Validate the encryption result
                if (updatedSession is null)
                {
                    throw new CryptographicException("Encryption failed: null session returned.");
                }

                if (encryptedMessage is null ||
                    encryptedMessage.Ciphertext is null ||
                    encryptedMessage.Nonce is null ||
                    encryptedMessage.SenderDHKey is null)
                {
                    throw new CryptographicException("Encryption failed: incomplete encrypted message returned.");
                }

                // Update session only after successful encryption
                _session = updatedSession;

                // Set timestamp in the EncryptedMessage object for replay protection
                encryptedMessage.Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

                // Convert encrypted message to transportable format using our standardized serialization
                var messageData = new
                {
                    ciphertext = Convert.ToBase64String(encryptedMessage.Ciphertext),
                    nonce = Convert.ToBase64String(encryptedMessage.Nonce),
                    messageNumber = encryptedMessage.MessageNumber,
                    senderDHKey = Convert.ToBase64String(encryptedMessage.SenderDHKey),
                    timestamp = encryptedMessage.Timestamp,
                    messageId = encryptedMessage.MessageId.ToString(),
                    sessionId = encryptedMessage.SessionId
                };

                // Use our standardized JSON serialization
                string jsonMessage = JsonSerialization.Serialize(messageData);
                byte[] messageBytes = Encoding.UTF8.GetBytes(jsonMessage);

                // Send the message with cancellation support
                await _webSocket.SendAsync(
                    new ArraySegment<byte>(messageBytes),
                    WebSocketMessageType.Text,
                    true, // endOfMessage
                    cancellationToken).ConfigureAwait(false);
            }
            catch (WebSocketException wsEx)
            {
                // Specific handling for WebSocket errors
                throw new WebSocketException($"WebSocket error while sending message: {wsEx.Message}", wsEx);
            }
            catch (OperationCanceledException)
            {
                // Pass through cancellation
                throw;
            }
            catch (Exception ex) when (
                ex is not InvalidOperationException &&
                ex is not ArgumentException &&
                ex is not WebSocketException &&
                ex is not CryptographicException)
            {
                // Wrap unexpected errors
                throw new Exception($"Error sending encrypted message: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Receives and decrypts a message from the server
        /// </summary>
        /// <param name="cancellationToken">The cancel token</param>
        /// <returns>Decrypted message</returns>
        public async Task<string?> ReceiveEncryptedMessageAsync(CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();

            if (_session is null)
            {
                throw new InvalidOperationException("Session not established. Call SetSession first.");
            }

            if (_webSocket.State != WebSocketState.Open)
            {
                throw new InvalidOperationException($"WebSocket connection is not open. Current state: {_webSocket.State}");
            }

            // Use a buffer pool for better memory efficiency
            byte[]? buffer = null;

            try
            {
                // Rent a buffer instead of allocating a new one
                buffer = ArrayPool<byte>.Shared.Rent(8192);

                // Receive message with cancellation support
                WebSocketReceiveResult result = await _webSocket.ReceiveAsync(
                    new ArraySegment<byte>(buffer), cancellationToken).ConfigureAwait(false);

                // Check if the socket was closed
                if (result.MessageType == WebSocketMessageType.Close)
                {
                    throw new WebSocketException("WebSocket connection was closed by the server.");
                }

                // Parse message - only use the bytes we actually received
                string json = Encoding.UTF8.GetString(buffer, 0, result.Count);

                // Use our standardized JSON deserialization with case-insensitive option for backward compatibility
                Dictionary<string, JsonElement>? messageData = JsonSerialization.DeserializeInsensitive<Dictionary<string, JsonElement>>(json);

                if (messageData is null)
                {
                    throw new FormatException("Failed to deserialize message data.");
                }

                // Validate required fields exist
                if (!messageData.ContainsKey("ciphertext") ||
                    !messageData.ContainsKey("nonce") ||
                    !messageData.ContainsKey("messageNumber") ||
                    !messageData.ContainsKey("senderDHKey"))
                {
                    throw new FormatException("Message is missing required fields.");
                }

                // Extract values with proper error handling
                byte[]? ciphertext = Helpers.GetBytesFromBase64(messageData, "ciphertext");
                byte[]? nonce = Helpers.GetBytesFromBase64(messageData, "nonce");
                byte[]? senderDHKey = Helpers.GetBytesFromBase64(messageData, "senderDHKey");

                // Get the message number with proper handling of different formats
                int messageNumber = Helpers.GetInt32Value(messageData["messageNumber"]);

                // Try to get timestamp if available
                long timestamp = 0;
                if (messageData.TryGetValue("timestamp", out JsonElement timestampElement))
                {
                    timestamp = Helpers.GetInt64Value(timestampElement, 0);

                    // Check if message is too old (5 minutes threshold for replay protection)
                    long currentTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                    if (timestamp > 0 && currentTime - timestamp > Constants.MAX_MESSAGE_AGE_MS)
                    {
                        throw new SecurityException("Message is too old (possible replay attack).");
                    }
                }

                // Try to get session ID if available
                string? sessionId = null;
                if (messageData.TryGetValue("sessionId", out JsonElement sessionIdElement) &&
                    sessionIdElement.ValueKind == JsonValueKind.String)
                {
                    sessionId = sessionIdElement.GetString();
                }

                // Try to get message ID if available
                Guid messageId = Guid.NewGuid(); // Default to a new ID
                if (messageData.TryGetValue("messageId", out JsonElement messageIdElement) &&
                    messageIdElement.ValueKind == JsonValueKind.String)
                {
                    string? messageIdStr = messageIdElement.GetString();
                    if (!string.IsNullOrEmpty(messageIdStr) && Guid.TryParse(messageIdStr, out Guid parsedId))
                    {
                        messageId = parsedId;
                    }
                }

                // Create the encrypted message
                var encryptedMessage = new EncryptedMessage
                {
                    Ciphertext = ciphertext,
                    Nonce = nonce,
                    MessageNumber = messageNumber,
                    SenderDHKey = senderDHKey,
                    Timestamp = timestamp,
                    MessageId = messageId,
                    SessionId = sessionId
                };

                // Validate the message before attempting decryption
                if (!encryptedMessage.Validate())
                {
                    throw new SecurityException("Message validation failed.");
                }

                var (updatedSession, decryptedMessage) = DoubleRatchet.DoubleRatchetDecrypt(_session, encryptedMessage);

                // Only update the session if decryption was successful
                if (updatedSession != null)
                {
                    _session = updatedSession;
                }
                else
                {
                    // Log decryption failure but don't throw - might want to return null instead
                    throw new CryptographicException("Decryption produced a null session.");
                }

                return decryptedMessage;
            }
            catch (WebSocketException wsEx)
            {
                // Specific handling for WebSocket errors
                throw new WebSocketException($"WebSocket error while receiving message: {wsEx.Message}", wsEx);
            }
            catch (OperationCanceledException)
            {
                // Pass through cancellation
                throw;
            }
            catch (JsonException ex)
            {
                // Convert JSON exceptions to FormatException
                throw new FormatException($"Invalid JSON format: {ex.Message}", ex);
            }
            catch (Exception ex) when (
                ex is not InvalidOperationException &&
                ex is not WebSocketException &&
                ex is not FormatException &&
                ex is not SecurityException &&
                ex is not CryptographicException)
            {
                // Wrap unexpected errors
                throw new Exception($"Error receiving encrypted message: {ex.Message}", ex);
            }
            finally
            {
                // Return the buffer to the pool when done
                if (buffer != null)
                {
                    ArrayPool<byte>.Shared.Return(buffer);
                    buffer = null;
                }
            }
        }

        /// <summary>
        /// Closes the connection gracefully
        /// </summary>
        /// <param name="statusDescription">Optional status description</param>
        /// <param name="cancellationToken">Optional cancellation token</param>
        public async Task CloseAsync(string? statusDescription = null, CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();

            await _connectionLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                if (_webSocket.State == WebSocketState.Open)
                {
                    await _webSocket.CloseAsync(
                        WebSocketCloseStatus.NormalClosure,
                        statusDescription ?? "Connection closed by client",
                        cancellationToken).ConfigureAwait(false);
                }
            }
            finally
            {
                _connectionLock.Release();
            }
        }

        /// <summary>
        /// Disposes the WebSocket client and releases resources
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Disposes the WebSocket client and releases resources
        /// </summary>
        /// <param name="disposing">True if called from Dispose(), false if called from finalizer</param>
        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                // Dispose managed resources
                CloseWebSocketSafe().GetAwaiter().GetResult();
                _connectionLock.Dispose();

                // Clear any sensitive data
                _session = null;
            }

            // Set disposed flag
            _disposed = true;
        }

        /// <summary>
        /// Safely closes the WebSocket connection
        /// </summary>
        private async Task CloseWebSocketSafe()
        {
            if (_webSocket is IDisposable disposableSocket)
            {
                try
                {
                    // Try to close the socket gracefully if it's open
                    if (_webSocket.State == WebSocketState.Open)
                    {
                        using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                        await _webSocket.CloseAsync(
                            WebSocketCloseStatus.NormalClosure,
                            "Client disposing",
                            timeoutCts.Token).ConfigureAwait(false);
                    }
                }
                catch
                {
                    // Ignore any exceptions during disposal
                }
                finally
                {
                    // Dispose the socket
                    disposableSocket.Dispose();
                }
            }
        }

        /// <summary>
        /// Throws an ObjectDisposedException if this object has been disposed
        /// </summary>
        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(SecureWebSocketClient));
            }
        }

        /// <summary>
        /// Finalizer to ensure resources are properly cleaned up
        /// </summary>
        ~SecureWebSocketClient()
        {
            Dispose(false);
        }
    }
}