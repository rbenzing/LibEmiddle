using System.Net.Http.Json;
using System.Text.Json;
using LibEmiddle.Abstractions;
using LibEmiddle.Domain;
using LibEmiddle.Core;

namespace LibEmiddle.Messaging.Transport
{
    /// <summary>
    /// Implementation of the mailbox transport using HTTP for remote communications.
    /// </summary>
    public class HttpMailboxTransport : BaseMailboxTransport
    {
        private readonly HttpClient _httpClient;
        private readonly string _baseUrl;
        private CancellationTokenSource? _pollingCts;
        private readonly JsonSerializerOptions _jsonOptions;

        /// <summary>
        /// Initializes a new instance of the HttpMailboxTransport class.
        /// </summary>
        /// <param name="cryptoProvider">Crypto provider for encryption operations.</param>
        /// <param name="httpClient">HTTP client for making API requests.</param>
        /// <param name="baseUrl">Base URL of the mailbox API.</param>
        /// <exception cref="ArgumentNullException">Thrown if any required parameters are null.</exception>
        public HttpMailboxTransport(
            ICryptoProvider cryptoProvider,
            HttpClient httpClient,
            string baseUrl)
            : base(cryptoProvider)
        {
            _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
            _baseUrl = baseUrl ?? throw new ArgumentNullException(nameof(baseUrl));

            if (string.IsNullOrEmpty(_baseUrl))
            {
                throw new ArgumentException("Base URL cannot be empty.", nameof(baseUrl));
            }

            // Configure JSON serialization options
            _jsonOptions = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                PropertyNameCaseInsensitive = true
            };
        }

        /// <inheritdoc/>
        protected override async Task<bool> SendMessageInternalAsync(MailboxMessage message)
        {
            try
            {
                var response = await _httpClient.PostAsJsonAsync(
                    $"{_baseUrl}/messages",
                    message,
                    _jsonOptions);

                if (!response.IsSuccessStatusCode)
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    LoggingManager.LogError("HttpMailboxTransport", $"Failed to send message {message.Id}. Status: {response.StatusCode}, Error: {errorContent}");
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError("HttpMailboxTransport", $"HTTP exception while sending message {message.Id}", ex);
                return false;
            }
        }

        /// <inheritdoc/>
        protected override async Task<List<MailboxMessage>> FetchMessagesInternalAsync(byte[] recipientKey, CancellationToken cancellationToken)
        {
            try
            {
                // Convert recipient key to Base64 for URL
                var recipientKeyBase64 = Convert.ToBase64String(recipientKey)
                    .Replace('+', '-')
                    .Replace('/', '_')
                    .Replace("=", "");

                var response = await _httpClient.GetAsync(
                    $"{_baseUrl}/messages/{recipientKeyBase64}",
                    cancellationToken);

                if (!response.IsSuccessStatusCode)
                {
                    var errorContent = await response.Content.ReadAsStringAsync(cancellationToken);
                    LoggingManager.LogError("HttpMailboxTransport", $"Failed to fetch messages. Status: {response.StatusCode}, Error: {errorContent}");
                    return [];
                }

                var messages = await response.Content.ReadFromJsonAsync<List<MailboxMessage>>(
                    _jsonOptions,
                    cancellationToken) ?? [];

                return messages;
            }
            catch (TaskCanceledException)
            {
                // Operation was cancelled, don't log as an error
                return [];
            }
            catch (Exception ex)
            {
                LoggingManager.LogError("HttpMailboxTransport", "HTTP exception while fetching messages", ex);
                return [];
            }
        }

        /// <inheritdoc/>
        protected override async Task<bool> DeleteMessageInternalAsync(string messageId)
        {
            try
            {
                var response = await _httpClient.DeleteAsync($"{_baseUrl}/messages/{messageId}");

                if (!response.IsSuccessStatusCode)
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    LoggingManager.LogError("HttpMailboxTransport", 
                        $"Failed to delete message {messageId}. Status: {response.StatusCode}, Error: {errorContent}");
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError("HttpMailboxTransport", $"HTTP exception while deleting message {messageId}", ex);
                return false;
            }
        }

        /// <inheritdoc/>
        protected override async Task<bool> MarkMessageAsReadInternalAsync(string messageId)
        {
            try
            {
                var content = new StringContent(string.Empty);
                var response = await _httpClient.PatchAsync($"{_baseUrl}/messages/{messageId}/read", content);

                if (!response.IsSuccessStatusCode)
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    LoggingManager.LogError("HttpMailboxTransport", 
                        $"Failed to mark message {messageId} as read. Status: {response.StatusCode}, Error: {errorContent}");
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError("HttpMailboxTransport", $"HTTP exception while marking message {messageId} as read", ex);
                return false;
            }
        }

        /// <inheritdoc/>
        protected override async Task StartListeningInternalAsync(byte[] localIdentityKey, int pollingInterval, CancellationToken cancellationToken)
        {
            await StopListeningInternalAsync();

            _pollingCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            var linkedToken = _pollingCts.Token;

            // Start polling task
            _ = Task.Run(async () =>
            {
                try
                {
                    while (!linkedToken.IsCancellationRequested)
                    {
                        try
                        {
                            var messages = await FetchMessagesAsync(localIdentityKey, linkedToken);

                            foreach (var message in messages)
                            {
                                // Notify listeners about new message
                                OnMessageReceived(message);

                                // Mark message as read to prevent refetching
                                await MarkMessageAsReadAsync(message.Id);
                            }

                            // Wait for the specified polling interval
                            await Task.Delay(pollingInterval, linkedToken);
                        }
                        catch (OperationCanceledException)
                        {
                            // Normal cancellation, break the loop
                            break;
                        }
                        catch (Exception ex)
                        {
                            LoggingManager.LogError("HttpMailboxTransport", "Error during message polling", ex);

                            // Continue polling even after errors
                            try
                            {
                                await Task.Delay(pollingInterval, linkedToken);
                            }
                            catch (OperationCanceledException)
                            {
                                // Normal cancellation, break the loop
                                break;
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    LoggingManager.LogError("HttpMailboxTransport", "Fatal error in polling loop", ex);
                }

                LoggingManager.LogInformation("HttpMailboxTransport", "Message polling stopped");
            }, linkedToken);

            LoggingManager.LogInformation("HttpMailboxTransport", "Started HTTP mailbox polling");
        }

        /// <inheritdoc/>
        protected override Task StopListeningInternalAsync()
        {
            if (_pollingCts != null)
            {
                if (!_pollingCts.IsCancellationRequested)
                {
                    _pollingCts.Cancel();
                }

                _pollingCts.Dispose();
                _pollingCts = null;

                LoggingManager.LogInformation("HttpMailboxTransport", "Stopped HTTP mailbox polling");
            }

            return Task.CompletedTask;
        }

        /// <inheritdoc/>
        protected override async Task<bool> UpdateDeliveryStatusInternalAsync(string messageId, bool isDelivered)
        {
            try
            {
                var content = new StringContent(JsonSerializer.Serialize(
                    new { isDelivered },
                    _jsonOptions));

                content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");

                var response = await _httpClient.PatchAsync(
                    $"{_baseUrl}/messages/{messageId}/delivery-status",
                    content);

                if (!response.IsSuccessStatusCode)
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    LoggingManager.LogError("HttpMailboxTransport", 
                        $"Failed to update delivery status for message {messageId}. Status: {response.StatusCode}, Error: {errorContent}");
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError("HttpMailboxTransport", $"HTTP exception while updating delivery status for message {messageId}", ex);
                return false;
            }
        }

        /// <summary>
        /// Disposes resources used by the transport.
        /// </summary>
        public void Dispose()
        {
            StopListeningAsync().GetAwaiter().GetResult();
            _pollingCts?.Dispose();
        }
    }
}