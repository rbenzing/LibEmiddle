using System.Net.Http.Json;
using System.Text.Json;
using LibEmiddle.Abstractions;
using LibEmiddle.Domain;
using LibEmiddle.Core;

namespace LibEmiddle.Messaging.Transport;

/// <summary>
/// Implementation of the mailbox transport using HTTP for remote communications.
/// </summary>
public sealed class HttpMailboxTransport : BaseMailboxTransport
{
    private readonly HttpClient _httpClient;
    private readonly string _baseUrl;
    private readonly bool _ownsHttpClient;
    private CancellationTokenSource? _pollingCts;
    private readonly JsonSerializerOptions _jsonOptions;

    /// <summary>
    /// Initializes a new instance of the HttpMailboxTransport class.
    /// </summary>
    /// <param name="cryptoProvider">Crypto provider for encryption operations.</param>
    /// <param name="httpClient">HTTP client for making API requests.</param>
    /// <param name="baseUrl">Base URL of the mailbox API.</param>
    /// <param name="ownsHttpClient">Whether this instance owns the HttpClient and should dispose it.</param>
    /// <exception cref="ArgumentNullException">Thrown if any required parameters are null.</exception>
    public HttpMailboxTransport(
        ICryptoProvider cryptoProvider,
        HttpClient httpClient,
        string baseUrl,
        bool ownsHttpClient = false)
        : base(cryptoProvider)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _baseUrl = baseUrl ?? throw new ArgumentNullException(nameof(baseUrl));
        _ownsHttpClient = ownsHttpClient;

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
                LoggingManager.LogError(nameof(HttpMailboxTransport), $"Failed to send message {message.Id}. Status: {response.StatusCode}, Error: {errorContent}");
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(HttpMailboxTransport), $"HTTP exception while sending message {message.Id}", ex);
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
                LoggingManager.LogError(nameof(HttpMailboxTransport), $"Failed to fetch messages. Status: {response.StatusCode}, Error: {errorContent}");
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
            LoggingManager.LogError(nameof(HttpMailboxTransport), "HTTP exception while fetching messages", ex);
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
                LoggingManager.LogError(nameof(HttpMailboxTransport),
                    $"Failed to delete message {messageId}. Status: {response.StatusCode}, Error: {errorContent}");
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(HttpMailboxTransport), $"HTTP exception while deleting message {messageId}", ex);
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
                LoggingManager.LogError(nameof(HttpMailboxTransport),
                    $"Failed to mark message {messageId} as read. Status: {response.StatusCode}, Error: {errorContent}");
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(HttpMailboxTransport), $"HTTP exception while marking message {messageId} as read", ex);
            return false;
        }
    }

    /// <inheritdoc/>
    protected override async Task StartListeningInternalAsync(byte[] localIdentityKey, int pollingInterval, CancellationToken cancellationToken)
    {
        // Stop any existing polling first
        await StopListeningInternalAsync();

        // Create new cancellation token source and use base class polling loop helper
        _pollingCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        await StartPollingLoopAsync(localIdentityKey, pollingInterval, cancellationToken, _pollingCts);
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

            LoggingManager.LogInformation(nameof(HttpMailboxTransport), "Stopped HTTP mailbox polling");
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
                LoggingManager.LogError(nameof(HttpMailboxTransport),
                    $"Failed to update delivery status for message {messageId}. Status: {response.StatusCode}, Error: {errorContent}");
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(HttpMailboxTransport), $"HTTP exception while updating delivery status for message {messageId}", ex);
            return false;
        }
    }

    /// <summary>
    /// Releases the managed resources used by the HttpMailboxTransport.
    /// </summary>
    protected override void DisposeManagedResources()
    {
        try
        {
            // Stop listening operations first
            StopListeningInternalAsync().ConfigureAwait(false).GetAwaiter().GetResult();
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(HttpMailboxTransport), "Error stopping listening during disposal", ex);
        }

        // Dispose the cancellation token source
        _pollingCts?.Dispose();

        // Only dispose HttpClient if we own it
        if (_ownsHttpClient)
        {
            _httpClient?.Dispose();
        }

        LoggingManager.LogDebug(nameof(HttpMailboxTransport), "HttpMailboxTransport disposed");
    }
}