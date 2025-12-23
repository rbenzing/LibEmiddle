using LibEmiddle.Abstractions;
using LibEmiddle.Domain;
using LibEmiddle.Core;

namespace LibEmiddle.Messaging.Transport;

/// <summary>
/// In-memory implementation of the mailbox transport for testing and local development.
/// </summary>
/// <param name="cryptoProvider">Crypto provider for encryption operations.</param>
/// <exception cref="ArgumentNullException">Thrown if any required parameters are null.</exception>
public sealed class InMemoryMailboxTransport(ICryptoProvider cryptoProvider) : BaseMailboxTransport(cryptoProvider)
{
    private readonly Dictionary<string, List<MailboxMessage>> _mailboxes = [];
    private readonly SemaphoreSlim _lock = new(1, 1);
    private CancellationTokenSource? _pollingCts;

    /// <inheritdoc/>
    protected override async Task<bool> SendMessageInternalAsync(MailboxMessage message)
    {
        await _lock.WaitAsync();
        try
        {
            var recipientKeyString = Convert.ToBase64String(message.RecipientKey);

            if (!_mailboxes.TryGetValue(recipientKeyString, out var mailbox))
            {
                mailbox = [];
                _mailboxes[recipientKeyString] = mailbox;
            }

            mailbox.Add(message);

            LoggingManager.LogInformation(nameof(InMemoryMailboxTransport), $"Added message {message.Id} to mailbox {recipientKeyString}");

            return true;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(InMemoryMailboxTransport), $"Error while adding message {message.Id} to mailbox", ex);
            return false;
        }
        finally
        {
            _lock.Release();
        }
    }

    /// <inheritdoc/>
    protected override async Task<List<MailboxMessage>> FetchMessagesInternalAsync(byte[] recipientKey, CancellationToken cancellationToken)
    {
        await _lock.WaitAsync(cancellationToken);
        try
        {
            var recipientKeyString = Convert.ToBase64String(recipientKey);

            if (_mailboxes.TryGetValue(recipientKeyString, out var mailbox))
            {
                // Get unread messages for this recipient
                var unreadMessages = mailbox
                    .Where(m => !m.IsRead && !m.IsExpired())
                    .ToList();

                LoggingManager.LogInformation(nameof(InMemoryMailboxTransport),
                    $"Fetched {unreadMessages.Count} unread messages for mailbox {recipientKeyString}");

                return unreadMessages;
            }

            return [];
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(InMemoryMailboxTransport), "Error while fetching messages from mailbox", ex);
            return [];
        }
        finally
        {
            _lock.Release();
        }
    }

    /// <inheritdoc/>
    protected override async Task<bool> DeleteMessageInternalAsync(string messageId)
    {
        await _lock.WaitAsync();
        try
        {
            bool messageFound = false;

            foreach (var mailbox in _mailboxes.Values)
            {
                var message = mailbox.FirstOrDefault(m => m.Id == messageId);
                if (message != null)
                {
                    mailbox.Remove(message);
                    messageFound = true;

                    LoggingManager.LogInformation(nameof(InMemoryMailboxTransport), $"Deleted message {messageId} from mailbox");
                    break;
                }
            }

            return messageFound;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(InMemoryMailboxTransport), $"Error while deleting message {messageId}", ex);
            return false;
        }
        finally
        {
            _lock.Release();
        }
    }

    /// <inheritdoc/>
    protected override async Task<bool> MarkMessageAsReadInternalAsync(string messageId)
    {
        await _lock.WaitAsync();
        try
        {
            bool messageFound = false;

            foreach (var mailbox in _mailboxes.Values)
            {
                var message = mailbox.FirstOrDefault(m => m.Id == messageId);
                if (message != null)
                {
                    message.IsRead = true;
                    message.ReadAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                    messageFound = true;

                    LoggingManager.LogInformation(nameof(InMemoryMailboxTransport), $"Marked message {messageId} as read");
                    break;
                }
            }

            return messageFound;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(InMemoryMailboxTransport), $"Error while marking message {messageId} as read", ex);
            return false;
        }
        finally
        {
            _lock.Release();
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

            LoggingManager.LogInformation(nameof(InMemoryMailboxTransport), "Stopped in-memory mailbox polling");
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    protected override async Task<bool> UpdateDeliveryStatusInternalAsync(string messageId, bool isDelivered)
    {
        await _lock.WaitAsync();
        try
        {
            bool messageFound = false;

            foreach (var mailbox in _mailboxes.Values)
            {
                var message = mailbox.FirstOrDefault(m => m.Id == messageId);
                if (message != null)
                {
                    message.IsDelivered = isDelivered;

                    if (isDelivered)
                    {
                        message.DeliveredAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                    }

                    messageFound = true;

                    LoggingManager.LogInformation(nameof(InMemoryMailboxTransport),
                        $"Updated delivery status for message {messageId} to {isDelivered}");
                    break;
                }
            }

            return messageFound;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(InMemoryMailboxTransport), $"Error while updating delivery status for message {messageId}", ex);
            return false;
        }
        finally
        {
            _lock.Release();
        }
    }

    /// <summary>
    /// Clears all messages from all mailboxes.
    /// </summary>
    /// <remarks>
    /// This method is primarily used for testing purposes.
    /// </remarks>
    /// <exception cref="ObjectDisposedException">Thrown if the object has been disposed.</exception>
    public async Task ClearAllMailboxesAsync()
    {
        ThrowIfDisposed();

        await _lock.WaitAsync();
        try
        {
            _mailboxes.Clear();
            LoggingManager.LogInformation(nameof(InMemoryMailboxTransport), "Cleared all mailboxes");
        }
        finally
        {
            _lock.Release();
        }
    }

    /// <summary>
    /// Gets the number of messages in all mailboxes.
    /// </summary>
    /// <returns>The total number of messages.</returns>
    /// <remarks>
    /// This method is primarily used for testing purposes.
    /// </remarks>
    /// <exception cref="ObjectDisposedException">Thrown if the object has been disposed.</exception>
    public async Task<int> GetTotalMessageCountAsync()
    {
        ThrowIfDisposed();

        await _lock.WaitAsync();
        try
        {
            return _mailboxes.Values.Sum(m => m.Count);
        }
        finally
        {
            _lock.Release();
        }
    }

    /// <summary>
    /// Gets all messages in a specific mailbox.
    /// </summary>
    /// <param name="recipientKey">The recipient's public key.</param>
    /// <returns>All messages in the mailbox.</returns>
    /// <remarks>
    /// This method is primarily used for testing purposes.
    /// </remarks>
    /// <exception cref="ArgumentNullException">Thrown if recipientKey is null.</exception>
    /// <exception cref="ObjectDisposedException">Thrown if the object has been disposed.</exception>
    public async Task<List<MailboxMessage>> GetAllMessagesAsync(byte[] recipientKey)
    {
        ThrowIfDisposed();

        if (recipientKey == null)
        {
            throw new ArgumentNullException(nameof(recipientKey));
        }

        await _lock.WaitAsync();
        try
        {
            var recipientKeyString = Convert.ToBase64String(recipientKey);

            if (_mailboxes.TryGetValue(recipientKeyString, out var mailbox))
            {
                return mailbox.ToList();
            }

            return [];
        }
        finally
        {
            _lock.Release();
        }
    }

    /// <summary>
    /// Releases the managed resources used by the InMemoryMailboxTransport.
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
            LoggingManager.LogError(nameof(InMemoryMailboxTransport), "Error stopping listening during disposal", ex);
        }

        // Dispose the cancellation token source
        _pollingCts?.Dispose();

        // Dispose the semaphore
        _lock?.Dispose();

        // Clear mailboxes to help with garbage collection
        try
        {
            _mailboxes.Clear();
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(InMemoryMailboxTransport), "Error clearing mailboxes during disposal", ex);
        }

        LoggingManager.LogDebug(nameof(InMemoryMailboxTransport), "InMemoryMailboxTransport disposed");
    }
}