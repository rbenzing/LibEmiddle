using LibEmiddle.Abstractions;
using LibEmiddle.Domain;
using LibEmiddle.Core;

namespace LibEmiddle.Messaging.Transport
{
    /// <summary>
    /// In-memory implementation of the mailbox transport for testing and local development.
    /// </summary>
    /// <param name="cryptoProvider">Crypto provider for encryption operations.</param>
    /// <exception cref="ArgumentNullException">Thrown if any required parameters are null.</exception>
    public class InMemoryMailboxTransport(ICryptoProvider cryptoProvider) : BaseMailboxTransport(cryptoProvider)
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

                LoggingManager.LogInformation("InMemoryMailboxTransport", $"Added message {message.Id} to mailbox {recipientKeyString}");

                return true;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError("InMemoryMailboxTransport", $"Error while adding message {message.Id} to mailbox", ex);
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

                    LoggingManager.LogInformation("InMemoryMailboxTransport", 
                        $"Fetched {unreadMessages.Count} unread messages for mailbox {recipientKeyString}");

                    return unreadMessages;
                }

                return new List<MailboxMessage>();
            }
            catch (Exception ex)
            {
                LoggingManager.LogError("InMemoryMailboxTransport", "Error while fetching messages from mailbox", ex);
                return new List<MailboxMessage>();
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

                        LoggingManager.LogInformation("InMemoryMailboxTransport", $"Deleted message {messageId} from mailbox");
                        break;
                    }
                }

                return messageFound;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError("InMemoryMailboxTransport", "Error while deleting message {messageId}", ex);
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

                        LoggingManager.LogInformation("InMemoryMailboxTransport", $"Marked message {messageId} as read");
                        break;
                    }
                }

                return messageFound;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError("InMemoryMailboxTransport", $"Error while marking message {messageId} as read", ex);
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
                            LoggingManager.LogError("InMemoryMailboxTransport", "Error during message polling", ex);

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
                    LoggingManager.LogError("InMemoryMailboxTransport", "Fatal error in polling loop", ex);
                }

                LoggingManager.LogInformation("InMemoryMailboxTransport", "Message polling stopped");
            }, linkedToken);

            LoggingManager.LogInformation("InMemoryMailboxTransport", "Started in-memory mailbox polling");
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

                LoggingManager.LogInformation("InMemoryMailboxTransport", "Stopped in-memory mailbox polling");
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

                        LoggingManager.LogInformation("InMemoryMailboxTransport", 
                            $"Updated delivery status for message {messageId} to {isDelivered}");
                        break;
                    }
                }

                return messageFound;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError("InMemoryMailboxTransport", $"Error while updating delivery status for message {messageId}", ex);
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
        public async Task ClearAllMailboxesAsync()
        {
            await _lock.WaitAsync();
            try
            {
                _mailboxes.Clear();
                LoggingManager.LogInformation("InMemoryMailboxTransport", "Cleared all mailboxes");
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
        public async Task<int> GetTotalMessageCountAsync()
        {
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
        public async Task<List<MailboxMessage>> GetAllMessagesAsync(byte[] recipientKey)
        {
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

                return new List<MailboxMessage>();
            }
            finally
            {
                _lock.Release();
            }
        }

        /// <summary>
        /// Disposes resources used by the transport.
        /// </summary>
        public void Dispose()
        {
            StopListeningAsync().GetAwaiter().GetResult();
            _pollingCts?.Dispose();
            _lock.Dispose();
        }
    }
}