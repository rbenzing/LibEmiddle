using LibEmiddle.Abstractions;
using LibEmiddle.Domain;
using LibEmiddle.Core;

namespace LibEmiddle.Messaging.Transport
{
    /// <summary>
    /// Base abstract class for mailbox transport implementations.
    /// Provides common functionality for different transport mechanisms.
    /// </summary>
    /// <remarks>
    /// Initializes a new instance of the BaseMailboxTransport class.
    /// </remarks>
    /// <param name="cryptoProvider">Crypto provider for encryption operations.</param>
    /// <exception cref="ArgumentNullException">Thrown if any required parameters are null.</exception>
    public abstract class BaseMailboxTransport(ICryptoProvider cryptoProvider) : IMailboxTransport
    {
        /// <summary>
        /// Crypto provider for encryption/decryption operations.
        /// </summary>
        protected readonly ICryptoProvider _cryptoProvider = cryptoProvider ?? throw new ArgumentNullException(nameof(cryptoProvider));

        /// <summary>
        /// Event raised when new messages are received.
        /// </summary>
        public event EventHandler<MailboxMessageReceivedEventArgs>? MessageReceived;

        /// <summary>
        /// Sends a message to a remote mailbox.
        /// </summary>
        /// <param name="message">The mailbox message to send.</param>
        /// <returns>True if the message was sent successfully, false otherwise.</returns>
        /// <exception cref="ArgumentNullException">Thrown if message is null.</exception>
        public virtual async Task<bool> SendMessageAsync(MailboxMessage message)
        {
            if (message == null)
            {
                throw new ArgumentNullException(nameof(message));
            }

            try
            {
                LoggingManager.LogDebug(nameof(BaseMailboxTransport), 
                    $"Sending message: {message.Id} to recipient: {Convert.ToBase64String(message.RecipientKey).Substring(0, Math.Min(8, message.RecipientKey.Length))}");

                // Implementation-specific send logic
                return await SendMessageInternalAsync(message);
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(BaseMailboxTransport), $"Error sending message {message.Id}", ex);
                return false;
            }
        }

        /// <summary>
        /// Implementation-specific method to send a mailbox message.
        /// </summary>
        /// <param name="message">The message to send.</param>
        /// <returns>True if successful, false otherwise.</returns>
        protected abstract Task<bool> SendMessageInternalAsync(MailboxMessage message);

        /// <summary>
        /// Fetches messages from a remote mailbox for a specific recipient.
        /// </summary>
        /// <param name="recipientKey">The public key of the recipient.</param>
        /// <param name="cancellationToken">Cancellation token to cancel the operation.</param>
        /// <returns>A list of mailbox messages.</returns>
        /// <exception cref="ArgumentNullException">Thrown if recipientKey is null.</exception>
        public virtual async Task<List<MailboxMessage>> FetchMessagesAsync(byte[] recipientKey, CancellationToken cancellationToken = default)
        {
            if (recipientKey == null || recipientKey.Length == 0)
            {
                throw new ArgumentNullException(nameof(recipientKey));
            }

            try
            {
                LoggingManager.LogDebug(nameof(BaseMailboxTransport), 
                    $"Fetching messages for recipient: {Convert.ToBase64String(recipientKey).Substring(0, Math.Min(8, recipientKey.Length))}");

                var messages = await FetchMessagesInternalAsync(recipientKey, cancellationToken);

                // Validate messages
                var validMessages = new List<MailboxMessage>();
                foreach (var message in messages)
                {
                    if (await ValidateMessageAsync(message))
                    {
                        validMessages.Add(message);
                    }
                    else
                    {
                        LoggingManager.LogWarning(nameof(BaseMailboxTransport), $"Discarded invalid message: {message.Id}");
                    }
                }

                return validMessages;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(BaseMailboxTransport), 
                    $"Error fetching messages for recipient: {Convert.ToBase64String(recipientKey).Substring(0, Math.Min(8, recipientKey.Length))}",
                    ex);
                return [];
            }
        }

        /// <summary>
        /// Implementation-specific method to fetch mailbox messages.
        /// </summary>
        /// <param name="recipientKey">The recipient's public key.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        /// <returns>A list of mailbox messages.</returns>
        protected abstract Task<List<MailboxMessage>> FetchMessagesInternalAsync(byte[] recipientKey, CancellationToken cancellationToken);

        /// <summary>
        /// Deletes a message from a remote mailbox.
        /// </summary>
        /// <param name="messageId">The ID of the message to delete.</param>
        /// <returns>True if the message was deleted successfully, false otherwise.</returns>
        /// <exception cref="ArgumentException">Thrown if messageId is null or empty.</exception>
        public virtual async Task<bool> DeleteMessageAsync(string messageId)
        {
            if (string.IsNullOrEmpty(messageId))
            {
                throw new ArgumentException("Message ID cannot be null or empty.", nameof(messageId));
            }

            try
            {
                LoggingManager.LogDebug(nameof(BaseMailboxTransport), $"Deleting message: {messageId}");
                return await DeleteMessageInternalAsync(messageId);
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(BaseMailboxTransport), $"Error deleting message {messageId}", ex);
                return false;
            }
        }

        /// <summary>
        /// Implementation-specific method to delete a mailbox message.
        /// </summary>
        /// <param name="messageId">The ID of the message to delete.</param>
        /// <returns>True if successful, false otherwise.</returns>
        protected abstract Task<bool> DeleteMessageInternalAsync(string messageId);

        /// <summary>
        /// Marks a message as read in a remote mailbox.
        /// </summary>
        /// <param name="messageId">The ID of the message to mark as read.</param>
        /// <returns>True if the message was marked as read successfully, false otherwise.</returns>
        /// <exception cref="ArgumentException">Thrown if messageId is null or empty.</exception>
        public virtual async Task<bool> MarkMessageAsReadAsync(string messageId)
        {
            if (string.IsNullOrEmpty(messageId))
            {
                throw new ArgumentException("Message ID cannot be null or empty.", nameof(messageId));
            }

            try
            {
                LoggingManager.LogDebug(nameof(BaseMailboxTransport), $"Marking message as read: {messageId}");
                bool result = await MarkMessageAsReadInternalAsync(messageId);

                if (result)
                {
                    LoggingManager.LogDebug(nameof(BaseMailboxTransport), $"Message marked as read: {messageId}");
                }

                return result;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(BaseMailboxTransport), $"Error marking message as read {messageId}", ex);
                return false;
            }
        }

        /// <summary>
        /// Implementation-specific method to mark a mailbox message as read.
        /// </summary>
        /// <param name="messageId">The ID of the message to mark as read.</param>
        /// <returns>True if successful, false otherwise.</returns>
        protected abstract Task<bool> MarkMessageAsReadInternalAsync(string messageId);

        /// <summary>
        /// Starts listening for incoming messages.
        /// </summary>
        /// <param name="localIdentityKey">The identity key of the user.</param>
        /// <param name="pollingInterval">Interval in milliseconds to poll for new messages.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        public virtual async Task StartListeningAsync(byte[] localIdentityKey, int pollingInterval = 5000, CancellationToken cancellationToken = default)
        {
            if (pollingInterval < 1000)
            {
                LoggingManager.LogWarning(nameof(BaseMailboxTransport), $"Polling interval is set to {pollingInterval}ms which may cause excessive resource usage. " +
                                  "Recommended minimum is 1000ms.");
            }

            LoggingManager.LogInformation(nameof(BaseMailboxTransport), $"Starting mailbox polling with interval: {pollingInterval}ms");

            await StartListeningInternalAsync(localIdentityKey, pollingInterval, cancellationToken);
        }

        /// <summary>
        /// Implementation-specific method to start listening for incoming messages.
        /// </summary>
        /// <param name="localIdentityKey">The identity key of the user.</param>
        /// <param name="pollingInterval">Interval in milliseconds to poll for new messages.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        protected abstract Task StartListeningInternalAsync(byte[] localIdentityKey, int pollingInterval, CancellationToken cancellationToken);

        /// <summary>
        /// Stops listening for incoming messages.
        /// </summary>
        /// <returns>A task representing the asynchronous operation.</returns>
        public virtual Task StopListeningAsync()
        {
            LoggingManager.LogInformation(nameof(BaseMailboxTransport), "Stopping mailbox polling");
            return StopListeningInternalAsync();
        }

        /// <summary>
        /// Implementation-specific method to stop listening for incoming messages.
        /// </summary>
        /// <returns>A task representing the asynchronous operation.</returns>
        protected abstract Task StopListeningInternalAsync();

        /// <summary>
        /// Validates the authenticity and integrity of a message through the protocol's
        /// built-in authentication mechanisms.
        /// </summary>
        /// <param name="message">The message to validate.</param>
        /// <returns>True if the message passes basic validation checks.</returns>
        /// <remarks>
        /// In the Signal protocol, authenticity is handled through the Double Ratchet's
        /// authenticated encryption and the X3DH key exchange, so additional transport-level
        /// signatures are not required.
        /// </remarks>
        protected virtual Task<bool> ValidateMessageAsync(MailboxMessage message)
        {
            // Basic validation - extend if needed for specific implementation requirements
            if (message == null)
            {
                return Task.FromResult(false);
            }

            if (message.SenderKey == null || message.SenderKey.Length == 0)
            {
                LoggingManager.LogWarning(nameof(BaseMailboxTransport), $"Message {message.Id} has no sender key");
                return Task.FromResult(false);
            }

            if (message.RecipientKey == null || message.RecipientKey.Length == 0)
            {
                LoggingManager.LogWarning(nameof(BaseMailboxTransport), $"Message {message.Id} has no recipient key");
                return Task.FromResult(false);
            }

            if (message.EncryptedPayload == null || !message.EncryptedPayload.IsValid())
            {
                LoggingManager.LogWarning(nameof(BaseMailboxTransport), $"Message {message.Id} has invalid encrypted payload");
                return Task.FromResult(false);
            }

            // Check expiration
            if (message.IsExpired())
            {
                LoggingManager.LogInformation(nameof(BaseMailboxTransport), $"Message {message.Id} has expired");
                return Task.FromResult(false);
            }

            // In Signal protocol, message authenticity is verified when decrypting
            // through the authenticated encryption scheme, not at transport level
            return Task.FromResult(true);
        }

        /// <summary>
        /// Raises the MessageReceived event with the specified message.
        /// </summary>
        /// <param name="message">The received message.</param>
        protected virtual void OnMessageReceived(MailboxMessage message)
        {
            try
            {
                MessageReceived?.Invoke(this, new MailboxMessageReceivedEventArgs(message));
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(BaseMailboxTransport), $"Error in message received event handler for {message.Id}", ex);
            }
        }

        /// <summary>
        /// Updates the delivery status of a message.
        /// </summary>
        /// <param name="messageId">The ID of the message.</param>
        /// <param name="isDelivered">Whether the message has been delivered.</param>
        /// <returns>True if the status was updated successfully, false otherwise.</returns>
        public virtual async Task<bool> UpdateDeliveryStatusAsync(string messageId, bool isDelivered)
        {
            if (string.IsNullOrEmpty(messageId))
            {
                throw new ArgumentException("Message ID cannot be null or empty.", nameof(messageId));
            }

            try
            {
                LoggingManager.LogDebug(nameof(BaseMailboxTransport), $"Updating delivery status for message {messageId} to {isDelivered}");

                return await UpdateDeliveryStatusInternalAsync(messageId, isDelivered);
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(BaseMailboxTransport), $"Error updating delivery status for message {messageId}", ex);
                return false;
            }
        }

        /// <summary>
        /// Implementation-specific method to update the delivery status of a message.
        /// </summary>
        /// <param name="messageId">The ID of the message.</param>
        /// <param name="isDelivered">Whether the message has been delivered.</param>
        /// <returns>True if successful, false otherwise.</returns>
        protected abstract Task<bool> UpdateDeliveryStatusInternalAsync(string messageId, bool isDelivered);
    }

    /// <summary>
    /// Event arguments for the MessageReceived event.
    /// </summary>
    public class MailboxMessageReceivedEventArgs : EventArgs
    {
        /// <summary>
        /// The received mailbox message.
        /// </summary>
        public MailboxMessage Message { get; }

        /// <summary>
        /// Initializes a new instance of the MailboxMessageReceivedEventArgs class.
        /// </summary>
        /// <param name="message">The received message.</param>
        public MailboxMessageReceivedEventArgs(MailboxMessage message)
        {
            Message = message ?? throw new ArgumentNullException(nameof(message));
        }
    }
}