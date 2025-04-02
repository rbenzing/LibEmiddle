using System.Collections.Concurrent;
using E2EELibrary.Communication.Abstract;
using E2EELibrary.Models;

namespace E2EELibrary.Communication
{
    /// <summary>
    /// Implements an in-memory version of the mailbox transport for testing or local-only scenarios.
    /// </summary>
    public class InMemoryMailboxTransport : IMailboxTransport
    {
        private readonly ConcurrentDictionary<string, ConcurrentBag<MailboxMessage>> _mailboxes;
        private readonly ConcurrentDictionary<string, MailboxMessage> _messagesById;

        /// <summary>
        /// Creates a new in-memory mailbox transport.
        /// </summary>
        public InMemoryMailboxTransport()
        {
            _mailboxes = new ConcurrentDictionary<string, ConcurrentBag<MailboxMessage>>();
            _messagesById = new ConcurrentDictionary<string, MailboxMessage>();
        }

        /// <summary>
        /// Sends a message to the in-memory mailbox.
        /// </summary>
        /// <param name="message">The message to send</param>
        /// <returns>True if the send operation was successful</returns>
        public Task<bool> SendMessageAsync(MailboxMessage message)
        {
            ArgumentNullException.ThrowIfNull(message, nameof(message));
            ArgumentNullException.ThrowIfNull(message.RecipientKey, nameof(message.RecipientKey));

            // Generate recipient ID from their public key
            string recipientId = Convert.ToBase64String(message.RecipientKey);

            // Ensure mailbox exists
            var mailbox = _mailboxes.GetOrAdd(recipientId, _ => new ConcurrentBag<MailboxMessage>());

            // Add message to mailbox
            mailbox.Add(message);
            _messagesById[message.MessageId] = message;

            return Task.FromResult(true);
        }

        /// <summary>
        /// Fetches messages from the in-memory mailbox.
        /// </summary>
        /// <param name="recipientKey">The recipient's public key</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>List of mailbox messages for the recipient</returns>
        public Task<List<MailboxMessage>> FetchMessagesAsync(byte[] recipientKey, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(recipientKey, nameof(recipientKey));

            // Check for cancellation
            cancellationToken.ThrowIfCancellationRequested();

            // Get recipient's mailbox
            string recipientId = Convert.ToBase64String(recipientKey);
            if (!_mailboxes.TryGetValue(recipientId, out var mailbox))
            {
                return Task.FromResult(new List<MailboxMessage>());
            }

            // Convert to list and filter out expired messages
            var messages = mailbox.Where(m => !m.IsExpired()).ToList();
            return Task.FromResult(messages);
        }

        /// <summary>
        /// Deletes a message from the in-memory storage.
        /// </summary>
        /// <param name="messageId">The message ID to delete</param>
        /// <returns>True if the deletion was successful</returns>
        public Task<bool> DeleteMessageAsync(string messageId)
        {
            // Remove from messages by ID dictionary
            if (!_messagesById.TryRemove(messageId, out var message))
            {
                return Task.FromResult(false);
            }

            // We can't easily remove from the ConcurrentBag, but that's okay for tests
            // In a real implementation, we would have a better data structure
            // Mark it as expired instead, so it won't be returned in future fetches
            if (message != null)
            {
                message.ExpiresAt = 1; // Set to a past time
            }

            return Task.FromResult(true);
        }

        /// <summary>
        /// Marks a message as read in the in-memory storage.
        /// </summary>
        /// <param name="messageId">The message ID to mark as read</param>
        /// <returns>True if the operation was successful</returns>
        public Task<bool> MarkMessageAsReadAsync(string messageId)
        {
            if (_messagesById.TryGetValue(messageId, out var message))
            {
                message.IsRead = true;
                message.ReadAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                return Task.FromResult(true);
            }

            return Task.FromResult(false);
        }

        /// <summary>
        /// Clears all mailboxes (for testing purposes only).
        /// </summary>
        public void Clear()
        {
            _mailboxes.Clear();
            _messagesById.Clear();
        }
    }
}