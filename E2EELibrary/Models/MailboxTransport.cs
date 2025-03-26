using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using E2EELibrary.Models;

namespace E2EELibrary.Communication
{
    /// <summary>
    /// Interface for mailbox transport implementations.
    /// </summary>
    public interface IMailboxTransport
    {
        /// <summary>
        /// Sends a message to a mailbox server.
        /// </summary>
        /// <param name="message">The message to send</param>
        Task<bool> SendMessageAsync(MailboxMessage message);

        /// <summary>
        /// Fetches messages from a mailbox server.
        /// </summary>
        /// <param name="recipientKey">The recipient's public key</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>List of mailbox messages</returns>
        Task<List<MailboxMessage>> FetchMessagesAsync(byte[] recipientKey, CancellationToken cancellationToken);

        /// <summary>
        /// Deletes a message from the server.
        /// </summary>
        /// <param name="messageId">The message ID to delete</param>
        Task<bool> DeleteMessageAsync(string messageId);

        /// <summary>
        /// Marks a message as read on the server.
        /// </summary>
        /// <param name="messageId">The message ID to mark as read</param>
        Task<bool> MarkMessageAsReadAsync(string messageId);
    }
}