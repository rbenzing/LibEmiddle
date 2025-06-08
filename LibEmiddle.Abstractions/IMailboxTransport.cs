using LibEmiddle.Domain;

namespace LibEmiddle.Abstractions;

/// <summary>
/// Defines the contract for mailbox transport implementations that handle
/// sending, receiving, and managing encrypted messages through various transport mechanisms.
/// </summary>
/// <remarks>
/// This interface provides the core functionality for message transport in the LibEmiddle
/// end-to-end encryption library. Implementations handle the actual transport layer
/// communication while the base transport class manages common functionality like
/// validation, logging, and event handling.
/// </remarks>
public interface IMailboxTransport : IDisposable
{
    /// <summary>
    /// Event raised when new messages are received from the transport layer.
    /// </summary>
    /// <remarks>
    /// Subscribers should handle exceptions in their event handlers as unhandled
    /// exceptions may disrupt the message receiving process.
    /// </remarks>
    event EventHandler<MailboxMessageReceivedEventArgs>? MessageReceived;

    /// <summary>
    /// Sends a message to a remote mailbox asynchronously.
    /// </summary>
    /// <param name="message">The mailbox message to send containing encrypted payload and routing information.</param>
    /// <returns>
    /// A task that represents the asynchronous send operation.
    /// The task result is true if the message was sent successfully; otherwise, false.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="message"/> is null.</exception>
    /// <exception cref="ObjectDisposedException">Thrown when the transport has been disposed.</exception>
    /// <remarks>
    /// The message should already be encrypted and signed before calling this method.
    /// Transport implementations are responsible for handling network failures and retries
    /// according to their specific requirements.
    /// </remarks>
    Task<bool> SendMessageAsync(MailboxMessage message);

    /// <summary>
    /// Fetches messages from a remote mailbox for a specific recipient asynchronously.
    /// </summary>
    /// <param name="recipientKey">The public key identifying the recipient's mailbox.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>
    /// A task that represents the asynchronous fetch operation.
    /// The task result contains a list of mailbox messages for the specified recipient.
    /// Returns an empty list if no messages are available or an error occurs.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="recipientKey"/> is null or empty.</exception>
    /// <exception cref="ObjectDisposedException">Thrown when the transport has been disposed.</exception>
    /// <exception cref="OperationCanceledException">Thrown when the operation is cancelled via the <paramref name="cancellationToken"/>.</exception>
    /// <remarks>
    /// This method performs validation on retrieved messages and filters out invalid ones.
    /// The returned messages are still encrypted and require decryption by the calling code.
    /// </remarks>
    Task<List<MailboxMessage>> FetchMessagesAsync(byte[] recipientKey, CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes a message from a remote mailbox asynchronously.
    /// </summary>
    /// <param name="messageId">The unique identifier of the message to delete.</param>
    /// <returns>
    /// A task that represents the asynchronous delete operation.
    /// The task result is true if the message was deleted successfully; otherwise, false.
    /// </returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="messageId"/> is null or empty.</exception>
    /// <exception cref="ObjectDisposedException">Thrown when the transport has been disposed.</exception>
    /// <remarks>
    /// This operation is typically performed after successfully processing a received message.
    /// If the message doesn't exist, implementations should return true to maintain idempotency.
    /// </remarks>
    Task<bool> DeleteMessageAsync(string messageId);

    /// <summary>
    /// Marks a message as read in a remote mailbox asynchronously.
    /// </summary>
    /// <param name="messageId">The unique identifier of the message to mark as read.</param>
    /// <returns>
    /// A task that represents the asynchronous mark-as-read operation.
    /// The task result is true if the message was marked as read successfully; otherwise, false.
    /// </returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="messageId"/> is null or empty.</exception>
    /// <exception cref="ObjectDisposedException">Thrown when the transport has been disposed.</exception>
    /// <remarks>
    /// This operation provides read receipt functionality and helps with message state management.
    /// If the message doesn't exist, implementations should return true to maintain idempotency.
    /// </remarks>
    Task<bool> MarkMessageAsReadAsync(string messageId);

    /// <summary>
    /// Starts listening for incoming messages asynchronously.
    /// </summary>
    /// <param name="localIdentityKey">The identity key of the local user for message filtering and routing.</param>
    /// <param name="pollingInterval">The interval in milliseconds between polling operations. Default is 5000ms.</param>
    /// <param name="cancellationToken">A token to cancel the listening operation.</param>
    /// <returns>A task that represents the asynchronous listening operation.</returns>
    /// <exception cref="ObjectDisposedException">Thrown when the transport has been disposed.</exception>
    /// <exception cref="OperationCanceledException">Thrown when the operation is cancelled via the <paramref name="cancellationToken"/>.</exception>
    /// <remarks>
    /// This method initiates continuous monitoring for new messages. Received messages will
    /// trigger the <see cref="MessageReceived"/> event. The actual implementation may use
    /// polling, WebSockets, or other push mechanisms depending on the transport type.
    /// A minimum polling interval of 1000ms is recommended to avoid excessive resource usage.
    /// </remarks>
    Task StartListeningAsync(byte[] localIdentityKey, int pollingInterval = 5000, CancellationToken cancellationToken = default);

    /// <summary>
    /// Stops listening for incoming messages asynchronously.
    /// </summary>
    /// <returns>A task that represents the asynchronous stop operation.</returns>
    /// <exception cref="ObjectDisposedException">Thrown when the transport has been disposed.</exception>
    /// <remarks>
    /// This method stops the message listening process initiated by <see cref="StartListeningAsync"/>.
    /// It should gracefully terminate any ongoing operations and clean up resources.
    /// </remarks>
    Task StopListeningAsync();

    /// <summary>
    /// Updates the delivery status of a message asynchronously.
    /// </summary>
    /// <param name="messageId">The unique identifier of the message.</param>
    /// <param name="isDelivered">True to mark the message as delivered; false to mark as undelivered.</param>
    /// <returns>
    /// A task that represents the asynchronous status update operation.
    /// The task result is true if the status was updated successfully; otherwise, false.
    /// </returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="messageId"/> is null or empty.</exception>
    /// <exception cref="ObjectDisposedException">Thrown when the transport has been disposed.</exception>
    /// <remarks>
    /// This method provides delivery confirmation functionality for message tracking.
    /// The delivery status helps with reliability guarantees and user experience features
    /// like delivery receipts in messaging applications.
    /// </remarks>
    Task<bool> UpdateDeliveryStatusAsync(string messageId, bool isDelivered);
}