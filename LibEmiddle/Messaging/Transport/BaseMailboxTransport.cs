using LibEmiddle.Abstractions;
using LibEmiddle.Domain;
using LibEmiddle.Core;

namespace LibEmiddle.Messaging.Transport;

/// <summary>
/// Base abstract class for mailbox transport implementations.
/// Provides common functionality for different transport mechanisms.
/// </summary>
/// <remarks>
/// Initializes a new instance of the BaseMailboxTransport class.
/// </remarks>
/// <param name="cryptoProvider">Crypto provider for encryption operations.</param>
/// <exception cref="ArgumentNullException">Thrown if any required parameters are null.</exception>
public abstract class BaseMailboxTransport(ICryptoProvider cryptoProvider) : IMailboxTransport, IDisposable
{
    /// <summary>
    /// Crypto provider for encryption/decryption operations.
    /// </summary>
    protected readonly ICryptoProvider _cryptoProvider = cryptoProvider ?? throw new ArgumentNullException(nameof(cryptoProvider));

    /// <summary>
    /// Tracks whether this object has been disposed.
    /// </summary>
    private bool _disposed;

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
    /// <exception cref="ObjectDisposedException">Thrown if the object has been disposed.</exception>
    public virtual async Task<bool> SendMessageAsync(MailboxMessage message)
    {
        ThrowIfDisposed();

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
    /// <exception cref="ObjectDisposedException">Thrown if the object has been disposed.</exception>
    public virtual async Task<List<MailboxMessage>> FetchMessagesAsync(byte[] recipientKey, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

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
    /// <exception cref="ObjectDisposedException">Thrown if the object has been disposed.</exception>
    public virtual async Task<bool> DeleteMessageAsync(string messageId)
    {
        ThrowIfDisposed();

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
    /// <exception cref="ObjectDisposedException">Thrown if the object has been disposed.</exception>
    public virtual async Task<bool> MarkMessageAsReadAsync(string messageId)
    {
        ThrowIfDisposed();

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
    /// <exception cref="ObjectDisposedException">Thrown if the object has been disposed.</exception>
    public virtual async Task StartListeningAsync(byte[] localIdentityKey, int pollingInterval = 5000, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        if (pollingInterval < 1000)
        {
            LoggingManager.LogWarning(nameof(BaseMailboxTransport), $"Polling interval is set to {pollingInterval}ms which may cause excessive resource usage. " +
                              "Recommended minimum is 1000ms.");
        }

        LoggingManager.LogInformation(nameof(BaseMailboxTransport), $"Starting mailbox polling with interval: {pollingInterval}ms");

        await StartListeningInternalAsync(localIdentityKey, pollingInterval, cancellationToken);
    }

    /// <summary>
    /// Helper method that provides a standard polling loop implementation for transport classes.
    /// </summary>
    /// <param name="localIdentityKey">The identity key of the user.</param>
    /// <param name="pollingInterval">Interval in milliseconds to poll for new messages.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    /// <param name="pollingCts">Cancellation token source for the polling operation (will be created if null).</param>
    /// <returns>A task representing the asynchronous polling operation.</returns>
    /// <remarks>
    /// This helper method provides the common polling loop logic used by transport implementations.
    /// It handles:
    /// <list type="bullet">
    /// <item><description>Continuous polling at the specified interval</description></item>
    /// <item><description>Message fetching and validation</description></item>
    /// <item><description>Event notifications for received messages</description></item>
    /// <item><description>Automatic mark-as-read after processing</description></item>
    /// <item><description>Error handling with retry logic</description></item>
    /// <item><description>Graceful shutdown on cancellation</description></item>
    /// </list>
    /// </remarks>
    protected Task StartPollingLoopAsync(
        byte[] localIdentityKey,
        int pollingInterval,
        CancellationToken cancellationToken,
        CancellationTokenSource? pollingCts = null)
    {
        // Create linked cancellation token if not provided
        pollingCts ??= CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var linkedToken = pollingCts.Token;

        // Start polling task
        _ = Task.Run(async () =>
        {
            try
            {
                while (!linkedToken.IsCancellationRequested)
                {
                    try
                    {
                        // Fetch messages
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
                        string transportName = GetType().Name;
                        LoggingManager.LogError(transportName, "Error during message polling", ex);

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
                string transportName = GetType().Name;
                LoggingManager.LogError(transportName, "Fatal error in polling loop", ex);
            }

            string finalTransportName = GetType().Name;
            LoggingManager.LogInformation(finalTransportName, "Message polling stopped");
        }, linkedToken);

        string currentTransportName = GetType().Name;
        LoggingManager.LogInformation(currentTransportName, "Started mailbox polling");

        return Task.CompletedTask;
    }

    /// <summary>
    /// Implementation-specific method to start listening for incoming messages.
    /// </summary>
    /// <param name="localIdentityKey">The identity key of the user.</param>
    /// <param name="pollingInterval">Interval in milliseconds to poll for new messages.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    /// <remarks>
    /// <para>
    /// <strong>Implementation Guidance:</strong>
    /// </para>
    /// <para>
    /// This method should implement a polling loop or push mechanism to monitor for new messages.
    /// The standard polling pattern is:
    /// </para>
    /// <code>
    /// protected override async Task StartListeningInternalAsync(
    ///     byte[] localIdentityKey,
    ///     int pollingInterval,
    ///     CancellationToken cancellationToken)
    /// {
    ///     await StartPollingLoopAsync(localIdentityKey, pollingInterval, cancellationToken);
    /// }
    /// </code>
    /// <para>
    /// For custom implementations, use the <see cref="StartPollingLoopAsync"/> helper method which handles:
    /// <list type="bullet">
    /// <item><description>Polling loop management</description></item>
    /// <item><description>Message fetching and validation</description></item>
    /// <item><description>Event raising</description></item>
    /// <item><description>Error handling and recovery</description></item>
    /// <item><description>Graceful cancellation</description></item>
    /// </list>
    /// </para>
    /// </remarks>
    protected abstract Task StartListeningInternalAsync(byte[] localIdentityKey, int pollingInterval, CancellationToken cancellationToken);

    /// <summary>
    /// Stops listening for incoming messages.
    /// </summary>
    /// <returns>A task representing the asynchronous operation.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the object has been disposed.</exception>
    public virtual async Task StopListeningAsync()
    {
        ThrowIfDisposed();

        LoggingManager.LogInformation(nameof(BaseMailboxTransport), "Stopping mailbox polling");
        await StopListeningInternalAsync();
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
    /// <exception cref="ObjectDisposedException">Thrown if the object has been disposed.</exception>
    public virtual async Task<bool> UpdateDeliveryStatusAsync(string messageId, bool isDelivered)
    {
        ThrowIfDisposed();

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

    /// <summary>
    /// Throws an ObjectDisposedException if this instance has been disposed.
    /// </summary>
    /// <exception cref="ObjectDisposedException">Thrown if the object has been disposed.</exception>
    protected void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(GetType().Name);
        }
    }

    /// <summary>
    /// Releases all resources used by the BaseMailboxTransport.
    /// </summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Releases the unmanaged resources used by the BaseMailboxTransport and optionally releases the managed resources.
    /// </summary>
    /// <param name="disposing">true to release both managed and unmanaged resources; false to release only unmanaged resources.</param>
    protected virtual void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (disposing)
            {
                // Clear event handlers to prevent memory leaks
                MessageReceived = null;

                // Stop any listening operations
                try
                {
                    StopListeningAsync().ConfigureAwait(false).GetAwaiter().GetResult();
                }
                catch (Exception ex)
                {
                    LoggingManager.LogError(nameof(BaseMailboxTransport), "Error stopping listening during disposal", ex);
                }

                // Dispose managed resources in derived classes
                DisposeManagedResources();
            }

            // Dispose unmanaged resources in derived classes
            DisposeUnmanagedResources();

            _disposed = true;
        }
    }

    /// <summary>
    /// Override this method in derived classes to dispose of managed resources.
    /// </summary>
    protected virtual void DisposeManagedResources()
    {
        // Base implementation does nothing - override in derived classes
    }

    /// <summary>
    /// Override this method in derived classes to dispose of unmanaged resources.
    /// </summary>
    protected virtual void DisposeUnmanagedResources()
    {
        // Base implementation does nothing - override in derived classes
    }
}