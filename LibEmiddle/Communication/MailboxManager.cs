using System.Collections.Concurrent;
using E2EELibrary.Core;
using E2EELibrary.Models;
using E2EELibrary.Encryption;
using E2EELibrary.KeyExchange;
using E2EELibrary.KeyManagement;
using E2EELibrary.Communication.Abstract;

namespace E2EELibrary.Communication
{
    /// <summary>
    /// Manages sending and receiving messages via an asynchronous mailbox system.
    /// Integrates seamlessly with the existing E2EELibrary components.
    /// </summary>
    /// <remarks>
    /// Creates a new mailbox manager.
    /// </remarks>
    /// <param name="identityKeyPair">The user's identity key pair</param>
    /// <param name="transport">The transport implementation to use</param>
    public class MailboxManager((byte[] publicKey, byte[] privateKey) identityKeyPair, IMailboxTransport transport) : IDisposable
    {
        private readonly (byte[] publicKey, byte[] privateKey) _identityKeyPair = identityKeyPair;
        private readonly IMailboxTransport _transport = transport ?? throw new ArgumentNullException(nameof(transport));
        private readonly CancellationTokenSource _cts = new CancellationTokenSource();
        private readonly ConcurrentDictionary<string, DoubleRatchetSession> _sessions =
            new ConcurrentDictionary<string, DoubleRatchetSession>();
        private readonly ConcurrentQueue<MailboxMessage> _outgoingQueue = new ConcurrentQueue<MailboxMessage>();
        private readonly ConcurrentDictionary<string, MailboxMessage> _incomingMessages =
            new ConcurrentDictionary<string, MailboxMessage>();

        private Task? _pollingTask;
        private Task? _sendingTask;
        private TimeSpan _pollingInterval = TimeSpan.FromSeconds(30);
        private bool _isRunning = false;
        private bool _autoSendReceipts = true;
        private readonly SemaphoreSlim _syncLock = new SemaphoreSlim(1, 1);

        /// <summary>
        /// Event raised when a new message is received.
        /// </summary>
        public event EventHandler<MailboxMessageEventArgs>? MessageReceived;

        /// <summary>
        /// Starts the mailbox manager (polling and sending)
        /// </summary>
        public void Start()
        {
            _syncLock.Wait();
            try
            {
                if (_isRunning)
                    return;

                _isRunning = true;
                _pollingTask = Task.Run(() => PollForMessagesAsync(_cts.Token));
                _sendingTask = Task.Run(() => ProcessOutgoingMessagesAsync(_cts.Token));
            }
            finally
            {
                _syncLock.Release();
            }
        }

        /// <summary>
        /// Stops the mailbox manager.
        /// </summary>
        public void Stop()
        {
            _syncLock.Wait();
            try
            {
                if (!_isRunning)
                    return;

                _cts.Cancel();
                _isRunning = false;

                // Wait for tasks to complete if they exist
                if (_pollingTask != null && _sendingTask != null)
                {
                    try
                    {
                        Task.WaitAll(new[] { _pollingTask, _sendingTask }, TimeSpan.FromSeconds(5));
                    }
                    catch (AggregateException)
                    {
                        // Tasks may be canceled
                    }
                }
            }
            finally
            {
                _syncLock.Release();
            }
        }

        /// <summary>
        /// Sets the polling interval.
        /// </summary>
        /// <param name="interval">The new polling interval</param>
        /// <param name="forTesting">Set to true to bypass the minimum interval check for testing purposes</param>
        public void SetPollingInterval(TimeSpan interval, bool forTesting = false)
        {
            // In production code, enforce a reasonable minimum to avoid excessive polling
            // For tests, allow shorter intervals when forTesting flag is set
            if (!forTesting && interval < TimeSpan.FromSeconds(5))
                throw new ArgumentException("Polling interval cannot be less than 5 seconds", nameof(interval));

            _pollingInterval = interval;
        }

        /// <summary>
        /// Sets whether to automatically send delivery and read receipts.
        /// </summary>
        /// <param name="autoSend">Whether to auto-send receipts</param>
        public void SetAutoSendReceipts(bool autoSend)
        {
            _autoSendReceipts = autoSend;
        }

        /// <summary>
        /// Enhanced message validation before processing
        /// </summary>
        /// <param name="message">Message to validate</param>
        /// <returns>True if message is valid</returns>
        private bool ValidateIncomingMessage(MailboxMessage message)
        {
            if (message == null)
                return false;

            if (message.EncryptedPayload == null ||
                message.RecipientKey == null ||
                message.SenderKey == null)
                return false;

            // Validate recipient is indeed us
            if (!SecureMemory.SecureCompare(message.RecipientKey, _identityKeyPair.publicKey))
                return false;

            // Check the encrypted payload
            if (!message.EncryptedPayload.Validate())
                return false;

            // Check for expired messages
            if (message.IsExpired())
                return false;

            // Check for suspiciously old messages
            long currentTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            if (currentTime - message.Timestamp > TimeSpan.FromDays(7).TotalMilliseconds)
                return false;

            return true;
        }

        /// <summary>
        /// Sends a message to a recipient using Double Ratchet encryption.
        /// </summary>
        /// <param name="recipientKey">The recipient's public key</param>
        /// <param name="message">The message to send</param>
        /// <param name="messageType">The type of message</param>
        /// <param name="timeToLive">How long the message should be valid (0 for no expiration)</param>
        /// <returns>The message ID</returns>
        public string SendMessage(byte[] recipientKey, string message, Enums.MessageType messageType = Enums.MessageType.Chat, long timeToLive = 0)
        {
            if (recipientKey == null || recipientKey.Length == 0)
                throw new ArgumentException("Recipient key cannot be null or empty", nameof(recipientKey));

            if (string.IsNullOrEmpty(message))
                throw new ArgumentException("Message cannot be null or empty", nameof(message));

            // Get or create session for this recipient
            string recipientId = Convert.ToBase64String(recipientKey);
            DoubleRatchetSession session = GetOrCreateSession(recipientId, recipientKey);

            // Encrypt the message
            var (updatedSession, encryptedPayload) = DoubleRatchet.DoubleRatchetEncrypt(session, message);

            // Update the session
            _sessions[recipientId] = updatedSession;

            // Create the mailbox message
            var mailboxMessage = new MailboxMessage
            {
                RecipientKey = recipientKey,
                SenderKey = _identityKeyPair.publicKey,
                EncryptedPayload = encryptedPayload,
                Type = messageType,
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
            };

            // Set expiration if requested
            if (timeToLive > 0)
            {
                mailboxMessage.ExpiresAt = mailboxMessage.Timestamp + timeToLive;
            }

            // Add to outgoing queue
            _outgoingQueue.Enqueue(mailboxMessage);

            return mailboxMessage.MessageId;
        }

        /// <summary>
        /// Gets all incoming messages.
        /// </summary>
        /// <param name="messageType">Optional type filter</param>
        /// <param name="onlyUnread">Whether to get only unread messages</param>
        /// <returns>List of messages with their decrypted content</returns>
        public List<(MailboxMessage Message, string? Content)> GetMessages(Enums.MessageType? messageType = null, bool onlyUnread = false)
        {
            var results = new List<(MailboxMessage, string?)>();

            foreach (var message in _incomingMessages.Values)
            {
                // Apply filters
                if (messageType.HasValue && message.Type != messageType.Value)
                    continue;

                if (onlyUnread && message.IsRead)
                    continue;

                // Try to decrypt the message
                string? content = null;
                try
                {
                    // Get session for this sender
                    string senderId = Convert.ToBase64String(message.SenderKey);
                    if (_sessions.TryGetValue(senderId, out var session))
                    {
                        var (updatedSession, decryptedMessage) = DoubleRatchet.DoubleRatchetDecrypt(
                            session, message.EncryptedPayload);

                        if (updatedSession != null && decryptedMessage != null)
                        {
                            // Update session
                            _sessions[senderId] = updatedSession;
                            content = decryptedMessage;
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"Error decrypting message {message.MessageId}: {ex.Message}");
                }

                results.Add((message, content));
            }

            return results;
        }

        /// <summary>
        /// Marks a message as read.
        /// </summary>
        /// <param name="messageId">The message ID</param>
        /// <returns>True if the message was marked as read</returns>
        public async Task<bool> MarkMessageAsReadAsync(string messageId)
        {
            if (_incomingMessages.TryGetValue(messageId, out var message))
            {
                message.IsRead = true;
                message.ReadAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

                // Send read receipt if enabled
                if (_autoSendReceipts)
                {
                    try
                    {
                        SendReceipt(message, isDeliveryReceipt: false);
                    }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine($"Error sending read receipt: {ex.Message}");
                    }
                }

                // Update on server
                try
                {
                    await _transport.MarkMessageAsReadAsync(messageId);
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"Error marking message as read on server: {ex.Message}");
                }

                return true;
            }

            return false;
        }

        /// <summary>
        /// Deletes a message.
        /// </summary>
        /// <param name="messageId">The message ID</param>
        /// <returns>True if the message was deleted</returns>
        public async Task<bool> DeleteMessageAsync(string messageId)
        {
            // First check if we even have this message locally
            if (!_incomingMessages.ContainsKey(messageId))
            {
                return false;
            }

            try
            {
                // Attempt to delete from server first
                bool serverRemoved = await _transport.DeleteMessageAsync(messageId);

                // Then remove from local collection if server deletion succeeded
                if (serverRemoved)
                {
                    _incomingMessages.TryRemove(messageId, out _);
                }

                return serverRemoved;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error deleting message on server: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Gets or creates a session for a contact.
        /// </summary>
        private DoubleRatchetSession GetOrCreateSession(string contactId, byte[] contactKey)
        {
            if (_sessions.TryGetValue(contactId, out var session))
            {
                return session;
            }

            // Create a new session
            // In a real system, you'd perform a proper key exchange first
            // This is a simplified implementation for integration purposes

            // Convert to X25519 for key exchange if needed
            byte[] x25519PrivateKey = _identityKeyPair.privateKey.Length != Constants.X25519_KEY_SIZE ?
                KeyConversion.DeriveX25519PrivateKeyFromEd25519(_identityKeyPair.privateKey) :
                _identityKeyPair.privateKey;

            // Ensure contact key is in X25519 format
            byte[] contactX25519Key = contactKey.Length != Constants.X25519_KEY_SIZE ?
                KeyConversion.DeriveX25519PublicKeyFromEd25519(contactKey) :
                contactKey;

            // Perform key exchange  
            byte[] sharedSecret = X3DHExchange.X3DHKeyExchange(contactX25519Key, x25519PrivateKey);

            // Initialize Double Ratchet
            var (rootKey, chainKey) = DoubleRatchetExchange.InitializeDoubleRatchet(sharedSecret);

            // Create a session with a unique ID
            string sessionId = $"session-{contactId}-{Guid.NewGuid()}";

            session = new DoubleRatchetSession(
                dhRatchetKeyPair: (_identityKeyPair.publicKey, x25519PrivateKey),
                remoteDHRatchetKey: contactX25519Key,
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumber: 0,
                sessionId: sessionId
            );

            // Store the session
            _sessions[contactId] = session;

            return session;
        }

        /// <summary>
        /// Returns true if the message isnt expired.
        /// </summary>
        /// <param name="message"></param>
        /// <returns></returns>
        protected virtual bool ShouldProcessMessage(MailboxMessage message)
        {
            // Skip expired messages
            if (message.IsExpired())
                return false;

            // Check other validation criteria
            return ValidateIncomingMessage(message);
        }

        /// <summary>
        /// Polls for new messages from the server.
        /// </summary>
        /// <param name="cancellationToken">The cancel token</param>
        private async Task PollForMessagesAsync(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    // Fetch new messages
                    var messages = await _transport.FetchMessagesAsync(_identityKeyPair.publicKey, cancellationToken);

                    foreach (var message in messages)
                    {
                        // Use the protected method for filtering
                        if (!ShouldProcessMessage(message))
                            continue;

                        // Add to our local store if it's new
                        if (_incomingMessages.TryAdd(message.MessageId, message))
                        {
                            // Mark as delivered
                            message.IsDelivered = true;
                            message.DeliveredAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

                            // Send delivery receipt if enabled
                            if (_autoSendReceipts)
                            {
                                try
                                {
                                    SendReceipt(message, isDeliveryReceipt: true);
                                }
                                catch (Exception ex)
                                {
                                    Console.Error.WriteLine($"Error sending delivery receipt: {ex.Message}");
                                }
                            }

                            // Raise event
                            OnMessageReceived(message);
                        }
                    }

                    // Wait for next poll
                    await Task.Delay(_pollingInterval, cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    break; // Cancellation requested
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"Error polling for messages: {ex.Message}");

                    try
                    {
                        // Wait longer after error
                        await Task.Delay(TimeSpan.FromMinutes(1), cancellationToken);
                    }
                    catch (OperationCanceledException)
                    {
                        break; // Cancellation requested
                    }
                }
            }
        }

        /// <summary>
        /// Processes outgoing messages.
        /// </summary>
        /// <param name="cancellationToken">The cancel token</param>
        private async Task ProcessOutgoingMessagesAsync(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    // Process up to 10 messages at a time
                    for (int i = 0; i < 10; i++)
                    {
                        if (cancellationToken.IsCancellationRequested)
                            break;

                        if (!_outgoingQueue.TryDequeue(out var message))
                            break; // No more messages

                        // Skip expired messages
                        if (message.IsExpired())
                            continue;

                        // Send the message
                        bool success = await _transport.SendMessageAsync(message);

                        // If failed, re-queue (unless expired)
                        if (!success && !message.IsExpired())
                        {
                            _outgoingQueue.Enqueue(message);
                        }
                    }

                    // Wait before checking again
                    await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    break; // Cancellation requested
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"Error sending messages: {ex.Message}");

                    try
                    {
                        // Wait longer after error
                        await Task.Delay(TimeSpan.FromSeconds(30), cancellationToken);
                    }
                    catch (OperationCanceledException)
                    {
                        break; // Cancellation requested
                    }
                }
            }
        }

        /// <summary>
        /// Sends a delivery or read receipt.
        /// </summary>
        private void SendReceipt(MailboxMessage originalMessage, bool isDeliveryReceipt)
        {
            // Create receipt data
            var receiptData = new
            {
                messageId = originalMessage.MessageId,
                timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                type = isDeliveryReceipt ? "delivery" : "read"
            };

            // Serialize to JSON
            string json = System.Text.Json.JsonSerializer.Serialize(receiptData);

            // Send as a normal message
            Enums.MessageType receiptType = isDeliveryReceipt ? Enums.MessageType.DeliveryReceipt : Enums.MessageType.ReadReceipt;
            SendMessage(originalMessage.SenderKey, json, receiptType);
        }

        /// <summary>
        /// Raises the MessageReceived event.
        /// </summary>
        protected virtual void OnMessageReceived(MailboxMessage message)
        {
            MessageReceived?.Invoke(this, new MailboxMessageEventArgs(message));
        }

        /// <summary>
        /// Disposes resources.
        /// </summary>
        public void Dispose()
        {
            Stop();
            _cts.Dispose();
            _syncLock.Dispose();
        }

        /// <summary>
        /// Gets statistics about the mailbox manager.
        /// </summary>
        public Dictionary<string, object> GetStatistics()
        {
            return new Dictionary<string, object>
            {
                ["totalIncomingMessages"] = _incomingMessages.Count,
                ["pendingOutgoingMessages"] = _outgoingQueue.Count,
                ["unreadMessages"] = _incomingMessages.Values.Count(m => !m.IsRead),
                ["activeSessions"] = _sessions.Count
            };
        }

        /// <summary>
        /// Exports a session for a recipient.
        /// </summary>
        /// <param name="recipientId">The recipient ID (Base64 of their public key)</param>
        /// <param name="encryptionKey">Optional key to encrypt the session data</param>
        /// <returns>Serialized session data</returns>
        public byte[] ExportSession(string recipientId, byte[]? encryptionKey = null)
        {
            if (!_sessions.TryGetValue(recipientId, out var session))
                throw new KeyNotFoundException($"No session found for recipient {recipientId}");

            return SessionPersistence.SerializeSession(session, encryptionKey);
        }

        /// <summary>
        /// Imports a session for a recipient.
        /// </summary>
        /// <param name="recipientId">The recipient ID (Base64 of their public key)</param>
        /// <param name="sessionData">The serialized session data</param>
        /// <param name="decryptionKey">Optional key to decrypt the session data</param>
        /// <returns>True if the session was imported successfully</returns>
        public bool ImportSession(string recipientId, byte[] sessionData, byte[]? decryptionKey = null)
        {
            try
            {
                var session = SessionPersistence.DeserializeSession(sessionData, decryptionKey);

                if (session != null && DoubleRatchetExchange.ValidateSession(session))
                {
                    _sessions[recipientId] = session;
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error importing session: {ex.Message}");
                return false;
            }
        }
    }

    /// <summary>
    /// Event arguments for mailbox message events.
    /// </summary>
    public class MailboxMessageEventArgs : EventArgs
    {
        /// <summary>
        /// The received message
        /// </summary>
        public MailboxMessage Message { get; }

        /// <summary>
        /// Creates new event arguments.
        /// </summary>
        /// <param name="message">The received message</param>
        public MailboxMessageEventArgs(MailboxMessage message)
        {
            Message = message;
        }
    }
}