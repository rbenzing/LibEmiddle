﻿using System.Collections.Concurrent;
using LibEmiddle.Abstractions;
using LibEmiddle.Core;
using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;

namespace LibEmiddle.Messaging.Transport
{
    /// <summary>
    /// Manages sending and receiving messages via an asynchronous mailbox system.
    /// Integrates seamlessly with the existing LibEmiddle components.
    /// </summary>
    /// <remarks>
    /// Creates a new mailbox manager.
    /// </remarks>
    /// <param name="identityKeyPair">The user's identity key pair</param>
    /// <param name="doubleRatchet">The double ratchet protocol implementation to use</param>
    /// <param name="transport">The transport implementation to use</param>
    /// <param name="cryptoProvider">The crypto provider implementation to use</param>
    public class MailboxManager(KeyPair identityKeyPair, IMailboxTransport transport, IDoubleRatchetProtocol doubleRatchet, ICryptoProvider cryptoProvider) : IDisposable
    {
        private readonly KeyPair _identityKeyPair = identityKeyPair;

        private readonly IDoubleRatchetProtocol _doubleRatchetProtocol = doubleRatchet ?? throw new ArgumentNullException(nameof(doubleRatchet));
        private readonly IMailboxTransport _mailboxTransport = transport ?? throw new ArgumentNullException(nameof(transport));
        private readonly ICryptoProvider _cryptoProvider = cryptoProvider ?? throw new ArgumentNullException(nameof(cryptoProvider));

        private readonly CancellationTokenSource _cts = new();
        private readonly ConcurrentDictionary<string, DoubleRatchetSession> _sessions = new();
        private readonly ConcurrentQueue<MailboxMessage> _outgoingQueue = new();
        private readonly ConcurrentDictionary<string, MailboxMessage> _incomingMessages = new();

        private Task? _pollingTask;
        private Task? _sendingTask;
        private TimeSpan _pollingInterval = TimeSpan.FromSeconds(30);
        private bool _isRunning = false;
        private bool _autoSendReceipts = true;
        private readonly SemaphoreSlim _syncLock = new(1, 1);

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
            if (!SecureMemory.SecureCompare(message.RecipientKey, _identityKeyPair.PublicKey))
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
        /// <param name="session">The double ratchet session.</param>
        /// <param name="messageType">The type of message</param>
        /// <param name="timeToLive">How long the message should be valid (0 for no expiration)</param>
        /// <returns>The message ID</returns>
        public string SendMessage(byte[] recipientKey, string message, DoubleRatchetSession session, MessageType messageType = MessageType.Chat, long timeToLive = 0)
        {
            if (recipientKey == null || recipientKey.Length == 0)
                throw new ArgumentException("Recipient key cannot be null or empty", nameof(recipientKey));

            if (string.IsNullOrEmpty(message))
                throw new ArgumentException("Message cannot be null or empty", nameof(message));

            // Get or create session for this recipient
            string recipientId = Convert.ToBase64String(recipientKey);

            // Encrypt the message
            var (updatedSession, encryptedPayload) = _doubleRatchetProtocol.EncryptAsync(session, message);

            ArgumentNullException.ThrowIfNull(updatedSession, nameof(updatedSession));
            ArgumentNullException.ThrowIfNull(encryptedPayload, nameof(encryptedPayload));

            // Update the session
            _sessions[recipientId] = updatedSession;

            // Create the mailbox message
            var mailboxMessage = new MailboxMessage(recipientKey, _identityKeyPair.PublicKey, encryptedPayload)
            {
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

            return mailboxMessage.Id;
        }

        /// <summary>
        /// Gets all incoming messages.
        /// </summary>
        /// <param name="messageType">Optional type filter</param>
        /// <param name="onlyUnread">Whether to get only unread messages</param>
        /// <returns>List of messages with their decrypted content</returns>
        public List<(MailboxMessage Message, string? Content)> GetMessages(MessageType? messageType = null, bool onlyUnread = false)
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
                        var (updatedSession, decryptedMessage) = _doubleRatchetProtocol.DecryptAsync(session, message.EncryptedPayload);

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
                    LoggingManager.LogError(nameof(MailboxManager), $"Error decrypting message {message.Id}: {ex.Message}");
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
                        LoggingManager.LogWarning(nameof(MailboxManager), $"Error sending read receipt: {ex.Message}");
                    }
                }

                // Update on server
                try
                {
                    await _mailboxTransport.MarkMessageAsReadAsync(messageId);
                }
                catch (Exception ex)
                {
                    LoggingManager.LogError(nameof(MailboxManager), $"Error marking message as read on server: {ex.Message}");
                }

                return true;
            }

            return false;
        }

        /// <summary>
        /// Async Sends a message.
        /// </summary>
        /// <param name="recipientKey"></param>
        /// <param name="message"></param>
        /// <param name="session"></param>
        /// <param name="messageType"></param>
        /// <param name="timeToLive"></param>
        /// <returns></returns>
        public async Task<string> SendMessageAsync(byte[] recipientKey, string message, DoubleRatchetSession session, MessageType messageType = MessageType.Chat, long timeToLive = 0)
        {
            return await Task.Run(() => SendMessage(recipientKey, message, session, messageType));
        }


        /// <summary>
        /// Async Deletes a message.
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
                bool serverRemoved = await _mailboxTransport.DeleteMessageAsync(messageId);

                // Then remove from local collection if server deletion succeeded
                if (serverRemoved)
                {
                    _incomingMessages.TryRemove(messageId, out _);
                }

                return serverRemoved;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(MailboxManager), $"Error deleting message on server: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Exports a session for a specific recipient.
        /// </summary>
        /// <param name="recipientId">The Base64-encoded recipient public key.</param>
        /// <param name="encryptionKey">Optional encryption key for the exported data.</param>
        /// <returns>The serialized session data.</returns>
        /// <exception cref="KeyNotFoundException">Thrown if session for the recipient doesn't exist.</exception>
        public byte[] ExportSession(string recipientId, byte[]? encryptionKey = null)
        {
            ArgumentException.ThrowIfNullOrEmpty(recipientId, nameof(recipientId));

            // Try to get session for this recipient from the sessions dictionary
            if (!_sessions.TryGetValue(recipientId, out var session))
            {
                throw new KeyNotFoundException($"No session found for recipient {recipientId}");
            }

            try
            {
                // Serialize the Double Ratchet session state
                var dto = new DoubleRatchetSessionDto
                {
                    SessionId = session.SessionId,
                    RootKey = Convert.ToBase64String(session.RootKey),
                    SenderChainKey = session.SenderChainKey != null ? Convert.ToBase64String(session.SenderChainKey) : null,
                    ReceiverChainKey = session.ReceiverChainKey != null ? Convert.ToBase64String(session.ReceiverChainKey) : null,
                    SenderRatchetKeyPair = new KeyPairDto
                    {
                        PublicKey = Convert.ToBase64String(session.SenderRatchetKeyPair.PublicKey),
                        PrivateKey = Convert.ToBase64String(session.SenderRatchetKeyPair.PrivateKey)
                    },
                    ReceiverRatchetPublicKey = session.ReceiverRatchetPublicKey != null ?
                        Convert.ToBase64String(session.ReceiverRatchetPublicKey) : null,
                    PreviousReceiverRatchetPublicKey = session.PreviousReceiverRatchetPublicKey != null ?
                        Convert.ToBase64String(session.PreviousReceiverRatchetPublicKey) : null,
                    SendMessageNumber = session.SendMessageNumber,
                    ReceiveMessageNumber = session.ReceiveMessageNumber,
                    SentMessages = session.SentMessages.ToDictionary(
                        kvp => kvp.Key,
                        kvp => Convert.ToBase64String(kvp.Value)
                    ),
                    SkippedMessageKeys = session.SkippedMessageKeys.ToDictionary(
                        kvp => new SkippedMessageKeyDto
                        {
                            DhPublicKey = Convert.ToBase64String(kvp.Key.DhPublicKey),
                            MessageNumber = kvp.Key.MessageNumber
                        },
                        kvp => Convert.ToBase64String(kvp.Value)
                    ),
                    IsInitialized = session.IsInitialized,
                    CreationTimestamp = session.CreationTimestamp
                };

                string json = JsonSerialization.Serialize(dto);
                byte[] data = System.Text.Encoding.Default.GetBytes(json);

                // If encryption is requested, encrypt the data
                if (encryptionKey != null)
                {
                    if (encryptionKey.Length != Constants.AES_KEY_SIZE)
                        throw new ArgumentException($"Encryption key must be {Constants.AES_KEY_SIZE} bytes", nameof(encryptionKey));

                    byte[] nonce = _cryptoProvider.GenerateRandomBytes(Constants.NONCE_SIZE);
                    byte[] encryptedData = _cryptoProvider.Encrypt(data, encryptionKey, nonce, null);

                    // Combine nonce and encrypted data for export
                    byte[] result = new byte[sizeof(int) + nonce.Length + encryptedData.Length];
                    using (var ms = new MemoryStream(result))
                    using (var writer = new BinaryWriter(ms))
                    {
                        writer.Write(nonce.Length);
                        writer.Write(nonce);
                        writer.Write(encryptedData);
                    }

                    return result;
                }

                return data;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(MailboxManager), $"Failed to export session for {recipientId}: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Imports a session for a specific recipient.
        /// </summary>
        /// <param name="recipientId">The Base64-encoded recipient public key.</param>
        /// <param name="sessionData">The serialized session data.</param>
        /// <param name="decryptionKey">Optional decryption key if the session data is encrypted.</param>
        /// <returns>True if the session was imported successfully.</returns>
        public bool ImportSession(string recipientId, byte[] sessionData, byte[]? decryptionKey = null)
        {
            ArgumentException.ThrowIfNullOrEmpty(recipientId, nameof(recipientId));
            ArgumentNullException.ThrowIfNull(sessionData, nameof(sessionData));

            try
            {
                byte[] dataToDeserialize = sessionData;

                // If decryption key provided, decrypt the data
                if (decryptionKey != null)
                {
                    if (decryptionKey.Length != Constants.AES_KEY_SIZE)
                        throw new ArgumentException($"Decryption key must be {Constants.AES_KEY_SIZE} bytes", nameof(decryptionKey));

                    try
                    {
                        // Extract nonce and encrypted data
                        using (var ms = new MemoryStream(sessionData))
                        using (var reader = new BinaryReader(ms))
                        {
                            int nonceLength = reader.ReadInt32();
                            byte[] nonce = reader.ReadBytes(nonceLength);
                            byte[] encryptedData = reader.ReadBytes((int)(ms.Length - ms.Position));

                            // Decrypt the data
                            dataToDeserialize = _cryptoProvider.Decrypt(encryptedData, decryptionKey, nonce, null);
                        }
                    }
                    catch (Exception ex)
                    {
                        LoggingManager.LogError(nameof(MailboxManager), $"Error decrypting session data: {ex.Message}");
                        return false;
                    }
                }

                // Deserialize the session data
                string json = System.Text.Encoding.UTF8.GetString(dataToDeserialize);
                var dto = JsonSerialization.Deserialize<DoubleRatchetSessionDto>(json);
                if (dto == null)
                {
                    LoggingManager.LogError(nameof(MailboxManager), "Failed to deserialize session data");
                    return false;
                }

                // Create the DoubleRatchetSession from DTO
                var session = new DoubleRatchetSession
                {
                    SessionId = dto.SessionId,
                    RootKey = Convert.FromBase64String(dto.RootKey),
                    SenderChainKey = dto.SenderChainKey != null ? Convert.FromBase64String(dto.SenderChainKey) : null,
                    ReceiverChainKey = dto.ReceiverChainKey != null ? Convert.FromBase64String(dto.ReceiverChainKey) : null,
                    SenderRatchetKeyPair = new KeyPair
                    {
                        PublicKey = Convert.FromBase64String(dto.SenderRatchetKeyPair.PublicKey),
                        PrivateKey = Convert.FromBase64String(dto.SenderRatchetKeyPair.PrivateKey)
                    },
                    ReceiverRatchetPublicKey = dto.ReceiverRatchetPublicKey != null ?
                        Convert.FromBase64String(dto.ReceiverRatchetPublicKey) : null,
                    PreviousReceiverRatchetPublicKey = dto.PreviousReceiverRatchetPublicKey != null ?
                        Convert.FromBase64String(dto.PreviousReceiverRatchetPublicKey) : null,
                    SendMessageNumber = dto.SendMessageNumber,
                    ReceiveMessageNumber = dto.ReceiveMessageNumber,
                    SentMessages = new Dictionary<uint, byte[]>(),
                    SkippedMessageKeys = new Dictionary<SkippedMessageKey, byte[]>(),
                    IsInitialized = dto.IsInitialized,
                    CreationTimestamp = dto.CreationTimestamp
                };

                // Reconstruct the dictionaries
                foreach (var kvp in dto.SentMessages)
                {
                    session.SentMessages[kvp.Key] = Convert.FromBase64String(kvp.Value);
                }

                foreach (var kvp in dto.SkippedMessageKeys)
                {
                    var key = new SkippedMessageKey(
                        Convert.FromBase64String(kvp.Key.DhPublicKey),
                        kvp.Key.MessageNumber
                    );
                    session.SkippedMessageKeys[key] = Convert.FromBase64String(kvp.Value);
                }

                // Add the session to our dictionary
                _sessions[recipientId] = session;

                LoggingManager.LogInformation(nameof(MailboxManager), $"Successfully imported session for {recipientId}");
                return true;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(MailboxManager), $"Failed to import session for {recipientId}: {ex.Message}");
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

            // Convert to X25519 for key exchange if needed
            byte[] x25519PrivateKey = _identityKeyPair.PrivateKey.Length != Constants.X25519_KEY_SIZE ?
                Sodium.ConvertEd25519PrivateKeyToX25519(_identityKeyPair.PrivateKey).ToArray() :
                _identityKeyPair.PrivateKey;

            // Ensure contact key is in X25519 format
            byte[] contactX25519Key = contactKey.Length != Constants.X25519_KEY_SIZE ?
                Sodium.ConvertEd25519PublicKeyToX25519(contactKey).ToArray() :
                contactKey;

            // Perform key exchange  
            byte[] sharedSecret = Sodium.HkdfDerive(contactX25519Key, x25519PrivateKey);

            // Create a session with a unique ID
            string sessionId = $"session-{contactId}-{Guid.NewGuid()}";

            // Initialize Double Ratchet
            DoubleRatchetSession drSession = _doubleRatchetProtocol.InitializeSessionAsSender(sharedSecret,
                contactX25519Key, sessionId);
            
            // Store the session
            _sessions[contactId] = drSession;

            return drSession;
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
                    var messages = await _mailboxTransport.FetchMessagesAsync(_identityKeyPair.PublicKey, cancellationToken);

                    foreach (var message in messages)
                    {
                        // Use the protected method for filtering
                        if (!ShouldProcessMessage(message))
                            continue;

                        // Add to our local store if it's new
                        if (_incomingMessages.TryAdd(message.Id, message))
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
                                    LoggingManager.LogError(nameof(MailboxManager), $"Error sending delivery receipt: {ex.Message}");
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
                    LoggingManager.LogError(nameof(MailboxManager), $"Error polling for messages: {ex.Message}");

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
                        bool success = await _mailboxTransport.SendMessageAsync(message);

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
                    LoggingManager.LogError(nameof(MailboxManager), $"Error sending messages: {ex.Message}");

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
                messageId = originalMessage.Id,
                timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                type = isDeliveryReceipt ? "delivery" : "read"
            };

            // Serialize to JSON
            string json = System.Text.Json.JsonSerializer.Serialize(receiptData);

            var messageType = isDeliveryReceipt ? MessageType.DeliveryReceipt : MessageType.ReadReceipt;
            string senderId = Convert.ToBase64String(originalMessage.SenderKey);
            DoubleRatchetSession session = GetOrCreateSession(senderId, originalMessage.SenderKey);

            // Send as a normal message
            SendMessage(originalMessage.SenderKey, json, session, messageType);
        }

        /// <summary>
        /// Raises the MessageReceived event.
        /// </summary>
        protected virtual void OnMessageReceived(MailboxMessage message)
        {
            MessageReceived?.Invoke(this, new MailboxMessageEventArgs(message));
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
        /// Disposes resources.
        /// </summary>
        public void Dispose()
        {
            Stop();
            _cts.Dispose();
            _syncLock.Dispose();
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