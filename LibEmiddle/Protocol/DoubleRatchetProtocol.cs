using System.Security.Cryptography;
using System.Security;
using System.Text;
using LibEmiddle.Abstractions;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain.Enums;
using LibEmiddle.Domain;
using LibEmiddle.Domain.Exceptions;

namespace LibEmiddle.Protocol
{
    /// <summary>
    /// Implements the Signal Double Ratchet protocol for forward secrecy and break-in recovery
    /// in encrypted message exchanges.
    /// </summary>
    public class DoubleRatchetProtocol(int maxSkippedMessageKeys = 100) : IDoubleRatchetProtocol
    {
        private readonly int _maxSkippedMessageKeys = maxSkippedMessageKeys;

        /// <summary>
        /// Initializes a new Double Ratchet session as the sender (Alice) using the shared key from X3DH
        /// and the recipient's initial ratchet public key.
        /// </summary>
        /// <param name="sharedKeyFromX3DH">The 32-byte shared key derived from X3DH key exchange</param>
        /// <param name="recipientInitialPublicKey">The recipient's initial ratchet public key (X25519)</param>
        /// <param name="sessionId">Unique identifier for this session</param>
        /// <returns>The initialized DoubleRatchetSession object</returns>
        public DoubleRatchetSession InitializeSessionAsSender(
            byte[] sharedKeyFromX3DH,
            byte[] recipientInitialPublicKey,
            string sessionId)
        {
            ArgumentNullException.ThrowIfNull(sharedKeyFromX3DH, nameof(sharedKeyFromX3DH));
            ArgumentNullException.ThrowIfNull(recipientInitialPublicKey, nameof(recipientInitialPublicKey));
            ArgumentNullException.ThrowIfNull(sessionId, nameof(sessionId));

            if (sharedKeyFromX3DH.Length != 32)
                throw new ArgumentException("Shared key must be 32 bytes", nameof(sharedKeyFromX3DH));

            if (recipientInitialPublicKey.Length != Constants.X25519_KEY_SIZE)
                throw new ArgumentException("Recipient's initial public key has invalid size", nameof(recipientInitialPublicKey));

            // Generate our initial ratchet key pair
            var senderRatchetKeyPair = Sodium.GenerateX25519KeyPair();
            if (senderRatchetKeyPair.PrivateKey == null || senderRatchetKeyPair.PublicKey == null)
                throw new CryptographicException("Failed to generate sender's initial ratchet key pair");

            // FIXED: Use Signal-compliant single root seed derivation
            var (rootKey, initialChainKey) = Sodium.DeriveInitialSessionKeys(sharedKeyFromX3DH);

            // Calculate the first DH output using our private key and their public key
            byte[] dhResult = Sodium.ScalarMult(
                senderRatchetKeyPair.PrivateKey,
                recipientInitialPublicKey);

            try
            {
                // FIXED: Use Signal-compliant ratchet key derivation 
                var (newRootKey, senderChainKey) = Sodium.DeriveRatchetKeys(rootKey, dhResult);

                // Initialize session state
                var session = new DoubleRatchetSession
                {
                    SessionId = sessionId,
                    RootKey = newRootKey,
                    SenderChainKey = senderChainKey,
                    ReceiverChainKey = null, // Will be established when receiving messages
                    SenderRatchetKeyPair = senderRatchetKeyPair,
                    ReceiverRatchetPublicKey = recipientInitialPublicKey,
                    PreviousReceiverRatchetPublicKey = null,
                    SendMessageNumber = 0,
                    ReceiveMessageNumber = 0,
                    SentMessages = new Dictionary<uint, byte[]>(),
                    SkippedMessageKeys = new Dictionary<SkippedMessageKey, byte[]>(),
                    IsInitialized = true,
                    CreationTimestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                };

                return session;
            }
            finally
            {
                // Securely clear the DH result and intermediate keys
                SecureMemory.SecureClear(dhResult);
                SecureMemory.SecureClear(rootKey);
                SecureMemory.SecureClear(initialChainKey);
            }
        }

        /// <summary>
        /// Initializes a new Double Ratchet session as the receiver (Bob) using the shared key from X3DH,
        /// the receiver's initial ratchet key pair, and the sender's ephemeral key.
        /// </summary>
        /// <param name="sharedKeyFromX3DH">The 32-byte shared key derived from X3DH key exchange</param>
        /// <param name="receiverInitialKeyPair">The receiver's initial ratchet key pair (X25519)</param>
        /// <param name="senderEphemeralKeyPublic">The sender's ephemeral public key from X3DH</param>
        /// <param name="sessionId">Unique identifier for this session</param>
        /// <returns>The initialized DoubleRatchetSession object</returns>
        public DoubleRatchetSession InitializeSessionAsReceiver(
            byte[] sharedKeyFromX3DH,
            KeyPair receiverInitialKeyPair,
            byte[] senderEphemeralKeyPublic,
            string sessionId)
        {
            ArgumentNullException.ThrowIfNull(sharedKeyFromX3DH, nameof(sharedKeyFromX3DH));
            ArgumentNullException.ThrowIfNull(senderEphemeralKeyPublic, nameof(senderEphemeralKeyPublic));
            ArgumentNullException.ThrowIfNull(sessionId, nameof(sessionId));

            if (sharedKeyFromX3DH.Length != 32)
                throw new ArgumentException("Shared key must be 32 bytes", nameof(sharedKeyFromX3DH));

            if (receiverInitialKeyPair.PrivateKey == null || receiverInitialKeyPair.PublicKey == null ||
                receiverInitialKeyPair.PrivateKey.Length != Constants.X25519_KEY_SIZE ||
                receiverInitialKeyPair.PublicKey.Length != Constants.X25519_KEY_SIZE)
                throw new ArgumentException("Receiver's initial key pair is invalid", nameof(receiverInitialKeyPair));

            if (senderEphemeralKeyPublic.Length != Constants.X25519_KEY_SIZE)
                throw new ArgumentException("Sender's ephemeral public key has invalid size", nameof(senderEphemeralKeyPublic));

            // FIXED: Use Signal-compliant single root seed derivation 
            var (rootKey, initialChainKey) = Sodium.DeriveInitialSessionKeys(sharedKeyFromX3DH);

            // Initialize session state - receiver starts with no DH ratchet step yet
            var session = new DoubleRatchetSession
            {
                SessionId = sessionId,
                RootKey = rootKey,
                SenderChainKey = null, // Will be established when sending first message
                ReceiverChainKey = initialChainKey, // Start with initial chain key for receiving
                SenderRatchetKeyPair = receiverInitialKeyPair,
                ReceiverRatchetPublicKey = null, // Will be set when receiving first message
                PreviousReceiverRatchetPublicKey = null,
                SendMessageNumber = 0,
                ReceiveMessageNumber = 0,
                SentMessages = new Dictionary<uint, byte[]>(),
                SkippedMessageKeys = new Dictionary<SkippedMessageKey, byte[]>(),
                IsInitialized = true,
                CreationTimestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
            };

            return session;
        }

        /// <summary>
        /// Alternative 3-parameter overload for receiver initialization when sender ephemeral key
        /// is derived from the session context.
        /// </summary>
        /// <param name="sharedKeyFromX3DH">The 32-byte shared key derived from X3DH key exchange</param>
        /// <param name="senderRatchetPublicKey">The sender's ratchet public key</param>
        /// <param name="sessionId">Unique identifier for this session</param>
        /// <returns>The initialized DoubleRatchetSession object</returns>
        public DoubleRatchetSession InitializeSessionAsReceiver(
            byte[] sharedKeyFromX3DH,
            byte[] senderRatchetPublicKey,
            string sessionId)
        {
            ArgumentNullException.ThrowIfNull(sharedKeyFromX3DH, nameof(sharedKeyFromX3DH));
            ArgumentNullException.ThrowIfNull(senderRatchetPublicKey, nameof(senderRatchetPublicKey));
            ArgumentNullException.ThrowIfNull(sessionId, nameof(sessionId));

            if (sharedKeyFromX3DH.Length != 32)
                throw new ArgumentException("Shared key must be 32 bytes", nameof(sharedKeyFromX3DH));

            if (senderRatchetPublicKey.Length != Constants.X25519_KEY_SIZE)
                throw new ArgumentException("Sender's ratchet public key has invalid size", nameof(senderRatchetPublicKey));

            // Generate receiver's initial ratchet key pair
            var receiverInitialKeyPair = Sodium.GenerateX25519KeyPair();
            if (receiverInitialKeyPair.PrivateKey == null || receiverInitialKeyPair.PublicKey == null)
                throw new CryptographicException("Failed to generate receiver's initial ratchet key pair");

            // Call the main initialization method
            return InitializeSessionAsReceiver(
                sharedKeyFromX3DH,
                receiverInitialKeyPair,
                senderRatchetPublicKey,
                sessionId);
        }

        /// <summary>
        /// Encrypts a message using the Double Ratchet protocol and updates the session state.
        /// </summary>
        /// <param name="session">The current Double Ratchet session state</param>
        /// <param name="message">The plaintext message to encrypt</param>
        /// <param name="rotationStrategy">The key rotation strategy to use</param>
        /// <returns>A tuple containing the updated session state and the encrypted message</returns>
        public (DoubleRatchetSession, EncryptedMessage) Encrypt(
            DoubleRatchetSession session,
            string message,
            KeyRotationStrategy rotationStrategy = KeyRotationStrategy.Standard)
        {
            ArgumentNullException.ThrowIfNull(session, nameof(session));
            ArgumentException.ThrowIfNullOrEmpty(message, nameof(message));

            if (!session.IsInitialized)
                throw new InvalidOperationException("Session is not properly initialized");

            // Create a deep clone of the session to avoid modifying the original during processing
            var updatedSession = DeepCloneSession(session);

            // Check if the sender chain key is initialized
            if (updatedSession.SenderChainKey == null)
            {
                // This is the first time we're sending a message, we need to initialize the chain
                if (updatedSession.ReceiverRatchetPublicKey == null)
                    throw new InvalidOperationException("Cannot encrypt: Receiver's ratchet public key not set");

                // For bidirectional communication, Bob needs to generate a new key pair when he sends his first message
                // This happens when Bob (receiver) wants to send a message back but is still using his original signed prekey
                // We detect this by checking if we don't have a receiver ratchet public key set (meaning we haven't received any rotated keys)
                // and our sender chain key is null (meaning we haven't sent any messages yet)
                if (updatedSession.ReceiverRatchetPublicKey != null && updatedSession.SenderChainKey == null)
                {
                    // Generate a new ratchet key pair for sending - this is Bob's first message back to Alice
                    updatedSession.SenderRatchetKeyPair = Sodium.GenerateX25519KeyPair();
                }

                // Calculate the first DH output using our private key and their public key
                byte[] dhResult = Sodium.ScalarMult(
                    updatedSession.SenderRatchetKeyPair.PrivateKey,
                    updatedSession.ReceiverRatchetPublicKey);

                try
                {
                    // FIXED: Use Signal-compliant ratchet key derivation
                    var (newRootKey, newChainKey) = Sodium.DeriveRatchetKeys(updatedSession.RootKey, dhResult);

                    updatedSession.RootKey = newRootKey;
                    updatedSession.SenderChainKey = newChainKey;
                }
                finally
                {
                    // Securely clear the DH result
                    SecureMemory.SecureClear(dhResult);
                }
            }

            // Determine if we should rotate keys based on the strategy
            bool shouldRotate = ShouldRotateRatchetKey(updatedSession, rotationStrategy);

            // If rotation is needed, update the ratchet key
            if (shouldRotate)
            {
                RotateRatchetKey(updatedSession);
            }

            byte[]? messageKey = null;
            try
            {
                // FIXED: Generate a message key and advance the chain using Signal-compliant derivation
                messageKey = Sodium.DeriveMessageKey(updatedSession.SenderChainKey);

                byte[] previousSenderChainKey = updatedSession.SenderChainKey;
                updatedSession.SenderChainKey = Sodium.AdvanceChainKey(previousSenderChainKey);
                // The superseded chain key is a clone owned by this session; zero it so a memory
                // capture cannot re-derive already-sent message keys.
                SecureMemory.SecureClear(previousSenderChainKey);

                // Encrypt the message
                byte[] plaintext = Encoding.UTF8.GetBytes(message);
                byte[] nonce = Sodium.GenerateRandomBytes(Constants.NONCE_SIZE);
                byte[] ciphertext = AES.AESEncrypt(plaintext, messageKey, nonce, null);

                // Create the encrypted message
                var encryptedMessage = new EncryptedMessage
                {
                    SessionId = session.SessionId,
                    SenderDHKey = updatedSession.SenderRatchetKeyPair.PublicKey,
                    SenderMessageNumber = updatedSession.SendMessageNumber,
                    PreviousChainLength = updatedSession.PreviousSendChainLength,
                    Ciphertext = ciphertext,
                    Nonce = nonce,
                    MessageId = Guid.NewGuid().ToString("N"),
                    Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                };

                // Increment the send message number
                updatedSession.SendMessageNumber++;

                // Sent message keys are deliberately NOT retained. Keeping them would let anyone
                // who obtains a persisted session decrypt previously sent traffic, which defeats
                // the forward secrecy the ratchet exists to provide.

                return (updatedSession, encryptedMessage);
            }
            catch (Exception ex) when (ex is not LibEmiddleException)
            {
                LoggingManager.LogError(nameof(DoubleRatchetProtocol), $"Encryption failed: {ex.Message}");
                throw new LibEmiddleException($"Message encryption failed: {ex.Message}", LibEmiddleErrorCode.EncryptionFailed, ex);
            }
            finally
            {
                if (messageKey != null)
                    SecureMemory.SecureClear(messageKey);
            }
        }

        /// <summary>
        /// Decrypts a message using the Double Ratchet protocol and updates the session state.
        /// </summary>
        /// <param name="session">The current Double Ratchet session state</param>
        /// <param name="encryptedMessage">The encrypted message to decrypt</param>
        /// <returns>A tuple containing the updated session state and the decrypted message</returns>
        public (DoubleRatchetSession, string) Decrypt(
            DoubleRatchetSession session,
            EncryptedMessage encryptedMessage)
                {
                    ArgumentNullException.ThrowIfNull(session, nameof(session));
                    ArgumentNullException.ThrowIfNull(encryptedMessage, nameof(encryptedMessage));

                    if (!session.IsInitialized)
                        throw new InvalidOperationException("Session is not properly initialized");

                    if (encryptedMessage.Ciphertext == null || encryptedMessage.Nonce == null || encryptedMessage.SenderDHKey == null)
                        throw new ArgumentException("Encrypted message is incomplete", nameof(encryptedMessage));

                    // Create a deep clone of the session to avoid modifying the original during processing
                    var updatedSession = DeepCloneSession(session);

                    try
                    {
                        // Check session ID match
                        if (encryptedMessage.SessionId != session.SessionId)
                        {
                            LoggingManager.LogWarning(nameof(DoubleRatchetProtocol), "Message session ID does not match current session");
                            throw new LibEmiddleException(
                                $"Message session ID '{encryptedMessage.SessionId}' does not match session '{session.SessionId}'.",
                                LibEmiddleErrorCode.InvalidMessage);
                        }

                        // Validate timestamp to reject negative timestamps and extremely old/future messages
                        if (encryptedMessage.Timestamp < 0)
                        {
                            LoggingManager.LogWarning(nameof(DoubleRatchetProtocol), "Message has negative timestamp");
                            throw new LibEmiddleException(
                                "Message has a negative timestamp and was rejected.",
                                LibEmiddleErrorCode.InvalidMessage);
                        }

                        // Check for extremely future timestamps (more than 1 hour in the future)
                        long currentTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                        if (encryptedMessage.Timestamp > currentTime + (60 * 60 * 1000))
                        {
                            LoggingManager.LogWarning(nameof(DoubleRatchetProtocol), "Message timestamp is too far in the future");
                            throw new LibEmiddleException(
                                "Message timestamp is more than 1 hour in the future and was rejected.",
                                LibEmiddleErrorCode.InvalidMessage);
                        }
                        // Check if this is a message we've already decrypted by looking in the skipped message keys
                        SkippedMessageKey skippedMessageKeyId = new SkippedMessageKey(
                            encryptedMessage.SenderDHKey,
                            encryptedMessage.SenderMessageNumber);

                        if (updatedSession.SkippedMessageKeys.TryGetValue(skippedMessageKeyId, out byte[]? skippedMsgKey))
                        {
                            try
                            {
                                string skippedPlaintext = DecryptWithKey(encryptedMessage, skippedMsgKey);

                                // Consume the key only once decryption has actually succeeded.
                                updatedSession.SkippedMessageKeys.Remove(skippedMessageKeyId);

                                return (updatedSession, skippedPlaintext);
                            }
                            finally
                            {
                                SecureMemory.SecureClear(skippedMsgKey);
                            }
                        }

                        bool isNewRatchetKey = false;

                        // FIXED: Check if this is the very first message (receiver hasn't seen any ratchet key yet)
                        if (updatedSession.ReceiverRatchetPublicKey == null)
                        {
                            LoggingManager.LogDebug(nameof(DoubleRatchetProtocol), "Receiving first message, setting initial ratchet key");

                            // This is the first message we're receiving
                            updatedSession.ReceiverRatchetPublicKey = encryptedMessage.SenderDHKey;
                            updatedSession.ReceiveMessageNumber = 0;
                            isNewRatchetKey = true;
                        }
                        // Check if we received a message with a new ratchet key
                        else if (!CryptographicOperations.FixedTimeEquals(updatedSession.ReceiverRatchetPublicKey, encryptedMessage.SenderDHKey))
                        {
                            LoggingManager.LogDebug(nameof(DoubleRatchetProtocol), "Received message with new ratchet key, updating session");

                            // Store current receiver key for later comparison
                            updatedSession.PreviousReceiverRatchetPublicKey = updatedSession.ReceiverRatchetPublicKey;

                            // Drain any message keys the peer sent on the OLD chain that we never
                            // received, before that chain is replaced. This must happen while
                            // ReceiveMessageNumber still refers to the old chain.
                            if (updatedSession.ReceiverChainKey != null &&
                                updatedSession.PreviousReceiverRatchetPublicKey != null)
                            {
                                SkipReceiverMessageKeys(
                                    updatedSession,
                                    updatedSession.PreviousReceiverRatchetPublicKey,
                                    updatedSession.ReceiveMessageNumber,
                                    encryptedMessage.PreviousChainLength);
                            }

                            // This is a message with a new ratchet key, we need to perform DH key exchange
                            updatedSession.ReceiverRatchetPublicKey = encryptedMessage.SenderDHKey;
                            updatedSession.ReceiveMessageNumber = 0;

                            isNewRatchetKey = true;
                        }

                        // If this is a new ratchet key, we need to derive a new receiver chain key
                        if (isNewRatchetKey)
                        {
                            // Calculate DH with our current private key and their public key
                            byte[] dhResult = Sodium.ScalarMult(
                                updatedSession.SenderRatchetKeyPair.PrivateKey,
                                updatedSession.ReceiverRatchetPublicKey);

                            try
                            {
                                // FIXED: Use Signal-compliant ratchet key derivation
                                var (newRootKey, newChainKey) = Sodium.DeriveRatchetKeys(updatedSession.RootKey, dhResult);

                                byte[] previousRootKey = updatedSession.RootKey;
                                updatedSession.RootKey = newRootKey;
                                SecureMemory.SecureClear(previousRootKey);

                                if (updatedSession.ReceiverChainKey != null)
                                    SecureMemory.SecureClear(updatedSession.ReceiverChainKey);

                                updatedSession.ReceiverChainKey = newChainKey;
                            }
                            finally
                            {
                                // Securely clear the DH result
                                SecureMemory.SecureClear(dhResult);
                            }

                            // Do NOT generate a new ratchet key pair here for unidirectional communication.
                            // The receiver should keep their current key pair because the sender is still using
                            // the receiver's current public key for DH calculations.
                            // A new key pair will be generated when the receiver actually sends a message.
                            if (updatedSession.SenderChainKey != null)
                                SecureMemory.SecureClear(updatedSession.SenderChainKey);

                            updatedSession.SenderChainKey = null; // Will be derived when sending
                            updatedSession.PreviousSendChainLength = updatedSession.SendMessageNumber;
                            updatedSession.SendMessageNumber = 0;
                        }

                        // Handle case where receiver chain key is null (shouldn't happen with fixed initialization)
                        if (updatedSession.ReceiverChainKey == null)
                        {
                            LoggingManager.LogError(nameof(DoubleRatchetProtocol),
                                "Receiver chain key is null - this indicates an initialization problem");
                            throw new InvalidOperationException(
                                "Receiver chain key is not initialized. This indicates a problem with session initialization.");
                        }

                        // Skip message keys if needed
                        if (encryptedMessage.SenderMessageNumber > updatedSession.ReceiveMessageNumber)
                        {
                            SkipMessageKeys(
                                updatedSession,
                                encryptedMessage.SenderMessageNumber - updatedSession.ReceiveMessageNumber);
                        }

                        // FIXED: Generate the message key for decryption using Signal-compliant derivation
                        byte[]? messageKey = null;
                        try
                        {
                            messageKey = Sodium.DeriveMessageKey(updatedSession.ReceiverChainKey);

                            byte[] previousReceiverChainKey = updatedSession.ReceiverChainKey;
                            updatedSession.ReceiverChainKey = Sodium.AdvanceChainKey(previousReceiverChainKey);
                            SecureMemory.SecureClear(previousReceiverChainKey);

                            // Decrypt the message
                            string decryptedMessage = DecryptWithKey(encryptedMessage, messageKey);

                            // Update the message number
                            updatedSession.ReceiveMessageNumber = encryptedMessage.SenderMessageNumber + 1;

                            return (updatedSession, decryptedMessage);
                        }
                        finally
                        {
                            if (messageKey != null)
                                SecureMemory.SecureClear(messageKey);
                        }
                    }
                    catch (Exception ex) when (ex is not LibEmiddleException)
                    {
                        LoggingManager.LogError(nameof(DoubleRatchetProtocol), $"Decryption failed: {ex.Message}");
                        throw new LibEmiddleException($"Message decryption failed: {ex.Message}", LibEmiddleErrorCode.DecryptionFailed, ex);
                    }
                }

        #region Helper Methods

        /// <summary>
        /// Skip ahead in the receiver chain to handle out-of-order messages
        /// </summary>
        private void SkipMessageKeys(DoubleRatchetSession session, uint count)
        {
            if (count > _maxSkippedMessageKeys)
                throw new SecurityException($"Too many skipped message keys: {count} > {_maxSkippedMessageKeys}");

            if (session.ReceiverChainKey == null)
                throw new InvalidOperationException("Cannot skip message keys: Receiver chain not initialized");

            if (session.ReceiverRatchetPublicKey == null)
                throw new InvalidOperationException("Cannot skip message keys: Receiver ratchet pk is null");

            byte[] currentChainKey = session.ReceiverChainKey;

            for (uint i = 0; i < count; i++)
            {
                // Store the skipped message key
                SkippedMessageKey skippedKey = new(
                    session.ReceiverRatchetPublicKey,
                    session.ReceiveMessageNumber + i
                );
                StoreSkippedMessageKey(session, skippedKey, Sodium.DeriveMessageKey(currentChainKey));

                // Advance the chain, zeroing the key we just consumed
                byte[] previous = currentChainKey;
                currentChainKey = Sodium.AdvanceChainKey(previous);
                SecureMemory.SecureClear(previous);
            }

            // Update the session chain key
            session.ReceiverChainKey = currentChainKey;

            TrimSkippedMessageKeys(session);
        }

        /// <summary>
        /// Skip all message keys in the previous receiver chain when a new ratchet arrives
        /// </summary>
        /// <param name="session">The session being updated. Its receiver chain is advanced to the end.</param>
        /// <param name="oldRatchetPublicKey">The ratchet public key the old receiving chain belongs to.</param>
        /// <param name="firstUnclaimedNumber">The next message number expected on the old chain.</param>
        /// <param name="previousChainLength">
        /// The sender's PN: how many messages they sent on the old chain in total. Message numbers
        /// in [firstUnclaimedNumber, previousChainLength) were sent but not yet received.
        /// </param>
        private void SkipReceiverMessageKeys(
            DoubleRatchetSession session,
            byte[] oldRatchetPublicKey,
            uint firstUnclaimedNumber,
            uint previousChainLength)
        {
            if (session.ReceiverChainKey == null)
                return;

            if (previousChainLength <= firstUnclaimedNumber)
                return;

            uint count = previousChainLength - firstUnclaimedNumber;
            if (count > _maxSkippedMessageKeys)
            {
                throw new SecurityException(
                    $"Too many skipped message keys across ratchet step: {count} > {_maxSkippedMessageKeys}");
            }

            LoggingManager.LogDebug(nameof(DoubleRatchetProtocol),
                $"Draining {count} unclaimed key(s) from the previous receiving chain");

            byte[] currentChainKey = session.ReceiverChainKey;

            for (uint i = 0; i < count; i++)
            {
                var skippedKey = new SkippedMessageKey(oldRatchetPublicKey, firstUnclaimedNumber + i);
                StoreSkippedMessageKey(session, skippedKey, Sodium.DeriveMessageKey(currentChainKey));

                byte[] previous = currentChainKey;
                currentChainKey = Sodium.AdvanceChainKey(previous);
                SecureMemory.SecureClear(previous);
            }

            // The old chain is fully drained; it is replaced by the caller's new DH derivation.
            SecureMemory.SecureClear(currentChainKey);
            session.ReceiverChainKey = null;

            TrimSkippedMessageKeys(session);
        }

        /// <summary>
        /// Stores a skipped message key, zeroing any key it displaces.
        /// </summary>
        private static void StoreSkippedMessageKey(
            DoubleRatchetSession session, SkippedMessageKey id, byte[] messageKey)
        {
            if (session.SkippedMessageKeys.TryGetValue(id, out byte[]? existing))
                SecureMemory.SecureClear(existing);

            session.SkippedMessageKeys[id] = messageKey;
        }

        /// <summary>
        /// Bounds the skipped-key store, zeroing every evicted key.
        /// </summary>
        private void TrimSkippedMessageKeys(DoubleRatchetSession session)
        {
            if (session.SkippedMessageKeys.Count <= _maxSkippedMessageKeys)
                return;

            int keysToRemove = session.SkippedMessageKeys.Count - _maxSkippedMessageKeys;

            // Evict by message number rather than Dictionary enumeration order, which is
            // unspecified and does not correspond to insertion order.
            var oldest = session.SkippedMessageKeys.Keys
                .OrderBy(k => k.MessageNumber)
                .Take(keysToRemove)
                .ToList();

            foreach (var key in oldest)
            {
                if (session.SkippedMessageKeys.TryGetValue(key, out byte[]? evicted))
                    SecureMemory.SecureClear(evicted);

                session.SkippedMessageKeys.Remove(key);
            }
        }

        /// <summary>
        /// Determines if the ratchet key should be rotated based on the strategy
        /// </summary>
        private bool ShouldRotateRatchetKey(DoubleRatchetSession session, KeyRotationStrategy strategy)
        {
            switch (strategy)
            {
                case KeyRotationStrategy.AfterEveryMessage:
                    return true;

                case KeyRotationStrategy.Standard:
                default:
                    // Never rotate on a send-count schedule.
                    //
                    // A DH ratchet step is only safe when it is a RESPONSE to a new ratchet key
                    // from the peer, because the peer must already hold the public key we are
                    // ratcheting against. Rotating unilaterally every N messages breaks that
                    // invariant: if both sides rotate while neither has received the other's new
                    // key, their DH inputs diverge and the session is permanently unrecoverable.
                    // Forward secrecy within a chain is already provided by the symmetric ratchet
                    // (each message key is derived then discarded); the DH ratchet is driven by
                    // Decrypt() when a new SenderDHKey arrives.
                    return false;
            }
        }

        /// <summary>
        /// Rotates the ratchet key to provide forward secrecy
        /// </summary>
        private void RotateRatchetKey(DoubleRatchetSession session)
        {
            if (session.ReceiverRatchetPublicKey == null)
                throw new InvalidOperationException("Cannot rotate ratchet key: Receiver's public key not set");

            // Generate a new ratchet key pair
            var newRatchetKeyPair = Sodium.GenerateX25519KeyPair();

            // Calculate DH with our new private key and their current public key
            byte[] dhResult = Sodium.ScalarMult(
                newRatchetKeyPair.PrivateKey,
                session.ReceiverRatchetPublicKey);

            try
            {
                // FIXED: Use Signal-compliant ratchet key derivation
                var (newRootKey, newChainKey) = Sodium.DeriveRatchetKeys(session.RootKey, dhResult);

                byte[] previousRootKey = session.RootKey;
                session.RootKey = newRootKey;
                SecureMemory.SecureClear(previousRootKey);

                if (session.SenderChainKey != null)
                    SecureMemory.SecureClear(session.SenderChainKey);

                session.SenderChainKey = newChainKey;

                // Update our ratchet key pair, zeroing the private key we are retiring
                if (session.SenderRatchetKeyPair.PrivateKey != null)
                    SecureMemory.SecureClear(session.SenderRatchetKeyPair.PrivateKey);

                session.SenderRatchetKeyPair = newRatchetKeyPair;
                session.PreviousSendChainLength = session.SendMessageNumber;
                session.SendMessageNumber = 0;

                LoggingManager.LogDebug(nameof(DoubleRatchetProtocol), "Rotated ratchet key pair");
            }
            finally
            {
                // Securely clear the DH result
                SecureMemory.SecureClear(dhResult);
            }
        }

        /// <summary>
        /// Decrypts a message using the provided message key
        /// </summary>
        private string DecryptWithKey(EncryptedMessage encryptedMessage, byte[] messageKey)
        {
            if (encryptedMessage.Ciphertext == null)
                throw new ArgumentNullException(nameof(encryptedMessage), "Cannot decrypt with key: Ciphertext is null.");
            if (encryptedMessage.Nonce == null)
                throw new ArgumentNullException(nameof(encryptedMessage), "Cannot decrypt with key: Nonce is null.");

            // Decrypt the message
            byte[] decrypted = AES.AESDecrypt(
                encryptedMessage.Ciphertext,
                messageKey,
                encryptedMessage.Nonce,
                null);

            try
            {
                return Encoding.UTF8.GetString(decrypted);
            }
            finally
            {
                SecureMemory.SecureClear(decrypted);
            }
        }

        /// <summary>
        /// Creates a deep clone of a Double Ratchet session to ensure changes don't affect the original
        /// </summary>
        private DoubleRatchetSession DeepCloneSession(DoubleRatchetSession original)
        {
            if (original == null)
                throw new ArgumentNullException(nameof(original), "Cannot deep clone session: Original is null.");

            // Create a new session object
            // Every byte array must be copied. Sharing a reference here would let the clone's
            // SecureClear calls zero key material still owned by the caller's session.
            var clone = new DoubleRatchetSession
            {
                SessionId = original.SessionId,
                RootKey = original.RootKey.ToArray(),
                SenderChainKey = original.SenderChainKey?.ToArray(),
                ReceiverChainKey = original.ReceiverChainKey?.ToArray(),
                SenderRatchetKeyPair = new KeyPair
                {
                    PublicKey = original.SenderRatchetKeyPair.PublicKey?.ToArray() ?? [],
                    PrivateKey = original.SenderRatchetKeyPair.PrivateKey?.ToArray() ?? []
                },
                ReceiverRatchetPublicKey = original.ReceiverRatchetPublicKey?.ToArray(),
                PreviousReceiverRatchetPublicKey = original.PreviousReceiverRatchetPublicKey?.ToArray(),
                SendMessageNumber = original.SendMessageNumber,
                ReceiveMessageNumber = original.ReceiveMessageNumber,
                PreviousSendChainLength = original.PreviousSendChainLength,
                SentMessages = new Dictionary<uint, byte[]>(),
                SkippedMessageKeys = new Dictionary<SkippedMessageKey, byte[]>(),
                IsInitialized = original.IsInitialized,
                CreationTimestamp = original.CreationTimestamp
            };

            // Copy the sent messages dictionary
            foreach (var kvp in original.SentMessages)
            {
                clone.SentMessages[kvp.Key] = kvp.Value.ToArray();
            }

            // Copy the skipped message keys dictionary
            foreach (var kvp in original.SkippedMessageKeys)
            {
                clone.SkippedMessageKeys[kvp.Key] = kvp.Value.ToArray();
            }

            return clone;
        }

        #endregion
    }
}
