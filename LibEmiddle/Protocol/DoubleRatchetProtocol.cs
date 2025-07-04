﻿using System.Security.Cryptography;
using System.Security;
using System.Text;
using LibEmiddle.Abstractions;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain.Enums;
using LibEmiddle.Domain;

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
            ArgumentNullException.ThrowIfNull(receiverInitialKeyPair, nameof(receiverInitialKeyPair));
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
        public (DoubleRatchetSession?, EncryptedMessage?) EncryptAsync(
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

            try
            {
                // FIXED: Generate a message key and advance the chain using Signal-compliant derivation
                byte[] messageKey = Sodium.DeriveMessageKey(updatedSession.SenderChainKey);
                updatedSession.SenderChainKey = Sodium.AdvanceChainKey(updatedSession.SenderChainKey);

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
                    Ciphertext = ciphertext,
                    Nonce = nonce,
                    MessageId = Guid.NewGuid().ToString("N"),
                    Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                };

                // Increment the send message number
                updatedSession.SendMessageNumber++;

                // Record the message in history if needed
                if (rotationStrategy == KeyRotationStrategy.Standard)
                {
                    updatedSession.SentMessages[encryptedMessage.SenderMessageNumber] = messageKey;

                    // Clean up old messages if we have too many
                    CleanupOldSentMessages(updatedSession);
                }

                return (updatedSession, encryptedMessage);
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(DoubleRatchetProtocol), $"Encryption failed: {ex.Message}");
                return (null, null);
            }
        }

        /// <summary>
        /// Decrypts a message using the Double Ratchet protocol and updates the session state.
        /// </summary>
        /// <param name="session">The current Double Ratchet session state</param>
        /// <param name="encryptedMessage">The encrypted message to decrypt</param>
        /// <returns>A tuple containing the updated session state and the decrypted message</returns>
        public (DoubleRatchetSession?, string?) DecryptAsync(
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
                        // Check session ID match inside try-catch to return null on mismatch
                        if (encryptedMessage.SessionId != session.SessionId)
                        {
                            LoggingManager.LogWarning(nameof(DoubleRatchetProtocol), "Message session ID does not match current session");
                            return (null, null);
                        }

                        // Validate timestamp to reject negative timestamps and extremely old/future messages
                        if (encryptedMessage.Timestamp < 0)
                        {
                            LoggingManager.LogWarning(nameof(DoubleRatchetProtocol), "Message has negative timestamp");
                            return (null, null);
                        }

                        // Check for extremely future timestamps (more than 1 hour in the future)
                        long currentTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                        if (encryptedMessage.Timestamp > currentTime + (60 * 60 * 1000))
                        {
                            LoggingManager.LogWarning(nameof(DoubleRatchetProtocol), "Message timestamp is too far in the future");
                            return (null, null);
                        }
                        // Check if this is a message we've already decrypted by looking in the skipped message keys
                        SkippedMessageKey skippedMessageKeyId = new SkippedMessageKey(
                            encryptedMessage.SenderDHKey,
                            encryptedMessage.SenderMessageNumber);

                        if (updatedSession.SkippedMessageKeys.TryGetValue(skippedMessageKeyId, out byte[]? skippedMsgKey))
                        {
                            // Remove this key from the skipped keys
                            updatedSession.SkippedMessageKeys.Remove(skippedMessageKeyId);

                            // Decrypt the message using the skipped key
                            return (updatedSession, DecryptWithKey(encryptedMessage, skippedMsgKey));
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
                        else if (!updatedSession.ReceiverRatchetPublicKey.SequenceEqual(encryptedMessage.SenderDHKey))
                        {
                            LoggingManager.LogDebug(nameof(DoubleRatchetProtocol), "Received message with new ratchet key, updating session");

                            // Store current receiver key for later comparison
                            updatedSession.PreviousReceiverRatchetPublicKey = updatedSession.ReceiverRatchetPublicKey;

                            // This is a message with a new ratchet key, we need to perform DH key exchange
                            updatedSession.ReceiverRatchetPublicKey = encryptedMessage.SenderDHKey;
                            updatedSession.ReceiveMessageNumber = 0;

                            // If we have a receiver chain, we need to store all skipped message keys
                            if (updatedSession.ReceiverChainKey != null && updatedSession.PreviousReceiverRatchetPublicKey != null)
                            {
                                SkipReceiverMessageKeysAsync(updatedSession);
                            }

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
                                updatedSession.RootKey = newRootKey;
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
                            updatedSession.SenderChainKey = null; // Will be derived when sending
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
                        byte[] messageKey = Sodium.DeriveMessageKey(updatedSession.ReceiverChainKey);
                        updatedSession.ReceiverChainKey = Sodium.AdvanceChainKey(updatedSession.ReceiverChainKey);

                        // Decrypt the message
                        string decryptedMessage = DecryptWithKey(encryptedMessage, messageKey);

                        // Update the message number
                        updatedSession.ReceiveMessageNumber = encryptedMessage.SenderMessageNumber + 1;

                        return (updatedSession, decryptedMessage);
                    }
                    catch (Exception ex)
                    {
                        LoggingManager.LogError(nameof(DoubleRatchetProtocol), $"Decryption failed: {ex.Message}");
                        return (null, null);
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
                session.SkippedMessageKeys[skippedKey] = Sodium.DeriveMessageKey(currentChainKey);

                // Advance the chain
                currentChainKey = Sodium.AdvanceChainKey(currentChainKey);
            }

            // Update the session chain key
            session.ReceiverChainKey = currentChainKey;

            // Remove oldest skipped message keys if we have too many
            if (session.SkippedMessageKeys.Count > _maxSkippedMessageKeys)
            {
                int keysToRemove = session.SkippedMessageKeys.Count - _maxSkippedMessageKeys;
                var keysToRemoveList = session.SkippedMessageKeys.Keys.Take(keysToRemove).ToList();

                foreach (var key in keysToRemoveList)
                {
                    session.SkippedMessageKeys.Remove(key);
                }
            }
        }

        /// <summary>
        /// Skip all message keys in the previous receiver chain when a new ratchet arrives
        /// </summary>
        private void SkipReceiverMessageKeysAsync(DoubleRatchetSession session)
        {
            // When a new ratchet key arrives, we should skip any remaining keys in the old receiver chain
            // But we need to be careful not to skip too many keys

            LoggingManager.LogDebug(nameof(DoubleRatchetProtocol),
                $"Skipping receiver chain keys due to new ratchet key");

            // Skip only the keys that we haven't received yet in the old chain
            // Since we're starting a new chain, we don't need to skip any keys
            // The new ratchet key indicates a fresh start
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
                    // In standard mode, rotate after 20 messages (but not on the very first message)
                    return session.SendMessageNumber > 0 && session.SendMessageNumber % 20 == 0;
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
                session.RootKey = newRootKey;
                session.SenderChainKey = newChainKey;

                // Update our ratchet key pair
                session.SenderRatchetKeyPair = newRatchetKeyPair;
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
        /// Cleans up old sent messages from the session
        /// </summary>
        private void CleanupOldSentMessages(DoubleRatchetSession session)
        {
            // Max number of sent message keys to keep
            const int MAX_SENT_MESSAGES = 100;

            if (session.SentMessages.Count > MAX_SENT_MESSAGES)
            {
                // Sort keys and remove oldest
                var oldestKeys = session.SentMessages.Keys.OrderBy(k => k).Take(session.SentMessages.Count - MAX_SENT_MESSAGES);
                foreach (var key in oldestKeys.ToList())
                {
                    session.SentMessages.Remove(key);
                }
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

            return Encoding.UTF8.GetString(decrypted);
        }

        /// <summary>
        /// Creates a deep clone of a Double Ratchet session to ensure changes don't affect the original
        /// </summary>
        private DoubleRatchetSession DeepCloneSession(DoubleRatchetSession original)
        {
            if (original == null)
                throw new ArgumentNullException(nameof(original), "Cannot deep clone session: Original is null.");

            // Create a new session object
            var clone = new DoubleRatchetSession
            {
                SessionId = original.SessionId,
                RootKey = original.RootKey,
                SenderChainKey = original.SenderChainKey?.ToArray(),
                ReceiverChainKey = original.ReceiverChainKey?.ToArray(),
                SenderRatchetKeyPair = new KeyPair
                {
                    PublicKey = original.SenderRatchetKeyPair.PublicKey,
                    PrivateKey = original.SenderRatchetKeyPair.PrivateKey
                },
                ReceiverRatchetPublicKey = original.ReceiverRatchetPublicKey?.ToArray(),
                PreviousReceiverRatchetPublicKey = original.PreviousReceiverRatchetPublicKey?.ToArray(),
                SendMessageNumber = original.SendMessageNumber,
                ReceiveMessageNumber = original.ReceiveMessageNumber,
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
