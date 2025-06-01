using System.Security.Cryptography;
using System.Security;
using System.Text;
using LibEmiddle.Abstractions;
using LibEmiddle.Core;
using LibEmiddle.Domain.Enums;
using LibEmiddle.Domain;

namespace LibEmiddle.Protocol
{
    /// <summary>
    /// Implements the Signal Double Ratchet protocol for forward secrecy and break-in recovery
    /// in encrypted message exchanges.
    /// </summary>
    public class DoubleRatchetProtocol : IDoubleRatchetProtocol
    {
        private readonly ICryptoProvider _cryptoProvider;
        private readonly int _maxSkippedMessageKeys;

        public DoubleRatchetProtocol(ICryptoProvider cryptoProvider, int maxSkippedMessageKeys = 100)
        {
            _cryptoProvider = cryptoProvider ?? throw new ArgumentNullException(nameof(cryptoProvider));
            _maxSkippedMessageKeys = maxSkippedMessageKeys;
        }

        /// <summary>
        /// Initializes a new Double Ratchet session as the sender (Alice) using the shared key from X3DH
        /// and the recipient's initial ratchet public key.
        /// </summary>
        /// <param name="sharedKeyFromX3DH">The 32-byte shared key derived from X3DH key exchange</param>
        /// <param name="recipientInitialPublicKey">The recipient's initial ratchet public key (X25519)</param>
        /// <param name="sessionId">Unique identifier for this session</param>
        /// <returns>The initialized DoubleRatchetSession object</returns>
        public async Task<DoubleRatchetSession> InitializeSessionAsSenderAsync(
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
            var senderRatchetKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.X25519);
            if (senderRatchetKeyPair.PrivateKey == null || senderRatchetKeyPair.PublicKey == null)
                throw new CryptographicException("Failed to generate sender's initial ratchet key pair");

            // Create KDF info constants
            byte[] rootKeyInfo = Encoding.Default.GetBytes("DoubleRatchetRoot");
            byte[] chainKeyInfo = Encoding.Default.GetBytes("DoubleRatchetChain");

            // Derive initial root key from the shared key
            byte[] rootKey = await _cryptoProvider.DeriveKeyAsync(
                sharedKeyFromX3DH,
                salt: null,
                info: rootKeyInfo,
                length: 32);

            // Calculate the first DH output using our private key and their public key
            byte[] dhResult = _cryptoProvider.ScalarMult(
                senderRatchetKeyPair.PrivateKey,
                recipientInitialPublicKey);

            try
            {
                // Derive sender's chain keys using the DH result
                var rootKeyChainKey = await CalculateRootKeyAndChainKeyAsync(rootKey, dhResult);

                // Initialize session state
                var session = new DoubleRatchetSession
                {
                    SessionId = sessionId,
                    RootKey = rootKeyChainKey.RootKey,
                    SenderChainKey = rootKeyChainKey.ChainKey,
                    ReceiverChainKey = null, // Will be established later when receiving messages
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
                // Securely clear the DH result
                SecureMemory.SecureClear(dhResult);
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
        public async Task<DoubleRatchetSession> InitializeSessionAsReceiverAsync(
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

            // Create KDF info constants
            byte[] rootKeyInfo = Encoding.Default.GetBytes("DoubleRatchetRoot");

            // Derive initial root key from the shared key
            byte[] rootKey = await _cryptoProvider.DeriveKeyAsync(
                sharedKeyFromX3DH,
                salt: null,
                info: rootKeyInfo,
                length: 32);

            // FIXED: Initialize the receiver chain key properly
            // The receiver needs to be able to decrypt messages from the start
            // We derive an initial receiver chain key from the shared secret and sender's ephemeral key
            byte[] dhResult = _cryptoProvider.ScalarMult(
                receiverInitialKeyPair.PrivateKey,
                senderEphemeralKeyPublic);

            try
            {
                // Derive initial receiver chain key using the DH result
                var rootKeyChainKey = await CalculateRootKeyAndChainKeyAsync(rootKey, dhResult);
                byte[] initialReceiverChainKey = rootKeyChainKey.ChainKey;
                byte[] updatedRootKey = rootKeyChainKey.RootKey;

                // Initialize session state with proper receiver chain
                var session = new DoubleRatchetSession
                {
                    SessionId = sessionId,
                    RootKey = updatedRootKey,
                    SenderChainKey = null, // Will be established when sending first message
                    ReceiverChainKey = initialReceiverChainKey, // FIXED: Now properly initialized
                    SenderRatchetKeyPair = receiverInitialKeyPair,
                    ReceiverRatchetPublicKey = senderEphemeralKeyPublic, // FIXED: Set the sender's key as receiver ratchet key
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
                // Securely clear the DH result
                SecureMemory.SecureClear(dhResult);
            }
        }

        /// <summary>
        /// Alternative 3-parameter overload for receiver initialization when sender ephemeral key
        /// is derived from the session context.
        /// </summary>
        /// <param name="sharedKeyFromX3DH">The 32-byte shared key derived from X3DH key exchange</param>
        /// <param name="senderRatchetPublicKey">The sender's ratchet public key</param>
        /// <param name="sessionId">Unique identifier for this session</param>
        /// <returns>The initialized DoubleRatchetSession object</returns>
        public async Task<DoubleRatchetSession> InitializeSessionAsReceiverAsync(
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
            var receiverInitialKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.X25519);
            if (receiverInitialKeyPair.PrivateKey == null || receiverInitialKeyPair.PublicKey == null)
                throw new CryptographicException("Failed to generate receiver's initial ratchet key pair");

            // Call the main initialization method
            return await InitializeSessionAsReceiverAsync(
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
        public async Task<(DoubleRatchetSession?, EncryptedMessage?)> EncryptAsync(
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

                // Calculate the first DH output using our private key and their public key
                byte[] dhResult = _cryptoProvider.ScalarMult(
                    updatedSession.SenderRatchetKeyPair.PrivateKey,
                    updatedSession.ReceiverRatchetPublicKey);

                try
                {
                    // Derive initial chain key using the DH result
                    var rootKeyChainKey = await CalculateRootKeyAndChainKeyAsync(updatedSession.RootKey, dhResult);
                    updatedSession.RootKey = rootKeyChainKey.RootKey;
                    updatedSession.SenderChainKey = rootKeyChainKey.ChainKey;
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
                await RotateRatchetKeyAsync(updatedSession);
            }

            try
            {
                // Generate a message key and advance the chain
                var messageKeyAndNextChain = await GenerateMessageKeyAndAdvanceChainAsync(updatedSession.SenderChainKey);
                byte[] messageKey = messageKeyAndNextChain.MessageKey;
                updatedSession.SenderChainKey = messageKeyAndNextChain.NextChainKey;

                // Encrypt the message
                byte[] plaintext = Encoding.Default.GetBytes(message);
                byte[] nonce = _cryptoProvider.GenerateRandomBytes(Constants.NONCE_SIZE);
                byte[] ciphertext = _cryptoProvider.Encrypt(plaintext, messageKey, nonce, null);

                // Create the encrypted message
                var encryptedMessage = new EncryptedMessage
                {
                    SessionId = session.SessionId,
                    SenderDHKey = updatedSession.SenderRatchetKeyPair.PublicKey,
                    SenderMessageNumber = updatedSession.SendMessageNumber,
                    Ciphertext = ciphertext,
                    Nonce = nonce,
                    MessageId = Guid.NewGuid().ToString("N")
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
        public async Task<(DoubleRatchetSession?, string?)> DecryptAsync(
            DoubleRatchetSession session,
            EncryptedMessage encryptedMessage)
        {
            ArgumentNullException.ThrowIfNull(session, nameof(session));
            ArgumentNullException.ThrowIfNull(encryptedMessage, nameof(encryptedMessage));

            if (!session.IsInitialized)
                throw new InvalidOperationException("Session is not properly initialized");

            if (encryptedMessage.Ciphertext == null || encryptedMessage.Nonce == null || encryptedMessage.SenderDHKey == null)
                throw new ArgumentException("Encrypted message is incomplete", nameof(encryptedMessage));

            if (encryptedMessage.SessionId != session.SessionId)
                throw new ArgumentException("Message session ID does not match current session", nameof(encryptedMessage));

            // Create a deep clone of the session to avoid modifying the original during processing
            var updatedSession = DeepCloneSession(session);

            try
            {
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

                // Check if we received a message with a new ratchet key
                if (updatedSession.ReceiverRatchetPublicKey == null ||
                    !updatedSession.ReceiverRatchetPublicKey.SequenceEqual(encryptedMessage.SenderDHKey))
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
                        await SkipReceiverMessageKeysAsync(updatedSession);
                    }

                    // Generate a new ratchet key pair
                    var newRatchetKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.X25519);

                    // Calculate DH with our current private key and their public key
                    byte[] dhResult = _cryptoProvider.ScalarMult(
                        updatedSession.SenderRatchetKeyPair.PrivateKey,
                        updatedSession.ReceiverRatchetPublicKey);

                    try
                    {
                        // Update the root key and generate new receiver chain key
                        var rootKeyChainKey = await CalculateRootKeyAndChainKeyAsync(updatedSession.RootKey, dhResult);
                        updatedSession.RootKey = rootKeyChainKey.RootKey;
                        updatedSession.ReceiverChainKey = rootKeyChainKey.ChainKey;
                    }
                    finally
                    {
                        // Securely clear the DH result
                        SecureMemory.SecureClear(dhResult);
                    }

                    // Update the sender ratchet key pair
                    updatedSession.SenderRatchetKeyPair = newRatchetKeyPair;
                    isNewRatchetKey = true;
                }

                // FIXED: Handle case where receiver chain key is still null (shouldn't happen with fixed initialization)
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
                    await SkipMessageKeysAsync(
                        updatedSession,
                        encryptedMessage.SenderMessageNumber - updatedSession.ReceiveMessageNumber - 1);
                }

                // Generate the message key for decryption
                var messageKeyAndNextChain = await GenerateMessageKeyAndAdvanceChainAsync(updatedSession.ReceiverChainKey);
                byte[] messageKey = messageKeyAndNextChain.MessageKey;
                updatedSession.ReceiverChainKey = messageKeyAndNextChain.NextChainKey;

                // Decrypt the message
                string decryptedMessage = DecryptWithKey(encryptedMessage, messageKey);

                // Update the message number
                updatedSession.ReceiveMessageNumber = encryptedMessage.SenderMessageNumber + 1;

                // If this was a new ratchet key and we've successfully decrypted a message,
                // we need to calculate a new sender chain key for future messages we'll send
                if (isNewRatchetKey)
                {
                    // This will be performed on the next encrypt operation
                    updatedSession.SenderChainKey = null;
                    updatedSession.SendMessageNumber = 0;
                }

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
        /// Calculates a new root key and chain key using the current root key and a DH output
        /// </summary>
        private async Task<(byte[] RootKey, byte[] ChainKey)> CalculateRootKeyAndChainKeyAsync(byte[] currentRootKey, byte[] dhOutput)
        {
            byte[] combined = new byte[currentRootKey.Length + dhOutput.Length];
            Buffer.BlockCopy(currentRootKey, 0, combined, 0, currentRootKey.Length);
            Buffer.BlockCopy(dhOutput, 0, combined, currentRootKey.Length, dhOutput.Length);

            try
            {
                // Derive 64 bytes: 32 for root key, 32 for chain key
                byte[] derived = await _cryptoProvider.DeriveKeyAsync(
                    combined,
                    salt: null,
                    info: Encoding.Default.GetBytes("DoubleRatchetKDF"),
                    length: 64);

                byte[] newRootKey = new byte[32];
                byte[] newChainKey = new byte[32];

                Buffer.BlockCopy(derived, 0, newRootKey, 0, 32);
                Buffer.BlockCopy(derived, 32, newChainKey, 0, 32);

                return (newRootKey, newChainKey);
            }
            finally
            {
                // Securely clear the combined buffer
                SecureMemory.SecureClear(combined);
            }
        }

        /// <summary>
        /// Generates a message key from a chain key and advances the chain
        /// </summary>
        private async Task<(byte[] MessageKey, byte[] NextChainKey)> GenerateMessageKeyAndAdvanceChainAsync(byte[] chainKey)
        {
            // Use HKDF to derive the next chain key
            byte[] nextChainKey = await _cryptoProvider.DeriveKeyAsync(
                chainKey,
                salt: null,
                info: Encoding.Default.GetBytes("WhisperChain"),
                length: 32);

            // Use HKDF to derive the message key
            byte[] messageKey = await _cryptoProvider.DeriveKeyAsync(
                chainKey,
                salt: null,
                info: Encoding.Default.GetBytes("WhisperMessage"),
                length: 32);

            return (messageKey, nextChainKey);
        }

        /// <summary>
        /// Skip ahead in the receiver chain to handle out-of-order messages
        /// </summary>
        private async Task SkipMessageKeysAsync(DoubleRatchetSession session, uint count)
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
                // Generate the message key and next chain key
                var keyAndChain = await GenerateMessageKeyAndAdvanceChainAsync(currentChainKey);

                // Store the skipped message key
                SkippedMessageKey skippedKey = new SkippedMessageKey(
                    session.ReceiverRatchetPublicKey,
                    session.ReceiveMessageNumber + i);
                session.SkippedMessageKeys[skippedKey] = keyAndChain.MessageKey;

                // Advance the chain
                currentChainKey = keyAndChain.NextChainKey;
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
        private async Task SkipReceiverMessageKeysAsync(DoubleRatchetSession session)
        {
            // Skip remaining keys in the old chain
            uint remainingKeys = 100; // Use a reasonable maximum

            LoggingManager.LogDebug(nameof(DoubleRatchetProtocol),
                $"Skipping receiver chain keys due to new ratchet key");

            await SkipMessageKeysAsync(session, Math.Min(remainingKeys, (uint)_maxSkippedMessageKeys));
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
                    // In standard mode, rotate after 20 messages or if no rotations have happened yet
                    return session.SendMessageNumber % 20 == 0 || session.SendMessageNumber == 0;
            }
        }

        /// <summary>
        /// Rotates the ratchet key to provide forward secrecy
        /// </summary>
        private async Task RotateRatchetKeyAsync(DoubleRatchetSession session)
        {
            if (session.ReceiverRatchetPublicKey == null)
                throw new InvalidOperationException("Cannot rotate ratchet key: Receiver's public key not set");

            // Generate a new ratchet key pair
            var newRatchetKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.X25519);

            // Calculate DH with our new private key and their current public key
            byte[] dhResult = _cryptoProvider.ScalarMult(
                newRatchetKeyPair.PrivateKey,
                session.ReceiverRatchetPublicKey);

            try
            {
                // Update the root key and generate new sender chain key
                var rootKeyChainKey = await CalculateRootKeyAndChainKeyAsync(session.RootKey, dhResult);
                session.RootKey = rootKeyChainKey.RootKey;
                session.SenderChainKey = rootKeyChainKey.ChainKey;

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
            byte[] decrypted = _cryptoProvider.Decrypt(
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
