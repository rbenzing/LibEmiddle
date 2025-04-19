using System.Collections.Concurrent;
using System.Text;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.KeyExchange;
using LibEmiddle.Messaging.Transport;

namespace LibEmiddle.Messaging.Group
{
    /// <summary>
    /// Manages the creation of outgoing Sender Key distribution messages and
    /// processes/stores incoming Sender Key states from other group members.
    /// Provides the mechanism to retrieve the correct message key for decrypting
    /// incoming group messages based on their iteration number.
    /// </summary>
    public class SenderKeyDistribution : IDisposable
    {
        /// <summary>
        /// Internal record to store the received state from a sender in a group.
        /// </summary>
        private sealed record ReceivedSenderKeyState
        {
            public uint Iteration { get; init; }
            public byte[] ChainKey { get; init; } = Array.Empty<byte>();

            // Method to securely clear the sensitive chain key
            public void Clear() => SecureMemory.SecureClear(ChainKey);
        }

        // Stores the current received state from each sender in each group
        // Key: "{groupId}:{senderIdentityKeyBase64}"
        // Value: ReceivedSenderKeyState (Iteration + ChainKey)
        private readonly ConcurrentDictionary<string, ReceivedSenderKeyState> _receivedStates = new();

        // Local user's identity key pair (needed for creating outgoing distributions)
        private readonly KeyPair _identityKeyPair;

        // Constants for KDF_CK
        private const byte MESSAGE_KEY_SEED_BYTE = 0x01;
        private const byte CHAIN_KEY_SEED_BYTE = 0x02;

        /// <summary>
        /// Creates a new SenderKeyDistribution instance.
        /// </summary>
        /// <param name="identityKeyPair">Identity key pair (Ed25519) for the local client.</param>
        public SenderKeyDistribution(KeyPair identityKeyPair)
        {
            if (identityKeyPair.PublicKey == null || identityKeyPair.PrivateKey == null)
                throw new ArgumentException("Identity key pair must contain public and private keys.");

            _identityKeyPair = identityKeyPair;
        }

        /// <summary>
        /// Creates a distribution message containing the sender chain key for a group.
        /// </summary>
        /// <param name="groupId">Group identifier.</param>
        /// <param name="chainKey">The current Chain Key for the sender state.</param>
        /// <param name="iteration">The current iteration number.</param>
        /// <returns>Distribution message ready for sharing.</returns>
        public SenderKeyDistributionMessage CreateDistributionMessage(
            string groupId,
            byte[] chainKey,
            uint iteration)
        {
            ArgumentException.ThrowIfNullOrEmpty(groupId, nameof(groupId));
            ArgumentNullException.ThrowIfNull(chainKey, nameof(chainKey));

            if (chainKey.Length != Constants.AES_KEY_SIZE)
                throw new ArgumentException("Invalid Chain Key size.", nameof(chainKey));

            // Data to sign: Include Group ID, Iteration, and Chain Key
            byte[] dataToSign;
            using (var ms = new MemoryStream())
            using (var writer = new BinaryWriter(ms))
            {
                writer.Write(Encoding.UTF8.GetBytes(groupId));
                writer.Write(BitConverter.GetBytes(iteration));
                writer.Write(chainKey);
                dataToSign = ms.ToArray();
            }

            // Sign the combined data with our identity key
            byte[] signature = MessageSigning.SignMessage(dataToSign, _identityKeyPair.PrivateKey);

            // Create the message object
            return new SenderKeyDistributionMessage
            {
                GroupId = groupId,
                ChainKey = chainKey,
                Iteration = iteration,
                SenderIdentityKey = _identityKeyPair.PublicKey,
                Signature = signature,
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                MessageId = Guid.NewGuid().ToString()
            };
        }

        /// <summary>
        /// Processes a received and validated sender key distribution message.
        /// Stores or updates the sender state for the given group and sender.
        /// </summary>
        /// <param name="distribution">The validated distribution message.</param>
        /// <returns>True if the state was processed and stored/updated successfully.</returns>
        public bool ProcessDistributionMessage(SenderKeyDistributionMessage distribution)
        {
            ArgumentNullException.ThrowIfNull(distribution, nameof(distribution));
            ArgumentNullException.ThrowIfNull(distribution.GroupId, nameof(distribution.GroupId));
            ArgumentNullException.ThrowIfNull(distribution.ChainKey, nameof(distribution.ChainKey));
            ArgumentNullException.ThrowIfNull(distribution.SenderIdentityKey, nameof(distribution.SenderIdentityKey));

            // Verify the signature
            if (!VerifyDistributionSignature(distribution))
            {
                LoggingManager.LogWarning(nameof(SenderKeyDistribution),
                    "Distribution message has invalid signature");
                return false;
            }

            string storageKey = GetStorageKey(distribution.GroupId, distribution.SenderIdentityKey);

            var newState = new ReceivedSenderKeyState
            {
                // Store copies of mutable data
                ChainKey = (byte[])distribution.ChainKey.Clone(),
                Iteration = distribution.Iteration
            };

            // Atomically add or update, ensuring we only store newer states
            bool stored = false;
            while (!stored)
            {
                if (!_receivedStates.TryGetValue(storageKey, out var existingState))
                {
                    // No existing state, try to add new state
                    if (_receivedStates.TryAdd(storageKey, newState))
                    {
                        LoggingManager.LogInformation(nameof(SenderKeyDistribution),
                            $"Added initial state for {storageKey}, iteration {newState.Iteration}");
                        stored = true;
                    }
                    // If TryAdd failed, another thread added a state concurrently - loop will retry
                }
                else
                {
                    // State already existed, only update if new iteration is >= current
                    if (newState.Iteration >= existingState.Iteration)
                    {
                        // Attempt to replace the existing state with the new state
                        if (_receivedStates.TryUpdate(storageKey, newState, existingState))
                        {
                            LoggingManager.LogInformation(nameof(SenderKeyDistribution),
                                $"Updated state for {storageKey} from iteration {existingState.Iteration} to {newState.Iteration}");
                            existingState.Clear(); // Clear the old chain key we just replaced
                            stored = true;
                        }
                        // If TryUpdate failed, another thread updated concurrently. Loop will retry
                    }
                    else
                    {
                        // Received an older state than we already have, discard the new one
                        LoggingManager.LogInformation(nameof(SenderKeyDistribution),
                            $"Discarded outdated state for {storageKey} (received {newState.Iteration}, current {existingState.Iteration})");
                        newState.Clear(); // Clear the key we aren't storing
                        stored = true; // Exit loop, we kept the existing newer state
                    }
                }
            }

            return true;
        }

        /// <summary>
        /// Verifies the signature on a distribution message
        /// </summary>
        /// <param name="distribution">Distribution message to verify</param>
        /// <returns>True if signature is valid</returns>
        public bool VerifyDistributionSignature(SenderKeyDistributionMessage distribution)
        {
            ArgumentNullException.ThrowIfNull(nameof(distribution));
            
            if (distribution.GroupId == null)
                throw new ArgumentNullException(nameof(distribution.GroupId));
            if (distribution.ChainKey == null)
                throw new ArgumentNullException(nameof(distribution.ChainKey));
            if (distribution.Signature == null)
                throw new ArgumentNullException(nameof(distribution.Signature));
            if (distribution.SenderIdentityKey == null)
                throw new ArgumentNullException(nameof(distribution.SenderIdentityKey));

            try
            {
                // Reconstruct the data that was signed
                byte[] dataToVerify;
                using (var ms = new MemoryStream())
                using (var writer = new BinaryWriter(ms))
                {
                    writer.Write(Encoding.UTF8.GetBytes(distribution.GroupId));
                    writer.Write(BitConverter.GetBytes(distribution.Iteration));
                    writer.Write(distribution.ChainKey);
                    dataToVerify = ms.ToArray();
                }

                // Verify the signature
                return MessageSigning.VerifySignature(
                    dataToVerify,
                    distribution.Signature,
                    distribution.SenderIdentityKey);
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(SenderKeyDistribution),
                    $"Error verifying signature: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Encrypts a sender key distribution message for a specific recipient
        /// </summary>
        /// <param name="distribution">Distribution message to encrypt</param>
        /// <param name="recipientPublicKey">Recipient's public key</param>
        /// <param name="senderPrivateKey">Sender's private key</param>
        /// <returns>Encrypted distribution message</returns>
        public static EncryptedSenderKeyDistribution EncryptSenderKeyDistribution(
            SenderKeyDistributionMessage distribution,
            byte[] recipientPublicKey,
            byte[] senderPrivateKey)
        {
            ArgumentNullException.ThrowIfNull(distribution, nameof(distribution));
            ArgumentNullException.ThrowIfNull(recipientPublicKey, nameof(recipientPublicKey));
            ArgumentNullException.ThrowIfNull(senderPrivateKey, nameof(senderPrivateKey));

            // Serialize the distribution message
            byte[] serializedData;
            using (var ms = new MemoryStream())
            using (var writer = new BinaryWriter(ms))
            {
                writer.Write(distribution.GroupId ?? string.Empty);
                writer.Write(distribution.Iteration);
                writer.Write(distribution.ChainKey?.Length ?? 0);
                if (distribution.ChainKey != null)
                    writer.Write(distribution.ChainKey);
                writer.Write(distribution.SenderIdentityKey?.Length ?? 0);
                if (distribution.SenderIdentityKey != null)
                    writer.Write(distribution.SenderIdentityKey);
                writer.Write(distribution.Signature?.Length ?? 0);
                if (distribution.Signature != null)
                    writer.Write(distribution.Signature);
                writer.Write(distribution.Timestamp);
                writer.Write(distribution.MessageId ?? string.Empty);

                serializedData = ms.ToArray();
            }

            // Generate a random nonce
            byte[] nonce = NonceGenerator.GenerateNonce();

            try
            {
                // Generate a shared secret using X25519
                byte[] sharedSecret = X3DHExchange.PerformX25519DH(senderPrivateKey, recipientPublicKey);

                // Derive an encryption key from the shared secret
                byte[] encryptionKey = KeyConversion.HkdfDerive(
                    sharedSecret,
                    null, // No salt needed
                    Encoding.UTF8.GetBytes("SenderKeyDistributionEncryption"),
                    Constants.AES_KEY_SIZE);

                // Encrypt the serialized data
                byte[] ciphertext = AES.AESEncrypt(serializedData, encryptionKey, nonce);

                // Create and return the encrypted distribution
                return new EncryptedSenderKeyDistribution
                {
                    Ciphertext = ciphertext,
                    Nonce = nonce,
                    RecipientPublicKey = recipientPublicKey,
                    SenderPublicKey = distribution.SenderIdentityKey
                };
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(SenderKeyDistribution), $"Error encrypting distribution: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Decrypts an encrypted sender key distribution message
        /// </summary>
        /// <param name="encryptedDistribution">Encrypted distribution message</param>
        /// <param name="recipientPrivateKey">Recipient's private key</param>
        /// <returns>Decrypted distribution message</returns>
        public static SenderKeyDistributionMessage DecryptSenderKeyDistribution(
            EncryptedSenderKeyDistribution encryptedDistribution,
            byte[] recipientPrivateKey)
        {
            ArgumentNullException.ThrowIfNull(encryptedDistribution, nameof(encryptedDistribution));
            ArgumentNullException.ThrowIfNull(recipientPrivateKey, nameof(recipientPrivateKey));
            ArgumentNullException.ThrowIfNull(encryptedDistribution.Ciphertext, nameof(encryptedDistribution.Ciphertext));
            ArgumentNullException.ThrowIfNull(encryptedDistribution.Nonce, nameof(encryptedDistribution.Nonce));
            ArgumentNullException.ThrowIfNull(encryptedDistribution.SenderPublicKey, nameof(encryptedDistribution.SenderPublicKey));
            ArgumentNullException.ThrowIfNull(encryptedDistribution.RecipientPublicKey, nameof(encryptedDistribution.RecipientPublicKey));

            try
            {
                // Generate a shared secret using X25519
                byte[] sharedSecret = X3DHExchange.PerformX25519DH(recipientPrivateKey, encryptedDistribution.SenderPublicKey);

                // Derive an encryption key from the shared secret
                byte[] encryptionKey = KeyConversion.HkdfDerive(
                    sharedSecret,
                    null, // No salt needed
                    Encoding.UTF8.GetBytes("SenderKeyDistributionEncryption"),
                    Constants.AES_KEY_SIZE);

                // Decrypt the ciphertext
                byte[] plaintext = AES.AESDecrypt(encryptedDistribution.Ciphertext, encryptionKey, encryptedDistribution.Nonce);

                // Deserialize the distribution message
                SenderKeyDistributionMessage distribution = new SenderKeyDistributionMessage();
                using (var ms = new MemoryStream(plaintext))
                using (var reader = new BinaryReader(ms))
                {
                    distribution.GroupId = reader.ReadString();
                    distribution.Iteration = reader.ReadUInt32();

                    int chainKeyLength = reader.ReadInt32();
                    if (chainKeyLength > 0)
                        distribution.ChainKey = reader.ReadBytes(chainKeyLength);

                    int senderKeyLength = reader.ReadInt32();
                    if (senderKeyLength > 0)
                        distribution.SenderIdentityKey = reader.ReadBytes(senderKeyLength);

                    int signatureLength = reader.ReadInt32();
                    if (signatureLength > 0)
                        distribution.Signature = reader.ReadBytes(signatureLength);

                    distribution.Timestamp = reader.ReadInt64();
                    distribution.MessageId = reader.ReadString();
                }

                return distribution;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(SenderKeyDistribution), $"Error decrypting distribution: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Retrieves the message key needed to decrypt an incoming group message,
        /// based on the sender and iteration number. Handles skipped messages by ratcheting forward.
        /// </summary>
        /// <param name="encryptedMessage">The incoming encrypted group message.</param>
        /// <param name="skippedKeyCache">A cache/store for skipped message keys.</param>
        /// <param name="explicitIteration">Optional explicit iteration to use.</param>
        /// <returns>The derived Message Key if successful, otherwise null.</returns>
        public byte[]? GetSenderKeyForMessage(
            EncryptedGroupMessage encryptedMessage,
            ISkippedMessageKeyStore skippedKeyCache,
            uint? explicitIteration = null)
        {
            ArgumentNullException.ThrowIfNull(encryptedMessage, nameof(encryptedMessage));
            ArgumentNullException.ThrowIfNull(encryptedMessage.GroupId, nameof(encryptedMessage.GroupId));
            ArgumentNullException.ThrowIfNull(encryptedMessage.SenderIdentityKey, nameof(encryptedMessage.SenderIdentityKey));
            ArgumentNullException.ThrowIfNull(skippedKeyCache, nameof(skippedKeyCache));

            // Extract iteration - either use explicit value, extract from message ID, or default to 0
            uint messageIteration = explicitIteration ?? ExtractIterationFromMessageId(encryptedMessage.MessageId) ?? 0;

            string storageKey = GetStorageKey(encryptedMessage.GroupId, encryptedMessage.SenderIdentityKey);

            if (!_receivedStates.TryGetValue(storageKey, out ReceivedSenderKeyState? currentState))
            {
                LoggingManager.LogWarning(nameof(SenderKeyDistribution),
                    $"No sender key state found for {storageKey}. Cannot decrypt message.");
                return null;
            }

            if (messageIteration < currentState.Iteration)
            {
                // Message is from the past relative to our current chain key state
                // Try to find the key in the skipped message key cache
                LoggingManager.LogDebug(nameof(SenderKeyDistribution),
                    $"Message iteration {messageIteration} is older than current state {currentState.Iteration}. Checking skipped cache.");

                return skippedKeyCache.GetSkippedMessageKey(
                    encryptedMessage.GroupId,
                    encryptedMessage.SenderIdentityKey,
                    messageIteration);
            }

            // Ratchet Forward or Derive Current
            byte[] currentChainKey = (byte[])currentState.ChainKey.Clone();
            uint currentIteration = currentState.Iteration;
            byte[]? derivedMessageKey = null;
            ReceivedSenderKeyState newState;

            try
            {
                // Ratchet forward efficiently if needed
                if (currentIteration < messageIteration)
                {
                    // Store intermediate keys while ratcheting
                    for (; currentIteration < messageIteration; currentIteration++)
                    {
                        byte[] skippedMessageKey = Sodium.GenerateHmacSha256([MESSAGE_KEY_SEED_BYTE], currentChainKey);
                        byte[] nextChainKey = Sodium.GenerateHmacSha256([CHAIN_KEY_SEED_BYTE], currentChainKey);

                        // Store the skipped message key
                        skippedKeyCache.StoreSkippedMessageKey(
                            encryptedMessage.GroupId,
                            encryptedMessage.SenderIdentityKey,
                            currentIteration,
                            skippedMessageKey);

                        // Update chain key for next iteration
                        SecureMemory.SecureClear(currentChainKey);
                        currentChainKey = nextChainKey;
                    }

                    // Create new state to update storage
                    newState = new ReceivedSenderKeyState
                    {
                        ChainKey = (byte[])currentChainKey.Clone(),
                        Iteration = messageIteration
                    };

                    // Try to update state atomically
                    if (!_receivedStates.TryUpdate(storageKey, newState, currentState))
                    {
                        // If update fails due to concurrent modification, don't throw - just proceed
                        // with current key for this message and let next message trigger the update
                        LoggingManager.LogWarning(nameof(SenderKeyDistribution),
                            $"Concurrent state update detected for {storageKey}");
                        newState.Clear();
                    }
                }

                // Derive the message key for the current iteration
                derivedMessageKey = Sodium.GenerateHmacSha256([MESSAGE_KEY_SEED_BYTE], currentChainKey);

                return derivedMessageKey;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(SenderKeyDistribution),
                    $"Error deriving key for {storageKey}: {ex.Message}");
                return null;
            }
            finally
            {
                // Clear any remaining sensitive data
                SecureMemory.SecureClear(currentChainKey);
            }
        }

        /// <summary>
        /// Extracts iteration from message ID if encoded in format "iter:{iteration}:{originalId}"
        /// </summary>
        /// <param name="messageId">Message ID to parse</param>
        /// <returns>Extracted iteration or null if not found</returns>
        private uint? ExtractIterationFromMessageId(string? messageId)
        {
            if (string.IsNullOrEmpty(messageId) || !messageId.StartsWith("iter:"))
            {
                return null;
            }

            string[] parts = messageId.Split(':', 3);
            if (parts.Length >= 2 && uint.TryParse(parts[1], out uint parsedIteration))
            {
                return parsedIteration;
            }

            return null;
        }

        /// <summary>
        /// Generates a storage key for dictionaries.
        /// </summary>
        private string GetStorageKey(string groupId, byte[] senderPublicKey)
        {
            string senderKeyBase64 = Convert.ToBase64String(senderPublicKey);
            return $"{groupId}:{senderKeyBase64}";
        }

        /// <summary>
        /// Removes all stored sender key states for a specific group.
        /// </summary>
        public bool DeleteGroupDistributions(string groupId)
        {
            ArgumentException.ThrowIfNullOrEmpty(groupId, nameof(groupId));

            bool anyRemoved = false;
            var keysToRemove = _receivedStates.Keys
                .Where(k => k.StartsWith($"{groupId}:"))
                .ToList();

            foreach (var key in keysToRemove)
            {
                if (_receivedStates.TryRemove(key, out ReceivedSenderKeyState? removedState))
                {
                    removedState?.Clear();
                    anyRemoved = true;
                }
            }

            return anyRemoved;
        }

        /// <summary>
        /// Securely clears all stored keys.
        /// </summary>
        public void Dispose()
        {
            foreach (var state in _receivedStates.Values)
            {
                state.Clear();
            }

            _receivedStates.Clear();
            GC.SuppressFinalize(this);
        }

        ~SenderKeyDistribution() => Dispose();

        /// <summary>
        /// Interface for Skipped Key Storage
        /// </summary>
        public interface ISkippedMessageKeyStore
        {
            void StoreSkippedMessageKey(string groupId, byte[] senderId, uint iteration, byte[] messageKey);
            byte[]? GetSkippedMessageKey(string groupId, byte[] senderId, uint iteration);
        }
    }
}