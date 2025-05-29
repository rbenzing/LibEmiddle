using System.Collections.Concurrent;
using System.Text;
using LibEmiddle.Core;
using LibEmiddle.Domain;
using LibEmiddle.Abstractions;

namespace LibEmiddle.Messaging.Group
{
    /// <summary>
    /// Handles cryptographic operations for group messages, including encryption,
    /// decryption, and authentication for group communication.
    /// </summary>
    /// <remarks>
    /// Initializes a new instance of the GroupMessageCrypto class.
    /// </remarks>
    /// <param name="cryptoProvider">The cryptographic provider implementation.</param>
    public class GroupMessageCrypto(ICryptoProvider cryptoProvider) : IGroupMessageCrypto
    {
        private readonly ICryptoProvider _cryptoProvider = cryptoProvider ?? throw new ArgumentNullException(nameof(cryptoProvider));

        // Records of when users joined groups, used for replay protection
        private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, long>> _groupJoinTimestamps = new();

        /// <summary>
        /// Encrypts a message for a group using a message key.
        /// </summary>
        /// <param name="groupId">The identifier of the group.</param>
        /// <param name="message">The plaintext message to encrypt.</param>
        /// <param name="messageKey">The message key to use for encryption.</param>
        /// <param name="senderKeyPair">The sender's key pair for signing.</param>
        /// <param name="rotationTimestamp">Timestamp of the last key rotation.</param>
        /// <returns>The encrypted group message.</returns>
        public EncryptedGroupMessage EncryptMessage(
            string groupId,
            string message,
            byte[] messageKey,
            KeyPair senderKeyPair,
            long rotationTimestamp)
        {
            if (string.IsNullOrEmpty(groupId))
                throw new ArgumentException("Group ID cannot be null or empty.", nameof(groupId));

            if (string.IsNullOrEmpty(message))
                throw new ArgumentException("Message cannot be null or empty.", nameof(message));

            if (messageKey == null || messageKey.Length != Constants.MESSAGE_KEY_SIZE)
                throw new ArgumentException($"Message key must be {Constants.MESSAGE_KEY_SIZE} bytes.", nameof(messageKey));

            if (senderKeyPair.PrivateKey == null || senderKeyPair.PublicKey == null)
                throw new ArgumentException("Sender key pair is incomplete.", nameof(senderKeyPair));

            try
            {
                // Generate a random nonce
                byte[] nonce = _cryptoProvider.GenerateRandomBytes(Constants.NONCE_SIZE);

                // Encode the message
                byte[] plaintext = Encoding.Default.GetBytes(message);

                // Create associated data (group ID and timestamp)
                byte[] associatedData = Encoding.Default.GetBytes($"{groupId}:{rotationTimestamp}");

                // Encrypt the message
                byte[] ciphertext = _cryptoProvider.Encrypt(plaintext, messageKey, nonce, associatedData);

                // Create the encrypted message
                var encryptedMessage = new EncryptedGroupMessage
                {
                    GroupId = groupId,
                    SenderIdentityKey = senderKeyPair.PublicKey,
                    Ciphertext = ciphertext,
                    Nonce = nonce,
                    Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    RotationEpoch = rotationTimestamp,
                    MessageId = Guid.NewGuid().ToString("N")
                };

                // Sign the message
                byte[] messageData = GetDataToSign(encryptedMessage);
                encryptedMessage.Signature = _cryptoProvider.Sign(messageData, senderKeyPair.PrivateKey);

                return encryptedMessage;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(GroupMessageCrypto), $"Error encrypting message for group {groupId}: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Decrypts a group message using a sender key.
        /// </summary>
        /// <param name="encryptedMessage">The encrypted message to decrypt.</param>
        /// <param name="senderKey">The sender key for decryption.</param>
        /// <returns>The decrypted message content.</returns>
        public string? DecryptMessage(EncryptedGroupMessage encryptedMessage, byte[] senderKey)
        {
            if (encryptedMessage == null)
                throw new ArgumentNullException(nameof(encryptedMessage));

            if (senderKey == null || senderKey.Length != Constants.MESSAGE_KEY_SIZE)
                throw new ArgumentException($"Sender key must be {Constants.MESSAGE_KEY_SIZE} bytes.", nameof(senderKey));

            try
            {
                string groupId = encryptedMessage.GroupId;

                // Verify the message
                if (!VerifyMessage(encryptedMessage))
                {
                    LoggingManager.LogWarning(nameof(GroupMessageCrypto), $"Message signature verification failed for group {groupId}");
                    return null;
                }

                // Check for replay attack
                if (!ValidateMessageTimestamp(groupId, encryptedMessage.SenderIdentityKey, encryptedMessage.Timestamp))
                {
                    LoggingManager.LogWarning(nameof(GroupMessageCrypto), $"Possible replay attack detected in group {groupId}");
                    return null;
                }

                // Create associated data (group ID and rotation epoch)
                byte[] associatedData = Encoding.Default.GetBytes($"{groupId}:{encryptedMessage.RotationEpoch}");

                // Decrypt the message
                byte[] decrypted = _cryptoProvider.Decrypt(
                    encryptedMessage.Ciphertext,
                    senderKey,
                    encryptedMessage.Nonce,
                    associatedData);

                // Decode the message
                return Encoding.UTF8.GetString(decrypted);
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(GroupMessageCrypto), $"Error decrypting message for group {encryptedMessage.GroupId}: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Records when the user joined a group for message validation.
        /// </summary>
        /// <param name="groupId">The identifier of the group.</param>
        /// <param name="identityKeyPair">The identifier of the user.</param>
        /// <returns>The join timestamp.</returns>
        public long RecordGroupJoin(string groupId, KeyPair identityKeyPair)
        {
            if (string.IsNullOrEmpty(groupId))
                throw new ArgumentException("Group ID cannot be null or empty.", nameof(groupId));

            var joinTimestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            var userId = identityKeyPair.PublicKey.ToString() ?? throw new ArgumentNullException(nameof(identityKeyPair.PublicKey), "User PK cannot be null.");

            // Record the join timestamp
            var groupTimestamps = _groupJoinTimestamps.GetOrAdd(groupId, _ => new ConcurrentDictionary<string, long>());
            groupTimestamps[userId] = joinTimestamp;

            return joinTimestamp;
        }

        /// <summary>
        /// Verifies the signature of a group message.
        /// </summary>
        /// <param name="message">The encrypted message to verify.</param>
        /// <returns>True if the signature is valid.</returns>
        private bool VerifyMessage(EncryptedGroupMessage message)
        {
            if (message.Signature == null || message.SenderIdentityKey == null)
                return false;

            // Get the data that was signed
            byte[] messageData = GetDataToSign(message);

            // Verify the signature
            return _cryptoProvider.VerifySignature(messageData, message.Signature, message.SenderIdentityKey);
        }

        /// <summary>
        /// Gets the data to sign for a group message.
        /// </summary>
        /// <param name="message">The encrypted message.</param>
        /// <returns>The data to sign.</returns>
        private byte[] GetDataToSign(EncryptedGroupMessage message)
        {

            ArgumentNullException.ThrowIfNull(nameof(message));

            if (message.MessageId == null)
                throw new ArgumentNullException(nameof(message.MessageId));

            // Combine all relevant fields for signing
            using var ms = new MemoryStream();
            using var writer = new BinaryWriter(ms);

            writer.Write(Encoding.Default.GetBytes(message.GroupId));
            writer.Write(message.SenderIdentityKey);
            writer.Write(message.Ciphertext);
            writer.Write(message.Nonce);
            writer.Write(message.Timestamp);
            writer.Write(message.RotationEpoch);
            writer.Write(Encoding.Default.GetBytes(message.MessageId));

            return ms.ToArray();
        }

        /// <summary>
        /// Validates a message timestamp to prevent replay attacks.
        /// </summary>
        /// <param name="groupId">The identifier of the group.</param>
        /// <param name="senderPublicKey">The sender's public key.</param>
        /// <param name="messageTimestamp">The message timestamp to validate.</param>
        /// <returns>True if the timestamp is valid.</returns>
        private bool ValidateMessageTimestamp(string groupId, byte[] senderPublicKey, long messageTimestamp)
        {             
            var userId = senderPublicKey.ToString() ?? throw new ArgumentNullException(nameof(senderPublicKey), "Sender PK cannot be null.");

            // Get our join timestamp for this group
            if (_groupJoinTimestamps.TryGetValue(groupId, out var groupTimestamps) &&
                groupTimestamps.TryGetValue(userId, out var joinTimestamp))
            {
                // Allow a small tolerance for clock skew
                const long CLOCK_SKEW_TOLERANCE_MS = 5 * 60 * 1000; // 5 minutes

                // Check if the message is too old (before we joined)
                if (messageTimestamp < joinTimestamp - CLOCK_SKEW_TOLERANCE_MS)
                {
                    LoggingManager.LogWarning(nameof(GroupMessageCrypto),
                        $"Message from before we joined group {groupId}: message={messageTimestamp}, join={joinTimestamp}");
                    return false;
                }

                // Check if the message is too far in the future
                long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                if (messageTimestamp > now + CLOCK_SKEW_TOLERANCE_MS)
                {
                    LoggingManager.LogWarning(nameof(GroupMessageCrypto),
                        $"Message from the future in group {groupId}: message={messageTimestamp}, now={now}");
                    return false;
                }
            }

            return true;
        }
    }
}