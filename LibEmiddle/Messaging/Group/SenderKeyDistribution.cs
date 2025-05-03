using System.Collections.Concurrent;
using System.Text;
using LibEmiddle.Core;
using LibEmiddle.Domain;
using LibEmiddle.Abstractions;

namespace LibEmiddle.Messaging.Group
{
    /// <summary>
    /// Manages the distribution of sender keys for group messaging,
    /// handling the secure sharing of encryption keys between group members.
    /// </summary>
    public class SenderKeyDistribution
    {
        private readonly ICryptoProvider _cryptoProvider;
        private readonly GroupKeyManager _keyManager;

        // Cache of distribution messages by group ID
        private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, SenderKeyDistributionMessage>> _distributionMessages =
            new ConcurrentDictionary<string, ConcurrentDictionary<string, SenderKeyDistributionMessage>>();

        /// <summary>
        /// Initializes a new instance of the SenderKeyDistribution class.
        /// </summary>
        /// <param name="cryptoProvider">The cryptographic provider implementation.</param>
        /// <param name="keyManager">The group key manager.</param>
        public SenderKeyDistribution(ICryptoProvider cryptoProvider, GroupKeyManager keyManager)
        {
            _cryptoProvider = cryptoProvider ?? throw new ArgumentNullException(nameof(cryptoProvider));
            _keyManager = keyManager ?? throw new ArgumentNullException(nameof(keyManager));
        }

        /// <summary>
        /// Creates a new sender key distribution message for a group.
        /// </summary>
        /// <param name="groupId">The identifier of the group.</param>
        /// <param name="chainKey">The chain key to distribute.</param>
        /// <param name="iteration">The current iteration of the chain.</param>
        /// <param name="senderKeyPair">Optional sender key pair for signing.</param>
        /// <returns>The created sender key distribution message.</returns>
        public SenderKeyDistributionMessage CreateDistributionMessage(
            string groupId,
            byte[] chainKey,
            uint iteration,
            KeyPair? senderKeyPair = null)
        {
            if (string.IsNullOrEmpty(groupId))
                throw new ArgumentException("Group ID cannot be null or empty.", nameof(groupId));

            if (chainKey == null || chainKey.Length != Constants.CHAIN_KEY_SIZE)
                throw new ArgumentException($"Chain key must be {Constants.CHAIN_KEY_SIZE} bytes.", nameof(chainKey));

            // Create the distribution message
            var distribution = new SenderKeyDistributionMessage
            {
                GroupId = groupId,
                ChainKey = chainKey.ToArray(), // Create a copy
                Iteration = iteration,
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
            };

            // Sign the message if a key pair is provided
            if (senderKeyPair != null && senderKeyPair.PrivateKey != null && senderKeyPair.PublicKey != null)
            {
                distribution.SenderIdentityKey = senderKeyPair.PublicKey.ToArray();
                byte[] dataToSign = GetDataToSign(distribution);
                distribution.Signature = _cryptoProvider.Sign(dataToSign, senderKeyPair.PrivateKey);
            }

            // Cache the distribution message
            var groupDistributions = _distributionMessages.GetOrAdd(groupId, _ => new ConcurrentDictionary<string, SenderKeyDistributionMessage>());
            string senderId = distribution.SenderIdentityKey != null ? Convert.ToBase64String(distribution.SenderIdentityKey) : "self";
            groupDistributions[senderId] = distribution;

            return distribution;
        }

        /// <summary>
        /// Processes a received sender key distribution message.
        /// </summary>
        /// <param name="distribution">The sender key distribution message to process.</param>
        /// <returns>True if the message was processed successfully.</returns>
        public bool ProcessDistributionMessage(SenderKeyDistributionMessage distribution)
        {
            if (distribution == null)
                throw new ArgumentNullException(nameof(distribution));

            // Validate the distribution message
            if (!_keyManager.ValidateDistributionMessage(distribution))
                return false;

            // Verify the signature if present
            if (distribution.Signature != null && distribution.SenderIdentityKey != null)
            {
                byte[] dataToSign = GetDataToSign(distribution);
                if (!_cryptoProvider.VerifySignature(dataToSign, distribution.Signature, distribution.SenderIdentityKey))
                {
                    LoggingManager.LogWarning(nameof(SenderKeyDistribution),
                        $"Invalid signature on distribution message for group {distribution.GroupId}");
                    return false;
                }
            }

            string groupId = distribution.GroupId;
            byte[]? senderIdentityKey = distribution.SenderIdentityKey;

            if (senderIdentityKey == null)
            {
                LoggingManager.LogWarning(nameof(SenderKeyDistribution),
                    $"Missing sender identity key in distribution message for group {groupId}");
                return false;
            }

            // Store the sender key for this group and sender
            bool stored = _keyManager.StoreSenderKey(groupId, senderIdentityKey, distribution.ChainKey);
            if (!stored)
            {
                LoggingManager.LogError(nameof(SenderKeyDistribution),
                    $"Failed to store sender key for group {groupId}");
                return false;
            }

            // Cache the distribution message
            var groupDistributions = _distributionMessages.GetOrAdd(groupId, _ => new ConcurrentDictionary<string, SenderKeyDistributionMessage>());
            string senderId = Convert.ToBase64String(senderIdentityKey);
            groupDistributions[senderId] = distribution;

            return true;
        }

        /// <summary>
        /// Gets the sender key for a specific message.
        /// </summary>
        /// <param name="message">The encrypted group message.</param>
        /// <returns>The sender key to use for decryption.</returns>
        public byte[]? GetSenderKeyForMessage(EncryptedGroupMessage message)
        {
            if (message == null)
                throw new ArgumentNullException(nameof(message));

            string groupId = message.GroupId;
            byte[] senderIdentityKey = message.SenderIdentityKey;

            // Get the sender key from the key manager
            return _keyManager.GetSenderKey(groupId, senderIdentityKey);
        }

        /// <summary>
        /// Gets a distribution message for a specific group and sender.
        /// </summary>
        /// <param name="groupId">The identifier of the group.</param>
        /// <param name="senderIdentityKey">The sender's identity key.</param>
        /// <returns>The sender key distribution message.</returns>
        public SenderKeyDistributionMessage? GetDistributionMessage(string groupId, byte[] senderIdentityKey)
        {
            if (string.IsNullOrEmpty(groupId))
                throw new ArgumentException("Group ID cannot be null or empty.", nameof(groupId));

            if (senderIdentityKey == null || senderIdentityKey.Length == 0)
                throw new ArgumentException("Sender identity key cannot be null or empty.", nameof(senderIdentityKey));

            if (_distributionMessages.TryGetValue(groupId, out var groupDistributions))
            {
                string senderId = Convert.ToBase64String(senderIdentityKey);
                if (groupDistributions.TryGetValue(senderId, out var distribution))
                {
                    return distribution;
                }
            }

            return null;
        }

        /// <summary>
        /// Deletes all distribution messages for a group.
        /// </summary>
        /// <param name="groupId">The identifier of the group.</param>
        /// <returns>True if the distribution messages were deleted.</returns>
        public bool DeleteGroupDistributions(string groupId)
        {
            if (string.IsNullOrEmpty(groupId))
                throw new ArgumentException("Group ID cannot be null or empty.", nameof(groupId));

            return _distributionMessages.TryRemove(groupId, out _);
        }

        /// <summary>
        /// Gets the data to sign for a distribution message.
        /// </summary>
        /// <param name="distribution">The distribution message.</param>
        /// <returns>The data to sign.</returns>
        private byte[] GetDataToSign(SenderKeyDistributionMessage distribution)
        {
            // Combine all relevant fields for signing
            using var ms = new System.IO.MemoryStream();
            using var writer = new System.IO.BinaryWriter(ms);

            writer.Write(Encoding.UTF8.GetBytes(distribution.GroupId));
            writer.Write(distribution.ChainKey);
            writer.Write(distribution.Iteration);
            writer.Write(distribution.Timestamp);
            if (distribution.SenderIdentityKey != null)
            {
                writer.Write(distribution.SenderIdentityKey);
            }

            return ms.ToArray();
        }

        /// <summary>
        /// Exports the state of all distribution messages for persistence.
        /// </summary>
        /// <returns>The serialized state.</returns>
        public string ExportState()
        {
            // In a real implementation, this would serialize the distribution message cache
            // to a format suitable for persistence

            // For simplicity, we'll return an empty string here
            return string.Empty;
        }

        /// <summary>
        /// Imports distribution message state from persistence.
        /// </summary>
        /// <param name="serializedState">The serialized state.</param>
        /// <returns>True if the state was imported successfully.</returns>
        public bool ImportState(string serializedState)
        {
            // In a real implementation, this would deserialize the distribution message cache
            // from a persisted format

            // For simplicity, we'll return true here
            return true;
        }
    }
}