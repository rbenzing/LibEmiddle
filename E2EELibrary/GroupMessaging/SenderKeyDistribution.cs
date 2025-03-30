using System.Collections.Concurrent;
using System.Security.Cryptography;
using E2EELibrary.Communication;
using E2EELibrary.Models;

namespace E2EELibrary.GroupMessaging
{
    /// <summary>
    /// Manages sender key distribution for secure group messaging
    /// </summary>
    public class SenderKeyDistribution
    {
        // Maps (groupId, senderKey64) to sender keys
        private readonly ConcurrentDictionary<string, byte[]> _senderKeys = new ConcurrentDictionary<string, byte[]>();

        // Identity key pair for this client
        private readonly (byte[] publicKey, byte[] privateKey) _identityKeyPair;

        /// <summary>
        /// Creates a new SenderKeyDistribution instance
        /// </summary>
        /// <param name="identityKeyPair">Identity key pair for this client</param>
        public SenderKeyDistribution((byte[] publicKey, byte[] privateKey) identityKeyPair)
        {
            _identityKeyPair = identityKeyPair;
        }

        /// <summary>
        /// Creates a distribution message for sharing a sender key
        /// </summary>
        /// <param name="groupId">Group identifier</param>
        /// <param name="senderKey">Sender key to distribute</param>
        /// <returns>Distribution message that can be shared with other members</returns>
        public SenderKeyDistributionMessage CreateDistributionMessage(string groupId, byte[] senderKey)
        {
            ArgumentNullException.ThrowIfNull(groupId, nameof(groupId));
            ArgumentNullException.ThrowIfNull(senderKey, nameof(senderKey));

            // Store the sender key locally
            string storageKey = GetStorageKey(groupId, _identityKeyPair.publicKey);
            _senderKeys[storageKey] = senderKey;

            // Sign the sender key
            byte[] signature = MessageSigning.SignMessage(senderKey, _identityKeyPair.privateKey);

            // Create the distribution message
            return new SenderKeyDistributionMessage
            {
                GroupId = groupId,
                SenderKey = senderKey,
                SenderIdentityKey = _identityKeyPair.publicKey,
                Signature = signature,
                MessageId = Guid.NewGuid().ToString()
            };
        }

        /// <summary>
        /// Processes a received sender key distribution message
        /// </summary>
        /// <param name="distribution">Distribution message to process</param>
        /// <returns>True if the distribution was valid and processed</returns>
        public bool ProcessDistributionMessage(SenderKeyDistributionMessage distribution)
        {
            ArgumentNullException.ThrowIfNull(distribution, nameof(distribution));
            ArgumentNullException.ThrowIfNull(distribution.GroupId, nameof(distribution.GroupId));
            ArgumentNullException.ThrowIfNull(distribution.SenderKey, nameof(distribution.SenderKey));
            ArgumentNullException.ThrowIfNull(distribution.SenderIdentityKey, nameof(distribution.SenderIdentityKey));
            ArgumentNullException.ThrowIfNull(distribution.Signature, nameof(distribution.Signature));

            // Verify the signature
            if (!MessageSigning.VerifySignature(distribution.SenderKey, distribution.Signature, distribution.SenderIdentityKey))
            {
                return false;
            }

            // Store the sender key
            string storageKey = GetStorageKey(distribution.GroupId, distribution.SenderIdentityKey);
            _senderKeys[storageKey] = distribution.SenderKey;

            return true;
        }

        /// <summary>
        /// Retrieves the sender key for a specific group message
        /// </summary>
        /// <param name="encryptedMessage">The encrypted group message</param>
        /// <returns>Sender key if available, otherwise null</returns>
        public byte[]? GetSenderKeyForMessage(EncryptedGroupMessage encryptedMessage)
        {
            ArgumentNullException.ThrowIfNull(encryptedMessage, nameof(encryptedMessage));
            ArgumentNullException.ThrowIfNull(encryptedMessage.GroupId, nameof(encryptedMessage.GroupId));
            ArgumentNullException.ThrowIfNull(encryptedMessage.SenderIdentityKey, nameof(encryptedMessage.SenderIdentityKey));

            // Get the storage key
            string storageKey = GetStorageKey(encryptedMessage.GroupId, encryptedMessage.SenderIdentityKey);

            // Retrieve the sender key
            if (_senderKeys.TryGetValue(storageKey, out byte[]? senderKey))
            {
                return senderKey;
            }

            return null;
        }

        /// <summary>
        /// Generates a storage key for the dictionary
        /// </summary>
        /// <param name="groupId">Group identifier</param>
        /// <param name="senderPublicKey">Sender's public key</param>
        /// <returns>Storage key string</returns>
        private string GetStorageKey(string groupId, byte[] senderPublicKey)
        {
            string senderKeyBase64 = Convert.ToBase64String(senderPublicKey);
            return $"{groupId}:{senderKeyBase64}";
        }

        /// <summary>
        /// Removes all sender keys for a group
        /// </summary>
        /// <param name="groupId">Group identifier</param>
        /// <returns>True if any keys were deleted</returns>
        public bool DeleteGroupDistributions(string groupId)
        {
            ArgumentNullException.ThrowIfNull(groupId, nameof(groupId));

            bool anyRemoved = false;

            // Find all keys for this group
            var keysToRemove = _senderKeys.Keys
                .Where(k => k.StartsWith($"{groupId}:"))
                .ToList();

            // Remove each key
            foreach (var key in keysToRemove)
            {
                anyRemoved |= _senderKeys.TryRemove(key, out _);
            }

            return anyRemoved;
        }

        /// <summary>
        /// Rotates a sender key for a group
        /// </summary>
        /// <param name="groupId">Group identifier</param>
        /// <param name="newSenderKey">New sender key</param>
        /// <returns>Distribution message with the new key</returns>
        public SenderKeyDistributionMessage RotateSenderKey(string groupId, byte[] newSenderKey)
        {
            ArgumentNullException.ThrowIfNull(groupId, nameof(groupId));
            ArgumentNullException.ThrowIfNull(newSenderKey, nameof(newSenderKey));

            // Store the new sender key
            string storageKey = GetStorageKey(groupId, _identityKeyPair.publicKey);
            _senderKeys[storageKey] = newSenderKey;

            // Sign the new sender key
            byte[] signature = MessageSigning.SignMessage(newSenderKey, _identityKeyPair.privateKey);

            // Create the distribution message
            return new SenderKeyDistributionMessage
            {
                GroupId = groupId,
                SenderKey = newSenderKey,
                SenderIdentityKey = _identityKeyPair.publicKey,
                Signature = signature,
                MessageId = Guid.NewGuid().ToString()
            };
        }

        /// <summary>
        /// Gets all sender keys for a group
        /// </summary>
        /// <param name="groupId">Group identifier</param>
        /// <returns>Dictionary mapping sender public keys to their sender keys</returns>
        public Dictionary<string, byte[]> GetAllSenderKeysForGroup(string groupId)
        {
            ArgumentNullException.ThrowIfNull(groupId, nameof(groupId));

            var result = new Dictionary<string, byte[]>();
            string groupPrefix = $"{groupId}:";

            foreach (var entry in _senderKeys)
            {
                // Check if this entry is for our group
                if (entry.Key.StartsWith(groupPrefix))
                {
                    // Extract the sender key part (after the colon)
                    string senderKeyBase64 = entry.Key.Substring(groupPrefix.Length);
                    result[senderKeyBase64] = entry.Value;
                }
            }

            return result;
        }

        /// <summary>
        /// Validates a sender key distribution message
        /// </summary>
        /// <param name="distribution">Distribution message to validate</param>
        /// <returns>True if the message is valid</returns>
        public bool ValidateDistributionMessage(SenderKeyDistributionMessage distribution)
        {
            ArgumentNullException.ThrowIfNull(distribution, nameof(distribution));

            // Check for null or empty fields
            if (string.IsNullOrEmpty(distribution.GroupId) ||
                distribution.SenderKey == null ||
                distribution.SenderKey.Length == 0 ||
                distribution.SenderIdentityKey == null ||
                distribution.SenderIdentityKey.Length == 0 ||
                distribution.Signature == null ||
                distribution.Signature.Length == 0)
            {
                return false;
            }

            // Verify the signature
            return MessageSigning.VerifySignature(distribution.SenderKey, distribution.Signature, distribution.SenderIdentityKey);
        }
    }
}