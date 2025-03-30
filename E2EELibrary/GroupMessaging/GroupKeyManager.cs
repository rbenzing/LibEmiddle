using System.Security.Cryptography;
using E2EELibrary.Core;
using E2EELibrary.KeyManagement;

namespace E2EELibrary.GroupMessaging
{
    /// <summary>
    /// Manages cryptographic keys for group chats, including generation, rotation, and derivation.
    /// </summary>
    public class GroupKeyManager
    {
        // Default key size for group keys
        private const int GROUP_KEY_SIZE = Constants.AES_KEY_SIZE;

        // Default number of days before triggering a key rotation
        private const int DEFAULT_ROTATION_DAYS = 30;

        // Store a map of group chain keys
        private readonly Dictionary<string, byte[]> _chainKeys = new Dictionary<string, byte[]>();

        /// <summary>
        /// Generates a new cryptographically secure key for group encryption
        /// </summary>
        /// <returns>New random key suitable for group encryption</returns>
        public byte[] GenerateGroupKey()
        {
            byte[] key = new byte[GROUP_KEY_SIZE];
            RandomNumberGenerator.Fill(key);
            return key;
        }

        /// <summary>
        /// Derives a chain key for message encryption from a sender key
        /// </summary>
        /// <param name="groupId">Group identifier</param>
        /// <param name="senderKey">Base sender key</param>
        /// <returns>Chain key for message encryption</returns>
        public byte[] DeriveChainKey(string groupId, byte[] senderKey)
        {
            // If we already have a chain key for this group, return it
            if (_chainKeys.TryGetValue(groupId, out byte[]? existingChainKey))
            {
                return existingChainKey;
            }

            // Otherwise, derive a new chain key using HKDF
            using var hmac = new HMACSHA256(senderKey);
            byte[] info = System.Text.Encoding.UTF8.GetBytes($"GroupChainKey-{groupId}");
            byte[] chainKey = hmac.ComputeHash(info);

            // Store for future use
            _chainKeys[groupId] = chainKey;

            return chainKey;
        }

        /// <summary>
        /// Updates the chain key for a group by performing a ratchet step
        /// </summary>
        /// <param name="groupId">Group identifier</param>
        /// <returns>New message key for encryption</returns>
        public byte[] RatchetChainKey(string groupId)
        {
            if (!_chainKeys.TryGetValue(groupId, out byte[]? currentChainKey))
            {
                throw new InvalidOperationException($"No chain key exists for group {groupId}");
            }

            // Perform a ratchet step to derive a new chain key and message key
            using var hmac = new HMACSHA256(currentChainKey);

            // CK_next = HMAC-SHA256(CK, 0x01)
            byte[] nextChainKey = hmac.ComputeHash(new byte[] { 0x01 });

            // Reset HMAC with the same key but new message
            hmac.Initialize();

            // MK = HMAC-SHA256(CK, 0x02)
            byte[] messageKey = hmac.ComputeHash(new byte[] { 0x02 });

            // Update the stored chain key
            _chainKeys[groupId] = nextChainKey;

            return messageKey;
        }

        /// <summary>
        /// Checks if a key should be rotated based on creation time
        /// </summary>
        /// <param name="keyCreationTime">Time when key was created (milliseconds since epoch)</param>
        /// <param name="rotationDays">Days after which to rotate (defaults to 30)</param>
        /// <returns>True if key rotation is recommended</returns>
        public bool ShouldRotateKey(long keyCreationTime, int rotationDays = DEFAULT_ROTATION_DAYS)
        {
            long currentTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            long rotationInterval = rotationDays * 24 * 60 * 60 * 1000L; // Convert days to milliseconds

            return (currentTime - keyCreationTime) > rotationInterval;
        }

        /// <summary>
        /// Derives a subkey for a specific purpose from the main group key
        /// </summary>
        /// <param name="groupKey">Base group key</param>
        /// <param name="purpose">Purpose of the derived key (e.g., "Encryption", "Authentication")</param>
        /// <returns>Derived key for specific purpose</returns>
        public byte[] DeriveSubkey(byte[] groupKey, string purpose)
        {
            using var hmac = new HMACSHA256(groupKey);
            byte[] info = System.Text.Encoding.UTF8.GetBytes(purpose);
            return hmac.ComputeHash(info);
        }

        /// <summary>
        /// Clears all chain keys for security (e.g., when app is closing)
        /// </summary>
        public void ClearAllChainKeys()
        {
            foreach (var key in _chainKeys.Values)
            {
                // Securely clear the key data
                SecureMemory.SecureClear(key);
            }

            _chainKeys.Clear();
        }

        /// <summary>
        /// Clears chain key for a specific group
        /// </summary>
        /// <param name="groupId">Group identifier</param>
        public void ClearChainKey(string groupId)
        {
            if (_chainKeys.TryGetValue(groupId, out byte[]? chainKey))
            {
                // Securely clear the key data
                SecureMemory.SecureClear(chainKey);
                _chainKeys.Remove(groupId);
            }
        }
    }
}