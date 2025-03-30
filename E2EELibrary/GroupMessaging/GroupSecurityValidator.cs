using System.Text.RegularExpressions;
using E2EELibrary.Models;

namespace E2EELibrary.GroupMessaging
{
    /// <summary>
    /// Validates security parameters for group operations
    /// </summary>
    public class GroupSecurityValidator
    {
        // Regular expression for valid group IDs
        private static readonly Regex _validGroupIdRegex = new("^[a-zA-Z0-9][a-zA-Z0-9_-]{3,63}$", RegexOptions.Compiled);

        // Maximum age for messages in milliseconds (5 minutes)
        private const long MAX_MESSAGE_AGE_MS = 5 * 60 * 1000;

        /// <summary>
        /// Validates a group ID
        /// </summary>
        /// <param name="groupId">Group identifier to validate</param>
        /// <exception cref="ArgumentException">Thrown if the group ID is invalid</exception>
        public void ValidateGroupId(string groupId)
        {
            ArgumentNullException.ThrowIfNull(groupId, nameof(groupId));

            if (!IsValidGroupId(groupId))
            {
                throw new ArgumentException(
                    "Group ID must be 4-64 characters, containing only letters, numbers, underscores and hyphens, " +
                    "and must start with a letter or number",
                    nameof(groupId));
            }
        }

        /// <summary>
        /// Checks if a group ID is valid
        /// </summary>
        /// <param name="groupId">Group identifier to check</param>
        /// <returns>True if the group ID is valid</returns>
        public bool IsValidGroupId(string groupId)
        {
            if (string.IsNullOrEmpty(groupId))
            {
                return false;
            }

            return _validGroupIdRegex.IsMatch(groupId);
        }

        /// <summary>
        /// Validates a distribution message
        /// </summary>
        /// <param name="distribution">Distribution message to validate</param>
        /// <returns>True if the distribution message is valid</returns>
        public bool ValidateDistributionMessage(SenderKeyDistributionMessage distribution)
        {
            // Check for null
            if (distribution == null)
            {
                return false;
            }

            // Check for required fields
            if (string.IsNullOrEmpty(distribution.GroupId) ||
                distribution.SenderKey == null || distribution.SenderKey.Length == 0 ||
                distribution.SenderIdentityKey == null || distribution.SenderIdentityKey.Length == 0 ||
                distribution.Signature == null || distribution.Signature.Length == 0)
            {
                return false;
            }

            // Validate group ID
            if (!IsValidGroupId(distribution.GroupId))
            {
                return false;
            }

            return true;
        }

        /// <summary>
        /// Validates an encrypted group message
        /// </summary>
        /// <param name="encryptedMessage">Encrypted message to validate</param>
        /// <returns>True if the message is valid</returns>
        public bool ValidateEncryptedMessage(EncryptedGroupMessage encryptedMessage)
        {
            // Check for null
            if (encryptedMessage == null)
            {
                return false;
            }

            // Check for required fields
            if (string.IsNullOrEmpty(encryptedMessage.GroupId) ||
                encryptedMessage.Ciphertext == null || encryptedMessage.Ciphertext.Length == 0 ||
                encryptedMessage.Nonce == null || encryptedMessage.Nonce.Length == 0 ||
                encryptedMessage.SenderIdentityKey == null || encryptedMessage.SenderIdentityKey.Length == 0)
            {
                return false;
            }

            // Validate group ID
            if (!IsValidGroupId(encryptedMessage.GroupId))
            {
                return false;
            }

            // Check message freshness to prevent replay attacks
            long currentTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            if (encryptedMessage.Timestamp <= 0 ||
                (currentTime - encryptedMessage.Timestamp) > MAX_MESSAGE_AGE_MS)
            {
                return false;
            }

            // Check for future timestamps (with 30 second allowance for clock skew)
            if (encryptedMessage.Timestamp > (currentTime + 30000))
            {
                return false;
            }

            return true;
        }

        /// <summary>
        /// Validates a sender key
        /// </summary>
        /// <param name="senderKey">Sender key to validate</param>
        /// <returns>True if the sender key is valid</returns>
        public bool ValidateSenderKey(byte[] senderKey)
        {
            // Check for null or empty
            if (senderKey == null || senderKey.Length == 0)
            {
                return false;
            }

            // Check key length
            if (senderKey.Length != 32)
            {
                return false;
            }

            // Check for all zeros (invalid key)
            bool allZeros = true;
            for (int i = 0; i < senderKey.Length; i++)
            {
                if (senderKey[i] != 0)
                {
                    allZeros = false;
                    break;
                }
            }

            if (allZeros)
            {
                return false;
            }

            return true;
        }

        /// <summary>
        /// Checks if the message ID has been used before (for replay protection)
        /// </summary>
        /// <param name="messageId">Message ID to check</param>
        /// <param name="processedIds">Set of already processed IDs</param>
        /// <returns>True if the message ID is new</returns>
        public bool IsMessageIdUnique(string messageId, HashSet<string> processedIds)
        {
            if (string.IsNullOrEmpty(messageId))
            {
                return false;
            }

            lock (processedIds)
            {
                return !processedIds.Contains(messageId);
            }
        }
    }
}