using System.Text.RegularExpressions;
using LibEmiddle.Core;
using LibEmiddle.Domain;

namespace LibEmiddle.Messaging.Group
{
    /// <summary>
    /// Validates security parameters for group operations
    /// </summary>
    public class GroupSecurityValidator
    {
        // Regular expression for valid group IDs (letters, numbers, underscores, hyphens)
        // 4-64 characters, starting with a letter or number
        private static readonly Regex _validGroupIdRegex = new("^[a-zA-Z0-9][a-zA-Z0-9_-]{3,63}$", RegexOptions.Compiled);

        // Maximum age for messages in milliseconds (5 minutes)
        // This helps prevent replay attacks
        private const long MAX_MESSAGE_AGE_MS = 5 * 60 * 1000;

        // Maximum future timestamp skew allowance (30 seconds)
        // This helps prevent attackers from creating messages with future timestamps
        // while allowing for some clock skew between devices
        private const long MAX_FUTURE_SKEW_MS = 30 * 1000;

        // Minimum group ID length for security
        private const int MIN_GROUP_ID_LENGTH = 4;

        // Maximum group ID length
        private const int MAX_GROUP_ID_LENGTH = 64;

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
                    $"Group ID must be {MIN_GROUP_ID_LENGTH}-{MAX_GROUP_ID_LENGTH} characters, " +
                    "containing only letters, numbers, underscores and hyphens, " +
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

            if (groupId.Length < MIN_GROUP_ID_LENGTH || groupId.Length > MAX_GROUP_ID_LENGTH)
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
                LoggingManager.LogWarning(nameof(GroupSecurityValidator), "Null distribution message");
                return false;
            }

            // Check for required fields
            if (string.IsNullOrEmpty(distribution.GroupId))
            {
                LoggingManager.LogWarning(nameof(GroupSecurityValidator), "Missing group ID");
                return false;
            }

            if (distribution.ChainKey == null || distribution.ChainKey.Length != Constants.AES_KEY_SIZE)
            {
                LoggingManager.LogWarning(nameof(GroupSecurityValidator),
                    $"Invalid chain key length: {distribution.ChainKey?.Length ?? 0}, expected {Constants.AES_KEY_SIZE}");
                return false;
            }

            if (distribution.SenderIdentityKey == null ||
                distribution.SenderIdentityKey.Length != Constants.ED25519_PUBLIC_KEY_SIZE)
            {
                LoggingManager.LogWarning(nameof(GroupSecurityValidator),
                    $"Invalid sender identity key length: {distribution.SenderIdentityKey?.Length ?? 0}, expected {Constants.ED25519_PUBLIC_KEY_SIZE}");
                return false;
            }

            if (distribution.Signature == null ||
                distribution.Signature.Length != Constants.ED25519_SIGNATURE_SIZE)
            {
                LoggingManager.LogWarning(nameof(GroupSecurityValidator),
                    $"Invalid signature length: {distribution.Signature?.Length ?? 0}, expected {Constants.ED25519_SIGNATURE_SIZE}");
                return false;
            }

            // Validate group ID format
            if (!IsValidGroupId(distribution.GroupId))
            {
                LoggingManager.LogWarning(nameof(GroupSecurityValidator), "Invalid group ID format");
                return false;
            }

            // Check message freshness
            long currentTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            // Check for future timestamps (with allowed clock skew)
            if (distribution.Timestamp > currentTime + MAX_FUTURE_SKEW_MS)
            {
                LoggingManager.LogWarning(nameof(GroupSecurityValidator),
                    $"Message timestamp is in the future: {distribution.Timestamp}, current time: {currentTime}");
                return false;
            }

            // Check for old messages (replay protection)
            if (currentTime - distribution.Timestamp > MAX_MESSAGE_AGE_MS)
            {
                LoggingManager.LogWarning(nameof(GroupSecurityValidator),
                    $"Message is too old: {distribution.Timestamp}, current time: {currentTime}");
                return false;
            }

            // Validate message ID (should not be empty)
            if (string.IsNullOrEmpty(distribution.MessageId))
            {
                LoggingManager.LogWarning(nameof(GroupSecurityValidator), "Missing message ID");
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
                LoggingManager.LogWarning(nameof(GroupSecurityValidator), "Null encrypted message");
                return false;
            }

            // Check for required fields
            if (string.IsNullOrEmpty(encryptedMessage.GroupId))
            {
                LoggingManager.LogWarning(nameof(GroupSecurityValidator), "Missing group ID");
                return false;
            }

            if (encryptedMessage.Ciphertext == null || encryptedMessage.Ciphertext.Length == 0)
            {
                LoggingManager.LogWarning(nameof(GroupSecurityValidator), "Missing or empty ciphertext");
                return false;
            }

            if (encryptedMessage.Nonce == null ||
                encryptedMessage.Nonce.Length != Constants.NONCE_SIZE)
            {
                LoggingManager.LogWarning(nameof(GroupSecurityValidator),
                    $"Invalid nonce length: {encryptedMessage.Nonce?.Length ?? 0}, expected {Constants.NONCE_SIZE}");
                return false;
            }

            if (encryptedMessage.SenderIdentityKey == null ||
                encryptedMessage.SenderIdentityKey.Length != Constants.ED25519_PUBLIC_KEY_SIZE)
            {
                LoggingManager.LogWarning(nameof(GroupSecurityValidator),
                    $"Invalid sender identity key length: {encryptedMessage.SenderIdentityKey?.Length ?? 0}, expected {Constants.ED25519_PUBLIC_KEY_SIZE}");
                return false;
            }

            // Validate group ID format
            if (!IsValidGroupId(encryptedMessage.GroupId))
            {
                LoggingManager.LogWarning(nameof(GroupSecurityValidator), "Invalid group ID format");
                return false;
            }

            // Check message freshness for replay protection
            long currentTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            if (encryptedMessage.Timestamp <= 0)
            {
                LoggingManager.LogWarning(nameof(GroupSecurityValidator), "Invalid timestamp (zero or negative)");
                return false;
            }

            // Check for old messages
            if (currentTime - encryptedMessage.Timestamp > MAX_MESSAGE_AGE_MS)
            {
                LoggingManager.LogWarning(nameof(GroupSecurityValidator),
                    $"Message is too old: {encryptedMessage.Timestamp}, current time: {currentTime}");
                return false;
            }

            // Check for future timestamps (with clock skew allowance)
            if (encryptedMessage.Timestamp > currentTime + MAX_FUTURE_SKEW_MS)
            {
                LoggingManager.LogWarning(nameof(GroupSecurityValidator),
                    $"Message timestamp is in the future: {encryptedMessage.Timestamp}, current time: {currentTime}");
                return false;
            }

            // Validate message ID (should not be empty)
            if (string.IsNullOrEmpty(encryptedMessage.MessageId))
            {
                LoggingManager.LogWarning(nameof(GroupSecurityValidator), "Missing message ID");
                return false;
            }

            return true;
        }

        /// <summary>
        /// Validates a chain key
        /// </summary>
        /// <param name="chainKey">Chain key to validate</param>
        /// <returns>True if the chain key is valid</returns>
        public bool ValidateChainKey(byte[] chainKey)
        {
            // Check for null or empty
            if (chainKey == null || chainKey.Length == 0)
            {
                LoggingManager.LogWarning(nameof(GroupSecurityValidator), "Null or empty chain key");
                return false;
            }

            // Check key length
            if (chainKey.Length != Constants.AES_KEY_SIZE)
            {
                LoggingManager.LogWarning(nameof(GroupSecurityValidator),
                    $"Invalid chain key length: {chainKey.Length}, expected {Constants.AES_KEY_SIZE}");
                return false;
            }

            // Check for all zeros (invalid key)
            bool allZeros = true;
            for (int i = 0; i < chainKey.Length; i++)
            {
                if (chainKey[i] != 0)
                {
                    allZeros = false;
                    break;
                }
            }

            if (allZeros)
            {
                LoggingManager.LogWarning(nameof(GroupSecurityValidator), "Chain key contains all zeros");
                return false;
            }

            // Check for key entropy (optional, can be implemented if needed)
            // This would check if the key has sufficient randomness

            return true;
        }

        /// <summary>
        /// Validates a group session
        /// </summary>
        /// <param name="session">Group session to validate</param>
        /// <returns>True if the session is valid</returns>
        public bool ValidateGroupSession(GroupSession session)
        {
            // Check for null
            if (session == null)
            {
                LoggingManager.LogWarning(nameof(GroupSecurityValidator), "Null group session");
                return false;
            }

            // Validate group ID
            if (!IsValidGroupId(session.GroupId))
            {
                LoggingManager.LogWarning(nameof(GroupSecurityValidator), "Invalid group ID format");
                return false;
            }

            // Validate chain key
            if (!ValidateChainKey(session.ChainKey))
            {
                LoggingManager.LogWarning(nameof(GroupSecurityValidator), "Invalid chain key");
                return false;
            }

            // Validate creator identity key
            if (session.CreatorIdentityKey == null ||
                session.CreatorIdentityKey.Length != Constants.ED25519_PUBLIC_KEY_SIZE)
            {
                LoggingManager.LogWarning(nameof(GroupSecurityValidator),
                    $"Invalid creator identity key length: {session.CreatorIdentityKey?.Length ?? 0}, expected {Constants.ED25519_PUBLIC_KEY_SIZE}");
                return false;
            }

            // Validate timestamps
            long currentTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            // Creation timestamp shouldn't be in the future
            if (session.CreationTimestamp > currentTime + MAX_FUTURE_SKEW_MS)
            {
                LoggingManager.LogWarning(nameof(GroupSecurityValidator),
                    $"Creation timestamp is in the future: {session.CreationTimestamp}, current time: {currentTime}");
                return false;
            }

            // Key establishment timestamp shouldn't be in the future
            if (session.KeyEstablishmentTimestamp > currentTime + MAX_FUTURE_SKEW_MS)
            {
                LoggingManager.LogWarning(nameof(GroupSecurityValidator),
                    $"Key establishment timestamp is in the future: {session.KeyEstablishmentTimestamp}, current time: {currentTime}");
                return false;
            }

            // Key establishment shouldn't be before creation
            if (session.KeyEstablishmentTimestamp < session.CreationTimestamp)
            {
                LoggingManager.LogWarning(nameof(GroupSecurityValidator),
                    $"Key establishment timestamp ({session.KeyEstablishmentTimestamp}) is before creation timestamp ({session.CreationTimestamp})");
                return false;
            }

            return true;
        }

        /// <summary>
        /// Validates a message ID for uniqueness (replay protection)
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

        /// <summary>
        /// Validates a member public key
        /// </summary>
        /// <param name="memberPublicKey">Member public key to validate</param>
        /// <returns>True if the key is valid</returns>
        public bool ValidateMemberPublicKey(byte[] memberPublicKey)
        {
            // Check for null or empty
            if (memberPublicKey == null || memberPublicKey.Length == 0)
            {
                LoggingManager.LogWarning(nameof(GroupSecurityValidator), "Null or empty member public key");
                return false;
            }

            // Check key length for Ed25519 public key
            if (memberPublicKey.Length != Constants.ED25519_PUBLIC_KEY_SIZE)
            {
                LoggingManager.LogWarning(nameof(GroupSecurityValidator),
                    $"Invalid member public key length: {memberPublicKey.Length}, expected {Constants.ED25519_PUBLIC_KEY_SIZE}");
                return false;
            }

            // Check for all zeros (invalid key)
            bool allZeros = true;
            for (int i = 0; i < memberPublicKey.Length; i++)
            {
                if (memberPublicKey[i] != 0)
                {
                    allZeros = false;
                    break;
                }
            }

            if (allZeros)
            {
                LoggingManager.LogWarning(nameof(GroupSecurityValidator), "Member public key contains all zeros");
                return false;
            }

            // Additional key validation could be added here (like checking point is on curve)
            // This would require specific Ed25519 validation code

            return true;
        }
    }
}