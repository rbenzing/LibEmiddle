using LibEmiddle.Core;
using LibEmiddle.Domain;
using LibEmiddle.Abstractions;

namespace LibEmiddle.Messaging.Group
{
    /// <summary>
    /// Validates the security properties of group messaging operations,
    /// ensuring integrity, authenticity, and proper permissions.
    /// </summary>
    public class GroupSecurityValidator
    {
        private readonly ICryptoProvider _cryptoProvider;
        private readonly GroupMemberManager _memberManager;

        // Cache of known public keys for validation
        private readonly Dictionary<string, byte[]> _knownPublicKeys = [];

        /// <summary>
        /// Initializes a new instance of the GroupSecurityValidator class.
        /// </summary>
        /// <param name="cryptoProvider">The cryptographic provider implementation.</param>
        /// <param name="memberManager">The group member manager.</param>
        public GroupSecurityValidator(ICryptoProvider cryptoProvider, GroupMemberManager memberManager)
        {
            _cryptoProvider = cryptoProvider ?? throw new ArgumentNullException(nameof(cryptoProvider));
            _memberManager = memberManager ?? throw new ArgumentNullException(nameof(memberManager));
        }

        /// <summary>
        /// Validates a group operation based on the actor's permissions.
        /// </summary>
        /// <param name="groupId">The identifier of the group.</param>
        /// <param name="actorPublicKey">The public key of the actor.</param>
        /// <param name="operation">The operation to validate.</param>
        /// <returns>True if the operation is allowed.</returns>
        public bool ValidateGroupOperation(string groupId, byte[] actorPublicKey, GroupOperation operation)
        {
            if (string.IsNullOrEmpty(groupId))
                throw new ArgumentException("Group ID cannot be null or empty.", nameof(groupId));

            if (actorPublicKey == null || actorPublicKey.Length == 0)
                throw new ArgumentException("Actor public key cannot be null or empty.", nameof(actorPublicKey));

            // Check if the actor is a member of the group
            if (!_memberManager.IsMember(groupId, actorPublicKey))
            {
                LoggingManager.LogWarning(nameof(GroupSecurityValidator),
                    $"Non-member attempting {operation} operation on group {groupId}");
                return false;
            }

            // Check if the actor has the required permissions
            switch (operation)
            {
                case GroupOperation.Send:
                    // All members can send messages
                    return true;

                case GroupOperation.AddMember:
                case GroupOperation.RemoveMember:
                case GroupOperation.PromoteAdmin:
                case GroupOperation.DemoteAdmin:
                    // Only admins can perform membership operations
                    return _memberManager.IsGroupAdmin(groupId, actorPublicKey);

                case GroupOperation.RotateKey:
                    // Check if the actor has key rotation permission
                    return _memberManager.HasKeyRotationPermission(groupId, actorPublicKey);

                case GroupOperation.DeleteGroup:
                    // Only the group owner can delete the group
                    var groupInfo = _memberManager.GetGroupInfo(groupId);
                    if (groupInfo?.CreatorPublicKey == null)
                        return false;

                    return ComparePublicKeys(groupInfo.CreatorPublicKey, actorPublicKey);

                default:
                    LoggingManager.LogWarning(nameof(GroupSecurityValidator),
                        $"Unknown operation {operation} requested for group {groupId}");
                    return false;
            }
        }

        /// <summary>
        /// Validates a sender key distribution message.
        /// </summary>
        /// <param name="distribution">The distribution message to validate.</param>
        /// <returns>True if the distribution message is valid.</returns>
        public bool ValidateDistributionMessage(SenderKeyDistributionMessage distribution)
        {
            if (distribution == null || distribution.GroupId == null)
                throw new ArgumentNullException(nameof(distribution));

            string groupId = distribution.GroupId;
            byte[]? senderIdentityKey = distribution.SenderIdentityKey;

            // Check if sender identity key is present
            if (senderIdentityKey == null || senderIdentityKey.Length == 0)
            {
                LoggingManager.LogWarning(nameof(GroupSecurityValidator),
                    $"Missing sender identity key in distribution message for group {groupId}");
                return false;
            }

            // Check if the sender is a member of the group
            if (!_memberManager.IsMember(groupId, senderIdentityKey))
            {
                LoggingManager.LogWarning(nameof(GroupSecurityValidator),
                    $"Non-member attempting to distribute sender key for group {groupId}");
                return false;
            }

            // Verify the signature if present
            if (distribution.Signature != null)
            {
                byte[] dataToSign = GetDataToSign(distribution);
                if (!_cryptoProvider.VerifySignature(dataToSign, distribution.Signature, senderIdentityKey))
                {
                    LoggingManager.LogWarning(nameof(GroupSecurityValidator),
                        $"Invalid signature on distribution message for group {groupId}");
                    return false;
                }
            }
            else
            {
                LoggingManager.LogWarning(nameof(GroupSecurityValidator),
                    $"Missing signature on distribution message for group {groupId}");
                return false;
            }

            return true;
        }

        /// <summary>
        /// Validates an encrypted group message.
        /// </summary>
        /// <param name="message">The encrypted message to validate.</param>
        /// <returns>True if the message is valid.</returns>
        public bool ValidateGroupMessage(EncryptedGroupMessage message)
        {
            if (message == null || message.GroupId == null || message.SenderIdentityKey == null)
                throw new ArgumentNullException(nameof(message));

            string groupId = message.GroupId;
            byte[] senderIdentityKey = message.SenderIdentityKey;

            // Check if the sender is a member of the group
            if (!_memberManager.IsMember(groupId, senderIdentityKey))
            {
                LoggingManager.LogWarning(nameof(GroupSecurityValidator),
                    $"Non-member attempting to send message to group {groupId}");
                return false;
            }

            // Verify the signature if present
            if (message.Signature != null)
            {
                byte[] dataToSign = GetDataToSign(message);
                if (!_cryptoProvider.VerifySignature(dataToSign, message.Signature, senderIdentityKey))
                {
                    LoggingManager.LogWarning(nameof(GroupSecurityValidator),
                        $"Invalid signature on message for group {groupId}");
                    return false;
                }
            }
            else
            {
                LoggingManager.LogWarning(nameof(GroupSecurityValidator),
                    $"Missing signature on message for group {groupId}");
                return false;
            }

            return true;
        }

        /// <summary>
        /// Gets the data to sign for a distribution message.
        /// </summary>
        /// <param name="distribution">The distribution message.</param>
        /// <returns>The data to sign.</returns>
        private byte[] GetDataToSign(SenderKeyDistributionMessage distribution)
        {
            if (distribution.GroupId == null)
                throw new ArgumentNullException(nameof(distribution.GroupId));
            if (distribution.ChainKey == null)
                throw new ArgumentNullException(nameof(distribution.ChainKey));

            // Combine all relevant fields for signing
            using var ms = new System.IO.MemoryStream();
            using var writer = new System.IO.BinaryWriter(ms);

            writer.Write(System.Text.Encoding.Default.GetBytes(distribution.GroupId));
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
        /// Gets the data to sign for an encrypted message.
        /// </summary>
        /// <param name="message">The encrypted message.</param>
        /// <returns>The data to sign.</returns>
        private byte[] GetDataToSign(EncryptedGroupMessage message)
        {
            if (message.GroupId == null)
                throw new ArgumentNullException(nameof(message.GroupId));
            if (message.SenderIdentityKey == null)
                throw new ArgumentNullException(nameof(message.SenderIdentityKey));
            if (message.Ciphertext == null)
                throw new ArgumentNullException(nameof(message.Ciphertext));
            if (message.Nonce == null)
                throw new ArgumentNullException(nameof(message.Nonce));

            // Combine all relevant fields for signing
            using var ms = new System.IO.MemoryStream();
            using var writer = new System.IO.BinaryWriter(ms);

            writer.Write(System.Text.Encoding.Default.GetBytes(message.GroupId));
            writer.Write(message.SenderIdentityKey);
            writer.Write(message.Ciphertext);
            writer.Write(message.Nonce);
            writer.Write(message.Timestamp);
            writer.Write(message.RotationEpoch);
            writer.Write(System.Text.Encoding.Default.GetBytes(message.MessageId ?? string.Empty));

            return ms.ToArray();
        }

        /// <summary>
        /// Registers a public key for validation.
        /// </summary>
        /// <param name="identifier">The identifier for the public key.</param>
        /// <param name="publicKey">The public key to register.</param>
        public void RegisterPublicKey(string identifier, byte[] publicKey)
        {
            if (string.IsNullOrEmpty(identifier))
                throw new ArgumentException("Identifier cannot be null or empty.", nameof(identifier));

            if (publicKey == null || publicKey.Length == 0)
                throw new ArgumentException("Public key cannot be null or empty.", nameof(publicKey));

            _knownPublicKeys[identifier] = publicKey.ToArray(); // Create a copy
        }

        /// <summary>
        /// Compares two public keys for equality.
        /// </summary>
        /// <param name="key1">The first public key.</param>
        /// <param name="key2">The second public key.</param>
        /// <returns>True if the keys are equal.</returns>
        private bool ComparePublicKeys(byte[] key1, byte[] key2)
        {
            if (key1 == null || key2 == null)
                return false;

            if (key1.Length != key2.Length)
                return false;

            // Use a constant-time comparison to prevent timing attacks
            return SecureMemory.SecureCompare(key1, key2);
        }
    }

    /// <summary>
    /// Represents the types of operations that can be performed on a group.
    /// </summary>
    public enum GroupOperation
    {
        /// <summary>
        /// Send a message to the group.
        /// </summary>
        Send,

        /// <summary>
        /// Add a member to the group.
        /// </summary>
        AddMember,

        /// <summary>
        /// Remove a member from the group.
        /// </summary>
        RemoveMember,

        /// <summary>
        /// Promote a member to admin.
        /// </summary>
        PromoteAdmin,

        /// <summary>
        /// Demote an admin to regular member.
        /// </summary>
        DemoteAdmin,

        /// <summary>
        /// Rotate the group key.
        /// </summary>
        RotateKey,

        /// <summary>
        /// Delete the group.
        /// </summary>
        DeleteGroup
    }
}