using E2EELibrary.Encryption;
using E2EELibrary.KeyManagement;
using E2EELibrary.Models;
using System.Collections.Concurrent;

namespace E2EELibrary.GroupMessaging
{
    /// <summary>
    /// Main manager class for group chat functionality. Acts as a facade for the underlying components.
    /// </summary>
    public class GroupChatManager
    {
        private readonly GroupKeyManager _keyManager;
        private readonly GroupMessageCrypto _messageCrypto;
        private readonly GroupMemberManager _memberManager;
        private readonly SenderKeyDistribution _distributionManager;
        private readonly GroupSessionPersistence _sessionPersistence;
        private readonly GroupSecurityValidator _securityValidator;

        /// <summary>
        /// Identity key pair for this client
        /// </summary>
        private readonly (byte[] publicKey, byte[] privateKey) _identityKeyPair;

        /// <summary>
        /// Creates a new GroupChatManager with the specified identity key pair
        /// </summary>
        /// <param name="identityKeyPair">Identity key pair for signing and verification</param>
        public GroupChatManager((byte[] publicKey, byte[] privateKey) identityKeyPair)
        {
            _identityKeyPair = identityKeyPair;

            _keyManager = new GroupKeyManager();
            _messageCrypto = new GroupMessageCrypto();
            _memberManager = new GroupMemberManager(identityKeyPair);
            _distributionManager = new SenderKeyDistribution(identityKeyPair);
            _sessionPersistence = new GroupSessionPersistence();
            _securityValidator = new GroupSecurityValidator();
        }

        /// <summary>
        /// Creates a new group with the specified ID
        /// </summary>
        /// <param name="groupId">Group identifier</param>
        /// <returns>Sender key for this group</returns>
        public byte[] CreateGroup(string groupId)
        {
            _securityValidator.ValidateGroupId(groupId);

            // Generate a new sender key and create group session
            byte[] senderKey = _keyManager.GenerateGroupKey();
            var groupSession = new GroupSession
            {
                GroupId = groupId,
                SenderKey = senderKey,
                CreatorIdentityKey = _identityKeyPair.publicKey,
                CreationTimestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
            };

            // Store the group session
            _sessionPersistence.StoreGroupSession(groupSession);

            return senderKey;
        }

        /// <summary>
        /// Creates a distribution message for sharing the sender key
        /// </summary>
        /// <param name="groupId">Group identifier</param>
        /// <returns>Distribution message to share with group members</returns>
        public SenderKeyDistributionMessage CreateDistributionMessage(string groupId)
        {
            _securityValidator.ValidateGroupId(groupId);

            // Get group session
            var groupSession = _sessionPersistence.GetGroupSession(groupId);
            if (groupSession == null)
            {
                throw new InvalidOperationException($"Group {groupId} does not exist or has been deleted");
            }

            // Create distribution message
            return _distributionManager.CreateDistributionMessage(groupId, groupSession.SenderKey);
        }

        /// <summary>
        /// Processes a received sender key distribution message
        /// </summary>
        /// <param name="distribution">Distribution message</param>
        /// <returns>True if the distribution was valid and processed</returns>
        public bool ProcessSenderKeyDistribution(SenderKeyDistributionMessage distribution)
        {
            // Validate distribution message
            if (!_securityValidator.ValidateDistributionMessage(distribution))
            {
                return false;
            }

            // Process distribution message
            return _distributionManager.ProcessDistributionMessage(distribution);
        }

        /// <summary>
        /// Encrypts a message for a group
        /// </summary>
        /// <param name="groupId">Group identifier</param>
        /// <param name="message">Message to encrypt</param>
        /// <returns>Encrypted group message</returns>
        public EncryptedGroupMessage EncryptGroupMessage(string groupId, string message)
        {
            _securityValidator.ValidateGroupId(groupId);

            // Get group session
            var groupSession = _sessionPersistence.GetGroupSession(groupId);
            if (groupSession == null)
            {
                throw new InvalidOperationException($"Group {groupId} does not exist or sender key not found");
            }

            // Encrypt message
            return _messageCrypto.EncryptMessage(groupId, message, groupSession.SenderKey, _identityKeyPair);
        }

        /// <summary>
        /// Decrypts a group message
        /// </summary>
        /// <param name="encryptedMessage">Encrypted group message</param>
        /// <returns>Decrypted message if successful, null otherwise</returns>
        public string? DecryptGroupMessage(EncryptedGroupMessage encryptedMessage)
        {
            // Validate the encrypted message
            if (!_securityValidator.ValidateEncryptedMessage(encryptedMessage))
            {
                return null;
            }

            // Find the sender key for this group and sender
            var senderKey = _distributionManager.GetSenderKeyForMessage(encryptedMessage);
            if (senderKey == null)
            {
                return null;
            }

            // Decrypt the message
            return _messageCrypto.DecryptMessage(encryptedMessage, senderKey);
        }

        /// <summary>
        /// Adds a member to a group
        /// </summary>
        /// <param name="groupId">Group identifier</param>
        /// <param name="memberPublicKey">Member's public key</param>
        /// <returns>True if the member was added successfully</returns>
        public bool AddGroupMember(string groupId, byte[] memberPublicKey)
        {
            return _memberManager.AddMember(groupId, memberPublicKey);
        }

        /// <summary>
        /// Removes a member from a group
        /// </summary>
        /// <param name="groupId">Group identifier</param>
        /// <param name="memberPublicKey">Member's public key</param>
        /// <returns>True if the member was removed successfully</returns>
        public bool RemoveGroupMember(string groupId, byte[] memberPublicKey)
        {
            var result = _memberManager.RemoveMember(groupId, memberPublicKey);

            // If member was an admin, we need to check if rotation is needed
            if (result && _memberManager.WasAdmin(groupId, memberPublicKey))
            {
                RotateGroupKey(groupId);
            }

            return result;
        }

        /// <summary>
        /// Rotates the group key and distributes it to all members
        /// </summary>
        /// <param name="groupId">Group identifier</param>
        /// <returns>New sender key</returns>
        public byte[] RotateGroupKey(string groupId)
        {
            // Check if user has permission to rotate key
            if (!_memberManager.HasKeyRotationPermission(groupId, _identityKeyPair.publicKey))
            {
                throw new UnauthorizedAccessException("You don't have permission to rotate the group key");
            }

            // Generate a new key and update the session
            byte[] newKey = _keyManager.GenerateGroupKey();
            var groupSession = _sessionPersistence.GetGroupSession(groupId);

            if (groupSession == null)
            {
                throw new InvalidOperationException($"Group {groupId} does not exist");
            }

            groupSession.SenderKey = newKey;
            groupSession.LastKeyRotation = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            // Store the updated session
            _sessionPersistence.StoreGroupSession(groupSession);

            return newKey;
        }

        /// <summary>
        /// Saves all group sessions to a secure file
        /// </summary>
        /// <param name="filePath">Path to save the sessions</param>
        /// <param name="password">Optional password for encryption</param>
        public void SaveGroupSessions(string filePath, string? password = null)
        {
            _sessionPersistence.SaveToFile(filePath, password);
        }

        /// <summary>
        /// Loads group sessions from a secure file
        /// </summary>
        /// <param name="filePath">Path to load the sessions from</param>
        /// <param name="password">Optional password for decryption</param>
        public void LoadGroupSessions(string filePath, string? password = null)
        {
            _sessionPersistence.LoadFromFile(filePath, password);
        }

        /// <summary>
        /// Checks if a group exists
        /// </summary>
        /// <param name="groupId">Group identifier</param>
        /// <returns>True if the group exists</returns>
        public bool GroupExists(string groupId)
        {
            return _sessionPersistence.GetGroupSession(groupId) != null;
        }

        /// <summary>
        /// Deletes a group
        /// </summary>
        /// <param name="groupId">Group identifier</param>
        /// <returns>True if the group was deleted</returns>
        public bool DeleteGroup(string groupId)
        {
            // Check if user has permission to delete the group
            if (!_memberManager.IsGroupAdmin(groupId, _identityKeyPair.publicKey))
            {
                throw new UnauthorizedAccessException("You don't have permission to delete this group");
            }

            return _sessionPersistence.DeleteGroupSession(groupId) &&
                   _memberManager.DeleteGroup(groupId) &&
                   _distributionManager.DeleteGroupDistributions(groupId);
        }
    }
}