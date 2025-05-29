using System.Collections.Concurrent;
using LibEmiddle.Core;
using LibEmiddle.Domain;
using LibEmiddle.Abstractions;
using LibEmiddle.Domain.Enums;

namespace LibEmiddle.Messaging.Group
{
    /// <summary>
    /// Manages group chat functionality, coordinating between key management, 
    /// messaging encryption, and member management in group contexts.
    /// </summary>
    public class GroupChatManager : IDisposable
    {
        private readonly IGroupKeyManager _keyManager;
        private readonly IGroupMemberManager _memberManager;
        private readonly IGroupMessageCrypto _messageCrypto;
        private readonly SenderKeyDistribution _distributionManager;
        private readonly KeyPair _identityKeyPair;
        private bool _disposed;

        // Active sessions
        private readonly ConcurrentDictionary<string, GroupSession> _activeGroups = new();

        /// <summary>
        /// Initializes a new instance of the GroupChatManager class.
        /// </summary>
        /// <param name="cryptoProvider">The cryptographic provider implementation.</param>
        /// <param name="identityKeyPair">The user's identity key pair.</param>
        public GroupChatManager(ICryptoProvider cryptoProvider, KeyPair identityKeyPair)
        {
            _identityKeyPair = identityKeyPair;

            // Create dependent components
            _keyManager = new GroupKeyManager(cryptoProvider);
            _memberManager = new GroupMemberManager();
            _messageCrypto = new GroupMessageCrypto(cryptoProvider);
            _distributionManager = new SenderKeyDistribution(cryptoProvider, _keyManager);
        }

        /// <summary>
        /// Creates a new group chat.
        /// </summary>
        /// <param name="groupId">The unique identifier for the group.</param>
        /// <param name="groupName">The display name for the group.</param>
        /// <param name="initialMembers">Optional initial member identities to add to the group.</param>
        /// <param name="options">Optional configuration options for the group.</param>
        /// <returns>The created group session.</returns>
        public async Task<GroupSession> CreateGroupAsync(
            string groupId,
            string groupName,
            IEnumerable<byte[]>? initialMembers = null,
            GroupSessionOptions? options = null)
        {
            if (string.IsNullOrEmpty(groupId))
                throw new ArgumentException("Group ID cannot be null or empty.", nameof(groupId));

            if (string.IsNullOrEmpty(groupName))
                throw new ArgumentException("Group name cannot be null or empty.", nameof(groupName));

            // Check if group already exists
            if (_activeGroups.TryGetValue(groupId, out _))
                throw new InvalidOperationException($"Group {groupId} already exists.");

            // Create options if none provided
            options ??= new GroupSessionOptions { GroupId = groupId, RotationStrategy = KeyRotationStrategy.Standard };

            // Generate initial chain key
            byte[] initialChainKey = _keyManager.GenerateInitialChainKey();

            try
            {
                // Initialize group structures
                bool keysInitialized = _keyManager.InitializeSenderState(groupId, initialChainKey);
                if (!keysInitialized)
                    throw new InvalidOperationException($"Failed to initialize key state for group {groupId}.");

                bool groupCreated = _memberManager.CreateGroup(
                    groupId,
                    groupName,
                    _identityKeyPair.PublicKey,
                    options.CreatorIsAdmin);

                if (!groupCreated)
                    throw new InvalidOperationException($"Failed to create group {groupId}.");

                // Create the group session
                var session = new GroupSession(
                    groupId,
                    _identityKeyPair,
                    _keyManager,
                    _memberManager,
                    _messageCrypto,
                    _distributionManager,
                    options.RotationStrategy);

                // Add initial members if provided
                if (initialMembers != null)
                {
                    foreach (var memberPublicKey in initialMembers)
                    {
                        await session.AddMemberAsync(memberPublicKey);
                    }
                }

                // Store the session
                _activeGroups[groupId] = session;

                return session;
            }
            catch (Exception ex)
            {
                // Clean up on failure
                _keyManager.ClearSenderState(groupId);
                _memberManager.DeleteGroup(groupId);

                LoggingManager.LogError(nameof(GroupChatManager), $"Failed to create group {groupId}: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Gets an existing group session by ID.
        /// </summary>
        /// <param name="groupId">The unique identifier of the group.</param>
        /// <returns>The group session.</returns>
        public Task<IGroupSession> GetGroupAsync(string groupId)
        {
            if (string.IsNullOrEmpty(groupId))
                throw new ArgumentException("Group ID cannot be null or empty.", nameof(groupId));

            if (_activeGroups.TryGetValue(groupId, out var session))
            {
                return Task.FromResult<IGroupSession>(session);
            }

            throw new KeyNotFoundException($"Group {groupId} not found.");
        }

        /// <summary>
        /// Lists the IDs of all active groups.
        /// </summary>
        /// <returns>A list of group IDs.</returns>
        public Task<List<string>> ListGroupsAsync()
        {
            return Task.FromResult(_activeGroups.Keys.ToList());
        }

        /// <summary>
        /// Joins an existing group using a sender key distribution message.
        /// </summary>
        /// <param name="distribution">The sender key distribution message.</param>
        /// <param name="rotationStrategy">Optional key rotation strategy.</param>
        /// <returns>The group session.</returns>
        public Task<IGroupSession> JoinGroupAsync(
            SenderKeyDistributionMessage distribution,
            KeyRotationStrategy rotationStrategy = KeyRotationStrategy.Standard)
        {
            if (distribution == null)
                throw new ArgumentNullException(nameof(distribution));

            if (distribution.GroupId == null)
                throw new ArgumentNullException(nameof(distribution.GroupId));

            string groupId = distribution.GroupId;

            // Check if we're already in this group
            if (_activeGroups.TryGetValue(groupId, out var existingSession))
            {
                // Process the distribution message to update our keys
                existingSession.ProcessDistributionMessage(distribution);
                return Task.FromResult<IGroupSession>(existingSession);
            }

            // Create group structures
            _memberManager.JoinGroup(groupId, _identityKeyPair.PublicKey);

            // Create a new session
            var session = new GroupSession(
                groupId,
                _identityKeyPair,
                _keyManager,
                _memberManager,
                _messageCrypto,
                _distributionManager,
                rotationStrategy);

            // Process the distribution message
            session.ProcessDistributionMessage(distribution);

            // Store the session
            _activeGroups[groupId] = session;

            return Task.FromResult<IGroupSession>(session);
        }

        /// <summary>
        /// Leaves a group.
        /// </summary>
        /// <param name="groupId">The unique identifier of the group.</param>
        /// <returns>True if the group was left successfully.</returns>
        public async Task<bool> LeaveGroupAsync(string groupId)
        {
            if (string.IsNullOrEmpty(groupId))
                throw new ArgumentException("Group ID cannot be null or empty.", nameof(groupId));

            if (!_activeGroups.TryRemove(groupId, out var session))
                return false;

            try
            {
                // Clean up resources
                await session.TerminateAsync();

                // Remove from member list but keep history
                _memberManager.LeaveGroup(groupId, _identityKeyPair.PublicKey);

                return true;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(GroupChatManager), $"Error leaving group {groupId}: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Sends a message to a group.
        /// </summary>
        /// <param name="groupId">The unique identifier of the group.</param>
        /// <param name="message">The message to send.</param>
        /// <returns>The encrypted message, ready for transport.</returns>
        public async Task<EncryptedGroupMessage?> SendMessageAsync(string groupId, string message)
        {
            if (string.IsNullOrEmpty(groupId))
                throw new ArgumentException("Group ID cannot be null or empty.", nameof(groupId));

            if (string.IsNullOrEmpty(message))
                throw new ArgumentException("Message cannot be null or empty.", nameof(message));

            if (!_activeGroups.TryGetValue(groupId, out var session))
                throw new KeyNotFoundException($"Group {groupId} not found.");

            return await session.EncryptMessageAsync(message);
        }

        /// <summary>
        /// Processes a received encrypted group message.
        /// </summary>
        /// <param name="encryptedMessage">The encrypted message.</param>
        /// <returns>The decrypted message content.</returns>
        public async Task<string?> ProcessMessageAsync(EncryptedGroupMessage encryptedMessage)
        {
            if (encryptedMessage == null)
                throw new ArgumentNullException(nameof(encryptedMessage));

            string groupId = encryptedMessage.GroupId;

            if (!_activeGroups.TryGetValue(groupId, out var session))
                throw new KeyNotFoundException($"Group {groupId} not found.");

            return await session.DecryptMessageAsync(encryptedMessage);
        }

        /// <summary>
        /// Saves the state of all active groups for persistence.
        /// </summary>
        /// <param name="storageProvider">The storage provider to use.</param>
        /// <returns>True if all states were saved successfully.</returns>
        public async Task<bool> SaveStateAsync(IStorageProvider storageProvider)
        {
            if (storageProvider == null)
                throw new ArgumentNullException(nameof(storageProvider));

            bool allSucceeded = true;

            foreach (var session in _activeGroups.Values)
            {
                try
                {
                    var state = await session.GetSerializedStateAsync();
                    await storageProvider.StoreAsync($"group:{session.GroupId}", state);
                }
                catch (Exception ex)
                {
                    LoggingManager.LogError(nameof(GroupChatManager), $"Failed to save state for group {session.GroupId}: {ex.Message}");
                    allSucceeded = false;
                }
            }

            return allSucceeded;
        }

        /// <summary>
        /// Loads saved group states from persistence.
        /// </summary>
        /// <param name="storageProvider">The storage provider to use.</param>
        /// <returns>The number of groups successfully loaded.</returns>
        public async Task<int> LoadStateAsync(IStorageProvider storageProvider)
        {
            if (storageProvider == null)
                throw new ArgumentNullException(nameof(storageProvider));

            int loadedCount = 0;
            var groupIds = await storageProvider.ListKeysAsync("group:");

            foreach (var key in groupIds)
            {
                try
                {
                    string groupId = key.Substring("group:".Length);
                    string state = await storageProvider.RetrieveAsync(key);

                    // Create a new session
                    var session = new GroupSession(
                        groupId,
                        _identityKeyPair,
                        _keyManager,
                        _memberManager,
                        _messageCrypto,
                        _distributionManager);

                    // Restore state
                    await session.RestoreSerializedStateAsync(state);

                    // Store the session
                    _activeGroups[groupId] = session;
                    loadedCount++;
                }
                catch (Exception ex)
                {
                    LoggingManager.LogError(nameof(GroupChatManager), $"Failed to load state for key {key}: {ex.Message}");
                }
            }

            return loadedCount;
        }

        /// <summary>
        /// Dispose
        /// </summary>
        public void Dispose()
        {
            if (_disposed)
                return;

            foreach (var session in _activeGroups.Values)
            {
                try
                {
                    session.Dispose(); // or await session.TerminateAsync() in an async DisposeAsync if needed
                }
                catch (Exception ex)
                {
                    LoggingManager.LogError(nameof(GroupChatManager), $"Failed to dispose group session: {ex.Message}");
                }
            }

            _disposed = true;
        }
    }
}