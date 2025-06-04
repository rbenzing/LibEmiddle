using System.Collections.Concurrent;
using LibEmiddle.Core;
using LibEmiddle.Domain;
using LibEmiddle.Abstractions;

namespace LibEmiddle.Messaging.Group
{
    /// <summary>
    /// Manages cryptographic keys and ratchet chains for group messaging sessions,
    /// supporting key generation, rotation, and secure distribution in group contexts.
    /// </summary>
    /// <remarks>
    /// Initializes a new instance of the GroupKeyManager class.
    /// </remarks>
    public class GroupKeyManager() : IGroupKeyManager
    {
        private readonly SemaphoreSlim _operationLock = new(1, 1);

        // In-memory storage for sender chain states
        private readonly ConcurrentDictionary<string, GroupSenderState> _senderStates = new();

        // In-memory storage for receiver chain states
        private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, byte[]>> _receiverStates = new();

        // Timestamps of last key rotations
        private readonly ConcurrentDictionary<string, long> _lastRotationTimestamps = new();

        /// <summary>
        /// Generates an initial chain key for a new group.
        /// </summary>
        /// <returns>A 32-byte random key suitable for initializing a group chain.</returns>
        public byte[] GenerateInitialChainKey()
        {
            return Sodium.GenerateRandomBytes(Constants.CHAIN_KEY_SIZE);
        }

        /// <summary>
        /// Initializes the sender state for a new group or after key rotation.
        /// </summary>
        /// <param name="groupId">The identifier of the group.</param>
        /// <param name="initialChainKey">The initial chain key for the group.</param>
        /// <returns>True if the sender state was initialized successfully.</returns>
        public bool InitializeSenderState(string groupId, byte[] initialChainKey)
        {
            if (string.IsNullOrEmpty(groupId))
                throw new ArgumentException("Group ID cannot be null or empty.", nameof(groupId));

            if (initialChainKey == null || initialChainKey.Length != Constants.CHAIN_KEY_SIZE)
                throw new ArgumentException($"Initial chain key must be {Constants.CHAIN_KEY_SIZE} bytes.", nameof(initialChainKey));

            try
            {
                var senderState = new GroupSenderState
                {
                    ChainKey = initialChainKey.ToArray(), // Create a copy
                    Iteration = 0,
                    CreationTimestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                };

                _senderStates[groupId] = senderState;
                _lastRotationTimestamps[groupId] = senderState.CreationTimestamp;

                return true;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(GroupKeyManager), $"Failed to initialize sender state for group {groupId}: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Gets the current sender state for a group.
        /// </summary>
        /// <param name="groupId">The identifier of the group.</param>
        /// <returns>The current sender state, or null if the group doesn't exist.</returns>
        public GroupSenderState? GetSenderState(string groupId)
        {
            if (string.IsNullOrEmpty(groupId))
                throw new ArgumentException("Group ID cannot be null or empty.", nameof(groupId));

            if (_senderStates.TryGetValue(groupId, out var state))
            {
                // Return a copy to prevent modification
                return new GroupSenderState
                {
                    ChainKey = state.ChainKey.ToArray(),
                    Iteration = state.Iteration,
                    CreationTimestamp = state.CreationTimestamp
                };
            }

            return null;
        }

        /// <summary>
        /// Clears the sender state for a group, typically when the group is deleted.
        /// </summary>
        /// <param name="groupId">The identifier of the group.</param>
        /// <returns>True if the sender state was cleared successfully.</returns>
        public bool ClearSenderState(string groupId)
        {
            if (string.IsNullOrEmpty(groupId))
                throw new ArgumentException("Group ID cannot be null or empty.", nameof(groupId));

            try
            {
                if (_senderStates.TryRemove(groupId, out var state))
                {
                    // Securely clear the chain key
                    SecureMemory.SecureClear(state.ChainKey);
                }

                // Clear receiver states for this group
                if (_receiverStates.TryRemove(groupId, out var receiverDict))
                {
                    foreach (var senderKey in receiverDict.Values)
                    {
                        SecureMemory.SecureClear(senderKey);
                    }
                }

                // Clear rotation timestamp
                _lastRotationTimestamps.TryRemove(groupId, out _);

                return true;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(GroupKeyManager), $"Failed to clear sender state for group {groupId}: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Gets a message key for encrypting a new message and advances the chain.
        /// </summary>
        /// <param name="groupId">The identifier of the group.</param>
        /// <returns>A tuple containing the message key and the current iteration.</returns>
        public (byte[] MessageKey, uint Iteration) GetSenderMessageKey(string groupId)
        {
            if (string.IsNullOrEmpty(groupId))
                throw new ArgumentException("Group ID cannot be null or empty.", nameof(groupId));

            _operationLock.Wait();
            try
            {
                if (!_senderStates.TryGetValue(groupId, out var state))
                    throw new KeyNotFoundException($"Group {groupId} does not exist or sender state not initialized.");

                // Generate message key from current chain key
                byte[] messageKey = Sodium.DeriveMessageKey(state.ChainKey);

                // Advance the chain
                state.ChainKey = Sodium.AdvanceChainKey(state.ChainKey);
                state.Iteration++;

                return (messageKey, state.Iteration - 1);
            }
            finally
            {
                _operationLock.Release();
            }
        }

        /// <summary>
        /// Stores a sender key for a specific sender in a group.
        /// </summary>
        /// <param name="groupId">The identifier of the group.</param>
        /// <param name="senderIdentityKey">The sender's identity key.</param>
        /// <param name="senderKey">The sender key to store.</param>
        /// <returns>True if the sender key was stored successfully.</returns>
        public bool StoreSenderKey(string groupId, byte[] senderIdentityKey, byte[] senderKey)
        {
            if (string.IsNullOrEmpty(groupId))
                throw new ArgumentException("Group ID cannot be null or empty.", nameof(groupId));

            if (senderIdentityKey == null || senderIdentityKey.Length == 0)
                throw new ArgumentException("Sender identity key cannot be null or empty.", nameof(senderIdentityKey));

            if (senderKey == null || senderKey.Length != Constants.CHAIN_KEY_SIZE)
                throw new ArgumentException($"Sender key must be {Constants.CHAIN_KEY_SIZE} bytes.", nameof(senderKey));

            try
            {
                var receiverDict = _receiverStates.GetOrAdd(groupId, _ => new ConcurrentDictionary<string, byte[]>());
                string senderKeyId = Convert.ToBase64String(senderIdentityKey);

                receiverDict[senderKeyId] = senderKey.ToArray(); // Create a copy
                return true;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(GroupKeyManager), $"Failed to store sender key for group {groupId}: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Retrieves a sender key for a specific sender in a group.
        /// </summary>
        /// <param name="groupId">The identifier of the group.</param>
        /// <param name="senderIdentityKey">The sender's identity key.</param>
        /// <returns>The sender key, or null if not found.</returns>
        public byte[]? GetSenderKey(string groupId, byte[] senderIdentityKey)
        {
            if (string.IsNullOrEmpty(groupId))
                throw new ArgumentException("Group ID cannot be null or empty.", nameof(groupId));

            if (senderIdentityKey == null || senderIdentityKey.Length == 0)
                throw new ArgumentException("Sender identity key cannot be null or empty.", nameof(senderIdentityKey));

            try
            {
                if (_receiverStates.TryGetValue(groupId, out var receiverDict))
                {
                    string senderKeyId = Convert.ToBase64String(senderIdentityKey);

                    if (receiverDict.TryGetValue(senderKeyId, out var senderKey))
                    {
                        return senderKey.ToArray(); // Return a copy
                    }
                }

                return null;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(GroupKeyManager), $"Failed to get sender key for group {groupId}: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Validates an encrypted group message.
        /// </summary>
        /// <param name="message">The encrypted group message to validate.</param>
        /// <returns>True if the message passes basic validation.</returns>
        public bool ValidateEncryptedMessage(EncryptedGroupMessage message)
        {
            if (message == null)
                return false;

            if (string.IsNullOrEmpty(message.GroupId))
                return false;

            if (message.Ciphertext == null || message.Ciphertext.Length == 0)
                return false;

            if (message.Nonce == null || message.Nonce.Length != Constants.NONCE_SIZE)
                return false;

            if (message.SenderIdentityKey == null || message.SenderIdentityKey.Length == 0)
                return false;

            if (message.Timestamp <= 0)
                return false;

            return true;
        }

        /// <summary>
        /// Validates a sender key distribution message.
        /// </summary>
        /// <param name="distribution">The distribution message to validate.</param>
        /// <returns>True if the distribution message passes basic validation.</returns>
        public bool ValidateDistributionMessage(SenderKeyDistributionMessage distribution)
        {
            if (distribution == null)
                return false;

            if (string.IsNullOrEmpty(distribution.GroupId))
                return false;

            if (distribution.SenderIdentityKey == null || distribution.SenderIdentityKey.Length == 0)
                return false;

            if (distribution.ChainKey == null || distribution.ChainKey.Length != Constants.CHAIN_KEY_SIZE)
                return false;

            if (distribution.Signature == null || distribution.Signature.Length == 0)
                return false;

            return true;
        }

        /// <summary>
        /// Gets the timestamp of the last key rotation for a group.
        /// </summary>
        /// <param name="groupId">The identifier of the group.</param>
        /// <returns>The timestamp of the last key rotation, or 0 if the group doesn't exist.</returns>
        public long GetLastRotationTimestamp(string groupId)
        {
            if (string.IsNullOrEmpty(groupId))
                throw new ArgumentException("Group ID cannot be null or empty.", nameof(groupId));

            return _lastRotationTimestamps.TryGetValue(groupId, out var timestamp) ? timestamp : 0;
        }

        /// <summary>
        /// Updates the timestamp of the last key rotation for a group.
        /// </summary>
        /// <param name="groupId">The identifier of the group.</param>
        /// <param name="timestamp">The timestamp to set.</param>
        public void UpdateLastRotationTimestamp(string groupId, long timestamp)
        {
            if (string.IsNullOrEmpty(groupId))
                throw new ArgumentException("Group ID cannot be null or empty.", nameof(groupId));

            _lastRotationTimestamps[groupId] = timestamp;
        }

        /// <summary>
        /// Exports the group key state for persistence.
        /// </summary>
        /// <param name="groupId">The identifier of the group.</param>
        /// <returns>A serializable group key state.</returns>
        public Task<GroupKeyState> ExportKeyStateAsync(string groupId)
        {
            if (string.IsNullOrEmpty(groupId))
                throw new ArgumentException("Group ID cannot be null or empty.", nameof(groupId));

            try
            {
                var keyState = new GroupKeyState
                {
                    GroupId = groupId,
                    LastRotationTimestamp = GetLastRotationTimestamp(groupId),
                    SenderState = null,
                    ReceiverStates = new Dictionary<string, string>()
                };

                // Export sender state if it exists
                if (_senderStates.TryGetValue(groupId, out var senderState))
                {
                    keyState.SenderState = new GroupSenderStateDto
                    {
                        ChainKey = Convert.ToBase64String(senderState.ChainKey),
                        Iteration = senderState.Iteration,
                        CreationTimestamp = senderState.CreationTimestamp
                    };
                }

                // Export receiver states if they exist
                if (_receiverStates.TryGetValue(groupId, out var receiverDict))
                {
                    foreach (var kvp in receiverDict)
                    {
                        keyState.ReceiverStates[kvp.Key] = Convert.ToBase64String(kvp.Value);
                    }
                }

                return Task.FromResult(keyState);
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(GroupKeyManager), $"Failed to export key state for group {groupId}: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Imports a group key state from persistence.
        /// </summary>
        /// <param name="keyState">The group key state to import.</param>
        /// <returns>True if the key state was imported successfully.</returns>
        public Task<bool> ImportKeyStateAsync(GroupKeyState keyState)
        {
            if (keyState == null)
                throw new ArgumentNullException(nameof(keyState));

            if (string.IsNullOrEmpty(keyState.GroupId))
                throw new ArgumentException("Group ID cannot be null or empty.");

            try
            {
                string groupId = keyState.GroupId;

                // Import sender state if it exists
                if (keyState.SenderState != null)
                {
                    var senderState = new GroupSenderState
                    {
                        ChainKey = Convert.FromBase64String(keyState.SenderState.ChainKey),
                        Iteration = keyState.SenderState.Iteration,
                        CreationTimestamp = keyState.SenderState.CreationTimestamp
                    };

                    _senderStates[groupId] = senderState;
                }

                // Import receiver states if they exist
                if (keyState.ReceiverStates != null && keyState.ReceiverStates.Count > 0)
                {
                    var receiverDict = _receiverStates.GetOrAdd(groupId, _ => new ConcurrentDictionary<string, byte[]>());

                    foreach (var kvp in keyState.ReceiverStates)
                    {
                        receiverDict[kvp.Key] = Convert.FromBase64String(kvp.Value);
                    }
                }

                // Import rotation timestamp
                _lastRotationTimestamps[groupId] = keyState.LastRotationTimestamp;

                return Task.FromResult(true);
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(GroupKeyManager), $"Failed to import key state for group {keyState.GroupId}: {ex.Message}");
                return Task.FromResult(false);
            }
        }
    }
}