using LibEmiddle.Core;
using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;
using LibEmiddle.Abstractions;
using LibEmiddle.Crypto;

namespace LibEmiddle.Messaging.Group
{
    /// <summary>
    /// Implements the IGroupSession interface, providing the main entry point
    /// for group chat functionality with end-to-end encryption.
    /// </summary>
    public class GroupSession : IGroupSession, ISession, IDisposable
    {
        private readonly SemaphoreSlim _sessionLock = new SemaphoreSlim(1, 1);
        private readonly string _groupId;
        private readonly KeyPair _identityKeyPair;
        private readonly GroupKeyManager _keyManager;
        private readonly GroupMemberManager _memberManager;
        private readonly GroupMessageCrypto _messageCrypto;
        private readonly SenderKeyDistribution _distributionManager;
        private readonly GroupSecurityValidator _securityValidator;
        private bool _disposed;

        // Required properties from interface
        public string SessionId { get; }
        public SessionType Type => SessionType.Group;
        public SessionState State { get; private set; }
        public string GroupId => _groupId;
        public byte[] ChainKey => _keyManager.GetSenderState(_groupId)?.ChainKey ?? Array.Empty<byte>();
        public uint Iteration => _keyManager.GetSenderState(_groupId)?.Iteration ?? 0;
        public IReadOnlyDictionary<string, string> Metadata;


        // Additional properties
        public DateTime CreatedAt { get; }
        public DateTime CreationTimestamp => CreatedAt;

        public KeyRotationStrategy RotationStrategy { get; set; }
        public byte[] CreatorPublicKey { get; }
        public byte[] CreatorIdentityKey => CreatorPublicKey;
        public DateTime KeyEstablishmentTimestamp => DateTimeOffset.FromUnixTimeSeconds(_keyManager.GetLastRotationTimestamp(_groupId)).UtcDateTime;

        // Events
        public event EventHandler<SessionStateChangedEventArgs>? StateChanged;

        /// <summary>
        /// Initializes a new instance of the GroupSession class.
        /// </summary>
        /// <param name="groupId">The unique identifier for the group.</param>
        /// <param name="identityKeyPair">The user's identity key pair.</param>
        /// <param name="keyManager">The group key manager.</param>
        /// <param name="memberManager">The group member manager.</param>
        /// <param name="messageCrypto">The group message crypto provider.</param>
        /// <param name="distributionManager">The sender key distribution manager.</param>
        /// <param name="rotationStrategy">The key rotation strategy to use.</param>
        public GroupSession(
            string groupId,
            KeyPair identityKeyPair,
            GroupKeyManager keyManager,
            GroupMemberManager memberManager,
            GroupMessageCrypto messageCrypto,
            SenderKeyDistribution distributionManager,
            KeyRotationStrategy rotationStrategy = KeyRotationStrategy.Standard)
        {
            _groupId = groupId ?? throw new ArgumentNullException(nameof(groupId));
            _identityKeyPair = identityKeyPair.Equals(null) ? throw new ArgumentNullException(nameof(identityKeyPair)) : identityKeyPair;
            _keyManager = keyManager ?? throw new ArgumentNullException(nameof(keyManager));
            _memberManager = memberManager ?? throw new ArgumentNullException(nameof(memberManager));
            _messageCrypto = messageCrypto ?? throw new ArgumentNullException(nameof(messageCrypto));
            _distributionManager = distributionManager ?? throw new ArgumentNullException(nameof(distributionManager));

            _securityValidator = new GroupSecurityValidator(
                new CryptoProvider(), // Use a new instance to avoid dependencies
                memberManager);

            SessionId = $"group-{groupId}-{Guid.NewGuid()}";
            CreatedAt = DateTime.UtcNow;
            State = SessionState.Initialized;
            RotationStrategy = rotationStrategy;

            // Get creator public key from group info
            var groupInfo = _memberManager.GetGroupInfo(groupId);
            CreatorPublicKey = groupInfo?.CreatorPublicKey ?? identityKeyPair.PublicKey;

            // Record group join time
            _messageCrypto.RecordGroupJoin(groupId);
        }

        /// <summary>
        /// Activates the session, enabling it to send and receive messages.
        /// </summary>
        /// <returns>True if the session was activated, false if it was already active.</returns>
        public async Task<bool> ActivateAsync()
        {
            ThrowIfDisposed();
            await _sessionLock.WaitAsync();
            try
            {
                if (State == SessionState.Terminated)
                    throw new InvalidOperationException("Cannot activate a terminated session.");
                if (State == SessionState.Active)
                    return false;

                var previousState = State;
                State = SessionState.Active;
                OnStateChanged(previousState, State);
                return true;
            }
            finally
            {
                _sessionLock.Release();
            }
        }

        /// <summary>
        /// Suspends the session, temporarily preventing it from sending and receiving messages.
        /// </summary>
        /// <param name="reason">Optional reason for suspension.</param>
        /// <returns>True if the session was suspended, false if it was already suspended.</returns>
        public async Task<bool> SuspendAsync(string? reason = null)
        {
            ThrowIfDisposed();
            await _sessionLock.WaitAsync();
            try
            {
                if (State == SessionState.Terminated)
                    throw new InvalidOperationException("Cannot suspend a terminated session.");
                if (State == SessionState.Suspended)
                    return false;

                var previousState = State;
                State = SessionState.Suspended;
                OnStateChanged(previousState, State);
                return true;
            }
            finally
            {
                _sessionLock.Release();
            }
        }

        /// <summary>
        /// Terminates the session permanently, preventing any further communication.
        /// </summary>
        /// <returns>True if the session was terminated, false if it was already terminated.</returns>
        public async Task<bool> TerminateAsync()
        {
            ThrowIfDisposed();
            await _sessionLock.WaitAsync();
            try
            {
                if (State == SessionState.Terminated)
                    return false;

                var previousState = State;
                State = SessionState.Terminated;

                // Clean up resources
                _keyManager.ClearSenderState(_groupId);
                _distributionManager.DeleteGroupDistributions(_groupId);

                OnStateChanged(previousState, State);
                return true;
            }
            finally
            {
                _sessionLock.Release();
            }
        }

        /// <summary>
        /// Adds a member to the group.
        /// </summary>
        /// <param name="memberPublicKey">The public key of the member to add.</param>
        /// <returns>True if the member was added successfully.</returns>
        public async Task<bool> AddMemberAsync(byte[] memberPublicKey)
        {
            ThrowIfDisposed();
            ArgumentNullException.ThrowIfNull(memberPublicKey, nameof(memberPublicKey));

            await _sessionLock.WaitAsync();
            try
            {
                if (State == SessionState.Terminated)
                    throw new InvalidOperationException("Cannot add member: Session is terminated.");

                // Check if the current user has permission
                if (!_securityValidator.ValidateGroupOperation(_groupId, _identityKeyPair.PublicKey, GroupOperation.AddMember))
                {
                    throw new UnauthorizedAccessException("You don't have permission to add members to this group.");
                }

                // Add the member
                return _memberManager.AddMember(_groupId, memberPublicKey);
            }
            finally
            {
                _sessionLock.Release();
            }
        }

        /// <summary>
        /// Removes a member from the group.
        /// </summary>
        /// <param name="memberPublicKey">The public key of the member to remove.</param>
        /// <returns>True if the member was removed successfully.</returns>
        public async Task<bool> RemoveMemberAsync(byte[] memberPublicKey)
        {
            ThrowIfDisposed();
            ArgumentNullException.ThrowIfNull(memberPublicKey, nameof(memberPublicKey));

            await _sessionLock.WaitAsync();
            try
            {
                if (State == SessionState.Terminated)
                    throw new InvalidOperationException("Cannot remove member: Session is terminated.");

                // Check if the current user has permission
                if (!_securityValidator.ValidateGroupOperation(_groupId, _identityKeyPair.PublicKey, GroupOperation.RemoveMember))
                {
                    throw new UnauthorizedAccessException("You don't have permission to remove members from this group.");
                }

                // Check if user being removed was an admin or owner
                bool wasAdmin = _memberManager.WasAdmin(_groupId, memberPublicKey);

                // Remove the member
                bool result = _memberManager.RemoveMember(_groupId, memberPublicKey);

                // If member was successfully removed, rotate the key
                if (result)
                {
                    await RotateKeyAsync();
                }

                return result;
            }
            finally
            {
                _sessionLock.Release();
            }
        }

        /// <summary>
        /// Encrypts a message for the group.
        /// </summary>
        /// <param name="message">The plaintext message to encrypt.</param>
        /// <returns>The encrypted group message.</returns>
        public async Task<EncryptedGroupMessage?> EncryptMessageAsync(string message)
        {
            ThrowIfDisposed();
            ArgumentException.ThrowIfNullOrEmpty(message, nameof(message));

            await _sessionLock.WaitAsync();
            try
            {
                if (State == SessionState.Terminated)
                    throw new InvalidOperationException("Cannot encrypt: Session is terminated.");
                if (State == SessionState.Suspended)
                    throw new InvalidOperationException("Cannot encrypt: Session is suspended.");

                // Auto-activate if needed
                if (State == SessionState.Initialized)
                {
                    State = SessionState.Active;
                    OnStateChanged(SessionState.Initialized, State);
                }

                // Check if the current user has permission to send messages
                if (!_securityValidator.ValidateGroupOperation(_groupId, _identityKeyPair.PublicKey, GroupOperation.Send))
                {
                    throw new UnauthorizedAccessException("You don't have permission to send messages in this group.");
                }

                // Check if key rotation is needed based on strategy
                if (RotationStrategy != KeyRotationStrategy.Standard)
                {
                    await CheckAndRotateKeyIfNeededAsync();
                }

                // Get the current group state
                var groupState = _keyManager.GetSenderState(_groupId);
                if (groupState == null)
                {
                    throw new InvalidOperationException($"Group {_groupId} does not exist or sender key not found");
                }

                // Encrypt the message
                var (messageKey, iteration) = _keyManager.GetSenderMessageKey(_groupId);
                try
                {
                    // Get last rotation timestamp
                    long rotationTimestamp = _keyManager.GetLastRotationTimestamp(_groupId);

                    // Encrypt the message
                    var encryptedMessage = _messageCrypto.EncryptMessage(
                        _groupId, message, messageKey, _identityKeyPair, rotationTimestamp);

                    // Append iteration information to the message ID
                    string originalMessageId = encryptedMessage.MessageId ?? Guid.NewGuid().ToString("N");
                    encryptedMessage.MessageId = $"iter:{iteration}:{originalMessageId}";

                    return encryptedMessage;
                }
                finally
                {
                    SecureMemory.SecureClear(messageKey);
                }
            }
            finally
            {
                _sessionLock.Release();
            }
        }

        /// <summary>
        /// Decrypts a group message.
        /// </summary>
        /// <param name="encryptedMessage">The encrypted group message to decrypt.</param>
        /// <returns>The decrypted message content.</returns>
        public async Task<string?> DecryptMessageAsync(EncryptedGroupMessage encryptedMessage)
        {
            ThrowIfDisposed();
            ArgumentNullException.ThrowIfNull(encryptedMessage, nameof(encryptedMessage));

            if (encryptedMessage.GroupId != _groupId)
                throw new ArgumentException($"Message is for group {encryptedMessage.GroupId}, but this session is for group {_groupId}");

            await _sessionLock.WaitAsync();
            try
            {
                // Validate the encrypted message
                if (!_securityValidator.ValidateGroupMessage(encryptedMessage))
                    return null;

                // State validation
                if (State == SessionState.Terminated)
                    throw new InvalidOperationException("Cannot decrypt: Session is terminated.");

                // Auto-activate if needed
                if (State == SessionState.Initialized)
                {
                    State = SessionState.Active;
                    OnStateChanged(SessionState.Initialized, State);
                }

                // Check membership
                if (!_memberManager.IsMember(_groupId, _identityKeyPair.PublicKey))
                {
                    LoggingManager.LogWarning(nameof(GroupSession), $"Rejecting message: user is not a member of group {_groupId}");
                    return null;
                }

                // Check if user was removed before message was created
                if (_memberManager.WasRemovedBeforeTimestamp(_groupId, _identityKeyPair.PublicKey, encryptedMessage.Timestamp))
                {
                    LoggingManager.LogWarning(nameof(GroupSession), $"Rejecting message: message was created after user was removed from group {_groupId}");
                    return null;
                }

                // Get the sender key
                var senderKey = _distributionManager.GetSenderKeyForMessage(encryptedMessage);
                if (senderKey == null)
                    return null;

                try
                {
                    // Decrypt the message
                    return _messageCrypto.DecryptMessage(encryptedMessage, senderKey);
                }
                finally
                {
                    SecureMemory.SecureClear(senderKey);
                }
            }
            finally
            {
                _sessionLock.Release();
            }
        }

        /// <summary>
        /// Rotates the group key for enhanced security.
        /// </summary>
        /// <returns>True if the key was rotated successfully.</returns>
        public async Task<bool> RotateKeyAsync()
        {
            ThrowIfDisposed();

            await _sessionLock.WaitAsync();
            try
            {
                if (State == SessionState.Terminated)
                    throw new InvalidOperationException("Cannot rotate key: Session is terminated.");

                // Check if the current user has permission
                if (!_securityValidator.ValidateGroupOperation(_groupId, _identityKeyPair.PublicKey, GroupOperation.RotateKey))
                {
                    throw new UnauthorizedAccessException("You don't have permission to rotate the group key");
                }

                // Generate a new chain key
                byte[] newKey = _keyManager.GenerateInitialChainKey();

                // Reinitialize the sender state
                _keyManager.InitializeSenderState(_groupId, newKey);

                // Update the last rotation timestamp
                long currentTimestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                _keyManager.UpdateLastRotationTimestamp(_groupId, currentTimestamp);

                // Remove outdated distribution messages
                _distributionManager.DeleteGroupDistributions(_groupId);

                // Create and process a new distribution message
                var distribution = CreateDistributionMessage();
                bool result = ProcessDistributionMessage(distribution);

                return result;
            }
            finally
            {
                _sessionLock.Release();
            }
        }

        /// <summary>
        /// Creates a distribution message for this group session.
        /// </summary>
        /// <returns>The sender key distribution message.</returns>
        public SenderKeyDistributionMessage CreateDistributionMessage()
        {
            ThrowIfDisposed();

            // Get the current chain key and iteration
            var senderState = _keyManager.GetSenderState(_groupId);
            if (senderState == null)
                throw new InvalidOperationException($"Group {_groupId} does not exist or has been deleted");

            return _distributionManager.CreateDistributionMessage(
                _groupId,
                senderState.ChainKey,
                senderState.Iteration,
                _identityKeyPair);
        }

        /// <summary>
        /// Processes a received distribution message to update the session's keys.
        /// </summary>
        /// <param name="distribution">The distribution message to process.</param>
        /// <returns>True if the message was processed successfully.</returns>
        public bool ProcessDistributionMessage(SenderKeyDistributionMessage distribution)
        {
            ThrowIfDisposed();

            // Validate the distribution message
            if (!_securityValidator.ValidateDistributionMessage(distribution))
                return false;

            // Check if this is for our group
            if (distribution.GroupId != _groupId)
                return false;

            // Check membership
            if (!_memberManager.IsMember(_groupId, _identityKeyPair.PublicKey))
                return false;

            // Record group join time if not already recorded
            _messageCrypto.RecordGroupJoin(_groupId);

            // Process the distribution message
            return _distributionManager.ProcessDistributionMessage(distribution);
        }

        /// <summary>
        /// Gets the serialized state of this session for persistence.
        /// </summary>
        /// <returns>The serialized session state.</returns>
        public async Task<string> GetSerializedStateAsync()
        {
            ThrowIfDisposed();

            await _sessionLock.WaitAsync();
            try
            {
                // Get key state
                var keyState = await _keyManager.ExportKeyStateAsync(_groupId);

                // Get group info
                var groupInfo = _memberManager.GetGroupInfo(_groupId);

                // Create the session state
                var sessionState = new GroupSessionState
                {
                    SessionId = SessionId,
                    GroupId = _groupId,
                    State = State,
                    CreatedAt = CreatedAt,
                    RotationStrategy = RotationStrategy,
                    KeyState = keyState,
                    GroupInfo = groupInfo
                };

                // Serialize the state
                return JsonSerialization.Serialize(sessionState);
            }
            finally
            {
                _sessionLock.Release();
            }
        }

        /// <summary>
        /// Restores the session state from a serialized representation.
        /// </summary>
        /// <param name="serializedState">The serialized session state.</param>
        /// <returns>True if the state was restored successfully.</returns>
        public async Task<bool> RestoreSerializedStateAsync(string serializedState)
        {
            ThrowIfDisposed();

            if (string.IsNullOrEmpty(serializedState))
                throw new ArgumentException("Serialized state cannot be null or empty.", nameof(serializedState));

            await _sessionLock.WaitAsync();
            try
            {
                // Deserialize the state
                var sessionState = JsonSerialization.Deserialize<GroupSessionState>(serializedState);
                if (sessionState == null)
                    throw new ArgumentException("Failed to deserialize session state.", nameof(serializedState));

                // Validate the state
                if (sessionState.GroupId != _groupId)
                    throw new ArgumentException($"Session state is for group {sessionState.GroupId}, but this session is for group {_groupId}");

                // Import key state
                if (sessionState.KeyState != null)
                {
                    await _keyManager.ImportKeyStateAsync(sessionState.KeyState);
                }

                // Update session state
                State = sessionState.State;
                RotationStrategy = sessionState.RotationStrategy;

                return true;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(GroupSession), $"Failed to restore session state: {ex.Message}");
                return false;
            }
            finally
            {
                _sessionLock.Release();
            }
        }

        // Helper methods
        private async Task CheckAndRotateKeyIfNeededAsync()
        {
            // Get current time
            long currentTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            // Get last rotation time
            long lastRotationTime = _keyManager.GetLastRotationTimestamp(_groupId);

            // Calculate elapsed time
            TimeSpan elapsed = TimeSpan.FromMilliseconds(currentTime - lastRotationTime);

            // Determine if rotation is needed based on strategy
            bool shouldRotate = RotationStrategy switch
            {
                KeyRotationStrategy.Hourly => elapsed >= TimeSpan.FromHours(1),
                KeyRotationStrategy.Daily => elapsed >= TimeSpan.FromDays(1),
                KeyRotationStrategy.Weekly => elapsed >= TimeSpan.FromDays(7),
                KeyRotationStrategy.Standard => elapsed >= TimeSpan.FromDays(7), // Default to weekly rotation
                KeyRotationStrategy.AfterEveryMessage => true,
                _ => false
            };

            if (shouldRotate && _memberManager.HasKeyRotationPermission(_groupId, _identityKeyPair.PublicKey))
            {
                try
                {
                    await RotateKeyAsync();
                }
                catch (Exception ex)
                {
                    LoggingManager.LogError(nameof(GroupSession),
                        $"Failed to rotate group key for {_groupId}: {ex.Message}");
                }
            }
        }

        // IDisposable implementation
        protected virtual void Dispose(bool disposing)
        {
            if (_disposed) return;

            if (disposing)
            {
                _sessionLock.Wait();
                try
                {
                    if (_disposed) return;

                    // Clean up resources
                    _keyManager.ClearSenderState(_groupId);
                    _sessionLock.Dispose();

                    var previousState = State;
                    State = SessionState.Terminated;
                    if (previousState != SessionState.Terminated)
                    {
                        // Don't raise event from Dispose if possible
                    }

                    _disposed = true;
                }
                finally
                {
                    _sessionLock.Release();
                }
            }

            _disposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private void ThrowIfDisposed()
        {
            if (_disposed) throw new ObjectDisposedException(nameof(GroupSession));
        }

        protected virtual void OnStateChanged(SessionState previousState, SessionState newState)
        {
            // Ensure event handlers don't block lock if called from within lock
            Task.Run(() => StateChanged?.Invoke(this, new SessionStateChangedEventArgs(previousState, newState)));
        }
    }

    /// <summary>
    /// Represents the serializable state of a group session.
    /// </summary>
    public class GroupSessionState
    {
        /// <summary>
        /// Gets or sets the session identifier.
        /// </summary>
        public string SessionId { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the group identifier.
        /// </summary>
        public string GroupId { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the session state.
        /// </summary>
        public SessionState State { get; set; }

        /// <summary>
        /// Gets or sets when the session was created.
        /// </summary>
        public DateTime CreatedAt { get; set; }

        /// <summary>
        /// Gets or sets the key rotation strategy.
        /// </summary>
        public KeyRotationStrategy RotationStrategy { get; set; }

        /// <summary>
        /// Gets or sets the key state.
        /// </summary>
        public GroupKeyState? KeyState { get; set; }

        /// <summary>
        /// Gets or sets the group information.
        /// </summary>
        public GroupInfo? GroupInfo { get; set; }
    }
}