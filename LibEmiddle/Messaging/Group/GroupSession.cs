using System.Collections.Concurrent;
using System.Text;
using LibEmiddle.Abstractions;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;

namespace LibEmiddle.Messaging.Group;

/// <summary>
/// Enhanced GroupSession that consolidates all group chat functionality into a single class,
/// implementing the IGroupSession interface while leveraging existing infrastructure.
/// Provides end-to-end encrypted group messaging with member management, key rotation,
/// and security validation using the Signal protocol.
/// </summary>
public sealed class GroupSession : IGroupSession, ISession, IDisposable
{
    private readonly SemaphoreSlim _sessionLock = new(1, 1);
    private readonly string _groupId;
    private readonly KeyPair _identityKeyPair;
    private bool _disposed;

    // Group member management using existing domain objects
    private readonly ConcurrentDictionary<string, GroupMember> _members = new();
    private readonly ConcurrentDictionary<string, long> _removedMembers = new();
    private GroupInfo? _groupInfo;

    // Group key state management
    private byte[] _currentChainKey = Array.Empty<byte>();
    private uint _currentIteration;
    private long _lastRotationTimestamp;
    private readonly ConcurrentDictionary<string, byte[]> _senderKeys = new(); // senderId -> chainKey

    // Message tracking for replay protection
    private readonly ConcurrentDictionary<string, long> _lastSeenSequence = new();
    private readonly ConcurrentDictionary<string, long> _joinTimestamps = new();

    // ISession interface properties
    public string SessionId { get; }
    public SessionType Type => SessionType.Group;
    public SessionState State { get; private set; }
    public DateTime CreatedAt { get; }

    // IGroupSession interface properties
    public string GroupId => _groupId;
    public byte[] ChainKey => _currentChainKey.ToArray();
    public uint Iteration => _currentIteration;
    public KeyRotationStrategy RotationStrategy { get; set; }
    public byte[] CreatorPublicKey { get; }
    public byte[] CreatorIdentityKey => CreatorPublicKey;
    public DateTime KeyEstablishmentTimestamp => DateTimeOffset.FromUnixTimeMilliseconds(_lastRotationTimestamp).UtcDateTime;
    public IReadOnlyDictionary<string, string>? Metadata { get; private set; }

    // Events
    public event EventHandler<SessionStateChangedEventArgs>? StateChanged;

    /// <summary>
    /// Initializes a new GroupSession with the specified parameters.
    /// </summary>
    /// <param name="groupId">Unique identifier for the group</param>
    /// <param name="groupName">The group name shown to the users</param>
    /// <param name="identityKeyPair">User's identity key pair</param>
    /// <param name="rotationStrategy">Key rotation strategy to use</param>
    /// <param name="creatorPublicKey">Public key of the group creator</param>
    public GroupSession(
        string groupId,
        string groupName,
        KeyPair identityKeyPair,
        KeyRotationStrategy rotationStrategy = KeyRotationStrategy.Standard,
        byte[]? creatorPublicKey = null)
    {
        _groupId = groupId ?? throw new ArgumentNullException(nameof(groupId));
        _identityKeyPair = identityKeyPair;
        RotationStrategy = rotationStrategy;
        CreatorPublicKey = creatorPublicKey ?? identityKeyPair.PublicKey;

        SessionId = $"group-{groupId}-{Guid.NewGuid():N}";
        CreatedAt = DateTime.UtcNow;
        State = SessionState.Initialized;
        _lastRotationTimestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        // Initialize group info
        _groupInfo = new GroupInfo
        {
            GroupId = groupId,
            GroupName = groupName,
            CreatedAt = _lastRotationTimestamp,
            CreatorPublicKey = CreatorPublicKey
        };

        // Record our join time
        RecordJoinTime(_identityKeyPair.PublicKey);
    }

    #region ISession Implementation

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

            // Clear sensitive data
            SecureMemory.SecureClear(_currentChainKey);
            foreach (var key in _senderKeys.Values)
            {
                SecureMemory.SecureClear(key);
            }
            _senderKeys.Clear();

            OnStateChanged(previousState, State);
            return true;
        }
        finally
        {
            _sessionLock.Release();
        }
    }

    #endregion

    #region Group Member Management

    public async Task<bool> AddMemberAsync(byte[] memberPublicKey)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(memberPublicKey);

        await _sessionLock.WaitAsync();
        try
        {
            if (State == SessionState.Terminated)
                throw new InvalidOperationException("Cannot add member: Session is terminated.");

            // Check permissions
            if (!HasPermission(GroupOperation.AddMember))
                throw new UnauthorizedAccessException("You don't have permission to add members to this group.");

            string memberId = GetMemberId(memberPublicKey);

            // Check if already a member
            if (_members.ContainsKey(memberId))
                return false;

            var member = new GroupMember
            {
                PublicKey = memberPublicKey.ToArray(),
                JoinedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                IsAdmin = false,
                IsOwner = false
            };

            bool added = _members.TryAdd(memberId, member);
            if (added)
            {
                _removedMembers.TryRemove(memberId, out _);
                RecordJoinTime(memberPublicKey);
            }

            return added;
        }
        finally
        {
            _sessionLock.Release();
        }
    }

    public async Task<bool> RemoveMemberAsync(byte[] memberPublicKey)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(memberPublicKey);

        await _sessionLock.WaitAsync();
        try
        {
            if (State == SessionState.Terminated)
                throw new InvalidOperationException("Cannot remove member: Session is terminated.");

            if (!HasPermission(GroupOperation.RemoveMember))
                throw new UnauthorizedAccessException("You don't have permission to remove members from this group.");

            string memberId = GetMemberId(memberPublicKey);

            if (_members.TryGetValue(memberId, out var member))
            {
                // Can't remove the owner
                if (member.IsOwner)
                    return false;

                if (_members.TryRemove(memberId, out _))
                {
                    _removedMembers[memberId] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

                    // Rotate key after removing member for forward secrecy
                    await RotateKeyAsync();
                    return true;
                }
            }

            return false;
        }
        finally
        {
            _sessionLock.Release();
        }
    }

    #endregion

    #region Message Encryption/Decryption

    public async Task<EncryptedGroupMessage?> EncryptMessageAsync(string message)
    {
        ThrowIfDisposed();
        ArgumentException.ThrowIfNullOrEmpty(message);

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

            // Check permissions
            if (!HasPermission(GroupOperation.Send))
                throw new UnauthorizedAccessException("You don't have permission to send messages in this group.");

            // Check if key rotation is needed
            await CheckAndRotateKeyIfNeededAsync();

            // Ensure we have a chain key
            if (_currentChainKey.Length == 0)
            {
                _currentChainKey = Sodium.GenerateRandomBytes(Constants.CHAIN_KEY_SIZE);
                _currentIteration = 0;
            }

            // Derive message key and advance chain
            byte[] messageKey = Sodium.DeriveMessageKey(_currentChainKey);
            _currentChainKey = Sodium.AdvanceChainKey(_currentChainKey);
            uint messageIteration = _currentIteration++;

            try
            {
                // Encrypt the message using AES
                byte[] plaintext = Encoding.UTF8.GetBytes(message);
                byte[] nonce = Sodium.GenerateRandomBytes(Constants.NONCE_SIZE);
                byte[] associatedData = Encoding.UTF8.GetBytes($"{_groupId}:{_lastRotationTimestamp}");
                byte[] ciphertext = AES.AESEncrypt(plaintext, messageKey, nonce, associatedData);

                var encryptedMessage = new EncryptedGroupMessage
                {
                    GroupId = _groupId,
                    SenderIdentityKey = _identityKeyPair.PublicKey,
                    Ciphertext = ciphertext,
                    Nonce = nonce,
                    Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    RotationEpoch = _lastRotationTimestamp,
                    MessageId = $"iter:{messageIteration}:{Guid.NewGuid():N}"
                };

                // Sign the message
                byte[] dataToSign = GetMessageDataToSign(encryptedMessage);
                encryptedMessage.Signature = Sodium.SignDetached(dataToSign, _identityKeyPair.PrivateKey);

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

    public async Task<string?> DecryptMessageAsync(EncryptedGroupMessage encryptedMessage)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(encryptedMessage);

        if (encryptedMessage.GroupId != _groupId)
            throw new ArgumentException($"Message is for group {encryptedMessage.GroupId}, but this session is for group {_groupId}");

        await _sessionLock.WaitAsync();
        try
        {
            // Validate message
            if (!ValidateGroupMessage(encryptedMessage))
                return null;

            if (State == SessionState.Terminated)
                throw new InvalidOperationException("Cannot decrypt: Session is terminated.");

            // Auto-activate if needed
            if (State == SessionState.Initialized)
            {
                State = SessionState.Active;
                OnStateChanged(SessionState.Initialized, State);
            }

            // Check membership and timing
            if (!IsMember(_identityKeyPair.PublicKey))
                return null;

            if (WasRemovedBeforeTimestamp(_identityKeyPair.PublicKey, encryptedMessage.Timestamp))
                return null;

            // Get sender key
            string senderId = GetMemberId(encryptedMessage.SenderIdentityKey);
            if (!_senderKeys.TryGetValue(senderId, out byte[]? senderKey))
                return null;

            try
            {
                // Decrypt the message
                byte[] associatedData = Encoding.UTF8.GetBytes($"{_groupId}:{encryptedMessage.RotationEpoch}");
                byte[] decrypted = AES.AESDecrypt(
                    encryptedMessage.Ciphertext,
                    senderKey,
                    encryptedMessage.Nonce,
                    associatedData);

                return Encoding.UTF8.GetString(decrypted);
            }
            catch
            {
                return null;
            }
        }
        finally
        {
            _sessionLock.Release();
        }
    }

    #endregion

    #region Key Management

    public async Task<bool> RotateKeyAsync()
    {
        ThrowIfDisposed();

        await _sessionLock.WaitAsync();
        try
        {
            if (State == SessionState.Terminated)
                throw new InvalidOperationException("Cannot rotate key: Session is terminated.");

            if (!HasPermission(GroupOperation.RotateKey))
                throw new UnauthorizedAccessException("You don't have permission to rotate the group key.");

            // Generate new chain key
            byte[] newChainKey = Sodium.GenerateRandomBytes(Constants.CHAIN_KEY_SIZE);

            // Clear old key securely
            SecureMemory.SecureClear(_currentChainKey);

            // Update state
            _currentChainKey = newChainKey;
            _currentIteration = 0;
            _lastRotationTimestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            // Clear old sender keys
            foreach (var key in _senderKeys.Values)
            {
                SecureMemory.SecureClear(key);
            }
            _senderKeys.Clear();

            // Create and process distribution message
            var distribution = CreateDistributionMessage();
            ProcessDistributionMessage(distribution);

            return true;
        }
        finally
        {
            _sessionLock.Release();
        }
    }

    public SenderKeyDistributionMessage CreateDistributionMessage()
    {
        ThrowIfDisposed();

        var distribution = new SenderKeyDistributionMessage
        {
            GroupId = _groupId,
            ChainKey = _currentChainKey.ToArray(),
            Iteration = _currentIteration,
            SenderIdentityKey = _identityKeyPair.PublicKey,
            Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
        };

        // Sign the distribution message
        byte[] dataToSign = GetDistributionDataToSign(distribution);
        distribution.Signature = Sodium.SignDetached(dataToSign, _identityKeyPair.PrivateKey);

        return distribution;
    }

    public bool ProcessDistributionMessage(SenderKeyDistributionMessage distribution)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(distribution);

        if (distribution.GroupId != _groupId)
            return false;

        if (distribution.SenderIdentityKey == null || distribution.ChainKey == null)
            return false;

        // Validate signature
        if (distribution.Signature != null)
        {
            byte[] dataToSign = GetDistributionDataToSign(distribution);
            if (!Sodium.SignVerifyDetached(distribution.Signature, dataToSign, distribution.SenderIdentityKey))
                return false;
        }

        // Check if sender is a member
        string senderId = GetMemberId(distribution.SenderIdentityKey);
        if (!_members.ContainsKey(senderId))
            return false;

        // Store the sender key
        _senderKeys[senderId] = distribution.ChainKey.ToArray();

        // Record join time if not already recorded
        RecordJoinTime(distribution.SenderIdentityKey);

        return true;
    }

    #endregion

    #region Security Validation

    private bool ValidateGroupMessage(EncryptedGroupMessage message)
    {
        // Basic validation
        if (message.Ciphertext?.Length == 0 || message.Nonce?.Length != Constants.NONCE_SIZE)
            return false;

        if (message.SenderIdentityKey == null || message.SenderIdentityKey?.Length == 0 || message.Timestamp <= 0)
            return false;

        // Check if sender is a member
        if (!IsMember(message.SenderIdentityKey!))
            return false;

        // Verify signature
        if (message.Signature != null)
        {
            byte[] dataToSign = GetMessageDataToSign(message);
            if (!Sodium.SignVerifyDetached(message.Signature, dataToSign, message.SenderIdentityKey))
                return false;
        }

        // Validate message sequence for replay protection
        return ValidateMessageSequence(message.SenderIdentityKey!, message.RotationEpoch, message.Timestamp);
    }

    private bool ValidateMessageSequence(byte[] senderKey, long sequence, long timestamp)
    {
        string senderId = GetMemberId(senderKey);

        if (_lastSeenSequence.TryGetValue(senderId, out long lastSeen))
        {
            if (sequence <= lastSeen)
            {
                LoggingManager.LogSecurityEvent(nameof(GroupSession), "Sequence replay detected", isAlert: true);
                return false;
            }
        }

        _lastSeenSequence[senderId] = sequence;
        return ValidateMessageTimestamp(senderKey, timestamp);
    }

    private bool ValidateMessageTimestamp(byte[] senderKey, long messageTimestamp)
    {
        string senderId = GetMemberId(senderKey);

        if (_joinTimestamps.TryGetValue(senderId, out long joinTimestamp))
        {
            const long CLOCK_SKEW_TOLERANCE_MS = 5 * 60 * 1000; // 5 minutes

            if (messageTimestamp < joinTimestamp - CLOCK_SKEW_TOLERANCE_MS)
                return false;

            long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            if (messageTimestamp > now + CLOCK_SKEW_TOLERANCE_MS)
                return false;
        }

        return true;
    }

    private bool HasPermission(GroupOperation operation)
    {
        string userId = GetMemberId(_identityKeyPair.PublicKey);

        if (!_members.TryGetValue(userId, out var member))
            return false;

        return operation switch
        {
            GroupOperation.Send => true, // All members can send
            GroupOperation.AddMember or GroupOperation.RemoveMember or
            GroupOperation.PromoteAdmin or GroupOperation.DemoteAdmin => member.IsAdmin || member.IsOwner,
            GroupOperation.RotateKey => member.IsAdmin || member.IsOwner,
            GroupOperation.DeleteGroup => member.IsOwner,
            _ => false
        };
    }

    #endregion

    #region State Management and Serialization

    public async Task<string> GetSerializedStateAsync()
    {
        ThrowIfDisposed();

        await _sessionLock.WaitAsync();
        try
        {
            var keyState = new GroupKeyState
            {
                GroupId = _groupId,
                LastRotationTimestamp = _lastRotationTimestamp,
                SenderState = new GroupSenderStateDto
                {
                    ChainKey = Convert.ToBase64String(_currentChainKey),
                    Iteration = _currentIteration,
                    CreationTimestamp = _lastRotationTimestamp
                },
                ReceiverStates = _senderKeys.ToDictionary(
                    kvp => kvp.Key,
                    kvp => Convert.ToBase64String(kvp.Value))
            };

            var sessionState = new GroupSessionState
            {
                SessionId = SessionId,
                GroupId = _groupId,
                State = State,
                CreatedAt = CreatedAt,
                RotationStrategy = RotationStrategy,
                KeyState = keyState,
                GroupInfo = _groupInfo
            };

            return JsonSerialization.Serialize(sessionState);
        }
        finally
        {
            _sessionLock.Release();
        }
    }

    public async Task<bool> RestoreSerializedStateAsync(string serializedState)
    {
        ThrowIfDisposed();
        ArgumentException.ThrowIfNullOrEmpty(serializedState);

        await _sessionLock.WaitAsync();
        try
        {
            var sessionState = JsonSerialization.Deserialize<GroupSessionState>(serializedState);
            if (sessionState?.GroupId != _groupId)
                return false;

            // Restore key state
            if (sessionState.KeyState?.SenderState != null)
            {
                _currentChainKey = Convert.FromBase64String(sessionState.KeyState.SenderState.ChainKey);
                _currentIteration = sessionState.KeyState.SenderState.Iteration;
                _lastRotationTimestamp = sessionState.KeyState.LastRotationTimestamp;

                // Restore receiver states
                foreach (var kvp in sessionState.KeyState.ReceiverStates)
                {
                    _senderKeys[kvp.Key] = Convert.FromBase64String(kvp.Value);
                }
            }

            // Restore session state
            State = sessionState.State;
            RotationStrategy = sessionState.RotationStrategy;

            // Restore group info and members
            if (sessionState.GroupInfo != null)
            {
                _groupInfo = sessionState.GroupInfo;

                foreach (var member in sessionState.GroupInfo.Members)
                {
                    _members[member.Key] = member.Value;
                }

                foreach (var removed in sessionState.GroupInfo.RemovedMembers)
                {
                    _removedMembers[removed.Key] = removed.Value;
                }
            }

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

    #endregion

    #region Helper Methods

    private async Task CheckAndRotateKeyIfNeededAsync()
    {
        long currentTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        TimeSpan elapsed = TimeSpan.FromMilliseconds(currentTime - _lastRotationTimestamp);

        bool shouldRotate = RotationStrategy switch
        {
            KeyRotationStrategy.Hourly => elapsed >= TimeSpan.FromHours(1),
            KeyRotationStrategy.Daily => elapsed >= TimeSpan.FromDays(1),
            KeyRotationStrategy.Weekly => elapsed >= TimeSpan.FromDays(7),
            KeyRotationStrategy.Standard => elapsed >= TimeSpan.FromDays(7),
            KeyRotationStrategy.AfterEveryMessage => true,
            _ => false
        };

        if (shouldRotate && HasPermission(GroupOperation.RotateKey))
        {
            try
            {
                await RotateKeyAsync();
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(GroupSession), $"Failed to rotate group key: {ex.Message}");
            }
        }
    }

    private void RecordJoinTime(byte[] publicKey)
    {
        string userId = GetMemberId(publicKey);
        _joinTimestamps[userId] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
    }

    private bool IsMember(byte[] publicKey)
    {
        string userId = GetMemberId(publicKey);
        return _members.ContainsKey(userId);
    }

    private bool WasRemovedBeforeTimestamp(byte[] publicKey, long timestamp)
    {
        string userId = GetMemberId(publicKey);
        return _removedMembers.TryGetValue(userId, out long removalTime) && removalTime < timestamp;
    }

    private static string GetMemberId(byte[] publicKey) => Convert.ToBase64String(publicKey);

    private static byte[] GetMessageDataToSign(EncryptedGroupMessage message)
    {
        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);

        writer.Write(Encoding.UTF8.GetBytes(message.GroupId));
        writer.Write(message.SenderIdentityKey);
        writer.Write(message.Ciphertext);
        writer.Write(message.Nonce);
        writer.Write(message.Timestamp);
        writer.Write(message.RotationEpoch);
        writer.Write(Encoding.UTF8.GetBytes(message.MessageId ?? string.Empty));

        return ms.ToArray();
    }

    private static byte[] GetDistributionDataToSign(SenderKeyDistributionMessage distribution)
    {
        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);

        writer.Write(Encoding.UTF8.GetBytes(distribution.GroupId!));
        writer.Write(distribution.ChainKey!);
        writer.Write(distribution.Iteration);
        writer.Write(distribution.Timestamp);
        if (distribution.SenderIdentityKey != null)
        {
            writer.Write(distribution.SenderIdentityKey);
        }

        return ms.ToArray();
    }

    private void OnStateChanged(SessionState previousState, SessionState newState)
    {
        Task.Run(() => StateChanged?.Invoke(this, new SessionStateChangedEventArgs(previousState, newState)));
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(GroupSession));
    }

    #endregion

    #region IDisposable Implementation

    public void Dispose()
    {
        if (_disposed)
            return;

        _sessionLock.Wait();
        try
        {
            if (_disposed)
                return;

            // Clear sensitive data
            SecureMemory.SecureClear(_currentChainKey);
            foreach (var key in _senderKeys.Values)
            {
                SecureMemory.SecureClear(key);
            }
            _senderKeys.Clear();

            var previousState = State;
            State = SessionState.Terminated;
            if (previousState != SessionState.Terminated)
            {
                OnStateChanged(previousState, State);
            }

            _disposed = true;
        }
        finally
        {
            _sessionLock.Release();
            _sessionLock.Dispose();
        }
    }

    #endregion
}

/// <summary>
/// Represents the serializable state of a group session.
/// </summary>
public class GroupSessionState
{
    public string SessionId { get; set; } = string.Empty;
    public string GroupId { get; set; } = string.Empty;
    public SessionState State { get; set; }
    public DateTime CreatedAt { get; set; }
    public KeyRotationStrategy RotationStrategy { get; set; }
    public GroupKeyState? KeyState { get; set; }
    public GroupInfo? GroupInfo { get; set; }
}