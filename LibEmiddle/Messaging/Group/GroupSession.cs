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
public sealed partial class GroupSession : IGroupSession, ISession, IDisposable
{
    private readonly SemaphoreSlim _sessionLock = new(1, 1);
    private readonly string _groupId;
    private readonly KeyPair _identityKeyPair;
    private volatile bool _disposed;
    private bool _isRotating;

    // Group member management using existing domain objects
    private readonly ConcurrentDictionary<string, GroupMember> _members = new();
    private readonly ConcurrentDictionary<string, long> _removedMembers = new();
    private GroupInfo? _groupInfo;

    // Group key state management
    private byte[] _currentChainKey = Array.Empty<byte>();
    private uint _currentIteration;
    private long _lastRotationTimestamp;
    private readonly ConcurrentDictionary<string, GroupSenderState> _senderKeys = new(); // senderId -> GroupSenderState

    // Message tracking for replay protection
    private readonly ConcurrentDictionary<string, long> _lastSeenSequence = new();
    private readonly ConcurrentDictionary<string, long> _joinTimestamps = new();
    private readonly ConcurrentDictionary<string, HashSet<string>> _seenMessageIds = new();

    // Enhanced Group Management
    private readonly ConcurrentDictionary<string, GroupInvitation> _activeInvitations = new();
    private readonly object _statisticsLock = new object();

    // ISession interface properties
    public string SessionId { get; }
    public SessionType Type => SessionType.Group;
    public SessionState State { get; private set; }
    public DateTime CreatedAt { get; }

    // IGroupSession interface properties
    public string GroupId => _groupId;
    public byte[] ChainKey => _currentChainKey;
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

        // Add creator as owner member
        string creatorId = GetMemberId(_identityKeyPair.PublicKey);
        var creatorMember = new GroupMember
        {
            PublicKey = _identityKeyPair.PublicKey.ToArray(),
            JoinedAt = _lastRotationTimestamp,
            IsAdmin = true,
            IsOwner = true,
            Role = MemberRole.Owner,
            LastActivity = DateTime.UtcNow
        };
        creatorMember.MigrateToRoleSystem();

        _members.TryAdd(creatorId, creatorMember);

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

            // Initialize chain key if not already set
            if (_currentChainKey.Length == 0)
            {
                _currentChainKey = Sodium.GenerateRandomBytes(Constants.CHAIN_KEY_SIZE);
                _currentIteration = 0;
                _lastRotationTimestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

                // Process our own distribution message so we can decrypt our own messages
                var ownDistribution = CreateDistributionMessage();
                ProcessDistributionMessage(ownDistribution);
            }

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
            foreach (var senderState in _senderKeys.Values)
            {
                SecureMemory.SecureClear(senderState.ChainKey);
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
            foreach (var senderState in _senderKeys.Values)
            {
                SecureMemory.SecureClear(senderState.ChainKey);
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
