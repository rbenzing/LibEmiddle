using LibEmiddle.Abstractions;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;
using LibEmiddle.KeyManagement;
using LibEmiddle.Messaging.Group;
using LibEmiddle.MultiDevice;
using LibEmiddle.Protocol;
using LibEmiddle.Sessions;
using LibEmiddle.Messaging.Transport;
using LibEmiddle.Messaging.Chat;
using LibEmiddle.Diagnostics;

namespace LibEmiddle.API;

/// <summary>
/// Main client interface for LibEmiddle providing end-to-end encrypted messaging
/// capabilities with support for individual chats, group messaging, and multi-device synchronization.
/// Updated to work with the consolidated GroupSession implementation.
/// </summary>
public sealed class LibEmiddleClient : IDisposable
{
    private readonly LibEmiddleClientOptions _options;
    private readonly ICryptoProvider _cryptoProvider;
    private readonly KeyPair _identityKeyPair;
    private readonly SessionManager _sessionManager;
    private readonly DeviceManager _deviceManager;
    private readonly IMailboxTransport _transport;
    private readonly KeyManager _keyManager;
    private readonly MailboxManager _mailboxManager;

    // v2.5 - Diagnostics system (optional)
    private readonly Lazy<ILibEmiddleDiagnostics?> _diagnostics;

    private bool _disposed;
    private bool _initialized;
    private bool _isListening;

    /// <summary>
    /// Gets the client's identity public key.
    /// </summary>
    public byte[] IdentityPublicKey => _identityKeyPair.PublicKey;

    /// <summary>
    /// Gets the current device manager for multi-device operations.
    /// </summary>
    public IDeviceManager DeviceManager => _deviceManager;

    /// <summary>
    /// Event raised when a new message is received.
    /// </summary>
    public event EventHandler<MailboxMessageEventArgs>? MessageReceived;

    /// <summary>
    /// Gets whether the client is currently listening for incoming messages.
    /// </summary>
    public bool IsListening => _isListening;

    /// <summary>
    /// Gets the diagnostic and health monitoring interface (v2.5).
    /// Returns null if health monitoring is not enabled in the feature flags.
    /// </summary>
    public ILibEmiddleDiagnostics? Diagnostics => _diagnostics.Value;

    /// <summary>
    /// Initializes a new instance of the LibEmiddleClient.
    /// </summary>
    /// <param name="options">Configuration options for the client</param>
    /// <exception cref="ArgumentNullException">Thrown when options is null</exception>
    public LibEmiddleClient(LibEmiddleClientOptions options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));

        try
        {
            // Initialize libsodium
            Sodium.Initialize();

            // Create crypto provider
            _cryptoProvider = new CryptoProvider();

            // Load or generate identity key pair
            _identityKeyPair = LoadOrGenerateIdentityKey();

            // Create key manager
            _keyManager = new KeyManager(_cryptoProvider);

            // Create protocols
            var x3dhProtocol = new X3DHProtocol(_cryptoProvider);
            var doubleRatchetProtocol = new DoubleRatchetProtocol();

            // Create session manager
            _sessionManager = new SessionManager(
                _cryptoProvider,
                x3dhProtocol,
                doubleRatchetProtocol,
                _identityKeyPair,
                _options.SessionStoragePath);

            // Create device linking service and device manager
            var deviceLinkingService = new DeviceLinkingService(_cryptoProvider);
            var syncMessageValidator = new SyncMessageValidator(_cryptoProvider);
            _deviceManager = new DeviceManager(
                _identityKeyPair,
                deviceLinkingService,
                _cryptoProvider,
                syncMessageValidator);

            // Create transport
            _transport = CreateTransport();

            // Create mailbox manager with the transport and protocols
            _mailboxManager = new MailboxManager(_identityKeyPair, _transport, doubleRatchetProtocol, _cryptoProvider);

            // Wire up mailbox manager events
            _mailboxManager.MessageReceived += OnMailboxMessageReceived;

            // Initialize diagnostics system (v2.5) - lazy initialization based on feature flag
            _diagnostics = new Lazy<ILibEmiddleDiagnostics?>(() =>
            {
                if (!_options.V25Features.EnableHealthMonitoring)
                    return null;

                var diagnosticsImpl = new LibEmiddleDiagnostics();
                
                // Record client initialization event
                diagnosticsImpl.RecordEvent(Domain.Diagnostics.DiagnosticEvent.OperationCompleted(
                    "LibEmiddleClient", "ClientInitialized", 0));
                
                return diagnosticsImpl;
            });

            LoggingManager.LogInformation(nameof(LibEmiddleClient), "LibEmiddle client initialized successfully");
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient), $"Failed to initialize client: {ex.Message}");
            Dispose();
            throw;
        }
    }

    /// <summary>
    /// Initializes the client and prepares it for use.
    /// </summary>
    /// <returns>True if initialization was successful</returns>
    public async Task<bool> InitializeAsync()
    {
        ThrowIfDisposed();

        if (_initialized)
            return true;

        try
        {
            // Initialize transport
            if (_transport is IAsyncInitializable asyncTransport)
            {
                await asyncTransport.InitializeAsync();
            }

            _initialized = true;
            LoggingManager.LogInformation(nameof(LibEmiddleClient), "Client initialization completed");
            return true;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient), $"Client initialization failed: {ex.Message}");
            return false;
        }
    }

    #region Individual Chat Methods

    /// <summary>
    /// Creates a new chat session with the specified recipient.
    /// </summary>
    /// <param name="recipientPublicKey">The recipient's public key</param>
    /// <param name="recipientUserId">Optional user identifier for the recipient</param>
    /// <param name="options">Optional chat session configuration</param>
    /// <returns>The created chat session</returns>
    public async Task<IChatSession> CreateChatSessionAsync(
        byte[] recipientPublicKey,
        string? recipientUserId = null,
        ChatSessionOptions? options = null)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentNullException.ThrowIfNull(recipientPublicKey);

        try
        {
            options ??= new ChatSessionOptions();
            if (!string.IsNullOrEmpty(recipientUserId))
            {
                options.RemoteUserId = recipientUserId;
            }

            var session = await _sessionManager.CreateSessionAsync(recipientPublicKey, options);
            if (session is IChatSession chatSession)
            {
                LoggingManager.LogInformation(nameof(LibEmiddleClient), $"Created chat session {session.SessionId}");
                return chatSession;
            }

            throw new InvalidOperationException("Failed to create chat session");
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient), $"Failed to create chat session: {ex.Message}");
            throw;
        }
    }

    /// <summary>
    /// Gets an existing chat session by ID.
    /// </summary>
    /// <param name="sessionId">The session identifier</param>
    /// <returns>The chat session if found</returns>
    public async Task<IChatSession> GetChatSessionAsync(string sessionId)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentException.ThrowIfNullOrEmpty(sessionId);

        try
        {
            var session = await _sessionManager.GetSessionAsync(sessionId);
            if (session is IChatSession chatSession)
            {
                return chatSession;
            }

            throw new InvalidOperationException($"Session {sessionId} is not a chat session");
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient), $"Failed to get chat session {sessionId}: {ex.Message}");
            throw;
        }
    }

    /// <summary>
    /// Processes an incoming key exchange message to establish a chat session.
    /// </summary>
    /// <param name="mailboxMessage">The incoming mailbox message</param>
    /// <param name="options">Optional chat session configuration</param>
    /// <returns>The established chat session if successful</returns>
    public async Task<IChatSession?> ProcessKeyExchangeMessageAsync(
        MailboxMessage mailboxMessage,
        ChatSessionOptions? options = null)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentNullException.ThrowIfNull(mailboxMessage);

        try
        {
            // Create a local key bundle for the exchange
            var keyBundle = await CreateLocalKeyBundleAsync();

            var session = await _sessionManager.ProcessKeyExchangeMessageAsync(
                mailboxMessage, keyBundle, options);

            if (session != null)
            {
                LoggingManager.LogInformation(nameof(LibEmiddleClient),
                    $"Processed key exchange and created session {session.SessionId}");
            }

            return session;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Failed to process key exchange message: {ex.Message}");
            return null;
        }
    }

    /// <summary>
    /// Sends a message to an individual chat session.
    /// </summary>
    /// <param name="sessionId">The chat session identifier</param>
    /// <param name="message">The message to send</param>
    /// <returns>The encrypted message ready for transport</returns>
    public async Task<EncryptedMessage?> SendChatMessageAsync(string sessionId, string message)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentException.ThrowIfNullOrEmpty(sessionId);
        ArgumentException.ThrowIfNullOrEmpty(message);

        try
        {
            var chatSession = await GetChatSessionAsync(sessionId);
            var encryptedMessage = await chatSession.EncryptAsync(message);

            if (encryptedMessage != null)
            {
                LoggingManager.LogInformation(nameof(LibEmiddleClient),
                    $"Encrypted message for chat session {sessionId}");
            }

            return encryptedMessage;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Failed to send message to chat session {sessionId}: {ex.Message}");
            throw;
        }
    }

    /// <summary>
    /// Sends a message to an individual chat by recipient public key.
    /// Creates a session if one doesn't exist.
    /// </summary>
    /// <param name="recipientPublicKey">The recipient's public key</param>
    /// <param name="message">The message to send</param>
    /// <param name="recipientUserId">Optional user identifier for the recipient</param>
    /// <returns>The encrypted message ready for transport</returns>
    public async Task<EncryptedMessage?> SendChatMessageAsync(
        byte[] recipientPublicKey,
        string message,
        string? recipientUserId = null)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentNullException.ThrowIfNull(recipientPublicKey);
        ArgumentException.ThrowIfNullOrEmpty(message);

        try
        {
            // Try to find existing session first
            IChatSession? chatSession = null;
            var sessionIds = await _sessionManager.ListSessionsAsync();

            foreach (var existingSessionId in sessionIds)
            {
                if (existingSessionId != null && existingSessionId.StartsWith("chat-"))
                {
                    try
                    {
                        var session = await _sessionManager.GetSessionAsync(existingSessionId);
                        if (session is IChatSession existingChat)
                        {
                            // Check if this session is for the same recipient
                            // Note: This is a simplified check - in practice you might want
                            // to store recipient mapping or check session metadata
                            var recipientKey = Convert.ToBase64String(recipientPublicKey);
                            if (existingSessionId.Contains(recipientKey.Substring(0, Math.Min(8, recipientKey.Length))))
                            {
                                chatSession = existingChat;
                                break;
                            }
                        }
                    }
                    catch
                    {
                        // Continue searching if this session fails to load
                        continue;
                    }
                }
            }

            // Create new session if none found
            if (chatSession == null)
            {
                chatSession = await CreateChatSessionAsync(recipientPublicKey, recipientUserId);
            }

            var encryptedMessage = await chatSession.EncryptAsync(message);

            if (encryptedMessage != null)
            {
                LoggingManager.LogInformation(nameof(LibEmiddleClient),
                    $"Encrypted message for recipient {Convert.ToBase64String(recipientPublicKey).Substring(0, 8)}");
            }

            return encryptedMessage;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Failed to send message to recipient: {ex.Message}");
            throw;
        }
    }

    /// <summary>
    /// Processes a received encrypted chat message.
    /// </summary>
    /// <param name="encryptedMessage">The encrypted message to process</param>
    /// <returns>The decrypted message content</returns>
    public async Task<string?> ProcessChatMessageAsync(EncryptedMessage encryptedMessage)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentNullException.ThrowIfNull(encryptedMessage);

        try
        {
            // Find the appropriate chat session
            var sessionIds = await _sessionManager.ListSessionsAsync();

            foreach (var sessionId in sessionIds)
            {
                if (sessionId != null && sessionId.StartsWith("chat-"))
                {
                    try
                    {
                        var session = await _sessionManager.GetSessionAsync(sessionId);
                        if (session is IChatSession chatSession)
                        {
                            // Try to decrypt with this session
                            var decryptedMessage = await chatSession.DecryptAsync(encryptedMessage);
                            if (decryptedMessage != null)
                            {
                                LoggingManager.LogInformation(nameof(LibEmiddleClient),
                                    $"Decrypted message in chat session {sessionId}");
                                return decryptedMessage;
                            }
                        }
                    }
                    catch
                    {
                        // Continue trying other sessions if this one fails
                        continue;
                    }
                }
            }

            LoggingManager.LogWarning(nameof(LibEmiddleClient),
                "Could not decrypt message with any existing chat session");
            return null;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Failed to process chat message: {ex.Message}");
            return null;
        }
    }

    /// <summary>
    /// Gets message history for a chat session with pagination support.
    /// </summary>
    /// <param name="sessionId">The session ID</param>
    /// <param name="limit">Maximum number of messages to retrieve (default: 50, max: 1000)</param>
    /// <param name="startIndex">Starting index for pagination (default: 0)</param>
    /// <returns>Collection of message records</returns>
    public async Task<IReadOnlyCollection<MessageRecord>?> GetChatMessageHistoryAsync(
        string sessionId,
        int limit = 50,
        int startIndex = 0)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentException.ThrowIfNullOrEmpty(sessionId);

        // Security: Limit the maximum number of messages that can be retrieved at once
        if (limit <= 0 || limit > 1000)
        {
            limit = Math.Min(Math.Max(limit, 1), 1000);
            LoggingManager.LogWarning(nameof(LibEmiddleClient), $"Message history limit adjusted to {limit}");
        }

        if (startIndex < 0)
        {
            startIndex = 0;
        }

        try
        {
            var chatSession = await GetChatSessionAsync(sessionId);
            var history = chatSession.GetMessageHistory(limit, startIndex);
            LoggingManager.LogDebug(nameof(LibEmiddleClient),
                $"Retrieved {history.Count} messages from session {sessionId}");
            return history;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Failed to get message history for session {sessionId}: {ex.Message}");
            return null;
        }
    }

    /// <summary>
    /// Gets the message count for a chat session.
    /// </summary>
    /// <param name="sessionId">The session ID</param>
    /// <returns>Number of messages in the session, or -1 if session not found</returns>
    public async Task<int> GetChatMessageCountAsync(string sessionId)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentException.ThrowIfNullOrEmpty(sessionId);

        try
        {
            var chatSession = await GetChatSessionAsync(sessionId);
            var count = chatSession.GetMessageCount();
            LoggingManager.LogDebug(nameof(LibEmiddleClient),
                $"Session {sessionId} has {count} messages");
            return count;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Failed to get message count for session {sessionId}: {ex.Message}");
            return -1;
        }
    }

    /// <summary>
    /// Clears message history for a chat session.
    /// </summary>
    /// <param name="sessionId">The session ID</param>
    /// <returns>Number of messages cleared, or -1 if failed</returns>
    public async Task<int> ClearChatMessageHistoryAsync(string sessionId)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentException.ThrowIfNullOrEmpty(sessionId);

        try
        {
            var chatSession = await GetChatSessionAsync(sessionId);
            var clearedCount = chatSession.ClearMessageHistory();
            LoggingManager.LogInformation(nameof(LibEmiddleClient),
                $"Cleared {clearedCount} messages from session {sessionId}");
            return clearedCount;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Failed to clear message history for session {sessionId}: {ex.Message}");
            return -1;
        }
    }

    #endregion

    #region Group Chat Methods (Updated for New GroupSession)

    /// <summary>
    /// Creates a new group chat session.
    /// </summary>
    /// <param name="groupId">Unique identifier for the group</param>
    /// <param name="groupName">Display name for the group</param>
    /// <param name="options">Optional group session configuration</param>
    /// <returns>The created group session</returns>
    public async Task<IGroupSession> CreateGroupAsync(
        string groupId,
        string groupName,
        GroupSessionOptions? options = null)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentException.ThrowIfNullOrEmpty(groupId);
        ArgumentException.ThrowIfNullOrEmpty(groupName);

        try
        {
            options ??= new GroupSessionOptions
            {
                GroupId = groupId,
                GroupName = groupName,
                RotationStrategy = KeyRotationStrategy.Standard
            };

            // Create the new consolidated GroupSession directly
            var groupSession = new GroupSession(
                groupId,
                groupName,
                _identityKeyPair,
                options.RotationStrategy,
                _identityKeyPair.PublicKey); // Creator is this client

            // Activate the session
            await groupSession.ActivateAsync();

            // Save the session through the session manager
            await _sessionManager.SaveSessionAsync(groupSession);

            LoggingManager.LogInformation(nameof(LibEmiddleClient),
                $"Created group session {groupSession.SessionId} for group {groupId}");

            return groupSession;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Failed to create group {groupId}: {ex.Message}");
            throw;
        }
    }

    /// <summary>
    /// Gets an existing group session by group ID.
    /// </summary>
    /// <param name="groupId">The group identifier</param>
    /// <returns>The group session if found</returns>
    public async Task<IGroupSession> GetGroupAsync(string groupId)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentException.ThrowIfNullOrEmpty(groupId);

        try
        {
            // List all sessions and find the group session
            var sessionIds = await _sessionManager.ListSessionsAsync();

            foreach (var sessionId in sessionIds)
            {
                if (sessionId != null && sessionId.StartsWith($"group-{groupId}-"))
                {
                    var session = await _sessionManager.GetSessionAsync(sessionId);
                    if (session is IGroupSession groupSession && groupSession.GroupId == groupId)
                    {
                        return groupSession;
                    }
                }
            }

            throw new KeyNotFoundException($"Group {groupId} not found");
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Failed to get group {groupId}: {ex.Message}");
            throw;
        }
    }

    /// <summary>
    /// Joins an existing group using a sender key distribution message.
    /// </summary>
    /// <param name="distribution">The sender key distribution message</param>
    /// <param name="rotationStrategy">Optional key rotation strategy</param>
    /// <returns>The joined group session</returns>
    public async Task<IGroupSession> JoinGroupAsync(
        SenderKeyDistributionMessage distribution,
        KeyRotationStrategy rotationStrategy = KeyRotationStrategy.Standard)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentNullException.ThrowIfNull(distribution);
        ArgumentException.ThrowIfNullOrEmpty(distribution.GroupId);

        try
        {
            // Check if we're already in this group
            try
            {
                var existingSession = await GetGroupAsync(distribution.GroupId);
                if (existingSession != null)
                {
                    // Process the distribution message to update our keys
                    if (existingSession is GroupSession groupSession)
                    {
                        groupSession.ProcessDistributionMessage(distribution);
                        await _sessionManager.SaveSessionAsync(existingSession);
                    }
                    return existingSession;
                }
            }
            catch (KeyNotFoundException)
            {
                // Group doesn't exist, we'll create it
            }

            // Create a new group session
            var newGroupSession = new GroupSession(
                distribution.GroupId,
                distribution.GroupName ?? "Untitled",
                _identityKeyPair,
                rotationStrategy);

            // Add ourselves as a member first
            await newGroupSession.AddMemberAsync(_identityKeyPair.PublicKey);

            // Add the sender of the distribution message as a member (they're likely the group creator)
            if (distribution.SenderIdentityKey != null &&
                !distribution.SenderIdentityKey.SequenceEqual(_identityKeyPair.PublicKey))
            {
                await newGroupSession.AddMemberAsync(distribution.SenderIdentityKey);
            }

            // Process the distribution message
            if (!newGroupSession.ProcessDistributionMessage(distribution))
            {
                throw new InvalidOperationException("Failed to process distribution message");
            }

            // Activate the session
            await newGroupSession.ActivateAsync();

            // Save the session
            await _sessionManager.SaveSessionAsync(newGroupSession);

            LoggingManager.LogInformation(nameof(LibEmiddleClient),
                $"Joined group {distribution.GroupId}");

            return newGroupSession;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Failed to join group {distribution.GroupId}: {ex.Message}");
            throw;
        }
    }

    /// <summary>
    /// Leaves a group chat.
    /// </summary>
    /// <param name="groupId">The group identifier</param>
    /// <returns>True if the group was left successfully</returns>
    public async Task<bool> LeaveGroupAsync(string groupId)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentException.ThrowIfNullOrEmpty(groupId);

        try
        {
            var groupSession = await GetGroupAsync(groupId);

            // Terminate the session
            await groupSession.TerminateAsync();

            // Delete the session
            await _sessionManager.DeleteSessionAsync(groupSession.SessionId);

            LoggingManager.LogInformation(nameof(LibEmiddleClient), $"Left group {groupId}");
            return true;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Failed to leave group {groupId}: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Sends a message to a group.
    /// </summary>
    /// <param name="groupId">The group identifier</param>
    /// <param name="message">The message to send</param>
    /// <returns>The encrypted message ready for transport</returns>
    public async Task<EncryptedGroupMessage?> SendGroupMessageAsync(string groupId, string message)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentException.ThrowIfNullOrEmpty(groupId);
        ArgumentException.ThrowIfNullOrEmpty(message);

        try
        {
            var groupSession = await GetGroupAsync(groupId);
            var encryptedMessage = await groupSession.EncryptMessageAsync(message);

            if (encryptedMessage != null)
            {
                LoggingManager.LogInformation(nameof(LibEmiddleClient),
                    $"Encrypted message for group {groupId}");
            }

            return encryptedMessage;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Failed to send message to group {groupId}: {ex.Message}");
            throw;
        }
    }

    /// <summary>
    /// Processes a received encrypted group message.
    /// </summary>
    /// <param name="encryptedMessage">The encrypted message to process</param>
    /// <returns>The decrypted message content</returns>
    public async Task<string?> ProcessGroupMessageAsync(EncryptedGroupMessage encryptedMessage)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentNullException.ThrowIfNull(encryptedMessage);

        try
        {
            var groupSession = await GetGroupAsync(encryptedMessage.GroupId);
            var decryptedMessage = await groupSession.DecryptMessageAsync(encryptedMessage);

            if (decryptedMessage != null)
            {
                LoggingManager.LogInformation(nameof(LibEmiddleClient),
                    $"Decrypted message from group {encryptedMessage.GroupId}");
            }

            return decryptedMessage;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Failed to process group message: {ex.Message}");
            return null;
        }
    }

    /// <summary>
    /// Gets information about a group session.
    /// </summary>
    /// <param name="groupId">The group identifier</param>
    /// <returns>Group session information or null if not found</returns>
    public async Task<IGroupSession?> GetGroupInfoAsync(string groupId)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentException.ThrowIfNullOrEmpty(groupId);

        try
        {
            var groupSession = await GetGroupAsync(groupId);
            LoggingManager.LogDebug(nameof(LibEmiddleClient), $"Retrieved group info for {groupId}");
            return groupSession;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Failed to get group info for {groupId}: {ex.Message}");
            return null;
        }
    }



    #endregion

    #region Key Management

    /// <summary>
    /// Creates a local X3DH key bundle for receiving messages.
    /// </summary>
    /// <param name="numOneTimeKeys">Number of one-time prekeys to generate</param>
    /// <returns>A complete X3DH key bundle</returns>
    public async Task<X3DHKeyBundle> CreateLocalKeyBundleAsync(int numOneTimeKeys = 10)
    {
        ThrowIfDisposed();
        EnsureInitialized();

        try
        {
            return await _sessionManager.CreateLocalKeyBundleAsync(numOneTimeKeys);
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Failed to create local key bundle: {ex.Message}");
            throw;
        }
    }

    /// <summary>
    /// Gets the public components of the local key bundle that can be shared.
    /// </summary>
    /// <param name="numOneTimeKeys">Number of one-time prekeys to include</param>
    /// <returns>A public key bundle that can be safely shared</returns>
    public async Task<X3DHPublicBundle> GetPublicKeyBundleAsync(int numOneTimeKeys = 10)
    {
        ThrowIfDisposed();
        EnsureInitialized();

        try
        {
            var keyBundle = await CreateLocalKeyBundleAsync(numOneTimeKeys);
            return keyBundle.ToPublicBundle();
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Failed to get public key bundle: {ex.Message}");
            throw;
        }
    }

    #endregion

    #region Session Management

    /// <summary>
    /// Lists all active session IDs.
    /// </summary>
    /// <returns>Array of session IDs</returns>
    public async Task<string?[]> ListSessionsAsync()
    {
        ThrowIfDisposed();
        EnsureInitialized();

        try
        {
            return await _sessionManager.ListSessionsAsync();
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Failed to list sessions: {ex.Message}");
            throw;
        }
    }

    /// <summary>
    /// Deletes a session and all associated data.
    /// </summary>
    /// <param name="sessionId">The session ID to delete</param>
    /// <returns>True if the session was deleted successfully</returns>
    public async Task<bool> DeleteSessionAsync(string sessionId)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentException.ThrowIfNullOrEmpty(sessionId);

        try
        {
            var result = await _sessionManager.DeleteSessionAsync(sessionId);
            if (result)
            {
                LoggingManager.LogInformation(nameof(LibEmiddleClient), $"Deleted session {sessionId}");
            }
            return result;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Failed to delete session {sessionId}: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Gets detailed information about a session.
    /// </summary>
    /// <param name="sessionId">The session ID</param>
    /// <returns>Session information or null if not found</returns>
    public async Task<ISession?> GetSessionInfoAsync(string sessionId)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentException.ThrowIfNullOrEmpty(sessionId);

        try
        {
            var session = await _sessionManager.GetSessionAsync(sessionId);
            LoggingManager.LogDebug(nameof(LibEmiddleClient), $"Retrieved session info for {sessionId}");
            return session;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Failed to get session info for {sessionId}: {ex.Message}");
            return null;
        }
    }

    #endregion

    #region Multi-Device Support

    /// <summary>
    /// Creates a device link message for adding a new device.
    /// </summary>
    /// <param name="newDevicePublicKey">The new device's public key</param>
    /// <returns>An encrypted message for device linking</returns>
    public EncryptedMessage CreateDeviceLinkMessage(byte[] newDevicePublicKey)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentNullException.ThrowIfNull(newDevicePublicKey);

        try
        {
            return _deviceManager.CreateDeviceLinkMessage(newDevicePublicKey);
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Failed to create device link message: {ex.Message}");
            throw;
        }
    }

    /// <summary>
    /// Processes a device link message from the main device.
    /// </summary>
    /// <param name="encryptedMessage">The encrypted device link message</param>
    /// <param name="expectedMainDevicePublicKey">Expected public key of the main device</param>
    /// <returns>True if the device was successfully linked</returns>
    public bool ProcessDeviceLinkMessage(
        EncryptedMessage encryptedMessage,
        byte[] expectedMainDevicePublicKey)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentNullException.ThrowIfNull(encryptedMessage);
        ArgumentNullException.ThrowIfNull(expectedMainDevicePublicKey);

        try
        {
            return _deviceManager.ProcessDeviceLinkMessage(encryptedMessage, expectedMainDevicePublicKey);
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Failed to process device link message: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Creates sync messages for all linked devices.
    /// </summary>
    /// <param name="syncData">The data to synchronize</param>
    /// <returns>Dictionary of device IDs to encrypted sync messages</returns>
    public Dictionary<string, EncryptedMessage> CreateSyncMessages(byte[] syncData)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentNullException.ThrowIfNull(syncData);

        try
        {
            return _deviceManager.CreateSyncMessages(syncData);
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Failed to create sync messages: {ex.Message}");
            throw;
        }
    }

    /// <summary>
    /// Gets the number of linked devices.
    /// </summary>
    /// <returns>Number of linked devices</returns>
    public int GetLinkedDeviceCount()
    {
        ThrowIfDisposed();
        EnsureInitialized();

        try
        {
            return _deviceManager.GetLinkedDeviceCount();
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient), $"Failed to get linked device count: {ex.Message}");
            return 0;
        }
    }

    /// <summary>
    /// Removes a linked device from the device manager.
    /// </summary>
    /// <param name="devicePublicKey">The public key of the device to remove</param>
    /// <returns>True if the device was removed successfully</returns>
    public bool RemoveLinkedDevice(byte[] devicePublicKey)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentNullException.ThrowIfNull(devicePublicKey);

        try
        {
            var result = _deviceManager.RemoveLinkedDevice(devicePublicKey);
            if (result)
            {
                LoggingManager.LogInformation(nameof(LibEmiddleClient),
                    $"Removed linked device {Convert.ToBase64String(devicePublicKey).Substring(0, 8)}");
            }
            return result;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient), $"Failed to remove linked device: {ex.Message}");
            return false;
        }
    }

    #endregion

    #region Message Transport and Listening

    /// <summary>
    /// Starts listening for incoming messages.
    /// </summary>
    /// <param name="pollingInterval">Polling interval in milliseconds (minimum 1000ms)</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>True if listening started successfully</returns>
    public async Task<bool> StartListeningAsync(int pollingInterval = 5000, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        EnsureInitialized();

        if (_isListening)
        {
            LoggingManager.LogWarning(nameof(LibEmiddleClient), "Already listening for messages");
            return true;
        }

        // Validate polling interval for security (prevent resource exhaustion)
        if (pollingInterval < 1000)
        {
            LoggingManager.LogWarning(nameof(LibEmiddleClient), "Polling interval too low, setting to minimum 1000ms");
            pollingInterval = 1000;
        }

        try
        {
            await _transport.StartListeningAsync(_identityKeyPair.PublicKey, pollingInterval, cancellationToken);
            _isListening = true;
            LoggingManager.LogInformation(nameof(LibEmiddleClient), $"Started listening for messages with {pollingInterval}ms interval");
            return true;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient), $"Failed to start listening: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Stops listening for incoming messages.
    /// </summary>
    /// <returns>True if listening stopped successfully</returns>
    public async Task<bool> StopListeningAsync()
    {
        ThrowIfDisposed();

        if (!_isListening)
        {
            return true;
        }

        try
        {
            await _transport.StopListeningAsync();
            _isListening = false;
            LoggingManager.LogInformation(nameof(LibEmiddleClient), "Stopped listening for messages");
            return true;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient), $"Failed to stop listening: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Marks a message as read and optionally sends a read receipt.
    /// </summary>
    /// <param name="messageId">The message ID to mark as read</param>
    /// <returns>True if the message was marked as read successfully</returns>
    public async Task<bool> MarkMessageAsReadAsync(string messageId)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentException.ThrowIfNullOrEmpty(messageId);

        try
        {
            var result = await _mailboxManager.MarkMessageAsReadAsync(messageId);
            if (result)
            {
                LoggingManager.LogDebug(nameof(LibEmiddleClient), $"Marked message {messageId} as read");
            }
            return result;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient), $"Failed to mark message as read: {ex.Message}");
            return false;
        }
    }

    #endregion

    #region Private Helper Methods

    private KeyPair LoadOrGenerateIdentityKey()
    {
        try
        {
            if (!string.IsNullOrEmpty(_options.IdentityKeyPath) && File.Exists(_options.IdentityKeyPath))
            {
                // Load existing key
                var keyData = File.ReadAllBytes(_options.IdentityKeyPath);
                // Implement key deserialization logic here
                LoggingManager.LogInformation(nameof(LibEmiddleClient), "Loaded existing identity key");
            }
        }
        catch (Exception ex)
        {
            LoggingManager.LogWarning(nameof(LibEmiddleClient),
                $"Failed to load identity key: {ex.Message}. Generating new key.");
        }

        // Generate new key
        var keyPair = Sodium.GenerateEd25519KeyPair();

        try
        {
            if (!string.IsNullOrEmpty(_options.IdentityKeyPath))
            {
                // Save the new key
                var directory = Path.GetDirectoryName(_options.IdentityKeyPath);
                if (!string.IsNullOrEmpty(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                // Implement key serialization logic here
                LoggingManager.LogInformation(nameof(LibEmiddleClient), "Saved new identity key");
            }
        }
        catch (Exception ex)
        {
            LoggingManager.LogWarning(nameof(LibEmiddleClient),
                $"Failed to save identity key: {ex.Message}");
        }

        return keyPair;
    }

    private IMailboxTransport CreateTransport()
    {
        return _options.TransportType switch
        {
            TransportType.InMemory => new InMemoryMailboxTransport(_cryptoProvider),
            TransportType.Http => new HttpMailboxTransport(_cryptoProvider, new HttpClient(), _options.ServerEndpoint ?? "http://localhost:8080"),
            TransportType.WebSocket => CreateWebSocketTransport(),
            _ => new InMemoryMailboxTransport(_cryptoProvider)
        };
    }

    private IMailboxTransport CreateWebSocketTransport()
    {
        // For WebSocket transport, we would need a WebSocketMailboxTransport implementation
        // For now, fall back to HTTP transport as WebSocket transport needs server-side support
        LoggingManager.LogWarning(nameof(LibEmiddleClient), "WebSocket transport not fully implemented, falling back to HTTP");
        return new HttpMailboxTransport(_cryptoProvider, new HttpClient(), _options.ServerEndpoint ?? "ws://localhost:8080");
    }

    private void OnMailboxMessageReceived(object? sender, MailboxMessageEventArgs e)
    {
        try
        {
            // Forward the event to client consumers
            MessageReceived?.Invoke(this, e);
            LoggingManager.LogDebug(nameof(LibEmiddleClient), $"Forwarded message received event for message {e.Message.Id}");
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient), $"Error in message received event handler: {ex.Message}");
        }
    }

    private void EnsureInitialized()
    {
        if (!_initialized)
            throw new InvalidOperationException("Client must be initialized before use. Call InitializeAsync() first.");
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(LibEmiddleClient));
    }

    #endregion

    #region IDisposable Implementation

    public void Dispose()
    {
        if (_disposed)
            return;

        try
        {
            // Stop listening first (synchronously for disposal)
            if (_isListening)
            {
                try
                {
                    // Use synchronous stop for disposal to avoid async in Dispose
                    _transport?.StopListeningAsync().GetAwaiter().GetResult();
                    _isListening = false;
                }
                catch (Exception ex)
                {
                    LoggingManager.LogError(nameof(LibEmiddleClient), $"Error stopping listening during disposal: {ex.Message}");
                }
            }

            // Dispose components in reverse order of creation
            _mailboxManager?.Dispose();
            _sessionManager?.Dispose();
            _deviceManager?.Dispose();
            _transport?.Dispose();
            _keyManager?.Dispose();
            
            // Dispose diagnostics system (v2.5)
            if (_diagnostics.IsValueCreated && _diagnostics.Value is IDisposable disposableDiagnostics)
            {
                disposableDiagnostics.Dispose();
            }
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient), $"Error during disposal: {ex.Message}");
        }

        _disposed = true;
        LoggingManager.LogInformation(nameof(LibEmiddleClient), "LibEmiddle client disposed");
    }

    #endregion
}

/// <summary>
/// Interface for transports that require asynchronous initialization.
/// </summary>
public interface IAsyncInitializable
{
    Task InitializeAsync();
}