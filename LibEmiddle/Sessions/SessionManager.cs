using System.Collections.Concurrent;
using LibEmiddle.Abstractions;
using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;
using LibEmiddle.Messaging.Chat;
using LibEmiddle.Messaging.Group;
using LibEmiddle.Protocol;
using LibEmiddle.Core;

namespace LibEmiddle.Sessions
{
    /// <summary>
    /// Implements the ISessionManager interface, providing centralized management
    /// for both individual and group chat sessions.
    /// </summary>
    /// <remarks>
    /// Initializes a new instance of the SessionManager class.
    /// </remarks>
    /// <param name="cryptoProvider">The cryptographic provider.</param>
    /// <param name="x3dhProtocol">The X3DH protocol implementation.</param>
    /// <param name="doubleRatchetProtocol">The Double Ratchet protocol implementation.</param>
    /// <param name="identityKeyPair">The identity key pair for this device.</param>
    /// <param name="sessionStoragePath">Optional path for storing session data.</param>
    public class SessionManager(
        ICryptoProvider cryptoProvider,
        IX3DHProtocol x3dhProtocol,
        IDoubleRatchetProtocol doubleRatchetProtocol,
        KeyPair identityKeyPair,
        string? sessionStoragePath = null) : ISessionManager, IDisposable
    {
        private readonly ICryptoProvider _cryptoProvider = cryptoProvider ?? throw new ArgumentNullException(nameof(cryptoProvider));
        private readonly IX3DHProtocol _x3dhProtocol = x3dhProtocol ?? throw new ArgumentNullException(nameof(x3dhProtocol));
        private readonly IDoubleRatchetProtocol _doubleRatchetProtocol = doubleRatchetProtocol ?? throw new ArgumentNullException(nameof(doubleRatchetProtocol));
        private readonly KeyPair _identityKeyPair = identityKeyPair;

        private readonly SessionPersistenceManager _persistenceManager = new(cryptoProvider, sessionStoragePath);
        private readonly ProtocolAdapter _protocolAdapter = new(
                x3dhProtocol,
                doubleRatchetProtocol,
                cryptoProvider);

        private readonly ConcurrentDictionary<string, ISession> _activeSessions = new();
        private readonly SemaphoreSlim _operationLock = new(1, 1);
        private bool _disposed;

        /// <inheritdoc/>
        public async Task<ISession> CreateSessionAsync(byte[] recipientKey, object? options = null)
        {
            ThrowIfDisposed();
            ArgumentNullException.ThrowIfNull(recipientKey, nameof(recipientKey));

            await _operationLock.WaitAsync();
            try
            {
                // Determine session type based on options
                if (options is GroupSessionOptions groupOptions)
                {
                    return await CreateGroupSessionAsync(groupOptions);
                }
                else
                {
                    return await CreateChatSessionAsync(recipientKey, options as ChatSessionOptions);
                }
            }
            finally
            {
                _operationLock.Release();
            }
        }

        /// <inheritdoc/>
        public async Task<ISession> GetSessionAsync(string sessionId)
        {
            ThrowIfDisposed();
            ArgumentException.ThrowIfNullOrEmpty(sessionId, nameof(sessionId));

            // Check in-memory cache first
            if (_activeSessions.TryGetValue(sessionId, out var session))
            {
                return session;
            }

            // Try to load from disk
            await _operationLock.WaitAsync();
            try
            {
                // Check again after acquiring lock (double-checked locking)
                if (_activeSessions.TryGetValue(sessionId, out session))
                {
                    return session;
                }

                // Determine session type from ID
                if (sessionId.StartsWith("group-"))
                {
                    var groupSession = await LoadGroupSessionAsync(sessionId);
                    if (groupSession != null)
                    {
                        _activeSessions[sessionId] = groupSession;
                        return groupSession;
                    }
                }
                else
                {
                    var chatSession = await LoadChatSessionAsync(sessionId);
                    if (chatSession != null)
                    {
                        _activeSessions[sessionId] = chatSession;
                        return chatSession;
                    }
                }

                throw new KeyNotFoundException($"Session {sessionId} not found.");
            }
            finally
            {
                _operationLock.Release();
            }
        }

        /// <inheritdoc/>
        public async Task<bool> SaveSessionAsync(ISession session)
        {
            ThrowIfDisposed();
            ArgumentNullException.ThrowIfNull(session, nameof(session));

            // Cache in memory
            _activeSessions[session.SessionId] = session;

            // Persist to disk based on session type
            if (session is IChatSession chatSession)
            {
                return await _persistenceManager.SaveChatSessionAsync(chatSession);
            }
            else if (session is IGroupSession groupSession)
            {
                return await _persistenceManager.SaveGroupSessionAsync(groupSession);
            }

            return false;
        }

        /// <inheritdoc/>
        public async Task<bool> DeleteSessionAsync(string sessionId)
        {
            ThrowIfDisposed();
            ArgumentException.ThrowIfNullOrEmpty(sessionId, nameof(sessionId));

            // Remove from memory
            _activeSessions.TryRemove(sessionId, out _);

            // Delete from disk
            return await _persistenceManager.DeleteSessionAsync(sessionId);
        }

        /// <inheritdoc/>
        public async Task<string?[]> ListSessionsAsync()
        {
            ThrowIfDisposed();

            // Get from disk
            return await _persistenceManager.ListSessionsAsync();
        }

        /// <inheritdoc/>
        public async Task<IChatSession> CreateDirectMessageSessionAsync(
            byte[] recipientIdentityKey,
            string recipientUserId)
        {
            ThrowIfDisposed();

            if (recipientUserId == null)
                throw new ArgumentNullException(nameof(recipientUserId));
            if (recipientIdentityKey == null)
                throw new ArgumentNullException(nameof(recipientIdentityKey));

            var options = new ChatSessionOptions
            {
                RemoteUserId = recipientUserId,
                AutoActivate = true
            };

            return (IChatSession)await CreateSessionAsync(recipientIdentityKey, options);
        }

        /// <summary>
        /// Creates a new chat session using X3DH and Double Ratchet protocols.
        /// </summary>
        /// <param name="recipientKey">The recipient's public key.</param>
        /// <param name="options">Optional chat session options.</param>
        /// <returns>The created chat session.</returns>
        private async Task<IChatSession> CreateChatSessionAsync(byte[] recipientKey, ChatSessionOptions? options = null)
        {
            // Use default options if none provided
            options ??= new ChatSessionOptions
            {
                RotationStrategy = KeyRotationStrategy.Standard,
                TrackMessageHistory = true,
                MaxTrackedMessages = 100,
                AutoActivate = true
            };

            try
            {
                LoggingManager.LogInformation("SessionManager", $"Creating new chat session with recipient key {Convert.ToBase64String(recipientKey).Substring(0, 8)}");

                // Get or generate recipient's key bundle
                X3DHPublicBundle recipientBundle;

                if (recipientKey.Length == Constants.ED25519_PUBLIC_KEY_SIZE)
                {
                    // This is an identity key, we need to fetch the full bundle
                    recipientBundle = await GetOrCreateRecipientBundleAsync(recipientKey);
                }
                else
                {
                    // This is already a bundle in serialized form, deserialize it
                    string bundleJson = System.Text.Encoding.UTF8.GetString(recipientKey);
                    recipientBundle = JsonSerialization.Deserialize<X3DHPublicBundle>(bundleJson)
                        ?? throw new ArgumentException("Invalid recipient bundle format", nameof(recipientKey));
                }

                // Validate the bundle
                if (!await _x3dhProtocol.ValidateKeyBundleAsync(recipientBundle))
                {
                    throw new ArgumentException("Invalid recipient key bundle", nameof(recipientKey));
                }

                // Generate a unique session ID
                string sessionId = $"chat-{Convert.ToBase64String(recipientKey).Substring(0, 8)}-{Guid.NewGuid():N}";

                // Use the protocol adapter to prepare a session with both X3DH and Double Ratchet
                var (drSession, initialMessageData) = await _protocolAdapter.PrepareSenderSessionAsync(
                    recipientBundle,
                    _identityKeyPair,
                    sessionId);

                // Create the chat session
                var chatSession = new ChatSession(
                    drSession,
                    recipientBundle.IdentityKey!,
                    _identityKeyPair.PublicKey!,
                    _doubleRatchetProtocol)
                {
                    RotationStrategy = options.RotationStrategy
                };

                // Set the initial message data for handshake
                chatSession.SetInitialMessageData(initialMessageData);

                // Add metadata if provided
                if (options.Metadata != null)
                {
                    foreach (var kvp in options.Metadata)
                    {
                        chatSession.Metadata[kvp.Key] = kvp.Value;
                    }
                }

                // Add remote user ID if provided
                if (!string.IsNullOrEmpty(options.RemoteUserId))
                {
                    chatSession.Metadata["RemoteUserId"] = options.RemoteUserId;
                }

                // Auto-activate if requested
                if (options.AutoActivate)
                {
                    await chatSession.ActivateAsync();
                }

                // Cache the session
                _activeSessions[chatSession.SessionId] = chatSession;

                // Persist the session
                await _persistenceManager.SaveChatSessionAsync(chatSession);

                LoggingManager.LogInformation("SessionManager", $"Successfully created chat session {sessionId}");

                return chatSession;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError("SessionManager", "Failed to create chat session", ex);
                throw;
            }
        }

        /// <inheritdoc/>
        public async Task<IChatSession?> ProcessKeyExchangeMessageAsync(
            MailboxMessage mailboxMessage,
            X3DHKeyBundle recipientBundle,
            ChatSessionOptions? options = null)
        {
            ThrowIfDisposed();
            ArgumentNullException.ThrowIfNull(mailboxMessage, nameof(mailboxMessage));
            ArgumentNullException.ThrowIfNull(recipientBundle, nameof(recipientBundle));

            // Use default options if none provided
            options ??= new ChatSessionOptions
            {
                RotationStrategy = KeyRotationStrategy.Standard,
                TrackMessageHistory = true,
                MaxTrackedMessages = 100,
                AutoActivate = true
            };

            try
            {
                LoggingManager.LogInformation("SessionManager", $"Processing key exchange message from {Convert.ToBase64String(mailboxMessage.SenderKey).Substring(0, 8)}");

                // Extract the X3DH initial message data
                InitialMessageData? initialMessageData = _protocolAdapter.ExtractInitialMessageData(mailboxMessage);
                if (initialMessageData == null)
                {
                    LoggingManager.LogWarning("SessionManager", "Failed to extract X3DH initial message data");
                    return null;
                }

                // Generate a unique session ID
                string sessionId = $"chat-{Convert.ToBase64String(mailboxMessage.SenderKey).Substring(0, 8)}-{Guid.NewGuid():N}";

                // Use the protocol adapter to prepare a receiver session
                var drSession = await _protocolAdapter.PrepareReceiverSessionAsync(
                    initialMessageData,
                    recipientBundle,
                    sessionId);

                // Create the chat session
                var chatSession = new ChatSession(
                    drSession,
                    mailboxMessage.SenderKey,
                    _identityKeyPair.PublicKey!,
                    _doubleRatchetProtocol)
                {
                    RotationStrategy = options.RotationStrategy
                };

                // Add metadata if provided
                if (options.Metadata != null)
                {
                    foreach (var kvp in options.Metadata)
                    {
                        chatSession.Metadata[kvp.Key] = kvp.Value;
                    }
                }

                // Add remote user ID if provided
                if (!string.IsNullOrEmpty(options.RemoteUserId))
                {
                    chatSession.Metadata["RemoteUserId"] = options.RemoteUserId;
                }

                // Auto-activate if requested
                if (options.AutoActivate)
                {
                    await chatSession.ActivateAsync();
                }

                // Cache the session
                _activeSessions[chatSession.SessionId] = chatSession;

                // Persist the session
                await _persistenceManager.SaveChatSessionAsync(chatSession);

                LoggingManager.LogInformation("SessionManager", $"Successfully created chat session {sessionId} from key exchange");

                return chatSession;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError("SessionManager", "Failed to process key exchange message", ex);
                return null;
            }
        }

        /// <summary>
        /// Creates a new group session.
        /// </summary>
        /// <param name="options">The group session options.</param>
        /// <returns>The created group session.</returns>
        private async Task<IGroupSession> CreateGroupSessionAsync(GroupSessionOptions options)
        {
            ArgumentNullException.ThrowIfNull(options, nameof(options));
            ArgumentException.ThrowIfNullOrEmpty(options.GroupId, "GroupId cannot be null or empty");

            try
            {
                // Create required components
                var keyManager = new GroupKeyManager();
                var memberManager = new GroupMemberManager();
                var messageCrypto = new GroupMessageCrypto();
                var distributionManager = new SenderKeyDistribution(keyManager);

                // Create the group
                string groupName = options.GroupName ?? $"Group {options.GroupId}";
                bool groupCreated = memberManager.CreateGroup(
                    options.GroupId,
                    groupName,
                    _identityKeyPair.PublicKey!,
                    true); // Creator is admin

                if (!groupCreated)
                {
                    throw new InvalidOperationException($"Failed to create group {options.GroupId}");
                }

                // Initialize group key
                byte[] initialChainKey = keyManager.GenerateInitialChainKey();
                keyManager.InitializeSenderState(options.GroupId, initialChainKey);

                // Create the session
                var groupSession = new GroupSession(
                    options.GroupId,
                    _identityKeyPair,
                    keyManager,
                    memberManager,
                    messageCrypto,
                    distributionManager,
                    options.RotationStrategy);

                // Activate the session
                await groupSession.ActivateAsync();

                // Cache the session
                _activeSessions[groupSession.SessionId] = groupSession;

                // Persist the session
                await _persistenceManager.SaveGroupSessionAsync(groupSession);

                return groupSession;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError("SessionManager", "Failed to create group session", ex);
                throw;
            }
        }

        /// <summary>
        /// Loads a chat session from persistent storage.
        /// </summary>
        /// <param name="sessionId">The ID of the session to load.</param>
        /// <returns>The loaded chat session, or null if not found.</returns>
        private async Task<IChatSession?> LoadChatSessionAsync(string sessionId)
        {
            try
            {
                return await _persistenceManager.LoadChatSessionAsync(sessionId, _doubleRatchetProtocol);
            }
            catch (Exception ex)
            {
                LoggingManager.LogError("SessionManager", $"Failed to load chat session {sessionId}", ex);
                return null;
            }
        }

        /// <summary>
        /// Loads a group session from persistent storage.
        /// </summary>
        /// <param name="sessionId">The ID of the session to load.</param>
        /// <returns>The loaded group session, or null if not found.</returns>
        private async Task<IGroupSession?> LoadGroupSessionAsync(string sessionId)
        {
            try
            {
                // Extract the group ID from the session ID
                string groupId = sessionId.Split('-')[1]; // Assumes format "group-{groupId}-{guid}"

                // Create required components
                var keyManager = new GroupKeyManager();
                var memberManager = new GroupMemberManager();
                var messageCrypto = new GroupMessageCrypto();
                var distributionManager = new SenderKeyDistribution(keyManager);

                return await _persistenceManager.LoadGroupSessionAsync(
                    sessionId,
                    _identityKeyPair,
                    keyManager,
                    memberManager,
                    messageCrypto,
                    distributionManager);
            }
            catch (Exception ex)
            {
                LoggingManager.LogError("SessionManager", $"Failed to load group session {sessionId}", ex);
                return null;
            }
        }

        /// <summary>
        /// Creates and validates a local X3DH key bundle for receiving messages.
        /// </summary>
        /// <param name="numOneTimeKeys">Number of one-time prekeys to generate.</param>
        /// <returns>A complete X3DH key bundle.</returns>
        public async Task<X3DHKeyBundle> CreateLocalKeyBundleAsync(int numOneTimeKeys = 10)
        {
            ThrowIfDisposed();

            try
            {
                LoggingManager.LogInformation("SessionManager", $"Creating local X3DH key bundle with {numOneTimeKeys} one-time keys");
                return await _x3dhProtocol.CreateKeyBundleAsync(_identityKeyPair, numOneTimeKeys);
            }
            catch (Exception ex)
            {
                LoggingManager.LogError("SessionManager", "Failed to create local key bundle", ex);
                throw;
            }
        }

        /// <summary>
        /// Gets or creates a recipient's key bundle.
        /// </summary>
        /// <param name="recipientKey">The recipient's identity key.</param>
        /// <returns>The recipient's key bundle.</returns>
        private async Task<X3DHPublicBundle> GetOrCreateRecipientBundleAsync(byte[] recipientKey)
        {
            // In a real implementation, this would fetch the bundle from a server
            // For now, we'll create a mock bundle for testing purposes

            // Generate a signed prekey
            var signedPreKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.X25519);

            // Sign the prekey with the recipient's identity key
            // Note: In a real scenario, the server would already have this bundle signed by the recipient
            // This is just for testing and demo purposes
            byte[] signature = new byte[64]; // Mock signature

            // Create the bundle
            return new X3DHPublicBundle
            {
                IdentityKey = recipientKey,
                SignedPreKey = signedPreKeyPair.PublicKey,
                SignedPreKeyId = 1,
                SignedPreKeySignature = signature,
                OneTimePreKeys = new List<byte[]>(),
                OneTimePreKeyIds = new List<uint>(),
                ProtocolVersion = $"{ProtocolVersion.MAJOR_VERSION}.{ProtocolVersion.MINOR_VERSION}",
                CreationTimestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
            };
        }

        #region IDisposable Implementation

        /// <summary>
        /// Disposes of resources used by the SessionManager.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Disposes of resources used by the SessionManager.
        /// </summary>
        /// <param name="disposing">True if disposing, false if finalizing.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                _operationLock.Dispose();

                // Dispose all active sessions
                foreach (var session in _activeSessions.Values)
                {
                    (session as IDisposable)?.Dispose();
                }

                _activeSessions.Clear();
            }

            _disposed = true;
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(SessionManager));
        }

        #endregion
    }
}