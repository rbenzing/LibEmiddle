using System.Collections.Concurrent;
using LibEmiddle.Abstractions;
using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;
using LibEmiddle.Messaging.Chat;
using LibEmiddle.Messaging.Group;
using LibEmiddle.Protocol;
using LibEmiddle.Core;
using LibEmiddle.KeyManagement;

namespace LibEmiddle.Sessions
{
    /// <summary>
    /// Implements the ISessionManager interface, providing centralized management
    /// for both individual and group chat sessions.
    /// Updated to work with the consolidated GroupSession implementation.
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

        /// <summary>
        /// Tracks consumed OPK IDs so that the same one-time prekey is never used twice.
        /// The storage path for the consumed-ID list is co-located with the session storage.
        /// </summary>
        internal readonly OPKManager _opkManager = new OPKManager(sessionStoragePath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "LibEmiddle",
            "Keys"));

        /// <summary>
        /// The caller's active local key bundle, held so that replenishment can reference
        /// the existing OPK count. Updated via <see cref="RegisterLocalKeyBundleAsync"/>.
        /// </summary>
        private X3DHKeyBundle? _localKeyBundle;
        private readonly object _localBundleLock = new object();

        private readonly ConcurrentDictionary<string, ISession> _activeSessions = new();

        /// <summary>
        /// Maps Base64(senderIdentityKey) → sessionId for O(1) incoming-message routing.
        /// Populated whenever a chat session is created or loaded.
        /// </summary>
        private readonly ConcurrentDictionary<string, string> _senderKeyIndex = new();

        /// <summary>
        /// In-memory cache of recipient public bundles keyed by Base64(identityKey).
        /// Each entry stores the bundle paired with its cache-insertion UTC timestamp.
        /// Entries older than <see cref="BundleCacheTtl"/> are considered stale.
        /// </summary>
        private readonly ConcurrentDictionary<string, (X3DHPublicBundle Bundle, DateTime CachedAt)> _bundleCache = new();

        /// <summary>
        /// How long a bundle is considered fresh in the in-memory cache before it must be
        /// re-fetched or re-loaded from disk.  Defaults to 72 hours.
        /// </summary>
        private static readonly TimeSpan BundleCacheTtl = TimeSpan.FromHours(72);

        private readonly SemaphoreSlim _operationLock = new(1, 1);
        private volatile bool _disposed;

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
                        if (chatSession is Messaging.Chat.ChatSession cs)
                            IndexChatSession(cs);
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

            // Update sender-key routing index for chat sessions
            if (session is Messaging.Chat.ChatSession cs)
                IndexChatSession(cs);

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

            // Remove from memory and update sender-key index
            if (_activeSessions.TryRemove(sessionId, out var removed) &&
                removed is Messaging.Chat.ChatSession removedChat)
            {
                UnindexChatSession(removedChat);
            }

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

                    // Cache the bundle so future calls with just the identity key can find it
                    if (recipientBundle.IdentityKey != null && recipientBundle.IdentityKey.Length > 0)
                    {
                        _ = _persistenceManager.SaveKeyBundleAsync(recipientBundle);
                    }
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

                // Cache the session and update sender-key routing index
                _activeSessions[chatSession.SessionId] = chatSession;
                IndexChatSession(chatSession);

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

                // Atomically check-and-mark the OPK as consumed BEFORE any key agreement work.
                // TryConsume performs the Contains check and HashSet.Add inside a single lock
                // acquisition, so two concurrent X3DH arrivals with the same OPK ID cannot both
                // slip through the guard. Passing allKnownIds also triggers replenishment if
                // the available count drops below the threshold.
                if (initialMessageData.RecipientOneTimePreKeyId.HasValue)
                {
                    uint opkId = initialMessageData.RecipientOneTimePreKeyId.Value;
                    IReadOnlyList<uint> allIds = recipientBundle.OneTimePreKeyIds;

                    // Guard: if every known OPK in the bundle has been consumed, there are no
                    // fresh keys to use. Throw so the caller can distinguish exhaustion from a
                    // duplicate-OPK rejection.
                    int available = _opkManager.GetAvailableCount(allIds);
                    if (available == 0 && allIds.Count > 0)
                    {
                        throw new InvalidOperationException(
                            "OPK exhausted: all one-time prekeys in the local bundle have been consumed. " +
                            "Replenish the bundle before accepting new X3DH handshakes.");
                    }

                    if (!_opkManager.TryConsume(opkId, allIds))
                    {
                        LoggingManager.LogSecurityEvent("SessionManager",
                            $"Rejected key-exchange: OPK {opkId} has already been consumed.",
                            isAlert: true);
                        return null;
                    }

                    LoggingManager.LogDebug("SessionManager",
                        $"OPK {opkId} atomically consumed before key agreement.");
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

                // Cache the session and update sender-key routing index
                _activeSessions[chatSession.SessionId] = chatSession;
                IndexChatSession(chatSession);

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
        /// Creates a new group session using the consolidated GroupSession implementation.
        /// </summary>
        /// <param name="options">The group session options.</param>
        /// <returns>The created group session.</returns>
        private async Task<IGroupSession> CreateGroupSessionAsync(GroupSessionOptions options)
        {
            ArgumentNullException.ThrowIfNull(options, nameof(options));
            ArgumentException.ThrowIfNullOrEmpty(options.GroupId, "GroupId cannot be null or empty");

            try
            {
                LoggingManager.LogInformation("SessionManager", $"Creating new group session for group {options.GroupId}");

                // Create the consolidated GroupSession directly
                var groupSession = new GroupSession(
                    options.GroupId,
                    options.GroupName,
                    _identityKeyPair,
                    options.RotationStrategy,
                    _identityKeyPair.PublicKey); // Creator is this device

                // Add the creator as the first member (owner/admin)
                await groupSession.AddMemberAsync(_identityKeyPair.PublicKey);

                // Activate the session
                await groupSession.ActivateAsync();

                // Cache the session
                _activeSessions[groupSession.SessionId] = groupSession;

                // Persist the session
                await _persistenceManager.SaveGroupSessionAsync(groupSession);

                LoggingManager.LogInformation("SessionManager", $"Successfully created group session {groupSession.SessionId}");

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
        /// Loads a group session from persistent storage using the new consolidated GroupSession.
        /// </summary>
        /// <param name="sessionId">The ID of the session to load.</param>
        /// <returns>The loaded group session, or null if not found.</returns>
        private async Task<IGroupSession?> LoadGroupSessionAsync(string sessionId)
        {
            try
            {
                // Extract the group ID from the session ID (format: "group-{groupId}-{guid}")
                // The group name is not stored in the session ID — it is restored from serialized state.
                var parts = sessionId.Split('-');
                if (parts.Length < 2 || string.IsNullOrEmpty(parts[1]))
                {
                    LoggingManager.LogError("SessionManager", $"Invalid group session ID format: {sessionId}");
                    return null;
                }

                string groupId = parts[1];

                // Create a new GroupSession instance with an empty group name placeholder;
                // the real name will be restored by RestoreSerializedStateAsync below.
                var groupSession = new GroupSession(
                    groupId,
                    string.Empty,
                    _identityKeyPair,
                    KeyRotationStrategy.Standard); // Default strategy, will be restored from state

                // Load and restore the serialized state
                var serializedState = await _persistenceManager.LoadGroupSessionStateAsync(sessionId);
                if (!string.IsNullOrEmpty(serializedState))
                {
                    bool restored = await groupSession.RestoreSerializedStateAsync(serializedState);
                    if (restored)
                    {
                        LoggingManager.LogInformation("SessionManager", $"Successfully loaded group session {sessionId}");
                        return groupSession;
                    }
                }

                LoggingManager.LogWarning("SessionManager", $"Failed to restore group session state for {sessionId}");
                return null;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError("SessionManager", $"Failed to load group session {sessionId}", ex);
                return null;
            }
        }

        /// <summary>
        /// Returns an existing active <see cref="IChatSession"/> with <paramref name="recipientPublicKey"/>,
        /// or creates a new one if none exists. Avoids opening duplicate sessions to the same peer.
        /// </summary>
        public async Task<IChatSession> GetOrCreateChatSessionAsync(
            byte[] recipientPublicKey,
            string? recipientUserId = null)
        {
            ThrowIfDisposed();
            ArgumentNullException.ThrowIfNull(recipientPublicKey, nameof(recipientPublicKey));

            // Fast path: check the in-memory session cache
            foreach (var kv in _activeSessions)
            {
                if (kv.Value is Messaging.Chat.ChatSession cs &&
                    cs.RemotePublicKey.AsSpan().SequenceEqual(recipientPublicKey))
                {
                    return cs;
                }
            }

            // No cached session — create one
            var options = string.IsNullOrEmpty(recipientUserId)
                ? null
                : new ChatSessionOptions { RemoteUserId = recipientUserId };

            var session = await CreateSessionAsync(recipientPublicKey, options);
            if (session is IChatSession chatSession)
                return chatSession;

            throw new InvalidOperationException("Failed to create a chat session for the given recipient key.");
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
                var bundle = await _x3dhProtocol.CreateKeyBundleAsync(_identityKeyPair, numOneTimeKeys);
                // Register the new bundle so OPK tracking has a reference to the current OPK list.
                await RegisterLocalKeyBundleAsync(bundle);
                return bundle;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError("SessionManager", "Failed to create local key bundle", ex);
                throw;
            }
        }

        /// <summary>
        /// Registers the current local X3DH key bundle with the OPK manager so that
        /// consumed-OPK tracking can determine the available count and trigger replenishment.
        /// Call this whenever the local bundle changes (e.g., after replenishment).
        /// </summary>
        /// <param name="bundle">The active local key bundle.</param>
        public Task RegisterLocalKeyBundleAsync(X3DHKeyBundle bundle)
        {
            ArgumentNullException.ThrowIfNull(bundle);

            lock (_localBundleLock)
            {
                _localKeyBundle = bundle;
            }

            // Configure the replenishment callback now that we have a bundle reference.
            _opkManager.SetReplenishmentCallback(async count =>
            {
                await ReplenishOPKsAsync(count).ConfigureAwait(false);
            });

            return Task.CompletedTask;
        }

        /// <summary>
        /// Returns the OPK IDs from the current local bundle that have not yet been consumed,
        /// i.e., the IDs that are safe to publish in the public bundle.
        /// </summary>
        public IReadOnlyList<uint> GetAvailableOPKIds()
        {
            X3DHKeyBundle? bundle;
            lock (_localBundleLock)
            {
                bundle = _localKeyBundle;
            }

            if (bundle == null)
                return Array.Empty<uint>();

            return _opkManager.FilterAvailable(bundle.OneTimePreKeyIds);
        }

        /// <summary>
        /// Generates <paramref name="count"/> new X25519 OPKs and appends them to the
        /// current local key bundle, then logs the updated available count.
        /// </summary>
        private async Task ReplenishOPKsAsync(int count)
        {
            X3DHKeyBundle? bundle;
            lock (_localBundleLock)
            {
                bundle = _localKeyBundle;
            }

            if (bundle == null)
            {
                LoggingManager.LogWarning("SessionManager", "Cannot replenish OPKs: no local key bundle registered.");
                return;
            }

            try
            {
                // Generate a temporary bundle that contains only the new OPKs.
                var tempBundle = await _x3dhProtocol.CreateKeyBundleAsync(_identityKeyPair, count);

                // Copy the new OPKs (public + private) into the existing bundle.
                lock (_localBundleLock)
                {
                    for (int i = 0; i < tempBundle.OneTimePreKeyIds.Count; i++)
                    {
                        uint newId = tempBundle.OneTimePreKeyIds[i];
                        byte[] newPublicKey = tempBundle.OneTimePreKeys[i];
                        byte[]? newPrivateKey = tempBundle.GetOneTimePreKeyPrivate(newId);

                        // Add the public key to the bundle's public list.
                        bundle.OneTimePreKeys.Add(newPublicKey);
                        bundle.OneTimePreKeyIds.Add(newId);

                        // Add the private key — requires the ID already in the public list.
                        if (newPrivateKey != null)
                        {
                            bundle.SetOneTimePreKeyPrivate(newId, newPrivateKey);
                        }
                    }
                }

                int available = _opkManager.GetAvailableCount(bundle.OneTimePreKeyIds);
                LoggingManager.LogInformation("SessionManager",
                    $"OPK replenishment complete: added {tempBundle.OneTimePreKeyIds.Count} new OPKs. Available: {available}");
            }
            catch (Exception ex)
            {
                LoggingManager.LogError("SessionManager", $"Failed to replenish OPKs: {ex.Message}");
            }
        }

        /// <summary>
        /// Retrieves a recipient's key bundle by their identity key.
        /// Checks the in-memory TTL cache first, then falls back to disk persistence.
        /// </summary>
        /// <param name="recipientKey">The recipient's Ed25519 identity public key (32 bytes).</param>
        /// <returns>The cached <see cref="X3DHPublicBundle"/> for this identity key.</returns>
        /// <exception cref="ArgumentException">
        /// Thrown when no cached bundle is found for the given identity key.
        /// Obtain the recipient's full X3DHPublicBundle (IdentityKey + SignedPreKey + signature)
        /// and pass it as UTF-8 JSON bytes to <see cref="CreateSessionAsync"/> first,
        /// or call <c>FetchRecipientKeyBundleAsync</c> on the client when the transport supports it.
        /// </exception>
        private async Task<X3DHPublicBundle> GetOrCreateRecipientBundleAsync(byte[] recipientKey)
        {
            // 1. Check in-memory bundle cache (with TTL enforcement)
            string cacheKey = Convert.ToBase64String(recipientKey);
            if (_bundleCache.TryGetValue(cacheKey, out var cached))
            {
                if (DateTime.UtcNow - cached.CachedAt < BundleCacheTtl)
                {
                    LoggingManager.LogDebug("SessionManager",
                        $"Bundle cache hit for identity key {cacheKey[..Math.Min(8, cacheKey.Length)]}");
                    return cached.Bundle;
                }

                // Entry is stale — remove it so it gets re-loaded below
                _bundleCache.TryRemove(cacheKey, out _);
            }

            // 2. Fall back to disk persistence
            var bundle = await _persistenceManager.LoadKeyBundleByIdentityKeyAsync(recipientKey);
            if (bundle != null)
            {
                // Warm the in-memory cache
                _bundleCache[cacheKey] = (bundle, DateTime.UtcNow);
                return bundle;
            }

            throw new ArgumentException(
                "No cached key bundle found for the supplied identity key. " +
                "Pass the recipient's full X3DHPublicBundle (serialized as UTF-8 JSON) as the " +
                "recipientKey argument to CreateSessionAsync to register it, or call " +
                "FetchRecipientKeyBundleAsync on the client when the transport supports it.",
                nameof(recipientKey));
        }

        /// <summary>
        /// Stores a recipient's public key bundle in both the in-memory TTL cache and
        /// on-disk persistence so that subsequent <see cref="CreateSessionAsync"/> calls
        /// with just the identity key can find it without a transport round-trip.
        /// </summary>
        /// <param name="bundle">The validated bundle to cache.</param>
        public async Task CacheRecipientBundleAsync(X3DHPublicBundle bundle)
        {
            ArgumentNullException.ThrowIfNull(bundle);
            if (bundle.IdentityKey == null || bundle.IdentityKey.Length == 0)
                throw new ArgumentException("Bundle must have a non-empty identity key.", nameof(bundle));

            string cacheKey = Convert.ToBase64String(bundle.IdentityKey);

            // Update in-memory cache
            _bundleCache[cacheKey] = (bundle, DateTime.UtcNow);

            // Persist to disk so it survives process restarts
            await _persistenceManager.SaveKeyBundleAsync(bundle);

            LoggingManager.LogInformation("SessionManager",
                $"Cached recipient bundle for identity key {cacheKey[..Math.Min(8, cacheKey.Length)]}");
        }

        /// <summary>
        /// Attempts to find the session ID for an incoming message based on the
        /// sender's identity key, enabling O(1) routing.
        /// </summary>
        /// <param name="senderIdentityKey">The sender's long-term identity public key.</param>
        /// <param name="sessionId">The matching session ID, if found.</param>
        /// <returns>True if a matching session was found; false otherwise.</returns>
        public bool TryGetSessionIdBySenderKey(byte[] senderIdentityKey, out string? sessionId)
        {
            if (senderIdentityKey == null || senderIdentityKey.Length == 0)
            {
                sessionId = null;
                return false;
            }

            string indexKey = Convert.ToBase64String(senderIdentityKey);
            return _senderKeyIndex.TryGetValue(indexKey, out sessionId);
        }

        /// <summary>
        /// Registers a chat session in the sender-key index so that incoming
        /// messages from the remote peer can be routed in O(1).
        /// </summary>
        private void IndexChatSession(Messaging.Chat.ChatSession chatSession)
        {
            if (chatSession.RemotePublicKey != null && chatSession.RemotePublicKey.Length > 0)
            {
                string indexKey = Convert.ToBase64String(chatSession.RemotePublicKey);
                _senderKeyIndex[indexKey] = chatSession.SessionId;
            }
        }

        /// <summary>
        /// Removes a chat session from the sender-key index.
        /// </summary>
        private void UnindexChatSession(Messaging.Chat.ChatSession chatSession)
        {
            if (chatSession.RemotePublicKey != null && chatSession.RemotePublicKey.Length > 0)
            {
                string indexKey = Convert.ToBase64String(chatSession.RemotePublicKey);
                _senderKeyIndex.TryRemove(indexKey, out _);
            }
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
                _senderKeyIndex.Clear();
                _bundleCache.Clear();
                _persistenceManager?.Dispose();
                _opkManager?.Dispose();
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