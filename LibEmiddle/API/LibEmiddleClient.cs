using LibEmiddle.Abstractions;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;
using LibEmiddle.KeyExchange;
using LibEmiddle.Messaging.Chat;
using LibEmiddle.Messaging.Group;
using LibEmiddle.Messaging.Transport;
using LibEmiddle.Models;
using LibEmiddle.MultiDevice;

namespace LibEmiddle.API
{
    /// <summary>
    /// Main client API for LibEmiddle secure messaging.
    /// Provides a simplified interface for end-to-end encrypted communications.
    /// </summary>
    public class LibEmiddleClient : IDisposable
    {
        private readonly ICryptoProvider _cryptoProvider;
        private readonly ISessionManager _sessionManager;
        private readonly IX3DHProtocol _x3dhProtocol;
        private readonly IDoubleRatchetProtocol _doubleRatchetProtocol;
        private readonly IKeyManager _keyManager;
        private readonly IMailboxTransport _mailboxTransport;
        private readonly KeyPair _identityKeyPair;
        private readonly X3DHKeyBundle _keyBundle;
        private bool _isInitialized;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the LibEmiddle client.
        /// </summary>
        /// <param name="options">Configuration options for the client.</param>
        public LibEmiddleClient(LibEmiddleClientOptions options)
        {
            ArgumentNullException.ThrowIfNull(options, nameof(options));

            // Create or use provided crypto provider
            _cryptoProvider = options.CryptoProvider ?? new CryptoProvider();

            // Create or use provided mailbox transport
            _mailboxTransport = options.MailboxTransport ?? new HttpMailboxTransport(options.ServerUrl);

            // Create protocol implementations
            _x3dhProtocol = new X3DHProtocol(_cryptoProvider);
            _doubleRatchetProtocol = new DoubleRatchetProtocol(_cryptoProvider);
            _keyManager = new KeyManager(_cryptoProvider);

            // Create session manager
            _sessionManager = new SessionManager(
                _cryptoProvider,
                _x3dhProtocol,
                _doubleRatchetProtocol,
                _keyManager,
                null, // Will be set after identity key is loaded or created
                options.SessionStoragePath);

            // Set client properties
            ClientId = options.ClientId ?? Guid.NewGuid().ToString("N");
            DeviceId = options.DeviceId ?? Guid.NewGuid().ToString("N");
        }

        /// <summary>
        /// Gets the unique identifier for this client.
        /// </summary>
        public string ClientId { get; }

        /// <summary>
        /// Gets the unique identifier for this device.
        /// </summary>
        public string DeviceId { get; }

        /// <summary>
        /// Gets the public identity key for this client.
        /// </summary>
        public byte[] IdentityPublicKey => _identityKeyPair.PublicKey;

        /// <summary>
        /// Initializes the client, loading or creating identity keys and registering with the server.
        /// </summary>
        /// <param name="password">Optional password to secure key storage.</param>
        /// <returns>True if initialization succeeded, false otherwise.</returns>
        public async Task<bool> InitializeAsync(string? password = null)
        {
            if (_isInitialized)
                return true;

            try
            {
                // Load or create identity key
                _identityKeyPair = await LoadOrCreateIdentityKeyAsync(password);

                // Generate or load key bundle
                _keyBundle = await GenerateKeyBundleAsync(_identityKeyPair);

                // Register with the server
                bool registered = await RegisterWithServerAsync();
                if (!registered)
                {
                    LoggingManager.LogError(nameof(LibEmiddleClient), "Failed to register with the server");
                    return false;
                }

                // Start message polling
                await StartMessagePollingAsync();

                _isInitialized = true;
                return true;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(LibEmiddleClient), $"Initialization failed: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Creates a new chat session with a recipient.
        /// </summary>
        /// <param name="recipientId">The ID of the recipient.</param>
        /// <returns>The chat session if successful, null otherwise.</returns>
        public async Task<IChatSession?> CreateChatSessionAsync(string recipientId)
        {
            EnsureInitialized();

            try
            {
                // Get recipient's public key bundle
                var recipientBundle = await GetRecipientBundleAsync(recipientId);
                if (recipientBundle == null)
                {
                    LoggingManager.LogError(nameof(LibEmiddleClient), $"Failed to get key bundle for recipient {recipientId}");
                    return null;
                }

                // Create the session
                var session = await _sessionManager.CreateSessionAsync(recipientBundle.IdentityKey) as IChatSession;
                if (session == null)
                {
                    LoggingManager.LogError(nameof(LibEmiddleClient), "Failed to create chat session");
                    return null;
                }

                return session;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(LibEmiddleClient), $"Error creating chat session: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Gets an existing chat session by ID.
        /// </summary>
        /// <param name="sessionId">The ID of the session.</param>
        /// <returns>The chat session if found, null otherwise.</returns>
        public async Task<IChatSession?> GetChatSessionAsync(string sessionId)
        {
            EnsureInitialized();

            try
            {
                return await _sessionManager.GetSessionAsync(sessionId) as IChatSession;
            }
            catch (KeyNotFoundException)
            {
                LoggingManager.LogWarning(nameof(LibEmiddleClient), $"Chat session {sessionId} not found");
                return null;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(LibEmiddleClient), $"Error getting chat session: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Creates a new group chat session.
        /// </summary>
        /// <param name="groupId">The ID of the group.</param>
        /// <param name="initialMembers">The list of initial member IDs to add to the group.</param>
        /// <returns>The group session if successful, null otherwise.</returns>
        public async Task<IGroupSession?> CreateGroupSessionAsync(string groupId, IEnumerable<string>? initialMembers = null)
        {
            EnsureInitialized();

            try
            {
                // Create group options
                var options = new GroupSessionOptions
                {
                    GroupId = groupId,
                    RotationStrategy = KeyRotationStrategy.Standard
                };

                // Create the session
                var session = await _sessionManager.CreateSessionAsync(Array.Empty<byte>(), options) as IGroupSession;
                if (session == null)
                {
                    LoggingManager.LogError(nameof(LibEmiddleClient), "Failed to create group session");
                    return null;
                }

                // Add initial members if provided
                if (initialMembers != null)
                {
                    foreach (var memberId in initialMembers)
                    {
                        // Get member's public key
                        var memberBundle = await GetRecipientBundleAsync(memberId);
                        if (memberBundle == null)
                        {
                            LoggingManager.LogWarning(nameof(LibEmiddleClient), $"Failed to get key bundle for member {memberId}");
                            continue;
                        }

                        // Add member to the group
                        await session.AddMemberAsync(memberBundle.IdentityKey);
                    }
                }

                return session;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(LibEmiddleClient), $"Error creating group session: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Gets an existing group session by ID.
        /// </summary>
        /// <param name="sessionId">The ID of the session.</param>
        /// <returns>The group session if found, null otherwise.</returns>
        public async Task<IGroupSession?> GetGroupSessionAsync(string sessionId)
        {
            EnsureInitialized();

            try
            {
                return await _sessionManager.GetSessionAsync(sessionId) as IGroupSession;
            }
            catch (KeyNotFoundException)
            {
                LoggingManager.LogWarning(nameof(LibEmiddleClient), $"Group session {sessionId} not found");
                return null;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(LibEmiddleClient), $"Error getting group session: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Sends an encrypted message to a recipient using an existing chat session.
        /// </summary>
        /// <param name="sessionId">The ID of the chat session.</param>
        /// <param name="message">The message to send.</param>
        /// <returns>True if the message was sent successfully, false otherwise.</returns>
        public async Task<bool> SendMessageAsync(string sessionId, string message)
        {
            EnsureInitialized();
            ArgumentException.ThrowIfNullOrEmpty(message, nameof(message));

            try
            {
                // Get the session
                var session = await _sessionManager.GetSessionAsync(sessionId);
                if (session == null)
                {
                    throw new KeyNotFoundException($"Session {sessionId} not found");
                }

                // Encrypt the message based on session type
                if (session is IChatSession chatSession)
                {
                    var encryptedMessage = await chatSession.EncryptAsync(message);
                    if (encryptedMessage == null)
                    {
                        LoggingManager.LogError(nameof(LibEmiddleClient), "Failed to encrypt message");
                        return false;
                    }

                    // Create mailbox message
                    var mailboxMessage = new MailboxMessage
                    {
                        MessageId = encryptedMessage.MessageId,
                        SenderId = ClientId,
                        SenderDeviceId = DeviceId,
                        RecipientId = ExtractRecipientId(sessionId),
                        SessionId = sessionId,
                        Type = MessageType.Individual,
                        Content = JsonSerialization.Serialize(encryptedMessage),
                        Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                    };

                    // Send the message
                    bool sent = await _mailboxTransport.SendMessageAsync(mailboxMessage);
                    if (sent)
                    {
                        // Update the session
                        await _sessionManager.SaveSessionAsync(chatSession);
                    }

                    return sent;
                }
                else if (session is IGroupSession groupSession)
                {
                    var encryptedMessage = await groupSession.EncryptMessageAsync(message);
                    if (encryptedMessage == null)
                    {
                        LoggingManager.LogError(nameof(LibEmiddleClient), "Failed to encrypt group message");
                        return false;
                    }

                    // Create mailbox message for group messaging
                    var mailboxMessage = new MailboxMessage
                    {
                        MessageId = encryptedMessage.MessageId,
                        SenderId = ClientId,
                        SenderDeviceId = DeviceId,
                        RecipientId = encryptedMessage.GroupId, // Group ID as recipient
                        SessionId = sessionId,
                        Type = MessageType.Group,
                        Content = JsonSerialization.Serialize(encryptedMessage),
                        Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                    };

                    // Send the message to all group members
                    bool sent = await _mailboxTransport.SendGroupMessageAsync(mailboxMessage);
                    if (sent)
                    {
                        // Update the session
                        await _sessionManager.SaveSessionAsync(groupSession);
                    }

                    return sent;
                }
                else
                {
                    throw new InvalidOperationException($"Unsupported session type for {sessionId}");
                }
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(LibEmiddleClient), $"Error sending message: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Processes received encrypted messages and returns the decrypted content.
        /// </summary>
        /// <param name="mailboxMessage">The received mailbox message.</param>
        /// <returns>The decrypted message content if successful, null otherwise.</returns>
        public async Task<string?> ProcessReceivedMessageAsync(MailboxMessage mailboxMessage)
        {
            EnsureInitialized();
            ArgumentNullException.ThrowIfNull(mailboxMessage, nameof(mailboxMessage));

            try
            {
                // Handle based on message type
                if (mailboxMessage.Type == MessageType.Individual)
                {
                    // Deserialize the encrypted message
                    var encryptedMessage = JsonSerialization.Deserialize<EncryptedMessage>(mailboxMessage.Content);
                    if (encryptedMessage == null)
                    {
                        LoggingManager.LogError(nameof(LibEmiddleClient), "Failed to deserialize encrypted message");
                        return null;
                    }

                    // Get the session
                    var session = await _sessionManager.GetSessionAsync(mailboxMessage.SessionId) as IChatSession;
                    if (session == null)
                    {
                        // We might need to create a new session or handle an incoming initial message
                        session = await HandleNewSessionMessageAsync(encryptedMessage, mailboxMessage);
                        if (session == null)
                        {
                            LoggingManager.LogError(nameof(LibEmiddleClient),
                                $"Failed to create session for incoming message {mailboxMessage.MessageId}");
                            return null;
                        }
                    }

                    // Decrypt the message
                    string? decryptedMessage = await session.DecryptAsync(encryptedMessage);
                    if (decryptedMessage == null)
                    {
                        LoggingManager.LogError(nameof(LibEmiddleClient), "Failed to decrypt message");
                        return null;
                    }

                    // Update the session
                    await _sessionManager.SaveSessionAsync(session);

                    return decryptedMessage;
                }
                else if (mailboxMessage.Type == MessageType.Group)
                {
                    // Deserialize the encrypted group message
                    var encryptedMessage = JsonSerialization.Deserialize<EncryptedGroupMessage>(mailboxMessage.Content);
                    if (encryptedMessage == null)
                    {
                        LoggingManager.LogError(nameof(LibEmiddleClient), "Failed to deserialize encrypted group message");
                        return null;
                    }

                    // Get the session
                    var session = await _sessionManager.GetSessionAsync(mailboxMessage.SessionId) as IGroupSession;
                    if (session == null)
                    {
                        LoggingManager.LogError(nameof(LibEmiddleClient), $"Group session {mailboxMessage.SessionId} not found");
                        return null;
                    }

                    // Decrypt the message
                    string? decryptedMessage = await session.DecryptMessageAsync(encryptedMessage);
                    if (decryptedMessage == null)
                    {
                        LoggingManager.LogError(nameof(LibEmiddleClient), "Failed to decrypt group message");
                        return null;
                    }

                    // Update the session
                    await _sessionManager.SaveSessionAsync(session);

                    return decryptedMessage;
                }
                else if (mailboxMessage.Type == MessageType.SenderKeyDistribution)
                {
                    return await HandleSenderKeyDistributionMessageAsync(mailboxMessage);
                }
                else if (mailboxMessage.Type == MessageType.DeviceSync)
                {
                    return await HandleDeviceSyncMessageAsync(mailboxMessage);
                }
                else
                {
                    LoggingManager.LogWarning(nameof(LibEmiddleClient), $"Unsupported message type: {mailboxMessage.Type}");
                    return null;
                }
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(LibEmiddleClient), $"Error processing received message: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Links a new device to this account.
        /// </summary>
        /// <param name="deviceId">The ID of the new device.</param>
        /// <param name="devicePublicKey">The public key of the new device.</param>
        /// <returns>True if the device was linked successfully, false otherwise.</returns>
        public async Task<bool> LinkDeviceAsync(string deviceId, byte[] devicePublicKey)
        {
            EnsureInitialized();
            ArgumentException.ThrowIfNullOrEmpty(deviceId, nameof(deviceId));
            ArgumentNullException.ThrowIfNull(devicePublicKey, nameof(devicePublicKey));

            try
            {
                // Create device manager
                var deviceManager = new DeviceManager(_cryptoProvider);

                // Create device sync message
                var syncMessage = deviceManager.CreateDeviceSyncMessage(
                    ClientId,
                    deviceId,
                    devicePublicKey,
                    _identityKeyPair);

                // Send the message
                var mailboxMessage = new MailboxMessage
                {
                    MessageId = Guid.NewGuid().ToString("N"),
                    SenderId = ClientId,
                    SenderDeviceId = DeviceId,
                    RecipientId = ClientId, // Send to self (other device)
                    RecipientDeviceId = deviceId,
                    Type = MessageType.DeviceSync,
                    Content = JsonSerialization.Serialize(syncMessage),
                    Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                };

                return await _mailboxTransport.SendMessageAsync(mailboxMessage);
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(LibEmiddleClient), $"Error linking device: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Revokes a linked device.
        /// </summary>
        /// <param name="deviceId">The ID of the device to revoke.</param>
        /// <returns>True if the device was revoked successfully, false otherwise.</returns>
        public async Task<bool> RevokeDeviceAsync(string deviceId)
        {
            EnsureInitialized();
            ArgumentException.ThrowIfNullOrEmpty(deviceId, nameof(deviceId));

            try
            {
                // Create device manager
                var deviceManager = new DeviceManager(Sodium.GenerateEd25519KeyPair());

                // Create device revocation message
                var revocationMessage = deviceManager.CreateDeviceRevocationMessage(
                    ClientId,
                    deviceId,
                    _identityKeyPair);

                // Send the message
                var mailboxMessage = new MailboxMessage
                {
                    MessageId = Guid.NewGuid().ToString("N"),
                    SenderId = ClientId,
                    SenderDeviceId = DeviceId,
                    RecipientId = ClientId, // Send to self (other devices)
                    Type = MessageType.DeviceRevocation,
                    Content = JsonSerialization.Serialize(revocationMessage),
                    Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                };

                return await _mailboxTransport.SendMessageAsync(mailboxMessage);
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(LibEmiddleClient), $"Error revoking device: {ex.Message}");
                return false;
            }
        }

        #region Helper Methods

        private void EnsureInitialized()
        {
            if (!_isInitialized)
                throw new InvalidOperationException("Client is not initialized. Call InitializeAsync first.");
        }

        private async Task<KeyPair> LoadOrCreateIdentityKeyAsync(string? password = null)
        {
            try
            {
                // Try to load existing identity key
                byte[]? privateKey = await _cryptoProvider.RetrieveKeyAsync($"identity:{ClientId}", password);
                if (privateKey != null)
                {
                    // Derive public key
                    var publicKey = _cryptoProvider.DerivePublicKey(privateKey, KeyType.Ed25519).ToArray();
                    return new KeyPair
                    {
                        PublicKey = publicKey,
                        PrivateKey = privateKey
                    };
                }
            }
            catch (Exception ex)
            {
                LoggingManager.LogWarning(nameof(LibEmiddleClient), $"Failed to load identity key: {ex.Message}");
                // Fall through to create a new key
            }

            // Create a new identity key
            var keyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);

            // Store the new key
            await _cryptoProvider.StoreKeyAsync($"identity:{ClientId}", keyPair.PrivateKey!, password);

            return keyPair;
        }

        private async Task<X3DHKeyBundle> GenerateKeyBundleAsync(KeyPair identityKeyPair)
        {
            try
            {
                // Check if we have a stored bundle
                string bundleKey = $"bundle:{ClientId}:{DeviceId}";
                string? bundleJson = await _keyManager.RetrieveJsonAsync(bundleKey);

                if (!string.IsNullOrEmpty(bundleJson))
                {
                    try
                    {
                        var storedBundle = JsonSerialization.Deserialize<X3DHKeyBundle>(bundleJson);
                        if (storedBundle != null)
                        {
                            // Validate the bundle
                            if (await LoadPrivateKeysForBundleAsync(storedBundle))
                            {
                                // Check if the bundle is still valid (not expired)
                                long ageMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - storedBundle.CreationTimestamp;
                                if (ageMs < Constants.SIGNED_PREKEY_ROTATION_MS)
                                {
                                    LoggingManager.LogDebug(nameof(LibEmiddleClient), "Using stored key bundle");
                                    return storedBundle;
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        LoggingManager.LogWarning(nameof(LibEmiddleClient), $"Error loading stored bundle: {ex.Message}");
                        // Fall through to create a new bundle
                    }
                }

                // Create a new key bundle
                var bundle = await _x3dhProtocol.CreateKeyBundleAsync(
                    identityKeyPair,
                    numOneTimeKeys: 20);

                // Store the bundle
                await StoreKeyBundleAsync(bundle);

                return bundle;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(LibEmiddleClient), $"Error generating key bundle: {ex.Message}");
                throw;
            }
        }

        private async Task<bool> LoadPrivateKeysForBundleAsync(X3DHKeyBundle bundle)
        {
            // Load identity key private component
            string idKeyPriv = $"bundle:{ClientId}:{DeviceId}:ik";
            byte[]? identityPrivateKey = await _keyManager.RetrieveKeyAsync(idKeyPriv);
            if (identityPrivateKey == null) return false;
            bundle.SetIdentityKeyPrivate(identityPrivateKey);

            // Load signed prekey private component
            string spkPriv = $"bundle:{ClientId}:{DeviceId}:spk:{bundle.SignedPreKeyId}";
            byte[]? signedPreKeyPrivate = await _keyManager.RetrieveKeyAsync(spkPriv);
            if (signedPreKeyPrivate == null) return false;
            bundle.SetSignedPreKeyPrivate(signedPreKeyPrivate);

            // Load one-time prekeys private components
            bool anyOPKLoaded = false;
            for (int i = 0; i < bundle.OneTimePreKeyIds.Count; i++)
            {
                uint opkId = bundle.OneTimePreKeyIds[i];
                string opkPriv = $"bundle:{ClientId}:{DeviceId}:opk:{opkId}";
                byte[]? opkPrivateKey = await _keyManager.RetrieveKeyAsync(opkPriv);
                if (opkPrivateKey != null)
                {
                    bundle.SetOneTimePreKeyPrivate(opkId, opkPrivateKey);
                    anyOPKLoaded = true;
                }
            }

            return anyOPKLoaded;
        }

        private async Task<bool> StoreKeyBundleAsync(X3DHKeyBundle bundle)
        {
            // Store bundle metadata
            string bundleKey = $"bundle:{ClientId}:{DeviceId}";
            await _keyManager.StoreJsonAsync(bundleKey, JsonSerialization.Serialize(bundle));

            // Store identity key private component
            string idKeyPriv = $"bundle:{ClientId}:{DeviceId}:ik";
            await _keyManager.StoreKeyAsync(idKeyPriv, bundle.GetIdentityKeyPrivate()!);

            // Store signed prekey private component
            string spkPriv = $"bundle:{ClientId}:{DeviceId}:spk:{bundle.SignedPreKeyId}";
            await _keyManager.StoreKeyAsync(spkPriv, bundle.GetSignedPreKeyPrivate()!);

            // Store one-time prekeys private components
            for (int i = 0; i < bundle.OneTimePreKeyIds.Count; i++)
            {
                uint opkId = bundle.OneTimePreKeyIds[i];
                byte[]? opkPrivateKey = bundle.GetOneTimePreKeyPrivate(opkId);
                if (opkPrivateKey != null)
                {
                    string opkPriv = $"bundle:{ClientId}:{DeviceId}:opk:{opkId}";
                    await _keyManager.StoreKeyAsync(opkPriv, opkPrivateKey);
                }
            }

            return true;
        }


        #endregion

        #region IDisposable Implementation

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                // Clean up managed resources
                (_mailboxTransport as IDisposable)?.Dispose();
                (_sessionManager as IDisposable)?.Dispose();
            }

            _disposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        #endregion
    }
}