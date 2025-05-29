using LibEmiddle.Abstractions;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.Messaging.Chat;
using LibEmiddle.Messaging.Group;
using LibEmiddle.Messaging.Transport;
using LibEmiddle.MultiDevice;
using LibEmiddle.Protocol;
using LibEmiddle.Sessions;

namespace LibEmiddle.API
{
    /// <summary>
    /// Main entry point for the E2EE library, providing a simplified API for common operations.
    /// This class serves as a facade for the various components of the library.
    /// </summary>
    public class LibEmiddleClient : IDisposable
    {
        private readonly GroupChatManager _groupChatManager;
        private readonly IGroupMemberManager _groupMemberManager;
        private readonly DeviceManager _deviceManager;
        private readonly IMailboxTransport _mailboxTransport;
        private readonly ICryptoProvider _cryptoProvider;
        private readonly X3DHProtocol _x3DHProtocol;
        private readonly DoubleRatchetProtocol _doubleRatchetProtocol;
        private readonly SessionManager _sessionManager;

        private readonly KeyPair _identityKeyPair;
        private ChatSession? _chatSession = null;
        private bool _disposed;

        /// <summary>
        /// Creates a new E2EE client with an existing identity key pair
        /// </summary>
        /// <param name="identityKeyPair">Identity key pair to use</param>
        public LibEmiddleClient(KeyPair identityKeyPair)
        {
            // Generate an X25519 identity key pair for this client
            _identityKeyPair = identityKeyPair.ToString() == null ? Sodium.GenerateX25519KeyPair() : identityKeyPair;
            _cryptoProvider = new CryptoProvider();
            _x3DHProtocol = new X3DHProtocol(_cryptoProvider);
            _doubleRatchetProtocol = new DoubleRatchetProtocol(_cryptoProvider);
            _sessionManager = new SessionManager(_cryptoProvider, _x3DHProtocol, _doubleRatchetProtocol, _identityKeyPair);
            _groupChatManager = new GroupChatManager(_cryptoProvider, _identityKeyPair);
            _groupMemberManager = new GroupMemberManager();
            _deviceManager = new DeviceManager(_identityKeyPair);
            _mailboxTransport = new InMemoryMailboxTransport(_cryptoProvider);
        }

        #region Key Management

        /// <summary>
        /// Generates an AES-GCM 32-bit sender key
        /// </summary>
        /// <returns>Random sender key suitable for group encryption</returns>
        public static byte[] GenerateInitialChainKey()
        {
            return SecureMemory.CreateSecureBuffer(Constants.AES_KEY_SIZE);
        }

        /// <summary>
        /// Generates an Ed25519 key pair for digital signatures
        /// </summary>
        /// <returns>Tuple containing (publicKey, privateKey)</returns>
        public static KeyPair GenerateSignatureKeyPair()
        {
            return Sodium.GenerateEd25519KeyPair();
        }

        /// <summary>
        /// Generates an X25519 key pair for secure key exchange
        /// </summary>
        /// <returns>Tuple containing (publicKey, privateKey)</returns>
        public static KeyPair GenerateKeyExchangeKeyPair()
        {
            return Sodium.GenerateX25519KeyPair();
        }

        #endregion

        #region Encryption

        /// <summary>
        /// Encrypts a message using the specified key
        /// </summary>
        /// <param name="message">Message to encrypt</param>
        /// <param name="key">Encryption key</param>
        /// <returns>Encrypted message</returns>
        public static EncryptedMessage EncryptMessage(string message, byte[] key)
        {
            return AES.Encrypt(message, key);
        }

        /// <summary>
        /// Decrypts a message using the specified key
        /// </summary>
        /// <param name="encryptedMessage">Encrypted message</param>
        /// <param name="key">Decryption key</param>
        /// <returns>Decrypted message</returns>
        public static string DecryptMessage(EncryptedMessage encryptedMessage, byte[] key)
        {
            return AES.Decrypt(encryptedMessage, key);
        }

        #endregion

        #region Authentication

        /// <summary>
        /// Signs a message using the specified private key
        /// </summary>
        /// <param name="message">Message to sign</param>
        /// <param name="privateKey">Private key for signing (64 bytes Ed25519)</param>
        /// <returns>Signature as a byte array</returns>
        public static byte[] SignMessage(byte[] message, byte[] privateKey)
        {
            return MessageSigning.SignMessage(message, privateKey);
        }

        /// <summary>
        /// Signs a text message using the specified private key
        /// </summary>
        /// <param name="message">Text message to sign</param>
        /// <param name="privateKey">Private key for signing</param>
        /// <returns>Signature as a Base64 string</returns>
        public static string SignTextMessage(string message, byte[] privateKey)
        {
            return MessageSigning.SignTextMessage(message, privateKey);
        }

        /// <summary>
        /// Verifies a signature for a message
        /// </summary>
        /// <param name="message">Original message</param>
        /// <param name="signature">Signature to verify</param>
        /// <param name="publicKey">Public key of the signer</param>
        /// <returns>True if the signature is valid</returns>
        public static bool VerifySignature(byte[] message, byte[] signature, byte[] publicKey)
        {
            return MessageSigning.VerifySignature(message, signature, publicKey);
        }

        /// <summary>
        /// Verifies a signature for a text message
        /// </summary>
        /// <param name="message">Original message</param>
        /// <param name="signatureBase64">Signature as a Base64 string</param>
        /// <param name="publicKey">Public key of the signer</param>
        /// <returns>True if the signature is valid</returns>
        public static bool VerifyTextMessage(string message, string signatureBase64, byte[] publicKey)
        {
            return MessageSigning.VerifyTextMessage(message, signatureBase64, publicKey);
        }

        /// <summary>
        /// Signs a message using this client's identity key
        /// </summary>
        /// <param name="message">Message to sign</param>
        /// <returns>Signature as a byte array</returns>
        public byte[] SignWithIdentityKey(byte[] message)
        {
            ThrowIfDisposed();
            return MessageSigning.SignMessage(message, _identityKeyPair.PrivateKey);
        }

        /// <summary>
        /// Signs a text message using this client's identity key
        /// </summary>
        /// <param name="message">Text message to sign</param>
        /// <returns>Signature as a Base64 string</returns>
        public string SignTextWithIdentityKey(string message)
        {
            ThrowIfDisposed();
            return MessageSigning.SignTextMessage(message, _identityKeyPair.PrivateKey);
        }

        #endregion

        #region Chat Session Management

        /// <summary>
        /// Gets or creates a chat session with a recipient
        /// </summary>
        /// <param name="recipientPublicKey">Recipient's public key</param>
        /// <returns>Chat session</returns>
        /// <exception cref="ArgumentNullException">Thrown when recipientPublicKey is null</exception>
        public ChatSession GetOrCreateChatSession(byte[] recipientPublicKey)
        {
            ThrowIfDisposed();

            if (recipientPublicKey == null)
                throw new ArgumentNullException(nameof(recipientPublicKey));

            ChatSession? session = _sessionManager.CreateSessionAsync(recipientPublicKey).GetAwaiter().GetResult() as ChatSession;

            if (session == null)
                throw new ArgumentNullException(nameof(session));

            _chatSession = session;

            return session;
        }

        /// <summary>
        /// Closes a chat session with a recipient
        /// </summary>
        /// <param name="sessionId">Recipient's public key</param>
        /// <exception cref="ArgumentNullException">Thrown when recipientPublicKey is null</exception>
        public void CloseChatSession(string sessionId)
        {
            ThrowIfDisposed();

            if (sessionId == null)
                throw new ArgumentNullException(nameof(sessionId));

            bool isDeleted = _sessionManager.DeleteSessionAsync(sessionId).GetAwaiter().GetResult();

            if (!isDeleted)
            {
                throw new ArgumentException($"Error SessionID {sessionId} was not deleted.", nameof(sessionId));
            }
        }

        /// <summary>
        /// Gets all active chat sessions
        /// </summary>
        /// <returns>Collection of active session keys (Base64 encoded recipient public keys)</returns>
        public IEnumerable<string?> GetActiveChatSessions()
        {
            ThrowIfDisposed();
            return _sessionManager.ListSessionsAsync().GetAwaiter().GetResult();
        }

        /// <summary>
        /// Configures the chat session manager to persist sessions to the specified path
        /// </summary>
        /// <param name="sessionStoragePath">Path to store session data</param>
        /// <param name="sessionEncryptionKey">Optional key to encrypt session data</param>
        /// <param name="enableLogging">Whether to enable detailed logging</param>
        public void ConfigureChatSessionStorage(string sessionStoragePath, byte[]? sessionEncryptionKey = null, bool enableLogging = false)
        {
            ThrowIfDisposed();

            if (_chatSession == null)
                throw new ArgumentNullException(nameof(_chatSession));

            _chatSession.ConfigureStorage(sessionStoragePath, sessionEncryptionKey, enableLogging);
        }

        #endregion

        #region Key Exchange & Secure Sessions

        /// <summary>
        /// Creates a key bundle for the X3DH key exchange protocol
        /// </summary>
        /// <returns>X3DH key bundle</returns>
        public X3DHKeyBundle CreateKeyBundle()
        {
            return _x3DHProtocol.CreateKeyBundleAsync().GetAwaiter().GetResult();
        }

        /// <summary>
        /// Gets the identity key pair for this client
        /// </summary>
        /// <returns>Identity key pair (publicKey, privateKey)</returns>
        public KeyPair GetIdentityKeyPair()
        {
            ThrowIfDisposed();
            return new KeyPair(_identityKeyPair.PublicKey, _identityKeyPair.PrivateKey);
        }

        /// <summary>
        /// Initiates a secure session with a recipient
        /// </summary>
        /// <param name="recipientBundle">Recipient's key bundle</param>
        /// <param name="senderIdentityKeyPair">Sender's identity key pair</param>
        /// <returns>Initial session for secure communication</returns>
        public SenderSessionResult InitiateSenderSession(X3DHPublicBundle recipientBundle, KeyPair senderIdentityKeyPair)
        {
            return _x3DHProtocol.InitiateSessionAsSenderAsync(recipientBundle, senderIdentityKeyPair).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Encrypts a message using the Double Ratchet algorithm
        /// </summary>
        /// <param name="session">Current Double Ratchet session</param>
        /// <param name="message">Message to encrypt</param>
        /// <returns>Updated session and encrypted message</returns>
        public (DoubleRatchetSession? updatedSession, EncryptedMessage? encryptedMessage)
            EncryptWithSession(DoubleRatchetSession session, string message)
        {
            return _doubleRatchetProtocol.EncryptAsync(session, message).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Decrypts a message using the Double Ratchet algorithm
        /// </summary>
        /// <param name="session">Current Double Ratchet session</param>
        /// <param name="encryptedMessage">Encrypted message</param>
        /// <returns>Updated session and decrypted message</returns>
        public (DoubleRatchetSession? updatedSession, string? decryptedMessage)
            DecryptWithSession(DoubleRatchetSession session, EncryptedMessage encryptedMessage)
        {
            return _doubleRatchetProtocol.DecryptAsync(session, encryptedMessage).GetAwaiter().GetResult();
        }

        #endregion

        #region Group Messaging

        /// <summary>
        /// Creates a new group
        /// </summary>
        /// <param name="groupId"></param>
        /// <param name="groupName"></param>
        /// <param name="initialMembers"></param>
        /// <returns>Sender key for this group</returns>
        public GroupSession CreateGroup(string groupId, string groupName, IEnumerable<byte[]>? initialMembers = null)
        {
            ThrowIfDisposed();
            return _groupChatManager.CreateGroupAsync(groupId, groupName, initialMembers).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Sends a group message
        /// </summary>
        /// <param name="groupId">Group identifier</param>
        /// <param name="message">The message to send</param>
        /// <returns>Encrypted group message</returns>
        public EncryptedGroupMessage? SendGroupMessage(string groupId, string message)
        {
            ThrowIfDisposed();
            return _groupChatManager.SendMessageAsync(groupId, message).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Processes a received group message
        /// </summary>
        /// <param name="distribution">Distribution message</param>
        /// <returns>True if the distribution was valid and processed</returns>
        public string? ProcessGroupMessage(EncryptedGroupMessage distribution)
        {
            ThrowIfDisposed();
            return _groupChatManager.ProcessMessageAsync(distribution).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Adds a member to a group
        /// </summary>
        /// <param name="groupId">Group identifier</param>
        /// <param name="memberPublicKey">Member's public key</param>
        /// <returns>True if the member was added successfully</returns>
        public bool AddGroupMember(string groupId, byte[] memberPublicKey)
        {
            ThrowIfDisposed();
            return _groupMemberManager.AddMember(groupId, memberPublicKey);
        }

        /// <summary>
        /// Removes a member from a group
        /// </summary>
        /// <param name="groupId">Group identifier</param>
        /// <param name="memberPublicKey">Member's public key</param>
        /// <returns>True if the member was removed successfully</returns>
        public bool RemoveGroupMember(string groupId, byte[] memberPublicKey)
        {
            ThrowIfDisposed();
            return _groupMemberManager.RemoveMember(groupId, memberPublicKey);
        }

        /// <summary>
        /// Checks if a group exists
        /// </summary>
        /// <param name="groupId">Group identifier</param>
        /// <returns>True if the group exists</returns>
        public async Task<bool> GroupExists(string groupId)
        {
            ThrowIfDisposed();
            return (await _groupChatManager.GetGroupAsync(groupId)).SessionId != null;
        }

        /// <summary>
        /// Deletes a group
        /// </summary>
        /// <param name="groupId">Group identifier</param>
        /// <returns>True if the group was deleted</returns>
        public async Task<bool> DeleteGroup(string groupId)
        {
            ThrowIfDisposed();
            return await _groupChatManager.LeaveGroupAsync(groupId);
        }

        #endregion

        #region Multi-Device Support

        /// <summary>
        /// Adds a linked device
        /// </summary>
        /// <param name="devicePublicKey">Public key of the device to link</param>
        public void AddLinkedDevice(byte[] devicePublicKey)
        {
            ThrowIfDisposed();
            _deviceManager.AddLinkedDevice(devicePublicKey);
        }

        /// <summary>
        /// Removes a linked device
        /// </summary>
        /// <param name="devicePublicKey">Public key of the device to remove</param>
        /// <returns>True if the device was found and removed</returns>
        public bool RemoveLinkedDevice(byte[] devicePublicKey)
        {
            ThrowIfDisposed();
            return _deviceManager.RemoveLinkedDevice(devicePublicKey);
        }

        /// <summary>
        /// Creates sync messages for linked devices
        /// </summary>
        /// <param name="syncData">Data to sync</param>
        /// <returns>Dictionary of encrypted messages for each device</returns>
        public Dictionary<string, EncryptedMessage> CreateSyncMessages(byte[] syncData)
        {
            ThrowIfDisposed();
            return _deviceManager.CreateSyncMessages(syncData);
        }

        /// <summary>
        /// Creates a device link message
        /// </summary>
        /// <param name="newDevicePublicKey">New device's public key</param>
        /// <returns>Encrypted link message</returns>
        public EncryptedMessage CreateDeviceLinkMessage(byte[] newDevicePublicKey)
        {
            return _deviceManager.CreateDeviceLinkMessage(newDevicePublicKey);
        }

        /// <summary>
        /// Gets the number of linked devices
        /// </summary>
        /// <returns>Number of linked devices</returns>
        public int GetLinkedDeviceCount()
        {
            ThrowIfDisposed();
            return _deviceManager.GetLinkedDeviceCount();
        }

        /// <summary>
        /// Checks if a device is already linked
        /// </summary>
        /// <param name="devicePublicKey">Device public key to check</param>
        /// <returns>True if the device is linked</returns>
        public bool IsDeviceLinked(byte[] devicePublicKey)
        {
            ThrowIfDisposed();
            return _deviceManager.IsDeviceLinked(devicePublicKey);
        }

        #endregion

        #region Session Resumption

        // TODO: add session persistence and initialization

        #endregion

        #region Device Revocation

        /// <summary>
        /// Creates a device revocation message for securely removing a device.
        /// </summary>
        /// <param name="revokedDeviceKey">Public key of the device to revoke</param>
        /// <param name="authorityKeyPair">Key pair with authority to revoke devices</param>
        /// <returns>A signed revocation message that can be distributed to other devices</returns>
        public DeviceRevocationMessage CreateDeviceRevocationMessage(byte[] revokedDeviceKey, KeyPair authorityKeyPair)
        {
            ThrowIfDisposed();

            long timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            // Combine device key and timestamp for signing
            byte[] timestampBytes = BitConverter.GetBytes(timestamp);
            byte[] dataToSign = SecureMemory.CreateSecureBuffer((uint)revokedDeviceKey.Length + (uint)timestampBytes.Length);

            revokedDeviceKey.AsSpan().CopyTo(dataToSign.AsSpan(0, revokedDeviceKey.Length));
            timestampBytes.AsSpan().CopyTo(dataToSign.AsSpan(revokedDeviceKey.Length));

            // Sign the combined data
            byte[] signature = MessageSigning.SignMessage(dataToSign, authorityKeyPair.PrivateKey);

            // Create and return the revocation message
            return new DeviceRevocationMessage
            {
                UserIdentityPublicKey = authorityKeyPair.PublicKey,
                RevokedDevicePublicKey = revokedDeviceKey,
                Timestamp = timestamp,
                Signature = signature
            };
        }

        /// <summary>
        /// Revokes a linked device and creates a revocation message
        /// </summary>
        /// <param name="devicePublicKey">Public key of the device to revoke</param>
        /// <param name="ownerKeyPair">The KeyPair of the device holder</param>
        /// <returns>A revocation message that should be distributed to other devices</returns>
        public DeviceRevocationMessage? RevokeLinkedDevice(byte[] devicePublicKey, KeyPair ownerKeyPair)
        {
            ThrowIfDisposed();

            if (_deviceManager.RemoveLinkedDevice(devicePublicKey))
            {
                return CreateDeviceRevocationMessage(devicePublicKey, ownerKeyPair);
            }

            return null;
        }

        #endregion

        #region Mailbox Integration

        /// <summary>
        /// Creates a mailbox manager using this client's identity key pair
        /// </summary>
        /// <param name="transport">The transport implementation to use</param>
        /// <returns>A configured mailbox manager</returns>
        public MailboxManager CreateMailboxManager(IMailboxTransport transport)
        {
            ThrowIfDisposed();
            return new MailboxManager(_identityKeyPair, transport, _doubleRatchetProtocol, _cryptoProvider);
        }

        #endregion

        #region Mailbox Transport Factories

        /// <summary>
        /// Creates an HTTP-based mailbox transport.
        /// </summary>
        /// <param name="serverUrl">The URL of the mailbox server</param>
        /// <returns>An HTTP mailbox transport</returns>
        public IMailboxTransport CreateHttpMailboxTransport(string serverUrl)
        {
            var httpClient = new HttpClient();
            return new HttpMailboxTransport(_cryptoProvider, httpClient, serverUrl);
        }

        /// <summary>
        /// Creates an in-memory mailbox transport for testing or local-only scenarios.
        /// </summary>
        /// <returns>An in-memory mailbox transport</returns>
        public IMailboxTransport CreateInMemoryMailboxTransport()
        {
            return new InMemoryMailboxTransport(_cryptoProvider);
        }

        #endregion

        #region IDisposable Implementation

        /// <summary>
        /// Disposes resources used by this client
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Disposes resources used by this client
        /// </summary>
        /// <param name="disposing">True if called from Dispose(), false if called from finalizer</param>
        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                // Dispose managed resources
                (_groupChatManager as IDisposable)?.Dispose();
                _deviceManager.Dispose();
                (_chatSession as IDisposable)?.Dispose();
            }

            _disposed = true;
        }

        /// <summary>
        /// Finalizer
        /// </summary>
        ~LibEmiddleClient()
        {
            Dispose(false);
        }

        /// <summary>
        /// Throws if this object has been disposed
        /// </summary>
        private void ThrowIfDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(LibEmiddleClient));
        }

        #endregion
    }

    /// <summary>
    /// Extension method to add the ConfigureStorage method to ChatSessionManager
    /// </summary>
    public static class ChatSessionManagerExtensions
    {
        /// <summary>
        /// Configures the storage options for the chat session manager
        /// </summary>
        /// <param name="session">Chat session to configure</param>
        /// <param name="sessionStoragePath">Path to store session data</param>
        /// <param name="sessionEncryptionKey">Optional key to encrypt session data</param>
        /// <param name="enableLogging">Whether to enable detailed logging</param>
        public static void ConfigureStorage(this ChatSession session, string sessionStoragePath, byte[]? sessionEncryptionKey = null, bool enableLogging = false)
        {
            // This extension method assumes these properties would be added to ChatSession
            // It serves as a placeholder until you can update the actual ChatSession class
            LoggingManager.LogInformation(nameof(ChatSession), $"Configuring storage path: {sessionStoragePath}");
        }
    }
}