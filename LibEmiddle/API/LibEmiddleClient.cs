using LibEmiddle.Abstractions;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.KeyExchange;
using LibEmiddle.Messaging.Chat;
using LibEmiddle.Messaging.Group;
using LibEmiddle.Messaging.Transport;
using LibEmiddle.Models;
using LibEmiddle.MultiDevice;

namespace LibEmiddle.API
{
    /// <summary>
    /// Main entry point for the E2EE library, providing a simplified API for common operations.
    /// This class serves as a facade for the various components of the library.
    /// </summary>
    public class LibEmiddleClient : IDisposable
    {
        private readonly GroupChatManager _groupChatManager;
        private readonly DeviceManager _deviceManager;
        private readonly ChatSessionManager _chatSessionManager;
        private readonly (byte[] publicKey, byte[] privateKey) _identityKeyPair;
        private bool _disposed;

        /// <summary>
        /// Creates a new E2EE client with X25519 keypair
        /// </summary>
        public LibEmiddleClient()
        {
            // Generate an X25519 identity key pair for this client
            _identityKeyPair = KeyGenerator.GenerateX25519KeyPair();
            _groupChatManager = new GroupChatManager(_identityKeyPair);
            _deviceManager = new DeviceManager(_identityKeyPair);
            _chatSessionManager = new ChatSessionManager(_identityKeyPair);
        }

        /// <summary>
        /// Creates a new E2EE client with an existing identity key pair
        /// </summary>
        /// <param name="identityKeyPair">Identity key pair to use</param>
        public LibEmiddleClient((byte[] publicKey, byte[] privateKey) identityKeyPair)
        {
            _identityKeyPair = identityKeyPair;
            _groupChatManager = new GroupChatManager(_identityKeyPair);
            _deviceManager = new DeviceManager(_identityKeyPair);
            _chatSessionManager = new ChatSessionManager(_identityKeyPair);
        }

        #region Key Management

        /// <summary>
        /// Generates an AES-GCM 32-bit sender key
        /// </summary>
        /// <returns>Random sender key suitable for group encryption</returns>
        public static byte[] GenerateSenderKey()
        {
            return KeyGenerator.GenerateSenderKey();
        }

        /// <summary>
        /// Generates an Ed25519 key pair for digital signatures
        /// </summary>
        /// <returns>Tuple containing (publicKey, privateKey)</returns>
        public static (byte[] publicKey, byte[] privateKey) GenerateSignatureKeyPair()
        {
            return KeyGenerator.GenerateEd25519KeyPair();
        }

        /// <summary>
        /// Generates an X25519 key pair for secure key exchange
        /// </summary>
        /// <returns>Tuple containing (publicKey, privateKey)</returns>
        public static (byte[] publicKey, byte[] privateKey) GenerateKeyExchangeKeyPair()
        {
            return KeyGenerator.GenerateX25519KeyPair();
        }

        /// <summary>
        /// Stores a key to a file with optional password protection
        /// </summary>
        /// <param name="key">Key to store</param>
        /// <param name="filePath">Path to store the key</param>
        /// <param name="password">Optional password for encryption</param>
        public static void StoreKeyToFile(byte[] key, string filePath, string? password = null)
        {
            KeyStorage.StoreKeyToFile(key, filePath, password);
        }

        /// <summary>
        /// Loads a key from a file
        /// </summary>
        /// <param name="filePath">Path to the key file</param>
        /// <param name="password">Password if the key is encrypted</param>
        /// <returns>The loaded key</returns>
        public static byte[] LoadKeyFromFile(string filePath, string? password = null)
        {
            return KeyStorage.LoadKeyFromFile(filePath, password);
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
        /// <param name="privateKey">Private key for signing</param>
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
            return MessageSigning.SignMessage(message, _identityKeyPair.privateKey);
        }

        /// <summary>
        /// Signs a text message using this client's identity key
        /// </summary>
        /// <param name="message">Text message to sign</param>
        /// <returns>Signature as a Base64 string</returns>
        public string SignTextWithIdentityKey(string message)
        {
            ThrowIfDisposed();
            return MessageSigning.SignTextMessage(message, _identityKeyPair.privateKey);
        }

        #endregion

        #region Chat Session Management

        /// <summary>
        /// Gets or creates a chat session with a recipient
        /// </summary>
        /// <param name="recipientPublicKey">Recipient's public key</param>
        /// <param name="recipientBundle">Optional recipient's key bundle, required for new sessions</param>
        /// <returns>Chat session</returns>
        /// <exception cref="ArgumentNullException">Thrown when recipientPublicKey is null</exception>
        public ChatSession GetOrCreateChatSession(
            byte[] recipientPublicKey,
            X3DHPublicBundle? recipientBundle = null)
        {
            ThrowIfDisposed();

            if (recipientPublicKey == null)
                throw new ArgumentNullException(nameof(recipientPublicKey));

            return _chatSessionManager.GetOrCreateSession(recipientPublicKey, recipientBundle);
        }

        /// <summary>
        /// Closes a chat session with a recipient
        /// </summary>
        /// <param name="recipientPublicKey">Recipient's public key</param>
        /// <exception cref="ArgumentNullException">Thrown when recipientPublicKey is null</exception>
        public void CloseChatSession(byte[] recipientPublicKey)
        {
            ThrowIfDisposed();

            if (recipientPublicKey == null)
                throw new ArgumentNullException(nameof(recipientPublicKey));

            _chatSessionManager.CloseSession(recipientPublicKey);
        }

        /// <summary>
        /// Gets all active chat sessions
        /// </summary>
        /// <returns>Collection of active session keys (Base64 encoded recipient public keys)</returns>
        public IEnumerable<string> GetActiveChatSessions()
        {
            ThrowIfDisposed();
            return _chatSessionManager.GetActiveSessions();
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

            _chatSessionManager.ConfigureStorage(sessionStoragePath, sessionEncryptionKey, enableLogging);
        }

        #endregion

        #region Key Exchange & Secure Sessions

        /// <summary>
        /// Creates a key bundle for the X3DH key exchange protocol
        /// </summary>
        /// <returns>X3DH key bundle</returns>
        public static X3DHKeyBundle CreateKeyBundle()
        {
            return X3DHExchange.CreateX3DHKeyBundle();
        }

        /// <summary>
        /// Gets the identity key pair for this client
        /// </summary>
        /// <returns>Identity key pair (publicKey, privateKey)</returns>
        public (byte[] publicKey, byte[] privateKey) GetIdentityKeyPair()
        {
            ThrowIfDisposed();
            return (_identityKeyPair.publicKey, _identityKeyPair.privateKey);
        }

        /// <summary>
        /// Creates an X3DH key bundle for this client
        /// </summary>
        /// <returns>X3DH key bundle</returns>
        public X3DHPublicBundle CreateX3DHPublicBundle()
        {
            ThrowIfDisposed();

            var bundle = X3DHExchange.CreateX3DHKeyBundle(
                (_identityKeyPair.publicKey, _identityKeyPair.privateKey)
            );

            return bundle.ToPublicBundle();
        }

        /// <summary>
        /// Initiates a secure session with a recipient
        /// </summary>
        /// <param name="recipientBundle">Recipient's key bundle</param>
        /// <param name="senderIdentityKeyPair">Sender's identity key pair</param>
        /// <returns>Initial session for secure communication</returns>
        public static X3DHSession InitiateSession(X3DHPublicBundle recipientBundle,
                                          (byte[] publicKey, byte[] privateKey) senderIdentityKeyPair)
        {
            return X3DHExchange.InitiateX3DHSession(recipientBundle, senderIdentityKeyPair, out var usedOneTimePreKeyId);
        }

        /// <summary>
        /// Encrypts a message using the Double Ratchet algorithm
        /// </summary>
        /// <param name="session">Current Double Ratchet session</param>
        /// <param name="message">Message to encrypt</param>
        /// <returns>Updated session and encrypted message</returns>
        public static (DoubleRatchetSession updatedSession, EncryptedMessage encryptedMessage)
            EncryptWithSession(DoubleRatchetSession session, string message)
        {
            return DoubleRatchet.DoubleRatchetEncrypt(session, message);
        }

        /// <summary>
        /// Decrypts a message using the Double Ratchet algorithm
        /// </summary>
        /// <param name="session">Current Double Ratchet session</param>
        /// <param name="encryptedMessage">Encrypted message</param>
        /// <returns>Updated session and decrypted message</returns>
        public static (DoubleRatchetSession? updatedSession, string? decryptedMessage)
            DecryptWithSession(DoubleRatchetSession session, EncryptedMessage encryptedMessage)
        {
            return DoubleRatchet.DoubleRatchetDecrypt(session, encryptedMessage);
        }

        #endregion

        #region Group Messaging

        /// <summary>
        /// Creates a new group
        /// </summary>
        /// <param name="groupId">Group identifier</param>
        /// <returns>Sender key for this group</returns>
        public byte[] CreateGroup(string groupId)
        {
            ThrowIfDisposed();
            return _groupChatManager.CreateGroup(groupId);
        }

        /// <summary>
        /// Creates a distribution message for sharing the sender key
        /// </summary>
        /// <param name="groupId">Group identifier</param>
        /// <returns>Distribution message to share with group members</returns>
        public SenderKeyDistributionMessage CreateGroupDistributionMessage(string groupId)
        {
            ThrowIfDisposed();
            return _groupChatManager.CreateDistributionMessage(groupId);
        }

        /// <summary>
        /// Processes a received sender key distribution message
        /// </summary>
        /// <param name="distribution">Distribution message</param>
        /// <returns>True if the distribution was valid and processed</returns>
        public bool ProcessGroupDistribution(SenderKeyDistributionMessage distribution)
        {
            ThrowIfDisposed();
            return _groupChatManager.ProcessSenderKeyDistribution(distribution);
        }

        /// <summary>
        /// Encrypts a message for a group
        /// </summary>
        /// <param name="groupId">Group identifier</param>
        /// <param name="message">Message to encrypt</param>
        /// <returns>Encrypted group message</returns>
        public EncryptedGroupMessage EncryptGroupMessage(string groupId, string message)
        {
            ThrowIfDisposed();
            return _groupChatManager.EncryptGroupMessage(groupId, message);
        }

        /// <summary>
        /// Decrypts a group message
        /// </summary>
        /// <param name="encryptedMessage">Encrypted group message</param>
        /// <returns>Decrypted message if successful, null otherwise</returns>
        public string? DecryptGroupMessage(EncryptedGroupMessage encryptedMessage)
        {
            ThrowIfDisposed();
            return _groupChatManager.DecryptGroupMessage(encryptedMessage);
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
            return _groupChatManager.AddGroupMember(groupId, memberPublicKey);
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
            return _groupChatManager.RemoveGroupMember(groupId, memberPublicKey);
        }

        /// <summary>
        /// Rotates the group key for enhanced security
        /// </summary>
        /// <param name="groupId">Group identifier</param>
        /// <returns>New sender key</returns>
        public byte[] RotateGroupKey(string groupId)
        {
            ThrowIfDisposed();
            return _groupChatManager.RotateGroupKey(groupId);
        }

        /// <summary>
        /// Checks if a group exists
        /// </summary>
        /// <param name="groupId">Group identifier</param>
        /// <returns>True if the group exists</returns>
        public bool GroupExists(string groupId)
        {
            ThrowIfDisposed();
            return _groupChatManager.GroupExists(groupId);
        }

        /// <summary>
        /// Deletes a group
        /// </summary>
        /// <param name="groupId">Group identifier</param>
        /// <returns>True if the group was deleted</returns>
        public bool DeleteGroup(string groupId)
        {
            ThrowIfDisposed();
            return _groupChatManager.DeleteGroup(groupId);
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
        /// <param name="mainDeviceKeyPair">Tuple of public and private keys</param>
        /// <param name="newDevicePublicKey">New device's public key</param>
        /// <returns>Encrypted link message</returns>
        public static EncryptedMessage CreateDeviceLinkMessage((byte[] publicKey, byte[] privateKey) mainDeviceKeyPair, byte[] newDevicePublicKey)
        {
            return DeviceLinking.CreateDeviceLinkMessage(mainDeviceKeyPair, newDevicePublicKey);
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

        /// <summary>
        /// Processes a device revocation message
        /// </summary>
        /// <param name="revocationMessage">The revocation message</param>
        /// <param name="trustedPublicKey">Trusted public key for verification</param>
        /// <returns>True if the message was valid and processed</returns>
        public bool ProcessDeviceRevocationMessage(DeviceRevocationMessage revocationMessage, byte[] trustedPublicKey)
        {
            ThrowIfDisposed();
            return _deviceManager.ProcessRevocationMessage(revocationMessage, trustedPublicKey);
        }

        #endregion

        #region Session Resumption

        /// <summary>
        /// Resumes a Double Ratchet session after an interruption or failure.
        /// </summary>
        /// <param name="session">The last known good session</param>
        /// <param name="lastProcessedMessageId">The ID of the last successfully processed message, if any</param>
        /// <returns>A session ready for continued communication, or null if resumption isn't possible</returns>
        public static DoubleRatchetSession ResumeDoubleRatchetSession(DoubleRatchetSession session, Guid? lastProcessedMessageId = null)
        {
            return DoubleRatchetExchange.ResumeSession(session, lastProcessedMessageId);
        }

        /// <summary>
        /// Serializes a Double Ratchet session for storage.
        /// </summary>
        /// <param name="session">The session to serialize</param>
        /// <param name="encryptionKey">Optional key to encrypt the serialized session</param>
        /// <returns>Serialized (and optionally encrypted) session data</returns>
        public static byte[] SerializeDoubleRatchetSession(DoubleRatchetSession session, byte[]? encryptionKey = null)
        {
            return SessionPersistence.SerializeSession(session, encryptionKey);
        }

        /// <summary>
        /// Deserializes a Double Ratchet session from storage.
        /// </summary>
        /// <param name="serializedData">The serialized session data</param>
        /// <param name="decryptionKey">Optional key to decrypt the serialized session</param>
        /// <returns>Deserialized Double Ratchet session</returns>
        public static DoubleRatchetSession DeserializeDoubleRatchetSession(byte[] serializedData, byte[]? decryptionKey = null)
        {
            return SessionPersistence.DeserializeSession(serializedData, decryptionKey);
        }

        #endregion

        #region Device Revocation

        /// <summary>
        /// Creates a device revocation message for securely removing a device.
        /// </summary>
        /// <param name="revokedDeviceKey">Public key of the device to revoke</param>
        /// <param name="authorityKeyPair">Key pair with authority to revoke devices</param>
        /// <returns>A signed revocation message that can be distributed to other devices</returns>
        public static DeviceRevocationMessage CreateDeviceRevocationMessage(byte[] revokedDeviceKey, (byte[] publicKey, byte[] privateKey) authorityKeyPair)
        {
            long timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            // Combine device key and timestamp for signing
            byte[] timestampBytes = BitConverter.GetBytes(timestamp);
            byte[] dataToSign = Sodium.GenerateRandomBytes(revokedDeviceKey.Length + timestampBytes.Length);

            revokedDeviceKey.AsSpan().CopyTo(dataToSign.AsSpan(0, revokedDeviceKey.Length));
            timestampBytes.AsSpan().CopyTo(dataToSign.AsSpan(revokedDeviceKey.Length));

            // Sign the combined data
            byte[] signature = MessageSigning.SignMessage(dataToSign, authorityKeyPair.privateKey);

            // Create and return the revocation message
            return new DeviceRevocationMessage
            {
                RevokedDeviceKey = revokedDeviceKey,
                RevocationTimestamp = timestamp,
                Signature = signature
            };
        }

        /// <summary>
        /// Validates a device revocation message.
        /// </summary>
        /// <param name="revocationMessage">The revocation message to validate</param>
        /// <param name="trustedPublicKey">The trusted public key for verification</param>
        /// <returns>True if the message is valid and properly signed</returns>
        public static bool ValidateDeviceRevocationMessage(DeviceRevocationMessage revocationMessage, byte[] trustedPublicKey)
        {
            return revocationMessage.Validate(trustedPublicKey);
        }

        /// <summary>
        /// Revokes a linked device and creates a revocation message
        /// </summary>
        /// <param name="devicePublicKey">Public key of the device to revoke</param>
        /// <returns>A revocation message that should be distributed to other devices</returns>
        public DeviceRevocationMessage RevokeLinkedDevice(byte[] devicePublicKey)
        {
            ThrowIfDisposed();
            return _deviceManager.RevokeLinkedDevice(devicePublicKey);
        }

        #endregion

        #region Mailbox Integration

        /// <summary>
        /// Creates a mailbox manager for handling asynchronous message delivery.
        /// </summary>
        /// <param name="identityKeyPair">The user's identity key pair</param>
        /// <param name="transport">The transport implementation to use</param>
        /// <returns>A configured mailbox manager</returns>
        public static MailboxManager CreateMailboxManager((byte[] publicKey, byte[] privateKey) identityKeyPair, IMailboxTransport transport)
        {
            return new MailboxManager(identityKeyPair, transport);
        }

        /// <summary>
        /// Creates a mailbox manager using this client's identity key pair
        /// </summary>
        /// <param name="transport">The transport implementation to use</param>
        /// <returns>A configured mailbox manager</returns>
        public MailboxManager CreateMailboxManager(IMailboxTransport transport)
        {
            ThrowIfDisposed();
            return new MailboxManager(_identityKeyPair, transport);
        }

        #endregion

        #region Mailbox Transport Factories

        /// <summary>
        /// Creates an HTTP-based mailbox transport.
        /// </summary>
        /// <param name="serverUrl">The URL of the mailbox server</param>
        /// <returns>An HTTP mailbox transport</returns>
        public static IMailboxTransport CreateHttpMailboxTransport(string serverUrl)
        {
            return new HttpMailboxTransport(serverUrl);
        }

        /// <summary>
        /// Creates an in-memory mailbox transport for testing or local-only scenarios.
        /// </summary>
        /// <returns>An in-memory mailbox transport</returns>
        public static IMailboxTransport CreateInMemoryMailboxTransport()
        {
            return new InMemoryMailboxTransport();
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
                (_chatSessionManager as IDisposable)?.Dispose();
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
        /// <param name="manager">Chat session manager to configure</param>
        /// <param name="sessionStoragePath">Path to store session data</param>
        /// <param name="sessionEncryptionKey">Optional key to encrypt session data</param>
        /// <param name="enableLogging">Whether to enable detailed logging</param>
        public static void ConfigureStorage(this ChatSessionManager manager, string sessionStoragePath, byte[]? sessionEncryptionKey = null, bool enableLogging = false)
        {
            // This extension method assumes these properties would be added to ChatSessionManager
            // It serves as a placeholder until you can update the actual ChatSessionManager class
            LoggingManager.LogInformation(nameof(ChatSessionManager), $"Configuring storage path: {sessionStoragePath}");
        }
    }
}