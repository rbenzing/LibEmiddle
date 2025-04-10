using System.Collections.Concurrent;
using System.Security.Cryptography;
using E2EELibrary.Core;
using E2EELibrary.Models;
using E2EELibrary.KeyExchange;
using E2EELibrary.Encryption;
using E2EELibrary.KeyManagement;

namespace E2EELibrary.Messaging
{
    /// <summary>
    /// Manages chat sessions with advanced persistence, recovery, and security features
    /// </summary>
    public class ChatSessionManager : IDisposable
    {
        // Active sessions in memory
        private readonly ConcurrentDictionary<string, ChatSession> _activeSessions =
            new ConcurrentDictionary<string, ChatSession>();

        // Identity key pair for the local user
        private readonly (byte[] publicKey, byte[] privateKey) _identityKeyPair;

        // Session persistence configuration
        private readonly string _sessionStoragePath;
        private readonly byte[]? _sessionEncryptionKey;

        // Logging and diagnostics
        private readonly bool _enableLogging;

        /// <summary>
        /// Creates a new ChatSessionManager
        /// </summary>
        /// <param name="identityKeyPair">Identity key pair for the local user</param>
        /// <param name="sessionStoragePath">Path to store persistent sessions</param>
        /// <param name="sessionEncryptionKey">Optional encryption key for session storage</param>
        /// <param name="enableLogging">Enable detailed logging</param>
        public ChatSessionManager(
            (byte[] publicKey, byte[] privateKey) identityKeyPair,
            string? sessionStoragePath = null,
            byte[]? sessionEncryptionKey = null,
            bool enableLogging = false)
        {
            _identityKeyPair = identityKeyPair;
            _sessionStoragePath = sessionStoragePath ??
                Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "E2EELibrary",
                    "Sessions"
                );

            // Ensure directory exists
            Directory.CreateDirectory(_sessionStoragePath);

            _sessionEncryptionKey = sessionEncryptionKey;
            _enableLogging = enableLogging;
        }

        /// <summary>
        /// Gets or creates a chat session with a recipient
        /// </summary>
        /// <param name="recipientPublicKey">Recipient's public key</param>
        /// <param name="recipientBundle">Optional recipient's X3DH bundle</param>
        /// <returns>Chat session</returns>
        public ChatSession GetOrCreateSession(
            byte[] recipientPublicKey,
            X3DHPublicBundle? recipientBundle = null)
        {
            string sessionKey = Convert.ToBase64String(recipientPublicKey);

            // Try to retrieve from active sessions first
            if (_activeSessions.TryGetValue(sessionKey, out var existingSession))
            {
                if (existingSession.IsValid())
                {
                    LogMessage($"Returning existing valid session for {sessionKey}");
                    return existingSession;
                }
            }

            // Try to load from persistent storage
            ChatSession? persistedSession = TryLoadPersistedSession(sessionKey);
            if (persistedSession != null && persistedSession.IsValid())
            {
                LogMessage($"Loaded persisted session for {sessionKey}");
                _activeSessions[sessionKey] = persistedSession;
                return persistedSession;
            }

            // Ensure we have a bundle to establish a new session
            if (recipientBundle == null)
            {
                throw new ArgumentException(
                    "Recipient bundle is required to create a new session",
                    nameof(recipientBundle));
            }

            // Create new session if no valid existing session found
            LogMessage($"Creating new session for {sessionKey}");
            var newSession = CreateNewSession(recipientPublicKey, recipientBundle);

            // Store in active sessions and persist
            _activeSessions[sessionKey] = newSession;
            PersistSession(newSession);

            return newSession;
        }

        /// <summary>
        /// Creates a new chat session with a recipient
        /// </summary>
        /// <param name="recipientPublicKey">Recipient's public key</param>
        /// <param name="recipientBundle">Recipient's X3DH bundle</param>
        /// <returns>New chat session</returns>
        private ChatSession CreateNewSession(
            byte[] recipientPublicKey,
            X3DHPublicBundle recipientBundle)
        {
            // Validate bundle
            if (recipientBundle == null)
                throw new ArgumentNullException(nameof(recipientBundle));

            if (recipientBundle.IdentityKey == null)
                throw new ArgumentException("Recipient bundle has null identity key", nameof(recipientBundle));

            // Use existing X3DH and Double Ratchet methods to establish session
            var x3dhSession = X3DHExchange.InitiateX3DHSession(
                recipientBundle,
                _identityKeyPair,
                out var usedOneTimePreKeyId
            );

            if (x3dhSession == null)
                throw new CryptographicException("Failed to establish X3DH session");

            // Initialize Double Ratchet with the shared secret from X3DH
            var (rootKey, chainKey) = DoubleRatchetExchange.InitializeDoubleRatchet(
                x3dhSession.RootKey
            );

            // Generate DH key pair for ratchet
            var dhKeyPair = KeyGenerator.GenerateX25519KeyPair();

            // Create a session with a unique ID
            string sessionId = $"session-{Guid.NewGuid()}";

            // Create the Double Ratchet session
            var doubleRatchetSession = new DoubleRatchetSession(
                dhRatchetKeyPair: dhKeyPair,
                remoteDHRatchetKey: recipientBundle.SignedPreKey ?? recipientBundle.IdentityKey,
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumber: 0,
                sessionId: sessionId
            );

            // Create and return the chat session
            return new ChatSession(
                doubleRatchetSession,
                recipientPublicKey,
                _identityKeyPair.publicKey
            );
        }

        /// <summary>
        /// Attempts to load a persisted session
        /// </summary>
        /// <param name="sessionKey">Session key (Base64 recipient public key)</param>
        /// <returns>Loaded chat session or null if not found</returns>
        private ChatSession? TryLoadPersistedSession(string sessionKey)
        {
            try
            {
                string sessionFilePath = Path.Combine(
                    _sessionStoragePath,
                    $"{sessionKey}_session.bin"
                );

                if (!File.Exists(sessionFilePath))
                    return null;

                // Use SessionPersistence to load the session
                byte[] serializedSession = File.ReadAllBytes(sessionFilePath);
                var loadedDoubleRatchetSession = SessionPersistence.DeserializeSession(
                    serializedSession,
                    _sessionEncryptionKey
                );

                if (loadedDoubleRatchetSession == null)
                    return null;

                // Create and return the chat session
                return new ChatSession(
                    loadedDoubleRatchetSession,
                    Convert.FromBase64String(sessionKey),
                    _identityKeyPair.publicKey
                );
            }
            catch (Exception ex)
            {
                LogMessage($"Error loading persisted session: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Persists a session to storage
        /// </summary>
        /// <param name="session">Session to persist</param>
        private void PersistSession(ChatSession session)
        {
            try
            {
                string sessionKey = Convert.ToBase64String(session.RemotePublicKey);
                string sessionFilePath = Path.Combine(
                    _sessionStoragePath,
                    $"{sessionKey}_session.bin"
                );

                // Serialize the Double Ratchet session
                byte[] serializedSession = SessionPersistence.SerializeSession(
                    session.GetCryptoSession(),
                    _sessionEncryptionKey
                );

                File.WriteAllBytes(sessionFilePath, serializedSession);
                LogMessage($"Persisted session for {sessionKey}");
            }
            catch (Exception ex)
            {
                LogMessage($"Error persisting session: {ex.Message}");
            }
        }

        /// <summary>
        /// Closes and removes a specific session
        /// </summary>
        /// <param name="recipientPublicKey">Recipient's public key</param>
        public void CloseSession(byte[] recipientPublicKey)
        {
            string sessionKey = Convert.ToBase64String(recipientPublicKey);

            if (_activeSessions.TryRemove(sessionKey, out var session))
            {
                // Dispose of session resources
                session.Dispose();

                // Remove persisted session file
                try
                {
                    string sessionFilePath = Path.Combine(
                        _sessionStoragePath,
                        $"{sessionKey}_session.bin"
                    );

                    if (File.Exists(sessionFilePath))
                    {
                        KeyStorage.SecureDeleteFile(sessionFilePath);
                    }
                }
                catch (Exception ex)
                {
                    LogMessage($"Error removing persisted session: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// Gets all active session keys
        /// </summary>
        /// <returns>Collection of session keys (base64 encoded recipient public keys)</returns>
        public IEnumerable<string> GetActiveSessions()
        {
            return _activeSessions.Keys.ToArray();
        }

        /// <summary>
        /// Logs messages if logging is enabled
        /// </summary>
        /// <param name="message">Message to log</param>
        private void LogMessage(string message)
        {
            if (_enableLogging)
            {
                LoggingManager.LogInformation(nameof(ChatSessionManager), message);
            }
        }

        /// <summary>
        /// Disposes of all active sessions
        /// </summary>
        public void Dispose()
        {
            foreach (var session in _activeSessions.Values)
            {
                session.Dispose();
            }
            _activeSessions.Clear();
        }
    }
}