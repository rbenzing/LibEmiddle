using System.Collections.Concurrent;
using System.Security.Cryptography;
using LibEmiddle.Core;
using LibEmiddle.KeyExchange;
using LibEmiddle.Crypto;
using LibEmiddle.Models;
using LibEmiddle.Domain;
using Microsoft.Extensions.Logging;

namespace LibEmiddle.Messaging.Chat
{
    /// <summary>
    /// Manages chat sessions with advanced persistence, recovery, and security features
    /// </summary>
    public class ChatSessionManager : IDisposable
    {
        // Active sessions in memory (Key: Base64 Public Key)
        private readonly ConcurrentDictionary<string, ChatSession> _activeSessions = new();

        // Identity key pair for the local user (Ed25519)
        private readonly KeyPair _identityKeyPair;

        // Session persistence configuration
        private readonly string _sessionStoragePath;
        private readonly byte[]? _sessionEncryptionKey; // 32-byte AES key

        // Logging and diagnostics
        private readonly bool _enableLogging;
        private bool _disposed = false;

        /// <summary>
        /// Creates a new ChatSessionManager.
        /// </summary>
        /// <param name="identityKeyPair">Identity key pair (Ed25519) for the local user.</param>
        /// <param name="sessionStoragePath">Optional path to store persistent sessions. Defaults to LocalApplicationData.</param>
        /// <param name="sessionEncryptionKey">Optional 32-byte AES key for encrypting session storage.</param>
        /// <param name="enableLogging">Enable detailed logging via LoggingManager.</param>
        public ChatSessionManager(
            KeyPair identityKeyPair,
            string? sessionStoragePath = null,
            byte[]? sessionEncryptionKey = null,
            bool enableLogging = false)
        {
            _identityKeyPair = identityKeyPair;
            // Validate identity key pair format?
            if (_identityKeyPair.PublicKey == null || _identityKeyPair.PrivateKey == null /* || Add size checks */)
                throw new ArgumentException("Provided identity key pair is invalid.", nameof(identityKeyPair));

            if (sessionEncryptionKey != null && sessionEncryptionKey.Length != Constants.AES_KEY_SIZE)
                throw new ArgumentException($"Session encryption key must be {Constants.AES_KEY_SIZE} bytes.", nameof(sessionEncryptionKey));

            _sessionStoragePath = sessionStoragePath ?? Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "LibEmiddle", // Consider making configurable
                    "Sessions"
                );

            try
            {
                // Ensure directory exists
                Directory.CreateDirectory(_sessionStoragePath);
            }
            catch (Exception ex)
            {
                // Log error - persistence might fail
                LogMessage($"CRITICAL: Failed to create session storage directory '{_sessionStoragePath}'. Persistence disabled. Error: {ex.Message}", LogLevel.Error);
                _sessionStoragePath = ""; // Disable persistence if directory fails
            }


            _sessionEncryptionKey = sessionEncryptionKey;
            _enableLogging = enableLogging;

            LogMessage("ChatSessionManager initialized.", LogLevel.Information);
            if (string.IsNullOrEmpty(_sessionStoragePath))
                LogMessage("Session persistence is disabled (storage path inaccessible).", LogLevel.Warning);
            else if (_sessionEncryptionKey == null)
                LogMessage("Session persistence enabled WITHOUT encryption (SECURITY RISK).", LogLevel.Warning);
            else
                LogMessage("Session persistence enabled with encryption.", LogLevel.Information);

        }

        /// <summary>
        /// Gets an existing chat session or initiates a new one with a recipient.
        /// If a new session is initiated, the necessary X3DH initial message data is also returned.
        /// </summary>
        /// <param name="recipientIdentityPublicKey">Recipient's public identity key (Ed25519).</param>
        /// <param name="recipientBundle">Recipient's public X3DH bundle (REQUIRED only if initiating a new session).</param>
        /// <returns>A tuple containing the ChatSession and optional InitialMessageData (only non-null if a new session was created).</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentException">If keys are invalid or bundle is missing when needed.</exception>
        /// <exception cref="CryptographicException">If session initiation fails.</exception>
        /// <exception cref="InvalidOperationException">If manager is disposed.</exception>
        public (ChatSession session, InitialMessageData? initialDataToSend) GetOrCreateSession(
            byte[] recipientIdentityPublicKey,
            X3DHPublicBundle? recipientBundle = null)
        {
            if (_disposed) throw new InvalidOperationException("ChatSessionManager has been disposed.");
            ArgumentNullException.ThrowIfNull(recipientIdentityPublicKey, nameof(recipientIdentityPublicKey));
            // Basic validation of recipient key
            if (!KeyValidation.ValidateEd25519PublicKey(recipientIdentityPublicKey)) // Assuming validation exists
                throw new ArgumentException("Invalid recipient public identity key.", nameof(recipientIdentityPublicKey));


            string sessionKey = Convert.ToBase64String(recipientIdentityPublicKey); // Use IK as identifier

            // 1. Try active sessions
            if (_activeSessions.TryGetValue(sessionKey, out var existingSession) && existingSession.IsValid())
            {
                LogMessage($"Returning active session for {sessionKey}", LogLevel.Debug);
                return (existingSession, null); // No initial data needed for existing session
            }

            // 2. Try persisted sessions (only if path is valid)
            if (!string.IsNullOrEmpty(_sessionStoragePath))
            {
                ChatSession? persistedSession = TryLoadPersistedSession(sessionKey, recipientIdentityPublicKey);
                if (persistedSession != null && persistedSession.IsValid())
                {
                    LogMessage($"Loaded persisted session for {sessionKey}", LogLevel.Information);
                    // AddOrUpdate is safer in concurrent scenarios
                    _activeSessions.AddOrUpdate(sessionKey, persistedSession, (key, existing) => {
                        existing?.Dispose(); // Dispose old one if replaced
                        return persistedSession;
                    });
                    return (persistedSession, null); // No initial data needed
                }
            }

            // 3. Need to create a new session
            LogMessage($"No valid session found for {sessionKey}. Attempting to create new session.", LogLevel.Information);
            if (recipientBundle == null)
            {
                throw new ArgumentException("Recipient's X3DH bundle is required to create a new session.", nameof(recipientBundle));
            }

            // Ensure the recipient bundle's identity key matches the provided key
            if (recipientBundle.IdentityKey == null || !recipientBundle.IdentityKey.SequenceEqual(recipientIdentityPublicKey))
            {
                throw new ArgumentException("Recipient bundle identity key does not match provided recipient public key.", nameof(recipientBundle));
            }

            // Create new session (this performs X3DH and initializes Double Ratchet)
            var (newSession, initialData) = CreateNewSession(recipientIdentityPublicKey, recipientBundle);

            // Store in active sessions and persist
            _activeSessions.AddOrUpdate(sessionKey, newSession, (key, existing) => {
                existing?.Dispose(); // Dispose old one if replaced due to race condition
                return newSession;
            });

            if (!string.IsNullOrEmpty(_sessionStoragePath))
            {
                PersistSession(newSession); // Persist the newly created session
            }

            LogMessage($"Successfully created new session for {sessionKey}", LogLevel.Information);
            return (newSession, initialData); // Return session AND initial data
        }

        /// <summary>
        /// Creates a new chat session by performing X3DH and initializing Double Ratchet.
        /// Should only be called by the initiator (sender).
        /// </summary>
        /// <param name="recipientIdentityPublicKey">Recipient's public identity key (Ed25519).</param>
        /// <param name="recipientBundle">Recipient's public X3DH bundle.</param>
        /// <returns>A tuple containing the new ChatSession and the InitialMessageData to be sent.</returns>
        /// <exception cref="CryptographicException">If session creation fails.</exception>
        /// <exception cref="InvalidOperationException">If recipient bundle is invalid.</exception>
        private (ChatSession session, InitialMessageData initialData) CreateNewSession(
            byte[] recipientIdentityPublicKey, // Ed25519
            X3DHPublicBundle recipientBundle)
        {
            // Input validation happens in GetOrCreateSession

            byte[]? sharedKey = null; // To ensure clearing in finally

            try
            {
                // 1. Perform X3DH Sender Initiation
                // This returns the shared key (SK) and the data Bob needs (Alice's IK, EK, used IDs)
                LogMessage($"Performing X3DH initiation with peer {Convert.ToBase64String(recipientIdentityPublicKey)}...", LogLevel.Debug);
                SenderSessionResult x3dhResult = X3DHExchange.InitiateSessionAsSender(
                    recipientBundle,
                    _identityKeyPair // Our long-term identity key pair
                );

                // Assign shared key locally for clearing, ensure it's valid
                sharedKey = x3dhResult?.SharedKey;
                if (sharedKey == null || sharedKey.Length != Constants.AES_KEY_SIZE || x3dhResult == null || x3dhResult.MessageDataToSend == null)
                {
                    throw new CryptographicException("X3DH initiation failed to produce required session key or initial message data.");
                }
                LogMessage($"X3DH initiation successful, derived SK.", LogLevel.Debug);


                // 2. Initialize Double Ratchet Sender State using the SK from X3DH
                // Requires SK, our identity key pair (for DH calc?), and Bob's public key used for the first DR DH step (his SPK).
                string sessionId = $"session-{Guid.NewGuid()}"; // Generate unique ID for this DR session instance
                LogMessage($"Initializing Double Ratchet session {sessionId} as sender...", LogLevel.Debug);
                DoubleRatchetSession initialDrSession = DoubleRatchet.InitializeSessionAsSender(
                    sharedKeyFromX3DH: sharedKey,
                    // Pass our identity keypair - Check if DR init *needs* IK or just generates its own ratchet key pair.
                    // If it only generates internally, this argument might be removable from InitializeSessionAsSender signature.
                    senderIdentityKeyPair: _identityKeyPair,
                    recipientSignedPreKeyPublic: recipientBundle.SignedPreKey ?? throw new InvalidOperationException("Recipient bundle missing SignedPreKey required for DR initialization."), // Bob's SPK is initial DHr
                    sessionId: sessionId
                );
                LogMessage($"Double Ratchet session {sessionId} initialized.", LogLevel.Debug);


                // --- The intermediate X3DHSession class is NOT needed ---


                // 3. Create the ChatSession wrapper using the initialized DoubleRatchetSession
                var chatSession = new ChatSession(
                    initialDrSession,
                    recipientIdentityPublicKey, // Store Bob's IK (Remote Key)
                    _identityKeyPair.PublicKey  // Store our own IK (Local Key)
                );

                // 4. Return the ChatSession and the InitialMessageData to be sent
                // The sharedKey itself is cleared in the finally block.
                return (chatSession, x3dhResult.MessageDataToSend);
            }
            catch (Exception ex) // Catch specific crypto exceptions if possible
            {
                LogMessage($"Failed to create new session: {ex.Message}", LogLevel.Error);
                // Wrap in a more specific exception if needed
                if (ex is CryptographicException || ex is KeyNotFoundException || ex is ArgumentException || ex is InvalidOperationException) throw;
                throw new CryptographicException($"Failed to create new session: {ex.Message}", ex);
            }
            finally
            {
                // 4. Securely clear the intermediate X3DH shared key now that DR is initialized
                // It's crucial this key is not stored long-term.
                if (sharedKey != null)
                    SecureMemory.SecureClear(sharedKey);
                LogMessage($"Intermediate shared key cleared.", LogLevel.Debug);
            }
        }

        /// <summary>
        /// Establishes a chat session as the responder (receiver) using the initial
        /// message data received from the initiator (sender). Performs X3DH key exchange
        /// and initializes the Double Ratchet state.
        /// </summary>
        /// <param name="initialMessage">The initial message data from the sender (containing their IK, EK, used IDs).</param>
        /// <param name="localKeyBundle">The receiver's OWN full X3DHKeyBundle (containing necessary private keys).</param>
        /// <returns>The newly established ChatSession.</returns>
        /// <exception cref="ArgumentNullException">If initialMessage or localKeyBundle is null.</exception>
        /// <exception cref="ArgumentException">If initialMessage data is invalid or keys have wrong sizes.</exception>
        /// <exception cref="KeyNotFoundException">If the pre-keys specified in initialMessage cannot be found in localKeyBundle.</exception>
        /// <exception cref="CryptographicException">If X3DH or Double Ratchet initialization fails.</exception>
        /// <exception cref="InvalidOperationException">If the manager is disposed or local bundle is incomplete.</exception>
        public ChatSession EstablishSessionFromInitialMessage(
            InitialMessageData initialMessage,
            X3DHKeyBundle localKeyBundle) // Need our OWN bundle with private keys
        {
            if (_disposed) throw new InvalidOperationException("ChatSessionManager has been disposed.");
            ArgumentNullException.ThrowIfNull(initialMessage, nameof(initialMessage));
            ArgumentNullException.ThrowIfNull(localKeyBundle, nameof(localKeyBundle));

            // Validate structure and basic content of incoming message data
            if (!initialMessage.IsValid())
                throw new ArgumentException("Received invalid initial message data.", nameof(initialMessage));

            // Use sender's IK as the session identifier
            byte[] senderIdentityPublicKey = initialMessage.SenderIdentityKeyPublic;
            string sessionKey = Convert.ToBase64String(senderIdentityPublicKey);

            // Prevent establishing duplicate session if one already exists (active or persisted)
            if (_activeSessions.TryGetValue(sessionKey, out var existingActiveSession))
            {
                LogMessage($"Session already active for {sessionKey}. Returning existing session.", LogLevel.Warning);
                return existingActiveSession;
            }
            if (!string.IsNullOrEmpty(_sessionStoragePath))
            {
                var loadedPersistedSession = TryLoadPersistedSession(sessionKey, senderIdentityPublicKey);
                if (loadedPersistedSession != null)
                {
                    LogMessage($"Session already persisted for {sessionKey}. Loading instead of establishing new.", LogLevel.Warning);
                    _activeSessions.TryAdd(sessionKey, loadedPersistedSession); // Add to active cache
                    return loadedPersistedSession;
                }
            }

            // --- Proceed with establishing new session ---

            // Variables for key copies - ensure they are cleared in finally
            byte[]? sharedKey = null;
            byte[]? receiverSPK_PrivateKey_Copy = null;
            // We don't need copies of IK/OPK private keys here, as X3DHExchange uses the bundle directly
            KeyPair receiverSignedPreKeyPair; // Struct or class

            try
            {
                LogMessage($"Attempting to establish new session with {sessionKey} using SPK ID {initialMessage.RecipientSignedPreKeyId} and OPK ID {(initialMessage.RecipientOneTimePreKeyId?.ToString() ?? "N/A")}", LogLevel.Information);

                // 1. Verify SPK ID and retrieve SPK keys from OUR bundle
                if (localKeyBundle.SignedPreKeyId != initialMessage.RecipientSignedPreKeyId)
                {
                    throw new KeyNotFoundException($"Received initial message using Signed PreKey ID {initialMessage.RecipientSignedPreKeyId}, but the receiver's current bundle has ID {localKeyBundle.SignedPreKeyId}. Cannot establish session (potentially using outdated key).");
                }

                // Get the keys associated with the matched SPK ID
                byte[]? receiverSPK_PublicKey = localKeyBundle.SignedPreKey;
                receiverSPK_PrivateKey_Copy = localKeyBundle.GetSignedPreKeyPrivate(); // Get COPY of private key

                if (receiverSPK_PrivateKey_Copy == null || receiverSPK_PublicKey == null)
                {
                    throw new InvalidOperationException($"Receiver's Signed PreKey components are missing for matching ID {initialMessage.RecipientSignedPreKeyId}. Bundle may be corrupt.");
                }
                // Construct the KeyPair needed for Double Ratchet init
                // Assuming KeyPair struct/class copies data or GetSignedPreKeyPrivate already returned a copy
                receiverSignedPreKeyPair = new KeyPair { PublicKey = receiverSPK_PublicKey, PrivateKey = receiverSPK_PrivateKey_Copy };


                // 2. Perform X3DH Receiver Establishment to get the shared secret (SK)
                // This function internally uses the private keys from localKeyBundle based on IDs in initialMessage
                sharedKey = X3DHExchange.EstablishSessionAsReceiver(
                    initialMessage,
                    localKeyBundle // Pass our full bundle
                );

                if (sharedKey == null || sharedKey.Length != Constants.AES_KEY_SIZE) // Ensure valid key size
                    throw new CryptographicException("X3DH establishment failed to produce a valid shared key.");

                // 3. Initialize Double Ratchet Receiver State
                string sessionId = $"session-{Guid.NewGuid()}"; // Unique ID for this DR session instance
                DoubleRatchetSession initialDrSession = DoubleRatchet.InitializeSessionAsReceiver(
                    sharedKeyFromX3DH: sharedKey,
                    receiverSignedPreKeyPair: receiverSignedPreKeyPair, // Our SPK pair is our initial DHs
                    senderEphemeralKeyPublic: initialMessage.SenderEphemeralKeyPublic, // Alice's EK is her initial DHr
                    sessionId: sessionId
                );

                // 4. Create the ChatSession wrapper
                var chatSession = new ChatSession(
                    initialDrSession,
                    senderIdentityPublicKey, // Store Alice's IK (Remote Key)
                    localKeyBundle.IdentityKey ?? throw new InvalidOperationException("Local bundle missing identity key.") // Store our own IK
                );

                // 5. Add to active sessions and persist
                _activeSessions.AddOrUpdate(sessionKey, chatSession, (key, existing) => {
                    LogMessage($"Replacing existing session reference for {key} during establishment (race condition?). Disposing old.", LogLevel.Warning);
                    existing?.Dispose();
                    return chatSession;
                });

                if (!string.IsNullOrEmpty(_sessionStoragePath))
                {
                    PersistSession(chatSession); // Persist the newly established session state
                }

                LogMessage($"Successfully established new session with {sessionKey}", LogLevel.Information);
                return chatSession;
            }
            catch (Exception ex)
            {
                // Log detailed error including potential KeyNotFoundException or CryptographicException
                LogMessage($"Failed to establish session from initial message for {sessionKey}: {ex.GetType().Name} - {ex.Message}", LogLevel.Error);
                // Clean up potentially created session from dictionary if it was added prematurely (unlikely with AddOrUpdate)
                _activeSessions.TryRemove(sessionKey, out var failedSession);
                failedSession?.Dispose();
                // Re-throw as a specific type for the caller
                if (ex is CryptographicException || ex is KeyNotFoundException || ex is ArgumentException || ex is InvalidOperationException) throw;
                throw new CryptographicException($"Failed to establish session: {ex.Message}", ex);
            }
            finally
            {
                // Securely clear intermediate sensitive data
                if (sharedKey != null)
                    SecureMemory.SecureClear(sharedKey);
                // Clear the COPY of the SPK private key we made
                if (receiverSPK_PrivateKey_Copy != null)
                    SecureMemory.SecureClear(receiverSPK_PrivateKey_Copy);
                // Note: The OPK private key copy retrieved internally by EstablishSessionAsReceiver
                // should ideally be cleared within that method's finally block.
                // If GetOneTimePreKeyPrivate was called *here*, we would clear its copy here too.
            }
        }

        /// <summary>
        /// Attempts to load a persisted Double Ratchet session state and wrap it in a ChatSession.
        /// </summary>
        private ChatSession? TryLoadPersistedSession(string sessionKey, byte[] recipientIdentityPublicKey)
        {
            if (string.IsNullOrEmpty(_sessionStoragePath)) return null; // Persistence disabled

            string sessionFilePath = Path.Combine(_sessionStoragePath, $"{sessionKey}_session.bin");
            if (!File.Exists(sessionFilePath)) return null;

            byte[]? serializedSessionData = null;
            try
            {
                serializedSessionData = File.ReadAllBytes(sessionFilePath);
                var loadedDrSession = SessionPersistence.DeserializeSession(
                    serializedSessionData,
                    _sessionEncryptionKey
                );

                // Need local public key to create ChatSession - assume it's always _identityKeyPair.PublicKey
                return new ChatSession(
                    loadedDrSession,
                    recipientIdentityPublicKey, // Key for this session
                    _identityKeyPair.PublicKey   // Our key
                );
            }
            catch (FileNotFoundException) { return null; } // Expected if file disappears
            catch (Exception ex) when (ex is CryptographicException || ex is InvalidDataException)
            {
                LogMessage($"Failed to load or decrypt persisted session for {sessionKey}: {ex.Message}. Deleting corrupt file.", LogLevel.Error);
                // Delete corrupt session file to prevent repeated load failures
                try { KeyStorage.SecureDeleteFile(sessionFilePath); } catch { /* Ignore delete error */ }
                return null;
            }
            catch (Exception ex)
            {
                LogMessage($"Unexpected error loading persisted session for {sessionKey}: {ex.Message}", LogLevel.Error);
                return null; // Don't crash, just fail to load
            }
            finally
            {
                if (serializedSessionData != null)
                    SecureMemory.SecureClear(serializedSessionData); // Clear data read from file
            }
        }

        /// <summary>
        /// Persists the cryptographic state of a session to storage.
        /// </summary>
        private void PersistSession(ChatSession session)
        {
            if (string.IsNullOrEmpty(_sessionStoragePath)) return; // Persistence disabled

            byte[]? serializedData = null;
            string sessionKey = "";
            string sessionFilePath = "";
            try
            {
                sessionKey = Convert.ToBase64String(session.RemotePublicKey);
                sessionFilePath = Path.Combine(_sessionStoragePath, $"{sessionKey}_session.bin");

                // Get the underlying DoubleRatchetSession state
                DoubleRatchetSession cryptoState = session.GetCryptoSessionState(); // Assumes method exists

                serializedData = SessionPersistence.SerializeSession(
                    cryptoState,
                    _sessionEncryptionKey
                );

                // Write atomically if possible (e.g., write to temp file, then rename)
                string tempFilePath = sessionFilePath + ".tmp";
                File.WriteAllBytes(tempFilePath, serializedData);
                File.Move(tempFilePath, sessionFilePath, overwrite: true); // Overwrite existing

                LogMessage($"Persisted session for {sessionKey}", LogLevel.Debug);
            }
            catch (Exception ex)
            {
                LogMessage($"Error persisting session for {sessionKey}: {ex.Message}", LogLevel.Error);
                // Attempt to clean up temp file if it exists
                try { if (File.Exists(sessionFilePath + ".tmp")) File.Delete(sessionFilePath + ".tmp"); } catch { /* Ignore cleanup error */ }
            }
            finally
            {
                if(serializedData != null)
                    SecureMemory.SecureClear(serializedData); // Clear serialized data bytes
            }
        }

        /// <summary>
        /// Closes and removes a specific session from memory and persistent storage.
        /// </summary>
        /// <param name="recipientPublicKey">Recipient's public identity key (Ed25519).</param>
        public void CloseSession(byte[] recipientPublicKey)
        {
            if (_disposed) return;
            ArgumentNullException.ThrowIfNull(recipientPublicKey, nameof(recipientPublicKey));
            string sessionKey = Convert.ToBase64String(recipientPublicKey);

            if (_activeSessions.TryRemove(sessionKey, out var session))
            {
                session.Dispose(); // Dispose resources held by ChatSession
                LogMessage($"Closed active session for {sessionKey}", LogLevel.Information);
            }

            // Remove persisted session file
            if (!string.IsNullOrEmpty(_sessionStoragePath))
            {
                try
                {
                    string sessionFilePath = Path.Combine(_sessionStoragePath, $"{sessionKey}_session.bin");
                    if (File.Exists(sessionFilePath))
                    {
                        KeyStorage.SecureDeleteFile(sessionFilePath); // Assumes this helper exists
                        LogMessage($"Removed persisted session file for {sessionKey}", LogLevel.Debug);
                    }
                }
                catch (Exception ex)
                {
                    LogMessage($"Error removing persisted session file for {sessionKey}: {ex.Message}", LogLevel.Error);
                }
            }
        }

        /// <summary>
        /// Gets all active session keys (Base64 encoded recipient public keys).
        /// </summary>
        public IEnumerable<string> GetActiveSessions() => _activeSessions.Keys.ToArray();

        /// <summary>
        /// Logs messages using LoggingManager if logging is enabled.
        /// </summary>
        private void LogMessage(string message, LogLevel level = LogLevel.Debug) // Added LogLevel
        {
            if (_enableLogging)
            {
                // Use your actual LoggingManager methods
                switch (level)
                {
                    case LogLevel.Error: LoggingManager.LogError(nameof(ChatSessionManager), message); break;
                    case LogLevel.Warning: LoggingManager.LogWarning(nameof(ChatSessionManager), message); break;
                    case LogLevel.Information: LoggingManager.LogInformation(nameof(ChatSessionManager), message); break;
                    case LogLevel.Debug: LoggingManager.LogDebug(nameof(ChatSessionManager), message); break; // Assuming LogDebug exists
                    default: LoggingManager.LogInformation(nameof(ChatSessionManager), message); break;
                }
            }
        }

        /// <summary>
        /// Disposes of resources held by the manager, primarily closing active sessions.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    // Dispose managed state (managed objects).
                    LogMessage("Disposing ChatSessionManager...", LogLevel.Information);
                    foreach (var kvp in _activeSessions)
                    {
                        kvp.Value.Dispose();
                    }
                    _activeSessions.Clear();
                    // Clear session encryption key if held directly? (depends on lifecycle)
                    // SecureMemory.SecureClear(_sessionEncryptionKey); // Be careful if key is shared/managed elsewhere
                }

                // Free unmanaged resources (unmanaged objects) and override finalizer
                // None in this example directly

                _disposed = true;
            }
        }
    }
}