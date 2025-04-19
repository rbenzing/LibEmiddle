using System.Collections.Concurrent;
using System.Collections.Immutable; // Required for ImmutableDictionary, ImmutableList, ImmutableHashSet
using System.Security.Cryptography;
using System.Text;
using LibEmiddle.Core; // For Constants, SecureMemory, Helpers
using LibEmiddle.Domain; // For DoubleRatchetSession, EncryptedMessage, etc.
using LibEmiddle.KeyExchange; // For X3DHExchange static class access, InitialMessageData

namespace LibEmiddle.Crypto
{
    /// <summary>
    /// Provides static methods for the Double Ratchet algorithm, handling session initialization,
    /// message encryption/decryption, Diffie-Hellman ratcheting, symmetric-key ratcheting,
    /// and skipped message handling. Operates on immutable DoubleRatchetSession state objects.
    /// </summary>
    internal static class DoubleRatchet
    {
        // --- Constants for KDFs ---
        private static readonly byte[] InfoRootKeyUpdate = 
            Encoding.UTF8.GetBytes($"{ProtocolVersion.PROTOCOL_ID}_{ProtocolVersion.MAJOR_VERSION}_{ProtocolVersion.MINOR_VERSION}");
        private const byte MESSAGE_KEY_SEED_BYTE = 0x01; // Seed byte for deriving Message Key via HMAC
        private const byte CHAIN_KEY_SEED_BYTE = 0x02; // Seed byte for deriving next Chain Key via HMAC
        private static readonly byte[] MessageKeySeed = [MESSAGE_KEY_SEED_BYTE]; // Pre-allocate
        private static readonly byte[] ChainKeySeed = [CHAIN_KEY_SEED_BYTE]; // Pre-allocate
        private static readonly Dictionary<string, int> SessionMessageCounters = new();

        // --- Session Locking (for async wrappers) ---
        private static readonly ConcurrentDictionary<string, SemaphoreSlim> _sessionLocks = new();
        private static readonly ConcurrentDictionary<string, long> _lockLastUsed = new();
        private const int LOCK_CLEANUP_THRESHOLD = 500; // Example threshold for cleanup
        private static readonly TimeSpan LOCK_MAX_UNUSED_TIME = TimeSpan.FromMinutes(10);

        // --- Double Ratchet Initialization ---
        /// <summary>
        /// Derrives the Double Ratchet keypair from a shared key (typically from X3DH).
        /// Creates the initial root key and chain key for the Double Ratchet session.
        /// </summary>
        /// <param name="sharedKey">32-byte shared secret derived from X3DH key agreement.</param>
        /// <returns>A tuple containing (rootKey, chainKey) used to initialize the Double Ratchet session.</returns>
        /// <exception cref="ArgumentException">Thrown when sharedKey is empty or has invalid length.</exception>
        /// <exception cref="CryptographicException">Thrown when key derivation fails.</exception>
        public static (byte[] rootKey, byte[] chainKey) DerriveDoubleRatchet(ReadOnlySpan<byte> sharedKey)
        {
            if (sharedKey.IsEmpty)
                throw new ArgumentException("Shared key cannot be empty", nameof(sharedKey));

            if (sharedKey.Length != Constants.AES_KEY_SIZE)
                throw new ArgumentException($"Shared key must be {Constants.AES_KEY_SIZE} bytes", nameof(sharedKey));

            try
            {
                // Derive a 64-byte key material using HKDF from the shared key
                byte[] derivedKeyMaterial = KeyConversion.HkdfDerive(
                    inputKeyMaterial: sharedKey.ToArray(), // Convert to array for compatibility with HkdfDerive
                    salt: null, // Using default salt (optional)
                    info: Encoding.UTF8.GetBytes("DR_INIT"), // Double Ratchet initialization info
                    outputLength: Constants.AES_KEY_SIZE * 2); // 64 bytes: 32 for root key, 32 for chain key

                // Create result arrays
                byte[] rootKey = new byte[Constants.AES_KEY_SIZE];
                byte[] chainKey = new byte[Constants.AES_KEY_SIZE];

                // Use Span<T> to efficiently copy portions of the derived key material
                derivedKeyMaterial.AsSpan(0, Constants.AES_KEY_SIZE).CopyTo(rootKey);
                derivedKeyMaterial.AsSpan(Constants.AES_KEY_SIZE, Constants.AES_KEY_SIZE).CopyTo(chainKey);

                // Securely clear the intermediate derived key material
                SecureMemory.SecureClear(derivedKeyMaterial);

                LoggingManager.LogDebug(nameof(DoubleRatchet), "Double Ratchet initial keys derived successfully");
                return (rootKey, chainKey);
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(DoubleRatchet), $"Failed to initialize Double Ratchet: {ex.Message}");
                throw new CryptographicException("Double Ratchet initialization failed", ex);
            }
        }

        /// <summary>
        /// Enhanced initialization method that creates a complete Double Ratchet session
        /// with support for both sender and receiver roles.
        /// </summary>
        /// <param name="sharedKeyFromX3DH">The 32-byte shared secret from X3DH exchange</param>
        /// <param name="localKeyPair">Local DH key pair (sender's new key pair or receiver's SPK pair)</param>
        /// <param name="remotePublicKey">Remote party's public key (recipient's SPK or sender's EK)</param>
        /// <param name="sessionId">Optional session ID, will generate if not provided</param>
        /// <param name="isInitiator">True if initializing as sender, false as receiver. Default: true</param>
        /// <returns>Fully initialized Double Ratchet session</returns>
        /// <exception cref="ArgumentNullException">If required parameters are null</exception>
        /// <exception cref="ArgumentException">If parameters have invalid format</exception>
        /// <exception cref="CryptographicException">If cryptographic operations fail</exception>
        public static DoubleRatchetSession InitializeDoubleRatchet(
            byte[] sharedKeyFromX3DH,
            KeyPair localKeyPair,
            byte[] remotePublicKey,
            string? sessionId = null,
            bool isInitiator = true)
        {
            // --- Validation ---
            ArgumentNullException.ThrowIfNull(sharedKeyFromX3DH, nameof(sharedKeyFromX3DH));

            if (localKeyPair.PublicKey == null || localKeyPair.PrivateKey == null)
                throw new ArgumentException("Local key pair must have both public and private keys", nameof(localKeyPair));

            ArgumentNullException.ThrowIfNull(remotePublicKey, nameof(remotePublicKey));

            // Size validation
            if (sharedKeyFromX3DH.Length != Constants.AES_KEY_SIZE)
                throw new ArgumentException($"Invalid X3DH shared key size. Expected {Constants.AES_KEY_SIZE}, got {sharedKeyFromX3DH.Length}.", nameof(sharedKeyFromX3DH));

            if (localKeyPair.PrivateKey.Length != Constants.X25519_KEY_SIZE || localKeyPair.PublicKey.Length != Constants.X25519_KEY_SIZE)
                throw new ArgumentException($"Invalid local key pair size. Keys must be {Constants.X25519_KEY_SIZE} bytes.", nameof(localKeyPair));

            if (remotePublicKey.Length != Constants.X25519_KEY_SIZE)
                throw new ArgumentException($"Invalid remote public key size. Expected {Constants.X25519_KEY_SIZE}, got {remotePublicKey.Length}.", nameof(remotePublicKey));

            byte[]? dhOutput = null;

            try
            {
                if (isInitiator) // Sender initialization path
                {
                    // Sender computes DH with its own private key and recipient's public key
                    dhOutput = X3DHExchange.PerformX25519DH(localKeyPair.PrivateKey, remotePublicKey);

                    // Derive RK, CKs using the KDF
                    var (rootKey, sendingChainKey) = KdfRootKey(sharedKeyFromX3DH, dhOutput);

                    // Create sender's initial state
                    return new DoubleRatchetSession(
                        dhRatchetKeyPair: localKeyPair,
                        remoteDHRatchetKey: remotePublicKey,
                        rootKey: rootKey,
                        sendingChainKey: sendingChainKey,
                        receivingChainKey: null, // Sender has no receiving chain initially
                        messageNumberSending: 0,
                        messageNumberReceiving: 0,
                        sessionId: sessionId ?? Guid.NewGuid().ToString(),
                        recentlyProcessedIds: ImmutableList<Guid>.Empty,
                        processedMessageNumbersReceiving: ImmutableHashSet<int>.Empty,
                        skippedMessageKeys: ImmutableDictionary<Tuple<byte[], int>, byte[]>.Empty
                    );
                }
                else // Receiver initialization path
                {
                    // Receiver computes DH with its own private key and sender's public key
                    dhOutput = X3DHExchange.PerformX25519DH(localKeyPair.PrivateKey, remotePublicKey);

                    // Derive RK, CKr using the KDF
                    var (rootKey, receivingChainKey) = KdfRootKey(sharedKeyFromX3DH, dhOutput);

                    // Create receiver's initial state
                    return new DoubleRatchetSession(
                        dhRatchetKeyPair: localKeyPair,
                        remoteDHRatchetKey: remotePublicKey,
                        rootKey: rootKey,
                        sendingChainKey: null, // Receiver has no sending chain initially
                        receivingChainKey: receivingChainKey,
                        messageNumberSending: 0,
                        messageNumberReceiving: 0,
                        sessionId: sessionId ?? Guid.NewGuid().ToString(),
                        recentlyProcessedIds: ImmutableList<Guid>.Empty,
                        processedMessageNumbersReceiving: ImmutableHashSet<int>.Empty,
                        skippedMessageKeys: ImmutableDictionary<Tuple<byte[], int>, byte[]>.Empty
                    );
                }
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(DoubleRatchet), $"Session initialization failed: {ex.Message}");
                throw new CryptographicException($"Failed to initialize {(isInitiator ? "sender" : "receiver")} session.", ex);
            }
            finally
            {
                SecureMemory.SecureClear(dhOutput);
            }
        }

        /// <summary>
        /// Initializes a Double Ratchet session for the initiator (Sender/Alice)
        /// using the shared key from X3DH.
        /// </summary>
        /// <param name="sharedKeyFromX3DH">The 32-byte shared secret (SK) derived from X3DHExchange.InitiateSessionAsSender.</param>
        /// <param name="recipientSignedPreKeyPublic">The recipient's public Signed PreKey (X25519) used in the X3DH exchange (acts as initial DHr).</param>
        /// <param name="sessionId">A unique identifier for this session.</param>
        /// <returns>The initial DoubleRatchetSession state for the sender.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static DoubleRatchetSession InitializeSessionAsSender(
            byte[] sharedKeyFromX3DH,
            byte[] recipientSignedPreKeyPublic, // Bob's SPK is initial DHr
            string sessionId)
        {
            ArgumentNullException.ThrowIfNull(sharedKeyFromX3DH, nameof(sharedKeyFromX3DH));
            ArgumentNullException.ThrowIfNull(recipientSignedPreKeyPublic, nameof(recipientSignedPreKeyPublic));

            // --- DETAILED ARGUMENT VALIDATION ---
            if (sharedKeyFromX3DH.Length != Constants.AES_KEY_SIZE)
                throw new ArgumentException($"Invalid X3DH shared key size. Expected {Constants.AES_KEY_SIZE}, got {sharedKeyFromX3DH.Length}.", nameof(sharedKeyFromX3DH));
            if (recipientSignedPreKeyPublic.Length != Constants.X25519_KEY_SIZE)
                throw new ArgumentException($"Invalid recipient public key size. Expected {Constants.X25519_KEY_SIZE}, got {recipientSignedPreKeyPublic.Length}.", nameof(recipientSignedPreKeyPublic));
            // --- End Validation ---

            byte[]? dhOutput = null;
            KeyPair? senderRatchetKeyPair = null;

            try
            {
                byte[] rootKey1 = sharedKeyFromX3DH;

                senderRatchetKeyPair = Sodium.GenerateX25519KeyPair();
                if (senderRatchetKeyPair?.PrivateKey == null || senderRatchetKeyPair?.PublicKey == null)
                    throw new CryptographicException("Failed to generate sender's initial DH ratchet key pair.");
                // Optional: Add size checks for generated keys if KeyGenerator isn't trusted
                // if (senderRatchetKeyPair.Value.PrivateKey.Length != Constants.X25519_KEY_SIZE) throw new CryptographicException(...);
                // if (senderRatchetKeyPair.Value.PublicKey.Length != Constants.X25519_KEY_SIZE) throw new CryptographicException(...);

                dhOutput = X3DHExchange.PerformX25519DH(senderRatchetKeyPair.Value.PrivateKey, recipientSignedPreKeyPublic);

                var (rootKey2, sendingChainKey) = KdfRootKey(rootKey1, dhOutput);

                var initialState = new DoubleRatchetSession(
                    dhRatchetKeyPair: senderRatchetKeyPair.Value,
                    remoteDHRatchetKey: recipientSignedPreKeyPublic,
                    rootKey: rootKey2,
                    sendingChainKey: sendingChainKey,
                    receivingChainKey: null,
                    messageNumberSending: 0,
                    messageNumberReceiving: 0,
                    sessionId: sessionId ?? Guid.NewGuid().ToString(),
                    recentlyProcessedIds: ImmutableList<Guid>.Empty,
                    processedMessageNumbersReceiving: ImmutableHashSet<int>.Empty,
                    skippedMessageKeys: ImmutableDictionary<Tuple<byte[], int>, byte[]>.Empty
                );

                LoggingManager.LogDebug(nameof(DoubleRatchet), $"Sender session {initialState.SessionId} initialized.");
                return initialState;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(DoubleRatchet), $"Sender session initialization failed: {ex.Message}");
                throw new CryptographicException("Failed to initialize sender session.", ex);
            }
            finally
            {
                SecureMemory.SecureClear(dhOutput);
            }
        }

        /// <summary>
        /// Initializes a Double Ratchet session for the responder (Receiver/Bob)
        /// using the shared key from X3DH and the sender's initial ephemeral key.
        /// </summary>
        /// <param name="sharedKeyFromX3DH">The 32-byte shared secret (SK) derived from X3DHExchange.EstablishSessionAsReceiver.</param>
        /// <param name="receiverSignedPreKeyPair">The receiver's Signed PreKey PAIR (SPKb) corresponding to the SPK ID used by the sender (acts as initial DHs_0).</param>
        /// <param name="senderEphemeralKeyPublic">The sender's public Ephemeral Key (EKA_pub) from the initial message (acts as initial DHr_1).</param>
        /// <param name="sessionId">A unique identifier for this session.</param>
        /// <returns>The initial DoubleRatchetSession state for the receiver.</returns>
        /// <exception cref="ArgumentNullException">If required arguments are null.</exception>
        /// <exception cref="ArgumentException">If keys have invalid size.</exception>
        /// <exception cref="CryptographicException">If DH or KDF operations fail.</exception>
        public static DoubleRatchetSession InitializeSessionAsReceiver(
             byte[] sharedKeyFromX3DH,
             KeyPair receiverSignedPreKeyPair, // Bob's SPK pair is initial DHs (DHs_0)
             byte[] senderEphemeralKeyPublic,  // Alice's EK is initial DHr (DHr_1)
             string sessionId)
        {
            // --- Argument Validation ---
            ArgumentNullException.ThrowIfNull(sharedKeyFromX3DH, nameof(sharedKeyFromX3DH));
            // Assuming KeyPair is struct/class where properties can be null if not initialized properly
            if (receiverSignedPreKeyPair.PrivateKey == null) throw new ArgumentNullException(nameof(receiverSignedPreKeyPair.PrivateKey), "Receiver SPK private key cannot be null.");
            if (receiverSignedPreKeyPair.PublicKey == null) throw new ArgumentNullException(nameof(receiverSignedPreKeyPair.PublicKey), "Receiver SPK public key cannot be null.");
            ArgumentNullException.ThrowIfNull(senderEphemeralKeyPublic, nameof(senderEphemeralKeyPublic));

            // --- Detailed Size Validation ---
            if (sharedKeyFromX3DH.Length != Constants.AES_KEY_SIZE)
                throw new ArgumentException($"Invalid X3DH shared key size. Expected {Constants.AES_KEY_SIZE}, got {sharedKeyFromX3DH.Length}.", nameof(sharedKeyFromX3DH));
            if (receiverSignedPreKeyPair.PrivateKey.Length != Constants.X25519_KEY_SIZE)
                throw new ArgumentException($"Invalid receiver private key size. Expected {Constants.X25519_KEY_SIZE}, got {receiverSignedPreKeyPair.PrivateKey.Length}.", nameof(receiverSignedPreKeyPair));
            if (receiverSignedPreKeyPair.PublicKey.Length != Constants.X25519_KEY_SIZE)
                throw new ArgumentException($"Invalid receiver public key size. Expected {Constants.X25519_KEY_SIZE}, got {receiverSignedPreKeyPair.PublicKey.Length}.", nameof(receiverSignedPreKeyPair));
            if (senderEphemeralKeyPublic.Length != Constants.X25519_KEY_SIZE)
                throw new ArgumentException($"Invalid sender public key size. Expected {Constants.X25519_KEY_SIZE}, got {senderEphemeralKeyPublic.Length}.", nameof(senderEphemeralKeyPublic));
            // --- End Validation ---

            byte[]? dhOutput = null; // For clearing in finally

            try
            {
                byte[] rootKey1 = sharedKeyFromX3DH; // Initial Root Key is SK from X3DH

                // Perform DH: Receiver's SPK private key (DHs_0.priv), Sender's EK public key (DHr_1)
                // PerformX25519DH handles internal validation and exceptions
                dhOutput = X3DHExchange.PerformX25519DH(receiverSignedPreKeyPair.PrivateKey, senderEphemeralKeyPublic);

                // KDF_RK(rootKey1, DH(DHs_0.priv, DHr_1)) -> rootKey2, CKr_1
                // KdfRootKey handles internal validation and exceptions
                var (rootKey2, receivingChainKey) = KdfRootKey(rootKey1, dhOutput);

                // Create initial state for the receiver
                var initialState = new DoubleRatchetSession(
                   dhRatchetKeyPair: receiverSignedPreKeyPair,    // Bob uses his SPK initially (DHs_0)
                   remoteDHRatchetKey: senderEphemeralKeyPublic, // Alice's EK is initial DHr (DHr_1)
                   rootKey: rootKey2,                            // New Root Key
                   sendingChainKey: null,                        // No Sending CK yet
                   receivingChainKey: receivingChainKey,         // Initial Receiving CK (CKr_1)
                   messageNumberSending: 0,                      // Ns = 0
                   messageNumberReceiving: 0,                    // Nr = 0
                   sessionId: sessionId ?? Guid.NewGuid().ToString(), // Ensure Session ID
                   // Initialize empty immutable collections for tracking state
                   recentlyProcessedIds: ImmutableList<Guid>.Empty,
                   processedMessageNumbersReceiving: ImmutableHashSet<int>.Empty,
                   skippedMessageKeys: ImmutableDictionary<Tuple<byte[], int>, byte[]>.Empty // Requires comparer for byte[] key
                );

                LoggingManager.LogDebug(nameof(DoubleRatchet), $"Receiver session {initialState.SessionId} initialized.");
                return initialState;
            }
            catch (Exception ex) // Catch crypto exceptions from DH or KDF, or others
            {
                LoggingManager.LogError(nameof(DoubleRatchet), $"Receiver session initialization failed: {ex.Message}");
                // Wrap in CryptographicException if it isn't already one
                if (ex is CryptographicException) throw;
                throw new CryptographicException("Failed to initialize receiver session.", ex);
            }
            finally
            {
                // Securely clear intermediate DH output
                SecureMemory.SecureClear(dhOutput);
                // The private key from receiverSignedPreKeyPair is now owned by the returned initialState object.
                // The input sharedKeyFromX3DH should be cleared by the caller (ChatSessionManager).
            }
        }


        /// <summary>
        /// Encrypts a message using the Double Ratchet algorithm. Handles DH ratchet steps and skipped messages.
        /// </summary>
        /// <param name="session"></param>
        /// <param name="message"></param>
        /// <param name="rotationStrategy"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="InvalidOperationException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static (DoubleRatchetSession updatedSession, EncryptedMessage encryptedMessage) DoubleRatchetEncrypt(
            DoubleRatchetSession session, 
            string message, 
            Enums.KeyRotationStrategy rotationStrategy = Enums.KeyRotationStrategy.Standard)
        {
            // --- Argument and State Validation ---
            ArgumentNullException.ThrowIfNull(session);
            if (string.IsNullOrEmpty(message)) throw new ArgumentException("Message cannot be null or empty", nameof(message));
            if (session.SendingChainKey == null) throw new InvalidOperationException("Cannot encrypt: Sending chain key is not initialized.");
            if (session.DHRatchetKeyPair.PublicKey == null) throw new InvalidOperationException("Invalid sender DH ratchet key pair in session");

            byte[]? nextChainKey = null;
            byte[]? messageKey = null;

            try
            {
                // --- Symmetric Ratchet (KDF_CK) ---
                (nextChainKey, messageKey) = KdfChainKey(session.SendingChainKey);

                // --- Encryption ---
                using var secureMessageKey = new SecureMemory.SecureArray<byte>(messageKey);
                byte[] plaintextBytes = Encoding.UTF8.GetBytes(message);
                byte[] nonce = NonceGenerator.GenerateNonce();
                byte[] ciphertext = AES.AESEncrypt(plaintextBytes, secureMessageKey.Value, nonce); // Assumes AEAD

                // --- Prepare Output ---
                var encryptedMessage = new EncryptedMessage
                {
                    Ciphertext = ciphertext,
                    Nonce = nonce,
                    MessageNumber = session.MessageNumberSending, // Ns
                    SenderDHKey = session.DHRatchetKeyPair.PublicKey, // DHs.pub
                    Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    MessageId = Guid.NewGuid(),
                    SessionId = session.SessionId
                };

                // Create updated session state (immutable)
                var updatedSession = session.WithUpdatedParameters(
                    newSendingChainKey: nextChainKey, // Update CKs
                    newMessageNumberSending: session.MessageNumberSending + 1 // Increment Ns
                );

                LoggingManager.LogDebug(nameof(DoubleRatchet), $"Encrypted message Ns={encryptedMessage.MessageNumber} for session {session.SessionId}");
                return (updatedSession, encryptedMessage);
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(DoubleRatchet), $"Encryption failed for session {session.SessionId}: {ex.Message}");
                throw new CryptographicException("Failed to encrypt message with Double Ratchet", ex);
            }
            finally
            {
                SecureMemory.SecureClear(nextChainKey); // Clear intermediate key
                                                        // messageKey cleared by SecureArray using block
            }
        }

        /// <summary>
        /// Decrypts a message using the Double Ratchet algorithm. Handles DH ratchet steps and skipped messages.
        /// </summary>
        public static (DoubleRatchetSession? updatedSession, string? decryptedMessage)
            DoubleRatchetDecrypt(DoubleRatchetSession? session, EncryptedMessage? encryptedMessage)
        {
            // --- Argument and Message Validation ---
            ArgumentNullException.ThrowIfNull(session, nameof(session));
            ArgumentNullException.ThrowIfNull(encryptedMessage, nameof(encryptedMessage));
            if (encryptedMessage.Ciphertext == null || encryptedMessage.Nonce == null || encryptedMessage.SenderDHKey == null)
                throw new ArgumentException("Encrypted message is missing required fields", nameof(encryptedMessage));
            if (session.SessionId != encryptedMessage.SessionId)
            {
                LoggingManager.LogWarning(nameof(DoubleRatchet), $"Session ID mismatch: expected {session.SessionId}, got {encryptedMessage.SessionId}");
                return (null, null);
            }
            if (session.HasProcessedMessageId(encryptedMessage.MessageId))
            { // Check Replay ID
                LoggingManager.LogWarning(nameof(DoubleRatchet), $"Message replay detected: {encryptedMessage.MessageId}");
                return (null, null);
            }
            if (!IsTimestampValid(encryptedMessage.Timestamp))
            { // Check Timestamp
                LoggingManager.LogWarning(nameof(DoubleRatchet), $"Invalid message timestamp {encryptedMessage.Timestamp} for message {encryptedMessage.MessageId}");
                return (null, null);
            }

            DoubleRatchetSession currentSessionState = session; // Use local var for state updates
            byte[]? messageKey = null;
            byte[]? dhOutput = null;
            KeyPair? newKeyPair = null;
            // Use builders for efficient immutable dictionary updates if many keys are skipped
            var skippedKeysBuilder = currentSessionState.SkippedMessageKeys.ToBuilder();
            bool skippedKeysModified = false; // Track if we need to update the dictionary


            try
            {
                // --- DH Ratchet Check ---
                if (!SecureMemory.SecureCompare(encryptedMessage.SenderDHKey, currentSessionState.RemoteDHRatchetKey))
                {
                    LoggingManager.LogDebug(nameof(DoubleRatchet), "DH ratchet step triggered.");

                    // Clear any skipped keys associated with the old remote key
                    var keysToKeep = ImmutableDictionary.CreateBuilder<Tuple<byte[], int>, byte[]>();
                    // NOTE: Requires custom comparer for byte[] key in Tuple for reliable operation!
                    // This simplistic approach assumes reference equality or requires a proper comparer implementation elsewhere.
                    // foreach(var kvp in currentSessionState.SkippedMessageKeys) {
                    //     if (!kvp.Key.Item1.SequenceEqual(currentSessionState.RemoteDHRatchetKey)) {
                    //         keysToKeep.Add(kvp.Key, kvp.Value);
                    //     } else {
                    //         SecureMemory.SecureClear(kvp.Value); // Clear skipped key for old ratchet
                    //     }
                    // }
                    // skippedKeysBuilder = keysToKeep; // Use the filtered set
                    // skippedKeysModified = true; // Mark as modified
                    // For simplicity if no reliable comparer, just clear ALL skipped keys on DH ratchet:
                    foreach (var kvp in skippedKeysBuilder) { SecureMemory.SecureClear(kvp.Value); }
                    skippedKeysBuilder.Clear();
                    skippedKeysModified = true;
                    LoggingManager.LogWarning(nameof(DoubleRatchet), "Cleared all skipped message keys due to DH Ratchet step.");


                    // Perform DH ratchet step
                    if (currentSessionState.DHRatchetKeyPair.PrivateKey == null) throw new InvalidOperationException("Missing own private key for DH ratchet.");
                    dhOutput = X3DHExchange.PerformX25519DH(currentSessionState.DHRatchetKeyPair.PrivateKey, encryptedMessage.SenderDHKey);
                    var (newRootKey, newReceivingChainKey) = KdfRootKey(currentSessionState.RootKey, dhOutput);
                    newKeyPair = Sodium.GenerateX25519KeyPair(); // Generate our new DHs

                    // Update local working state variable
                    currentSessionState = currentSessionState.WithUpdatedParameters(
                        newDHRatchetKeyPair: newKeyPair.Value,
                        newRemoteDHRatchetKey: encryptedMessage.SenderDHKey,
                        newRootKey: newRootKey,
                        newReceivingChainKey: newReceivingChainKey,
                        resetReceivingChainState: true // Reset Nr and processed numbers set
                    );
                    SecureMemory.SecureClear(dhOutput); dhOutput = null;
                    LoggingManager.LogDebug(nameof(DoubleRatchet), "DH ratchet completed, session state updated.");
                }

                // --- Skipped Message / Symmetric Ratchet ---
                if (currentSessionState.ReceivingChainKey == null)
                    throw new InvalidOperationException("Cannot decrypt: Receiving chain key is null after potential DH ratchet.");

                byte[] currentReceivingChainKey = (byte[])currentSessionState.ReceivingChainKey.Clone(); // Work with a copy
                uint currentReceivingMsgNum = (uint)currentSessionState.MessageNumberReceiving; // Expected Nr
                uint targetMsgNum = (uint)encryptedMessage.MessageNumber; // Received N

                LoggingManager.LogDebug(nameof(DoubleRatchet), $"Attempting decrypt for Nr={targetMsgNum}, current expected Nr={currentReceivingMsgNum}");

                var keyIdentifierForLookup = Tuple.Create(currentSessionState.RemoteDHRatchetKey, (int)targetMsgNum);
                // WARNING: Tuple key requires custom comparer for byte[] equality!

                if (targetMsgNum < currentReceivingMsgNum)
                {
                    // Message is older than expected - check cache
                    if (skippedKeysBuilder.TryGetValue(keyIdentifierForLookup, out messageKey!))
                    {
                        LoggingManager.LogDebug(nameof(DoubleRatchet), $"Found key for old message (Nr={targetMsgNum}) in skipped cache.");
                        skippedKeysBuilder.Remove(keyIdentifierForLookup); // Remove used key
                        skippedKeysModified = true;
                        // DO NOT advance chain state
                        SecureMemory.SecureClear(currentReceivingChainKey); // Clear the temp copy as it wasn't used
                    }
                    else
                    {
                        LoggingManager.LogWarning(nameof(DoubleRatchet), $"Old message (Nr={targetMsgNum}) received, but key not in skipped cache. Discarding.");
                        SecureMemory.SecureClear(currentReceivingChainKey);
                        return (null, null); // Discard message, key lost
                    }
                }
                else
                {
                    // Message is current or from the future - ratchet forward if needed
                    while (currentReceivingMsgNum < targetMsgNum)
                    {
                        byte[] skippedMsgKey;
                        byte[] nextChainKey;
                        (nextChainKey, skippedMsgKey) = KdfChainKey(currentReceivingChainKey);

                        // Store key for skipped message N = currentReceivingMsgNum
                        var skippedKeyId = Tuple.Create(currentSessionState.RemoteDHRatchetKey, (int)currentReceivingMsgNum);
                        skippedKeysBuilder[skippedKeyId] = skippedMsgKey; // Add/overwrite skipped key
                        skippedKeysModified = true;

                        SecureMemory.SecureClear(currentReceivingChainKey); // Clear previous temp chain key
                        currentReceivingChainKey = nextChainKey;
                        currentReceivingMsgNum++;
                        LoggingManager.LogDebug(nameof(DoubleRatchet), $"Ratcheted CKr forward, stored skipped key for Nr={currentReceivingMsgNum - 1}");
                    }
                    // Now currentReceivingMsgNum == targetMsgNum
                    // Derive the key for *this* message and the *next* chain key
                    byte[] nextReceivingChainKeyFinal;
                    (nextReceivingChainKeyFinal, messageKey) = KdfChainKey(currentReceivingChainKey);

                    // Update the session state variables needed for the final immutable update
                    currentSessionState = currentSessionState.WithUpdatedParameters(
                         newReceivingChainKey: nextReceivingChainKeyFinal,
                         newMessageNumberReceiving: (int)(targetMsgNum + 1) // Nr becomes N+1
                    );
                    SecureMemory.SecureClear(currentReceivingChainKey); // Clear final temp chain key
                }

                // --- Decryption ---
                if (messageKey == null)
                {
                    // Logic error above if this happens
                    LoggingManager.LogError(nameof(DoubleRatchet), "Message key is null after ratchet/cache check.");
                    return (null, null);
                }

                using var secureMessageKey = new SecureMemory.SecureArray<byte>(messageKey);
                byte[]? plaintext = null;
                string? decryptedMessage = null;
                try
                {
                    plaintext = AES.AESDecrypt(encryptedMessage.Ciphertext, secureMessageKey.Value, encryptedMessage.Nonce);
                    if (plaintext == null) { LoggingManager.LogWarning(nameof(DoubleRatchet), "Decryption failed (AEAD authentication failed)."); return (null, null); }
                    if (!Helpers.IsValidUtf8(plaintext)) { LoggingManager.LogWarning(nameof(DoubleRatchet), "Decrypted plaintext is not valid UTF-8."); return (null, null); }
                    decryptedMessage = Encoding.UTF8.GetString(plaintext);
                    LoggingManager.LogDebug(nameof(DoubleRatchet), $"Decryption successful for message Nr={targetMsgNum}.");
                }
                catch (CryptographicException ex)
                {
                    LoggingManager.LogError(nameof(DoubleRatchet), $"Decryption failed: {ex.Message}");
                    return (null, null);
                }
                finally
                {
                    SecureMemory.SecureClear(plaintext); // Clear plaintext bytes if necessary
                }

                // --- Final State Update ---
                // Mark message ID as processed and update skipped keys if they were modified
                currentSessionState = currentSessionState.WithProcessedMessageId(encryptedMessage.MessageId);
                if (skippedKeysModified)
                {
                    currentSessionState = currentSessionState.WithUpdatedParameters(newSkippedMessageKeys: skippedKeysBuilder.ToImmutable());
                }

                return (currentSessionState, decryptedMessage);
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(DoubleRatchet), $"Unexpected error during decryption: {ex.Message} {ex.StackTrace}");
                return (null, null); // Don't throw, return null tuple
            }
            finally
            {
                // Ensure intermediates are cleared
                SecureMemory.SecureClear(dhOutput);
                SecureMemory.SecureClear(newKeyPair?.PrivateKey); // Clear newly generated private key if not used
                // messageKey is cleared by SecureArray
            }
        }

        /// <summary>
        /// Validates that a DoubleRatchetSession is properly initialized with required keys and valid state.
        /// Used to verify session integrity before performing cryptographic operations.
        /// </summary>
        /// <param name="session">The DoubleRatchetSession to validate.</param>
        /// <returns>True if the session is valid and can be used for cryptographic operations, false otherwise.</returns>
        public static bool ValidateSession(DoubleRatchetSession? session)
        {
            // Check for null session
            if (session == null)
                return false;

            try
            {
                // Validate required components
                if (session.RootKey == null || session.RootKey.Length != Constants.AES_KEY_SIZE)
                    return false;

                // DHRatchetKeyPair validation (need both keys)
                if (session.DHRatchetKeyPair.PublicKey == null ||
                    session.DHRatchetKeyPair.PrivateKey == null ||
                    session.DHRatchetKeyPair.PublicKey.Length != Constants.X25519_KEY_SIZE ||
                    session.DHRatchetKeyPair.PrivateKey.Length != Constants.X25519_KEY_SIZE)
                    return false;

                // Remote DHRatchet key validation
                if (session.RemoteDHRatchetKey == null ||
                    session.RemoteDHRatchetKey.Length != Constants.X25519_KEY_SIZE)
                    return false;

                // Validate X25519 public keys
                if (!Sodium.ValidateX25519PublicKey(session.DHRatchetKeyPair.PublicKey) ||
                    !Sodium.ValidateX25519PublicKey(session.RemoteDHRatchetKey))
                    return false;

                // SessionId should not be null or empty
                if (string.IsNullOrEmpty(session.SessionId))
                    return false;

                // Chain keys can be null initially, but if present must be valid size
                if (session.SendingChainKey != null && session.SendingChainKey.Length != Constants.AES_KEY_SIZE)
                    return false;

                if (session.ReceivingChainKey != null && session.ReceivingChainKey.Length != Constants.AES_KEY_SIZE)
                    return false;

                // Message numbers should be non-negative
                if (session.MessageNumberSending < 0 || session.MessageNumberReceiving < 0)
                    return false;

                // All validation checks passed
                return true;
            }
            catch (Exception ex)
            {
                // Log any unexpected errors during validation
                LoggingManager.LogError(nameof(DoubleRatchet), $"Error validating session: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Performs a Diffie-Hellman ratchet step with improved key derivation
        /// </summary>
        /// <param name="rootKey">Current root key</param>
        /// <param name="dhOutput">Output from new Diffie-Hellman exchange</param>
        /// <returns>New root key and chain key</returns>
        public static (byte[] newRootKey, byte[] newChainKey) DHRatchetStep(ReadOnlySpan<byte> rootKey, ReadOnlySpan<byte> dhOutput)
        {
            ArgumentNullException.ThrowIfNull(rootKey.ToArray());
            ArgumentNullException.ThrowIfNull(dhOutput.ToArray());

            if (rootKey.Length != Constants.AES_KEY_SIZE)
                throw new ArgumentException($"Root key must be {Constants.AES_KEY_SIZE} bytes", nameof(rootKey));

            // Create secure copies to prevent accidental modification
            byte[] rootKeyCopy = SecureMemory.CreateSecureBuffer((uint)rootKey.Length);
            rootKey.ToArray().AsSpan().CopyTo(rootKeyCopy.AsSpan());

            byte[] dhOutputCopy = SecureMemory.CreateSecureBuffer((uint)dhOutput.Length);
            dhOutput.ToArray().AsSpan().CopyTo(dhOutputCopy.AsSpan());

            try
            {
                byte[] prk = KeyConversion.HkdfDerive(
                    rootKeyCopy,
                    salt: dhOutputCopy,
                    info: Encoding.UTF8.GetBytes("RootKeyDerivation")
                );

                byte[] newRootKey = KeyConversion.HkdfDerive(
                    prk,
                    info: Encoding.UTF8.GetBytes("NewRootKey")
                );

                byte[] newChainKey = KeyConversion.HkdfDerive(
                    prk,
                    info: Encoding.UTF8.GetBytes("NewChainKey")
                );

                // Securely clear the intermediate PRK value
                SecureMemory.SecureClear(prk);

                return (newRootKey, newChainKey);
            }
            finally
            {
                // Securely clear our copies
                SecureMemory.SecureClear(rootKeyCopy);
                SecureMemory.SecureClear(dhOutputCopy);
            }
        }

        /// <summary>
        /// Performs a step in the Double Ratchet to derive new keys
        /// </summary>
        /// <param name="chainKey">Current chain key</param>
        /// <param name="sessionId">Optional session ID for tracking</param>
        /// <param name="strategy">Key rotation strategy</param>
        /// <returns>New chain key and message key</returns>
        public static (byte[] newChainKey, byte[] messageKey) RatchetStep(
            ReadOnlySpan<byte> chainKey,
            string sessionId = "",
            Enums.KeyRotationStrategy strategy = Enums.KeyRotationStrategy.Standard)
        {
            ArgumentNullException.ThrowIfNull(chainKey.ToArray(), nameof(chainKey));

            if (chainKey.Length != Constants.AES_KEY_SIZE)
                throw new ArgumentException($"Chain key must be {Constants.AES_KEY_SIZE} bytes", nameof(chainKey));

            if (!string.IsNullOrEmpty(sessionId))
            {
                lock (SessionMessageCounters)
                {
                    if (!SessionMessageCounters.ContainsKey(sessionId))
                        SessionMessageCounters[sessionId] = 0;

                    SessionMessageCounters[sessionId]++;
                }
            }

            // Derive new chain key using HKDF
            byte[] newChainKey = Sodium.HkdfDerive(
                chainKey,
                salt: Sodium.GenerateRandomBytes(Constants.DEFAULT_SALT_SIZE),
                info: Encoding.UTF8.GetBytes("EmiddleKDFChain"),
                outputLength: Constants.AES_KEY_SIZE
            );

            // Derive message key using HKDF
            byte[] messageKey = Sodium.HkdfDerive(
                chainKey,
                salt: Sodium.GenerateRandomBytes(Constants.DEFAULT_SALT_SIZE),
                info: Encoding.UTF8.GetBytes("EmiddleKDFMsgKey"),
                outputLength: Constants.AES_KEY_SIZE
            );

            if (ShouldRotateKey(sessionId, strategy))
            {
                LoggingManager.LogInformation(
                    nameof(DoubleRatchet),
                    $"DH Key rotation triggered for session {sessionId} (Strategy: {strategy})"
                );
                // TODO: Additional DH key rotation logic would go here for full implementation
            }

            return (newChainKey, messageKey);
        }

        /// <summary>
        /// Resumes a Double Ratchet session, optionally marking a previously processed message ID.
        /// This is useful after deserializing a persisted session to ensure replay protection logic is maintained.
        /// </summary>
        /// <param name="session">The session to resume.</param>
        /// <param name="lastProcessedMessageId">Optional last processed message ID to mark as processed.</param>
        /// <returns>A new session instance with updated state.</returns>
        /// <exception cref="ArgumentNullException">Thrown if session is null.</exception>
        public static DoubleRatchetSession ResumeSession(DoubleRatchetSession session, Guid? lastProcessedMessageId = null)
        {
            ArgumentNullException.ThrowIfNull(session, nameof(session));

            // Create a new session with the same state but potentially marking a message as processed
            if (lastProcessedMessageId.HasValue)
            {
                // Use the session's WithProcessedMessageId method to mark the message as processed
                return session.WithProcessedMessageId(lastProcessedMessageId.Value);
            }

            // If no message ID to process, just return the session as is
            return session;
        }

        // --- Async Wrappers ---
        public static async Task<(DoubleRatchetSession? updatedSession, EncryptedMessage? encryptedMessage)>
            DoubleRatchetEncryptAsync(DoubleRatchetSession session, string message, Enums.KeyRotationStrategy rotationStrategy = Enums.KeyRotationStrategy.Standard)
        {
            ArgumentNullException.ThrowIfNull(session);
            var sessionLock = GetSessionLock(session.SessionId); await sessionLock.WaitAsync();
            try { return DoubleRatchetEncrypt(session, message, rotationStrategy); }
            catch (Exception ex) { LoggingManager.LogError(nameof(DoubleRatchet), $"Async Encrypt Error: {ex.Message}"); return (null, null); }
            finally { sessionLock.Release(); CleanupUnusedLocksIfNeeded(); }
        }

        public static async Task<(DoubleRatchetSession? updatedSession, string? decryptedMessage)>
            DoubleRatchetDecryptAsync(DoubleRatchetSession? session, EncryptedMessage? encryptedMessage)
        {
            ArgumentNullException.ThrowIfNull(session); ArgumentNullException.ThrowIfNull(encryptedMessage);
            var sessionLock = GetSessionLock(session.SessionId); await sessionLock.WaitAsync();
            try { return DoubleRatchetDecrypt(session, encryptedMessage); }
            catch (Exception ex) { LoggingManager.LogError(nameof(DoubleRatchet), $"Async Decrypt Error: {ex.Message}"); return (null, null); }
            finally { sessionLock.Release(); CleanupUnusedLocksIfNeeded(); }
        }


        // --- Internal KDF Functions ---
        private static (byte[] newRootKey, byte[] newChainKey) KdfRootKey(byte[] rootKey, byte[] dhOutput)
        {
            // Assumes KeyConversion.HkdfDerive implements HKDF-Expand(salt, ikm, info, L) correctly (e.g., using HMAC-SHA256)
            byte[] hkdfOutput = Sodium.HkdfDerive(salt: rootKey, inputKeyMaterial: dhOutput, info: InfoRootKeyUpdate, outputLength: 64);
            if (hkdfOutput == null || hkdfOutput.Length != 64) throw new CryptographicException("KDF_RK: Invalid output length.");
            byte[] newRootKey = hkdfOutput.Take(32).ToArray();
            byte[] newChainKey = hkdfOutput.Skip(32).Take(32).ToArray();
            SecureMemory.SecureClear(hkdfOutput);
            return (newRootKey, newChainKey);
        }

        private static (byte[] nextChainKey, byte[] messageKey) KdfChainKey(byte[] chainKey)
        {
            byte[] messageKey = Sodium.GenerateHmacSha256(MessageKeySeed, chainKey);
            byte[] nextChainKey = Sodium.GenerateHmacSha256(ChainKeySeed, chainKey);
            if (messageKey == null || messageKey.Length != 32 || nextChainKey == null || nextChainKey.Length != 32)
                throw new CryptographicException("KDF_CK: Invalid output length.");
            return (nextChainKey, messageKey);
        }

        private static bool ShouldRotateKey(string sessionId, Enums.KeyRotationStrategy strategy)
        {
            if (string.IsNullOrEmpty(sessionId))
                return false;

            lock (SessionMessageCounters)
            {
                if (!SessionMessageCounters.ContainsKey(sessionId))
                    return false;

                int count = SessionMessageCounters[sessionId];

                return strategy switch
                {
                    Enums.KeyRotationStrategy.Standard => count % 20 == 0, // Change to rotate every 20 messages
                    Enums.KeyRotationStrategy.Hourly => count % 1 == 0, // Change to rotate every 1 hour
                    Enums.KeyRotationStrategy.Daily => count % 7 == 0, // Change to rotate every 7 days
                    _ => false
                };
            }
        }

        // --- Session Locking Management & Helpers ---
        private static SemaphoreSlim GetSessionLock(string sessionId) { 
            _lockLastUsed[sessionId] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(); 
            return _sessionLocks.GetOrAdd(sessionId, _ => new SemaphoreSlim(1, 1)); 
        }
        private static void CleanupUnusedLocksIfNeeded() { 
            if (_sessionLocks.Count > LOCK_CLEANUP_THRESHOLD) { 
                Task.Run(() => CleanupUnusedLocks()); 
            } 
        }
        private static void CleanupUnusedLocks() { 
            try { 
                long cutoff = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - (long)LOCK_MAX_UNUSED_TIME.TotalMilliseconds; 
                var expired = _lockLastUsed.Where(e => e.Value < cutoff).Select(e => e.Key).Take(100).ToList(); 
                int removed = 0; foreach (var sid in expired) { 
                    if (_lockLastUsed.TryRemove(sid, out _) && 
                        _sessionLocks.TryRemove(sid, out var sem)) { 
                            sem.Dispose(); 
                            removed++; 
                        } 
                    } 
                    if (removed > 0) 
                        LoggingManager.LogInformation(nameof(DoubleRatchet), $"Cleaned {removed} expired session locks."); 
            } catch (Exception ex) { 
                LoggingManager.LogWarning(nameof(DoubleRatchet), $"Lock cleanup error: {ex.Message}"); 
            } 
        }
        private static bool IsTimestampValid(long messageTimestamp) { 
            const long expirationThreshold = 5 * 60 * 1000; 
            const long futureTolerance = 10 * 1000; 
            long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(); 
            if (messageTimestamp > now + futureTolerance) 
                return false; 
            if (messageTimestamp < now - expirationThreshold) 
                return false; 
            return true; 
        }
    }


} // End Namespace