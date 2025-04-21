using LibEmiddle.Abstractions;
using LibEmiddle.Core;
using LibEmiddle.Domain;
using System.Security.Cryptography;

namespace LibEmiddle.Crypto
{
    /// <summary>
    /// Implementation of ICryptoProvider using libsodium for cryptographic operations.
    /// </summary>
    public class CryptoProvider : ICryptoProvider
    {
        private bool _isInitialized;

        /// <summary>
        /// Initializes the crypto provider and libsodium.
        /// </summary>
        public void Initialize()
        {
            if (!_isInitialized)
            {
                Sodium.Initialize();
                _isInitialized = true;
            }
        }

        /// <summary>
        /// Gets whether the provider has been initialized.
        /// </summary>
        public bool IsInitialized => _isInitialized;

        /// <summary>
        /// Encrypts data using AES-GCM.
        /// </summary>
        public byte[] Encrypt(
            byte[] plaintext,
            byte[] key, 
            byte[] nonce,
            byte[]? additionalData = null)
        {
            Initialize();
            return AES.AESEncrypt(plaintext, key, nonce, additionalData);
        }

        /// <summary>
        /// Decrypts data using AES-GCM.
        /// </summary>
        public byte[] Decrypt(
            byte[] ciphertext, 
            byte[] key, 
            byte[] nonce, 
            byte[]? additionalData = null)
        {
            Initialize();
            return AES.AESDecrypt(ciphertext, key, nonce, additionalData);
        }

        /// <summary>
        /// Generates a key pair of the specified type.
        /// </summary>
        public KeyPair GenerateKeyPair(KeyType keyType)
        {
            Initialize();

            if (keyType == KeyType.Ed25519)
            {
                return KeyAuth.GenerateSigningKeyPair();
            }
            else if (keyType == KeyType.X25519)
            {
                return Sodium.GenerateX25519KeyPair();
            }
            else
            {
                throw new ArgumentException($"Unsupported key type: {keyType}", nameof(keyType));
            }
        }

        /// <summary>
        /// Generates a nonce of the specified size.
        /// </summary>
        public byte[] GenerateNonce(uint size = 12)
        {
            ArgumentNullException.ThrowIfNullOrEmpty(size.ToString(), nameof(size));

            Initialize();
            return NonceGenerator.GenerateNonce(size);
        }

        /// <summary>
        /// HMAC-SHA256 on the input data (normalizedPublicKey) using the provided key (existingSharedKey).
        /// </summary>
        /// <param name="normalizedPublicKey"></param>
        /// <param name="existingSharedKey"></param>
        /// <returns></returns>
        public byte[] GenerateHmacSha256(byte[] normalizedPublicKey, byte[] existingSharedKey)
        {
            Initialize();
            return Sodium.GenerateHmacSha256(normalizedPublicKey, existingSharedKey);
        }

        /// <summary>
        /// Derives a key using HKDF.
        /// </summary>
        public byte[] DeriveKey(
            byte[] ikm, 
            byte[]? salt = null, 
            byte[]? info = null, 
            int length = 32)
        {
            Initialize();
            return Sodium.HkdfDerive(ikm, salt, info, length);
        }

        /// <summary>
        /// Signs a message using Ed25519.
        /// </summary>
        public byte[] Sign(byte[] message, byte[] privateKey)
        {
            Initialize();
            return Sodium.SignDetached(message, privateKey);
        }

        /// <summary>
        /// Verifies a signature using Ed25519.
        /// </summary>
        public bool Verify(byte[] message, byte[] signature, byte[] publicKey)
        {
            Initialize();
            return Sodium.VerifyDetached(signature, message, publicKey);
        }

        /// <summary>
        /// Converts an Ed25519 public key to X25519.
        /// </summary>
        public byte[] ConvertEd25519PublicKeyToX25519(ReadOnlySpan<byte> ed25519PublicKey)
        {
            Initialize();
            return Sodium.ConvertEd25519PublicKeyToX25519(ed25519PublicKey);
        }

        /// <summary>
        /// Derives an X25519 private key from an Ed25519 private key.
        /// </summary>
        public byte[] DeriveX25519PrivateKeyFromEd25519(ReadOnlySpan<byte> ed25519PrivateKey)
        {
            Initialize();
            return KeyConversion.DeriveX25519PrivateKeyFromEd25519(ed25519PrivateKey);
        }

        /// <summary>
        /// Generates an Ed25519 key pair from a 32-byte seed.
        /// </summary>
        /// <param name="seed"></param>
        /// <returns></returns>
        public KeyPair GenerateEd25519KeyPairFromSeed(byte[] seed)
        {
            Initialize();
            return Sodium.GenerateEd25519KeyPairFromSeed(seed);
        }

        /// <summary>
        /// Derrives the Double Ratchet keypair from a shared key (typically from X3DH).
        /// Creates the initial root key and chain key for the Double Ratchet session.
        /// </summary>
        /// <param name="sharedKey">32-byte shared secret derived from X3DH key agreement.</param>
        /// <returns>A tuple containing (rootKey, chainKey) used to initialize the Double Ratchet session.</returns>
        /// <exception cref="ArgumentException">Thrown when sharedKey is empty or has invalid length.</exception>
        /// <exception cref="CryptographicException">Thrown when key derivation fails.</exception>
        public (byte[] rootKey, byte[] chainKey) DeriveDoubleRatchet(byte[] sharedKey)
        {
            Initialize();
            return DoubleRatchet.DeriveDoubleRatchet(sharedKey);
        }

        /// <summary>
        /// Initializes a Double Ratchet session for the initiator (Sender)
        /// using the shared key from X3DH.
        /// </summary>
        /// <param name="sharedKeyFromX3DH">The 32-byte shared secret (SK) derived from X3DHExchange.InitiateSessionAsSender.</param>
        /// <param name="senderIdentityKeyPair">Sender's own identity key pair (needed for initial DH calculation in DR init).</param>
        /// <param name="recipientSignedPreKeyPublic">The recipient's public Signed PreKey (X25519) used in the X3DH exchange.</param>
        /// <param name="sessionId">A unique identifier for this session.</param>
        /// <returns>The initial DoubleRatchetSession state for the sender.</returns>
        public DoubleRatchetSession InitializeSessionAsSender(
            byte[] sharedKeyFromX3DH,
            KeyPair senderIdentityKeyPair,
            byte[] recipientSignedPreKeyPublic,
            string sessionId)
        {
            Initialize();
            return DoubleRatchet.InitializeDoubleRatchet(sharedKeyFromX3DH, senderIdentityKeyPair, 
                recipientSignedPreKeyPublic, sessionId, true);
        }

        /// <summary>
        /// Initializes a Double Ratchet session for the responder (Receiver)
        /// using the shared key from X3DH and the sender's initial ephemeral key.
        /// </summary>
        /// <param name="sharedKeyFromX3DH">The 32-byte shared secret (SK) derived from X3DHExchange.EstablishSessionAsReceiver.</param>
        /// <param name="receiverSignedPreKeyPair">The receiver's Signed PreKey PAIR corresponding to the SPK ID used by the sender.</param>
        /// <param name="senderEphemeralKeyPublic">The sender's public Ephemeral Key (EKA_pub) from the initial message.</param>
        /// <param name="sessionId">A unique identifier for this session.</param>
        /// <returns>The initial DoubleRatchetSession state for the receiver.</returns>
        public DoubleRatchetSession InitializeSessionAsReceiver(
             byte[] sharedKeyFromX3DH,
             KeyPair receiverSignedPreKeyPair,
             byte[] senderEphemeralKeyPublic,
             string sessionId)
        {
            Initialize();
            return DoubleRatchet.InitializeDoubleRatchet(sharedKeyFromX3DH, receiverSignedPreKeyPair,
                senderEphemeralKeyPublic, sessionId, false);
        }

        /// <summary>
        /// Resumes a Double Ratchet session, optionally marking a previously processed message ID.
        /// This is useful after deserializing a persisted session to ensure replay protection logic is maintained.
        /// </summary>
        /// <param name="session">The session to resume.</param>
        /// <param name="lastProcessedMessageId">Optional last processed message ID to mark as processed.</param>
        /// <returns>A new session instance with updated state.</returns>
        /// <exception cref="ArgumentNullException">Thrown if session is null.</exception>
        public DoubleRatchetSession ResumeSession(
            DoubleRatchetSession session, 
            Guid? lastProcessedMessageId = null)
        {
            Initialize();
            return DoubleRatchet.ResumeSession(session, lastProcessedMessageId);
        }

        /// <summary>
        /// Validates that a DoubleRatchetSession is properly initialized with required keys and valid state.
        /// Used to verify session integrity before performing cryptographic operations.
        /// </summary>
        /// <param name="session">The DoubleRatchetSession to validate.</param>
        /// <returns>True if the session is valid and can be used for cryptographic operations, false otherwise.</returns>
        public bool ValidateSession(DoubleRatchetSession? session)
        {
            Initialize();
            return DoubleRatchet.ValidateSession(session);
        }

        /// <summary>
        /// Performs a Diffie-Hellman ratchet step with improved key derivation
        /// </summary>
        /// <param name="rootKey">Current root key</param>
        /// <param name="dhOutput">Output from new Diffie-Hellman exchange</param>
        /// <returns>New root key and chain key</returns>
        public (byte[] newRootKey, byte[] newChainKey) DHRatchetStep(
            byte[] rootKey, 
            byte[] dhOutput)
        {
            Initialize();
            return DoubleRatchet.DHRatchetStep(rootKey, dhOutput);
        }

        /// <summary>
        /// Performs a step in the Double Ratchet to derive new keys
        /// </summary>
        /// <param name="chainKey">Current chain key</param>
        /// <param name="sessionId">Session ID for tracking</param>
        /// <param name="strategy">Key rotation strategy</param>
        /// <returns>New chain key and message key</returns>
        public (byte[] newChainKey, byte[] messageKey) RatchetStep(
            byte[] chainKey,
            string sessionId,
            Enums.KeyRotationStrategy strategy = Enums.KeyRotationStrategy.Standard)
        {
            Initialize();
            return DoubleRatchet.RatchetStep(chainKey, sessionId, strategy);
        }

        /// <summary>
        /// Encrypts a message using the Double Ratchet algorithm.
        /// </summary>
        /// <param name="session"></param>
        /// <param name="message"></param>
        /// <param name="rotationStrategy"></param>
        /// <returns></returns>
        public (DoubleRatchetSession updatedSession, EncryptedMessage encryptedMessage) DoubleRatchetEncrypt(
            DoubleRatchetSession session, 
            string message, 
            Enums.KeyRotationStrategy rotationStrategy = Enums.KeyRotationStrategy.Standard)
        {
            Initialize();
            return DoubleRatchet.DoubleRatchetEncrypt(session, message, rotationStrategy);
        }

        /// <summary>
        /// Decrypts a message using the Double Ratchet algorithm.
        /// </summary>
        /// <param name="session"></param>
        /// <param name="encryptedMessage"></param>
        /// <returns></returns>
        public (DoubleRatchetSession? updatedSession, string? decryptedMessage) DoubleRatchetDecrypt(
            DoubleRatchetSession session, 
            EncryptedMessage encryptedMessage)
        {
            ArgumentNullException.ThrowIfNullOrEmpty(session.ToString(), nameof(session));

            Initialize();
            return DoubleRatchet.DoubleRatchetDecrypt(session, encryptedMessage);
        }

        /// <summary>
        /// Encrypts a message using the Double Ratchet algorithm asynchronously.
        /// </summary>
        /// <param name="session"></param>
        /// <param name="message"></param>
        /// <param name="rotationStrategy"></param>
        /// <returns></returns>
        public async Task<(DoubleRatchetSession? updatedSession, EncryptedMessage? encryptedMessage)> DoubleRatchetEncryptAsync(
            DoubleRatchetSession session, 
            string message, 
            Enums.KeyRotationStrategy rotationStrategy = Enums.KeyRotationStrategy.Standard)
        {
            ArgumentNullException.ThrowIfNullOrEmpty(session.ToString(), nameof(session));

            Initialize();
            return (await DoubleRatchet.DoubleRatchetEncryptAsync(session, message, rotationStrategy));
        }

        /// <summary>
        /// Decrypts a message using the Double Ratchet algorithm asynchronously.
        /// </summary>
        /// <param name="session"></param>
        /// <param name="encryptedMessage"></param>
        /// <returns></returns>
        public async Task<(DoubleRatchetSession? updatedSession, string? decryptedMessage)> DoubleRatchetDecryptAsync(
            DoubleRatchetSession session, 
            EncryptedMessage encryptedMessage)
        {
            ArgumentNullException.ThrowIfNullOrEmpty(session.ToString(), nameof(session));

            Initialize();
            return (await DoubleRatchet.DoubleRatchetDecryptAsync(session, encryptedMessage));
        }

        /// <summary>
        /// Validates an X25519 public key to ensure it's not an invalid or dangerous value
        /// </summary>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public bool ValidateX25519PublicKey(byte[] publicKey)
        {
            return Sodium.ValidateX25519PublicKey(publicKey);
        }

        /// <summary>
        /// Exports a key to a secure Base64 string representation
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public string ExportKeyToBase64(byte[] key)
        {
            return KeyConversion.ExportKeyToBase64(key);
        }

        /// <summary>
        /// Imports a key from a Base64 string representation
        /// </summary>
        /// <param name="base64Key"></param>
        /// <returns></returns>
        public byte[] ImportKeyFromBase64(string base64Key)
        {
            return KeyConversion.ImportKeyFromBase64(base64Key);
        }

        /// <summary>
        /// Securely stores a key to a file with optional password protection and salt rotation
        /// </summary>
        /// <param name="key">Key to store</param>
        /// <param name="filePath">Path where the key will be stored</param>
        /// <param name="password">Optional password for additional encryption</param>
        /// <param name="saltRotationDays">Number of days after which the salt should be rotated (default: 30)</param>
        public void StoreKeyToFile(byte[] key, string filePath, string? password = null, int saltRotationDays = 30)
        {
            KeyStorage.StoreKeyToFile(key, filePath, password, saltRotationDays);
        }

        /// <summary>
        /// Loads a key from a file, decrypting it if it was password-protected
        /// and handling salt rotation if needed
        /// </summary>
        /// <param name="filePath">Path to the stored key</param>
        /// <param name="password">Password if the key was encrypted</param>
        /// <param name="forceRotation">Force salt rotation regardless of time elapsed</param>
        /// <returns>The loaded key</returns>
        public byte[] LoadKeyFromFile(string filePath, string? password = null, bool forceRotation = false)
        {
            return KeyStorage.LoadKeyFromFile(filePath, password, forceRotation);
        }

        /// <summary>
        /// Securely clears sensitive data from memory.
        /// </summary>
        public void SecureClear(byte[] data)
        {
            SecureMemory.SecureClear(data);
        }

        /// <summary>
        /// Securely compares two byte arrays in constant time.
        /// </summary>
        public bool SecureCompare(byte[] a, byte[] b)
        {
            return SecureMemory.SecureCompare(a, b);
        }
    }
} 