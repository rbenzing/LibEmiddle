using LibEmiddle.Domain;

namespace LibEmiddle.Abstractions
{
    /// <summary>
    /// Defines the contract for cryptographic operations used by the library.
    /// Implementing this interface allows swapping the underlying cryptographic engine.
    /// </summary>
    public interface ICryptoProvider
    {
        // Initialization
        void Initialize();
        bool IsInitialized { get; }

        // Symmetric encryption
        byte[] Encrypt(byte[] plaintext, byte[] key, byte[] nonce, byte[]? additionalData = null);
        byte[] Decrypt(byte[] ciphertext, byte[] key, byte[] nonce, byte[]? additionalData = null);

        // Key generation
        KeyPair GenerateKeyPair(KeyType keyType);
        KeyPair GenerateEd25519KeyPairFromSeed(byte[] seed);
        byte[] GenerateSymmetricKey();
        byte[] GenerateNonce(int size = 12);
        byte[] GenerateHmacSha256(byte[] existingSharedKey, byte[] normalizedPublicKey);

        // Key derivation
        byte[] DeriveKey(byte[] ikm, byte[]? salt = null, byte[]? info = null, int length = 32);

        // Digital signatures
        byte[] Sign(byte[] message, byte[] privateKey);
        bool Verify(byte[] message, byte[] signature, byte[] publicKey);

        // Key exchange

        DoubleRatchetSession InitializeSessionAsSender(
            byte[] sharedKeyFromX3DH,
            KeyPair senderIdentityKeyPair,
            byte[] recipientSignedPreKeyPublic,
            string sessionId);

        DoubleRatchetSession InitializeSessionAsReceiver(
             byte[] sharedKeyFromX3DH,
             KeyPair receiverSignedPreKeyPair,
             byte[] senderEphemeralKeyPublic,
             string sessionId);

        (DoubleRatchetSession? updatedSession, EncryptedMessage? encryptedMessage) DoubleRatchetEncrypt(DoubleRatchetSession session, string message, Enums.KeyRotationStrategy rotationStrategy = Enums.KeyRotationStrategy.Standard);
        (DoubleRatchetSession? updatedSession, string? decryptedMessage) DoubleRatchetDecrypt(DoubleRatchetSession session, EncryptedMessage encryptedMessage);
        Task<(DoubleRatchetSession? updatedSession, EncryptedMessage? encryptedMessage)> DoubleRatchetEncryptAsync(DoubleRatchetSession session, string message, Enums.KeyRotationStrategy rotationStrategy = Enums.KeyRotationStrategy.Standard);
        Task<(DoubleRatchetSession? updatedSession, string? decryptedMessage)> DoubleRatchetDecryptAsync(DoubleRatchetSession session, EncryptedMessage encryptedMessage);

        // Key conversion
        byte[] ConvertEd25519PublicKeyToX25519(byte[] ed25519PublicKey);
        byte[] DeriveX25519PrivateKeyFromEd25519(byte[] ed25519PrivateKey);
        bool ValidateX25519PublicKey(byte[] publicKey);
        string ExportKeyToBase64(byte[] key);
        byte[] ImportKeyFromBase64(string base64Key);
        byte[] LoadKeyFromFile(string filePath, string? password = null, bool forceRotation = false);
        void StoreKeyToFile(byte[] key, string filePath, string? password = null, int saltRotationDays = 30);

        // Secure memory handling
        void SecureClear(byte[] data);
        bool SecureCompare(byte[] a, byte[] b);

        // Random generation
        byte[] GenerateRandomBytes(int count);
    }

    /// <summary>
    /// Types of asymmetric key pairs supported by the library
    /// </summary>
    public enum KeyType
    {
        /// <summary>
        /// Ed25519 keys for digital signatures
        /// </summary>
        Ed25519,

        /// <summary>
        /// X25519 keys for key exchange
        /// </summary>
        X25519
    }
}