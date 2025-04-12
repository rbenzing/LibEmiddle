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
        (byte[] publicKey, byte[] privateKey) GenerateKeyPair(KeyType keyType);
        byte[] GenerateSymmetricKey(int size = 32);
        byte[] GenerateNonce(int size = 12);

        // Key derivation
        byte[] DeriveKey(byte[] ikm, byte[]? salt = null, byte[]? info = null, int length = 32);

        // Digital signatures
        byte[] Sign(byte[] message, byte[] privateKey);
        bool Verify(byte[] message, byte[] signature, byte[] publicKey);

        // Key exchange
        byte[] ComputeSharedSecret(byte[] privateKey, byte[] publicKey);

        // Key conversion
        byte[] ConvertEd25519PublicKeyToX25519(byte[] ed25519PublicKey);
        byte[] DeriveX25519PrivateKeyFromEd25519(byte[] ed25519PrivateKey);

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