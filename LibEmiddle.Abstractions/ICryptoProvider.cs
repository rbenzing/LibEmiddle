using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;

namespace LibEmiddle.Abstractions
{
    /// <summary>
    /// Defines the contract for cryptographic operations used by the library.
    /// Implementing this interface allows swapping the underlying cryptographic engine.
    /// </summary>
    public interface ICryptoProvider
    {
        /// <summary>
        /// Generates a random cryptographically secure key pair.
        /// </summary>
        /// <param name="keyType">The type of key pair to generate.</param>
        /// <returns>A newly generated key pair.</returns>
        public Task<KeyPair> GenerateKeyPairAsync(KeyType keyType);

        /// <summary>
        /// Generates a specified number of random bytes.
        /// </summary>
        /// <param name="count">The number of random bytes to generate.</param>
        /// <returns>An array of random bytes.</returns>
        public byte[] GenerateRandomBytes(uint count);

        /// <summary>
        /// Generates a random nonce of x size
        /// </summary>
        /// <param name="size">The length of the nonce</param>
        /// <returns></returns>
        public byte[] GenerateNonce(uint size = Constants.NONCE_SIZE);

        /// <summary>
        /// Signs data using an Ed25519 private key.
        /// </summary>
        /// <param name="data">The data to sign.</param>
        /// <param name="privateKey">The Ed25519 private key to sign with (64 bytes).</param>
        /// <returns>The Ed25519 signature (64 bytes).</returns>
        public byte[] Sign(byte[] data, byte[] privateKey);

        /// <summary>
        /// Verifies an Ed25519 signature against data using a public key.
        /// </summary>
        /// <param name="message">The data that was signed.</param>
        /// <param name="signature">The Ed25519 signature to verify (64 bytes).</param>
        /// <param name="publicKey">The Ed25519 public key to verify with (32 bytes).</param>
        /// <returns>True if the signature is valid, false otherwise.</returns>
        public bool VerifySignature(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKey);

        /// <summary>
        /// Encrypts data using a key and nonce.
        /// </summary>
        /// <param name="plaintext">The data to encrypt.</param>
        /// <param name="key">The encryption key.</param>
        /// <param name="nonce">Optional nonce for encryption.</param>
        /// <param name="associatedData">Optional associated data for AEAD encryption.</param>
        /// <returns>The encrypted data.</returns>
        public byte[] Encrypt(byte[] plaintext, byte[] key, byte[]? nonce, byte[]? associatedData);

        /// <summary>
        /// Decrypts data using a key and nonce.
        /// </summary>
        /// <param name="ciphertext">The data to decrypt.</param>
        /// <param name="key">The decryption key.</param>
        /// <param name="nonce">Optional nonce for decryption.</param>
        /// <param name="associatedData">Optional associated data for AEAD decryption.</param>
        /// <returns>The decrypted data.</returns>
        public byte[] Decrypt(byte[] ciphertext, byte[] key, byte[]? nonce, byte[]? associatedData);

        /// <summary>
        /// Performs X25519 scalar multiplication to compute a shared secret.
        /// </summary>
        /// <param name="privateKey">The X25519 private key (32 bytes).</param>
        /// <param name="publicKey">The X25519 public key (32 bytes).</param>
        /// <returns>The 32-byte shared secret.</returns>
        public byte[] ScalarMult(byte[] privateKey, byte[] publicKey);

        /// <summary>
        /// Derives a key from input key material.
        /// </summary>
        /// <param name="inputKeyMaterial">The input key material.</param>
        /// <param name="salt">Optional salt.</param>
        /// <param name="info">Optional context info.</param>
        /// <param name="length">Optional desired output length. (default: 32)</param>
        /// <returns>The derived key.</returns>
        [Obsolete("Please use DeriveMessageKey instead.")]
        public byte[] DeriveKey(byte[] inputKeyMaterial, byte[]? salt, byte[]? info, int length = 32);

        /// <summary>
        /// Derives a message key from a chain key following Signal Protocol specification.
        /// </summary>
        /// <param name="chainKey">The chain key to derive from (32 bytes)</param>
        /// <returns>A 32-byte message key for encryption</returns>
        public byte[] DeriveMessageKey(ReadOnlySpan<byte> chainKey);

        /// <summary>
        /// Derives initial session keys from X3DH shared secret following Signal Protocol v3 specification.
        /// Both root key and chain key are derived from a single root seed.
        /// </summary>
        /// <param name="sharedSecret">The 32-byte shared secret from X3DH key agreement</param>
        /// <returns>A tuple containing (rootKey, initialChainKey) both 32 bytes each</returns>
        public (byte[] RootKey, byte[] InitialChainKey) DeriveInitialSessionKeys(ReadOnlySpan<byte> sharedSecret);

        /// <summary>
        /// Advances a chain key to the next iteration following Signal Protocol specification.
        /// </summary>
        /// <param name="chainKey">The current chain key (32 bytes)</param>
        /// <returns>The next chain key in the sequence (32 bytes)</returns>
        public byte[] AdvanceChainKey(ReadOnlySpan<byte> chainKey);

        /// <summary>
        /// Derives a key from a password.
        /// </summary>
        /// <param name="password">The password.</param>
        /// <returns>The derived key.</returns>
        public byte[] DeriveKeyFromPassword(string password);

        /// <summary>
        /// Converts an Ed25519 public key to an X25519 public key.
        /// </summary>
        /// <param name="ed25519PublicKey">The Ed25519 public key (32 bytes).</param>
        /// <returns>The corresponding X25519 public key (32 bytes).</returns>
        public byte[] ConvertEd25519PublicKeyToX25519(byte[] ed25519PublicKey);

        /// <summary>
        /// Converts an Ed25519 private key to an X25519 private key.
        /// </summary>
        /// <param name="ed25519PrivateKey">The Ed25519 private key (64 bytes).</param>
        /// <returns>The corresponding X25519 private key (32 bytes).</returns>
        public byte[] ConvertEd25519PrivateKeyToX25519(byte[] ed25519PrivateKey);

        /// <summary>
        /// Validates that an Ed25519 public key is properly formatted.
        /// </summary>
        /// <param name="publicKey">The Ed25519 public key to validate (must be 32 bytes).</param>
        /// <returns>True if the key is valid, false otherwise.</returns>
        public bool ValidateEd25519PublicKey(byte[] publicKey);

        /// <summary>
        /// Validates that an X25519 public key is properly formatted.
        /// </summary>
        /// <param name="publicKey">The X25519 public key to validate (must be 32 bytes).</param>
        /// <returns>True if the key is valid, false otherwise.</returns>
        public bool ValidateX25519PublicKey(byte[] publicKey);

        /// <summary>
        /// Disposes of resources used by the CryptoProvider.
        /// </summary>
        public void Dispose();


        // ASYNC

        /// <summary>
        /// Asynchronously derives a key from input key material.
        /// </summary>
        /// <param name="inputKeyMaterial">The input key material.</param>
        /// <param name="salt">Optional salt.</param>
        /// <param name="info">Optional context info.</param>
        /// <param name="length">Optional desired output length. (default: 32)</param>
        /// <returns>The derived key.</returns>
        [Obsolete("Please use DeriveMessageKey instead.")]
        public Task<byte[]> DeriveKeyAsync(byte[] inputKeyMaterial, byte[]? salt, byte[]? info, int length = 32);

        /// <summary>
        /// Asynchronously derives a key from a password.
        /// </summary>
        /// <param name="password">The password.</param>
        /// <returns>The derived key.</returns>
        public Task<byte[]> DeriveKeyFromPasswordAsync(string password);

        /// <summary>
        /// Stores a key in the platform's secure key storage.
        /// </summary>
        /// <param name="keyId">The identifier for the key.</param>
        /// <param name="key">The key to store.</param>
        /// <param name="password">Optional password for additional protection.</param>
        /// <returns>True if the key was stored successfully.</returns>
        public Task<bool> StoreKeyAsync(string keyId, byte[] key, string? password = null);

        /// <summary>
        /// Retrieves a key from the platform's secure key storage.
        /// </summary>
        /// <param name="keyId">The identifier for the key.</param>
        /// <param name="password">Optional password if the key was protected with one.</param>
        /// <returns>The retrieved key, or null if not found.</returns>
        public Task<byte[]?> RetrieveKeyAsync(string keyId, string? password = null);

        /// <summary>
        /// Deletes a key from the platform's secure key storage.
        /// </summary>
        /// <param name="keyId">The identifier for the key.</param>
        /// <param name="password">Optional password if the key was protected with one.</param>
        /// <returns>True if the key was deleted successfully.</returns>
        public Task<bool> DeleteKeyAsync(string keyId, string? password = null);

        /// <summary>
        /// Stores a JSON string in the platform's secure storage.
        /// </summary>
        /// <param name="keyId">The identifier for the data.</param>
        /// <param name="jsonData">The JSON data to store.</param>
        /// <returns>True if the data was stored successfully.</returns>
        public Task<bool> StoreJsonAsync(string keyId, string jsonData);

        /// <summary>
        /// Retrieves a JSON string from the platform's secure storage.
        /// </summary>
        /// <param name="keyId">The identifier for the data.</param>
        /// <returns>The retrieved JSON data, or null if not found.</returns>
        public Task<string?> RetrieveJsonAsync(string keyId);

        /// <summary>
        /// Stores data in the platform's secure storage.
        /// </summary>
        /// <param name="keyId">The identifier for the data.</param>
        /// <param name="data">The data to store.</param>
        /// <returns>True if the data was stored successfully.</returns>
        public Task<bool> StoreAsync(string keyId, string data);

        /// <summary>
        /// Retrieves data from the platform's secure storage.
        /// </summary>
        /// <param name="keyId">The identifier for the data.</param>
        /// <returns>The retrieved data, or null if not found.</returns>
        public Task<string?> RetrieveAsync(string keyId);

        /// <summary>
        /// Asynchronously signs data using an Ed25519 private key.
        /// </summary>
        /// <param name="data">The data to sign.</param>
        /// <param name="privateKey">The Ed25519 private key to sign with (64 bytes).</param>
        /// <returns>The Ed25519 signature (64 bytes).</returns>
        public Task<byte[]> SignAsync(byte[] data, byte[] privateKey);
    }
}