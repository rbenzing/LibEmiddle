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
        /// Derives a public key from a private key.
        /// </summary>
        /// <param name="privateKey">The private key to derive from.</param>
        /// <param name="keyType">The type of key to derive.</param>
        /// <returns>The derived public key.</returns>
        public Span<byte> DerivePublicKey(Span<byte> privateKey, KeyType keyType);

        /// <summary>
        /// Generates a specified number of random bytes.
        /// </summary>
        /// <param name="count">The number of random bytes to generate.</param>
        /// <returns>An array of random bytes.</returns>
        public byte[] GenerateRandomBytes(int count);

        /// <summary>
        /// Signs data using a private key.
        /// </summary>
        /// <param name="data">The data to sign.</param>
        /// <param name="privateKey">The private key to sign with.</param>
        /// <returns>The signature.</returns>
        public byte[] Sign(byte[] data, byte[] privateKey);

        /// <summary>
        /// Verifies a signature against data using a public key.
        /// </summary>
        /// <param name="data">The data that was signed.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <param name="publicKey">The public key to verify with.</param>
        /// <returns>True if the signature is valid, false otherwise.</returns>
        public bool VerifySignature(byte[] data, byte[] signature, byte[] publicKey);

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
        /// Performs scalar multiplication (X25519).
        /// </summary>
        /// <param name="privateKey">The private key.</param>
        /// <param name="publicKey">The public key.</param>
        /// <returns>The shared secret.</returns>
        public byte[] ScalarMult(byte[] privateKey, byte[] publicKey);

        /// <summary>
        /// Derives a key from input key material.
        /// </summary>
        /// <param name="inputKeyMaterial">The input key material.</param>
        /// <param name="salt">Optional salt.</param>
        /// <param name="info">Optional context info.</param>
        /// <param name="length">Optional desired output length. (default: 32)</param>
        /// <returns>The derived key.</returns>
        public byte[] DeriveKey(byte[] inputKeyMaterial, byte[]? salt, byte[]? info, int length = 32);

        /// <summary>
        /// Derives a key from a password.
        /// </summary>
        /// <param name="password">The password.</param>
        /// <returns>The derived key.</returns>
        public byte[] DeriveKeyFromPassword(string password);

        /// <summary>
        /// Converts an Ed25519 public key to an X25519 public key.
        /// </summary>
        /// <param name="ed25519PublicKey">The Ed25519 public key.</param>
        /// <returns>The X25519 public key.</returns>
        public byte[] ConvertEd25519PublicKeyToX25519(byte[] ed25519PublicKey);

        /// <summary>
        /// Converts an Ed25519 private key to an X25519 private key.
        /// </summary>
        /// <param name="ed25519PrivateKey">The Ed25519 private key.</param>
        /// <returns>The X25519 private key.</returns>
        public byte[] ConvertEd25519PrivateKeyToX25519(byte[] ed25519PrivateKey);

        /// <summary>
        /// Validates that an Ed25519 public key is properly formatted.
        /// </summary>
        /// <param name="publicKey">The public key to validate.</param>
        /// <returns>True if the key is valid, false otherwise.</returns>
        public bool ValidateEd25519PublicKey(byte[] publicKey);

        /// <summary>
        /// Generates a random nonce of x size
        /// </summary>
        /// <param name="size">The length of the nonce</param>
        /// <returns></returns>
        public byte[] GenerateNonce(uint size = Constants.NONCE_SIZE);

        /// <summary>
        /// Validates that an X25519 public key is properly formatted.
        /// </summary>
        /// <param name="publicKey">The public key to validate.</param>
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
        /// Async signs data using a private key.
        /// </summary>
        /// <param name="data"></param>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public Task<byte[]> SignAsync(byte[] data, byte[] privateKey);
    }
}