using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;

namespace LibEmiddle.Abstractions
{
    /// <summary>
    /// Defines an interface for key management operations, including key generation,
    /// derivation, storage, retrieval, and rotation for secure messaging.
    /// </summary>
    public interface IKeyManager
    {
        /// <summary>
        /// Generates a key pair for cryptographic operations.
        /// </summary>
        /// <param name="keyType">The type of key pair to generate.</param>
        /// <returns>The generated key pair.</returns>
        Task<KeyPair> GenerateKeyPairAsync(KeyType keyType);

        /// <summary>
        /// Derives a key from input key material.
        /// </summary>
        /// <param name="inputKey">The input key material.</param>
        /// <param name="salt">Optional salt for key derivation.</param>
        /// <param name="info">Optional context info for key derivation.</param>
        /// <param name="length">Desired output key length in bytes.</param>
        /// <returns>The derived key.</returns>
        Task<byte[]> DeriveKeyAsync(byte[] inputKey, byte[]? salt = null, byte[]? info = null, int length = 32);

        /// <summary>
        /// Stores a key securely.
        /// </summary>
        /// <param name="keyId">The identifier for the key.</param>
        /// <param name="key">The key to store.</param>
        /// <param name="password">Optional password for additional protection.</param>
        /// <returns>True if the key was stored successfully.</returns>
        Task<bool> StoreKeyAsync(string keyId, byte[] key, string? password = null);

        /// <summary>
        /// Retrieves a key from secure storage.
        /// </summary>
        /// <param name="keyId">The identifier for the key.</param>
        /// <param name="password">Optional password if the key was protected with one.</param>
        /// <returns>The retrieved key, or null if not found.</returns>
        Task<byte[]?> RetrieveKeyAsync(string keyId, string? password = null);

        /// <summary>
        /// Deletes a key from secure storage.
        /// </summary>
        /// <param name="keyId">The identifier for the key.</param>
        /// <returns>True if the key was deleted successfully.</returns>
        Task<bool> DeleteKeyAsync(string keyId);

        /// <summary>
        /// Stores a serialized object in secure storage.
        /// </summary>
        /// <param name="keyId">The identifier for the object.</param>
        /// <param name="jsonData">The serialized JSON data to store.</param>
        /// <returns>True if the data was stored successfully.</returns>
        Task<bool> StoreJsonAsync(string keyId, string jsonData);

        /// <summary>
        /// Retrieves a serialized object from secure storage.
        /// </summary>
        /// <param name="keyId">The identifier for the object.</param>
        /// <returns>The serialized JSON data, or null if not found.</returns>
        Task<string?> RetrieveJsonAsync(string keyId);

        /// <summary>
        /// Rotates a key, generating a new one and securely updating storage.
        /// </summary>
        /// <param name="keyId">The identifier for the key to rotate.</param>
        /// <param name="keyType">The type of key to generate.</param>
        /// <param name="password">Optional password for key protection.</param>
        /// <returns>The new key pair.</returns>
        Task<KeyPair> RotateKeyPairAsync(string keyId, KeyType keyType, string? password = null);

        /// <summary>
        /// Gets the remaining time until a key should be rotated.
        /// </summary>
        /// <param name="keyId">The identifier for the key.</param>
        /// <param name="rotationPeriod">The period after which keys should be rotated.</param>
        /// <returns>The time remaining, or TimeSpan.Zero if rotation is needed.</returns>
        Task<TimeSpan> GetTimeUntilRotationAsync(string keyId, TimeSpan rotationPeriod);
    }
}
