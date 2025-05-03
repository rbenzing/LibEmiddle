using System.Collections.Concurrent;
using LibEmiddle.Abstractions;
using LibEmiddle.Core;
using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;

namespace LibEmiddle.KeyExchange
{
    /// <summary>
    /// Implements the IKeyManager interface, providing management of cryptographic keys
    /// including generation, derivation, storage, retrieval, and rotation.
    /// </summary>
    public class KeyManager : IKeyManager, IDisposable
    {
        private readonly ICryptoProvider _cryptoProvider;
        private readonly KeyStorage _keyStorage;
        private readonly ConcurrentDictionary<string, byte[]> _keyCache = new ConcurrentDictionary<string, byte[]>();
        private readonly TimeSpan _cacheExpiration = TimeSpan.FromMinutes(10);
        private readonly Timer _cacheCleanupTimer;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the KeyManager class.
        /// </summary>
        /// <param name="cryptoProvider">The cryptographic provider to use.</param>
        public KeyManager(ICryptoProvider cryptoProvider)
        {
            _cryptoProvider = cryptoProvider ?? throw new ArgumentNullException(nameof(cryptoProvider));
            _keyStorage = new KeyStorage();

            // Set up cache cleanup timer
            _cacheCleanupTimer = new Timer(CleanupCache, null, TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(5));
        }

        /// <summary>
        /// Generates a key pair for cryptographic operations.
        /// </summary>
        /// <param name="keyType">The type of key pair to generate.</param>
        /// <returns>The generated key pair.</returns>
        public async Task<KeyPair> GenerateKeyPairAsync(KeyType keyType)
        {
            try
            {
                KeyPair keyPair = await _cryptoProvider.GenerateKeyPairAsync(keyType);

                // Log key generation (without revealing key material)
                LoggingManager.LogInformation(nameof(KeyManager), $"Generated new {keyType} key pair");

                return keyPair;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(KeyManager), $"Failed to generate {keyType} key pair: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Derives a key from input key material.
        /// </summary>
        /// <param name="inputKey">The input key material.</param>
        /// <param name="salt">Optional salt for key derivation.</param>
        /// <param name="info">Optional context info for key derivation.</param>
        /// <param name="length">Desired output key length in bytes.</param>
        /// <returns>The derived key.</returns>
        public async Task<byte[]> DeriveKeyAsync(byte[] inputKey, byte[]? salt = null, byte[]? info = null, int length = 32)
        {
            if (inputKey == null)
                throw new ArgumentNullException(nameof(inputKey));

            if (length <= 0)
                throw new ArgumentOutOfRangeException(nameof(length), "Length must be greater than zero");

            try
            {
                return await _cryptoProvider.DeriveKeyAsync(inputKey, salt, info, length);
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(KeyManager), $"Failed to derive key: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Stores a key securely.
        /// </summary>
        /// <param name="keyId">The identifier for the key.</param>
        /// <param name="key">The key to store.</param>
        /// <param name="password">Optional password for additional protection.</param>
        /// <returns>True if the key was stored successfully.</returns>
        public async Task<bool> StoreKeyAsync(string keyId, byte[] key, string? password = null)
        {
            if (string.IsNullOrEmpty(keyId))
                throw new ArgumentException("Key ID cannot be null or empty", nameof(keyId));

            if (key == null)
                throw new ArgumentNullException(nameof(key));

            try
            {
                bool success = await _cryptoProvider.StoreKeyAsync(keyId, key, password);

                // If storage was successful, update the cache
                if (success)
                {
                    CacheKey(keyId, key);
                }

                return success;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(KeyManager), $"Failed to store key {keyId}: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Retrieves a key from secure storage.
        /// </summary>
        /// <param name="keyId">The identifier for the key.</param>
        /// <param name="password">Optional password if the key was protected with one.</param>
        /// <returns>The retrieved key, or null if not found.</returns>
        public async Task<byte[]?> RetrieveKeyAsync(string keyId, string? password = null)
        {
            if (string.IsNullOrEmpty(keyId))
                throw new ArgumentException("Key ID cannot be null or empty", nameof(keyId));

            try
            {
                // Check the cache first
                if (_keyCache.TryGetValue(keyId, out byte[]? cachedKey))
                {
                    return cachedKey.ToArray(); // Return a copy
                }

                // Not in cache, retrieve from storage
                byte[]? key = await _cryptoProvider.RetrieveKeyAsync(keyId, password);

                // If key was found, update the cache
                if (key != null)
                {
                    CacheKey(keyId, key);
                }

                return key;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(KeyManager), $"Failed to retrieve key {keyId}: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Deletes a key from secure storage.
        /// </summary>
        /// <param name="keyId">The identifier for the key.</param>
        /// <returns>True if the key was deleted successfully.</returns>
        public async Task<bool> DeleteKeyAsync(string keyId)
        {
            if (string.IsNullOrEmpty(keyId))
                throw new ArgumentException("Key ID cannot be null or empty", nameof(keyId));

            try
            {
                // Remove from cache
                _keyCache.TryRemove(keyId, out _);

                // Delete from storage
                return await _cryptoProvider.DeleteKeyAsync(keyId);
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(KeyManager), $"Failed to delete key {keyId}: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Stores a serialized object in secure storage.
        /// </summary>
        /// <param name="keyId">The identifier for the object.</param>
        /// <param name="jsonData">The serialized JSON data to store.</param>
        /// <returns>True if the data was stored successfully.</returns>
        public async Task<bool> StoreJsonAsync(string keyId, string jsonData)
        {
            if (string.IsNullOrEmpty(keyId))
                throw new ArgumentException("Key ID cannot be null or empty", nameof(keyId));

            if (string.IsNullOrEmpty(jsonData))
                throw new ArgumentException("JSON data cannot be null or empty", nameof(jsonData));

            try
            {
                return await _cryptoProvider.StoreJsonAsync(keyId, jsonData);
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(KeyManager), $"Failed to store JSON for {keyId}: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Retrieves a serialized object from secure storage.
        /// </summary>
        /// <param name="keyId">The identifier for the object.</param>
        /// <returns>The serialized JSON data, or null if not found.</returns>
        public async Task<string?> RetrieveJsonAsync(string keyId)
        {
            if (string.IsNullOrEmpty(keyId))
                throw new ArgumentException("Key ID cannot be null or empty", nameof(keyId));

            try
            {
                return await _cryptoProvider.RetrieveJsonAsync(keyId);
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(KeyManager), $"Failed to retrieve JSON for {keyId}: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Rotates a key, generating a new one and securely updating storage.
        /// </summary>
        /// <param name="keyId">The identifier for the key to rotate.</param>
        /// <param name="keyType">The type of key to generate.</param>
        /// <param name="password">Optional password for key protection.</param>
        /// <returns>The new key pair.</returns>
        public async Task<KeyPair> RotateKeyPairAsync(string keyId, KeyType keyType, string? password = null)
        {
            if (string.IsNullOrEmpty(keyId))
                throw new ArgumentException("Key ID cannot be null or empty", nameof(keyId));

            try
            {
                // Generate a new key pair
                KeyPair newKeyPair = await GenerateKeyPairAsync(keyType);

                // Store the private key
                bool success = await StoreKeyAsync($"{keyId}.private", newKeyPair.PrivateKey!, password);
                if (!success)
                {
                    throw new InvalidOperationException($"Failed to store private key for {keyId}");
                }

                // Store the public key
                success = await StoreKeyAsync($"{keyId}.public", newKeyPair.PublicKey!, null);
                if (!success)
                {
                    // Cleanup if partial operation
                    await DeleteKeyAsync($"{keyId}.private");
                    throw new InvalidOperationException($"Failed to store public key for {keyId}");
                }

                // Store rotation metadata
                var metadata = new KeyFileMetadata
                {
                    KeyId = keyId,
                    RotationTimestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    KeyType = keyType.ToString()
                };

                await StoreJsonAsync($"{keyId}.metadata", JsonSerialization.Serialize(metadata));

                LoggingManager.LogInformation(nameof(KeyManager), $"Successfully rotated key {keyId}");
                return newKeyPair;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(KeyManager), $"Failed to rotate key {keyId}: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Gets the remaining time until a key should be rotated.
        /// </summary>
        /// <param name="keyId">The identifier for the key.</param>
        /// <param name="rotationPeriod">The period after which keys should be rotated.</param>
        /// <returns>The time remaining, or TimeSpan.Zero if rotation is needed.</returns>
        public async Task<TimeSpan> GetTimeUntilRotationAsync(string keyId, TimeSpan rotationPeriod)
        {
            if (string.IsNullOrEmpty(keyId))
                throw new ArgumentException("Key ID cannot be null or empty", nameof(keyId));

            try
            {
                // Retrieve rotation metadata
                string? metadataJson = await RetrieveJsonAsync($"{keyId}.metadata");
                if (string.IsNullOrEmpty(metadataJson))
                {
                    // No metadata found, assume rotation is needed
                    return TimeSpan.Zero;
                }

                var metadata = JsonSerialization.Deserialize<KeyFileMetadata>(metadataJson);
                if (metadata == null)
                {
                    // Invalid metadata, assume rotation is needed
                    return TimeSpan.Zero;
                }

                // Calculate time since last rotation
                long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                TimeSpan timeSinceRotation = TimeSpan.FromMilliseconds(now - metadata.RotationTimestamp);

                // Calculate time until next rotation
                if (timeSinceRotation >= rotationPeriod)
                {
                    // Rotation already due
                    return TimeSpan.Zero;
                }

                return rotationPeriod - timeSinceRotation;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(KeyManager), $"Error calculating rotation time for {keyId}: {ex.Message}");

                // In case of error, assume rotation is needed
                return TimeSpan.Zero;
            }
        }

        /// <summary>
        /// Caches a key for faster access.
        /// </summary>
        /// <param name="keyId">The identifier for the key.</param>
        /// <param name="key">The key to cache.</param>
        private void CacheKey(string keyId, byte[] key)
        {
            // Store a copy in the cache
            _keyCache[keyId] = key.ToArray();
        }

        /// <summary>
        /// Cleans up expired entries from the key cache.
        /// </summary>
        private void CleanupCache(object? state)
        {
            try
            {
                // For now, just clear the entire cache
                _keyCache.Clear();
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(KeyManager), $"Error cleaning up key cache: {ex.Message}");
            }
        }

        /// <summary>
        /// Disposes of resources used by the KeyManager.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Disposes of resources used by the KeyManager.
        /// </summary>
        /// <param name="disposing">True if disposing, false if finalizing.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                _cacheCleanupTimer.Dispose();

                // Clear and dispose the key cache
                foreach (var key in _keyCache.Values)
                {
                    SecureMemory.SecureClear(key);
                }
                _keyCache.Clear();

                // Dispose the key storage
                _keyStorage.Dispose();
            }

            _disposed = true;
        }
    }
}