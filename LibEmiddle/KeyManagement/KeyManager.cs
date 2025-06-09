using System.Collections.Concurrent;
using LibEmiddle.Abstractions;
using LibEmiddle.Core;
using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;

namespace LibEmiddle.KeyManagement
{
    /// <summary>
    /// Implements the IKeyManager interface, providing management of cryptographic keys
    /// including generation, derivation, storage, retrieval, and rotation.
    /// </summary>
    public class KeyManager : IKeyManager, IDisposable
    {
        private readonly ICryptoProvider _cryptoProvider;
        private readonly KeyStorage _keyStorage;
        private readonly ConcurrentDictionary<string, CachedKey> _keyCache = new();
        private readonly TimeSpan _cacheExpiration = TimeSpan.FromMinutes(10);
        private readonly Timer _cacheCleanupTimer;
        private readonly object _cacheLock = new object();
        private bool _disposed;

        /// <summary>
        /// Represents a cached key with expiration time
        /// </summary>
        private sealed class CachedKey : IDisposable
        {
            public byte[] Key { get; private set; }
            public DateTime ExpirationTime { get; }
            private bool _disposed;

            public CachedKey(byte[] key, TimeSpan expiration)
            {
                Key = new byte[key.Length];
                Array.Copy(key, Key, key.Length);
                ExpirationTime = DateTime.UtcNow.Add(expiration);
            }

            public byte[] GetKeyCopy()
            {
                if (_disposed)
                    throw new ObjectDisposedException(nameof(CachedKey));

                var copy = new byte[Key.Length];
                Array.Copy(Key, copy, Key.Length);
                return copy;
            }

            public bool IsExpired => DateTime.UtcNow > ExpirationTime;

            public void Dispose()
            {
                if (!_disposed)
                {
                    SecureMemory.SecureClear(Key);
                    _disposed = true;
                }
            }
        }

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

        /// <inheritdoc/>
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

        /// <inheritdoc/>
        public async Task<byte[]?> RetrieveKeyAsync(string keyId, string? password = null)
        {
            if (string.IsNullOrEmpty(keyId))
                throw new ArgumentException("Key ID cannot be null or empty", nameof(keyId));

            try
            {
                // Check the cache first with secure handling
                lock (_cacheLock)
                {
                    if (_keyCache.TryGetValue(keyId, out CachedKey? cachedKey))
                    {
                        if (!cachedKey.IsExpired)
                        {
                            return cachedKey.GetKeyCopy(); // Return a secure copy
                        }
                        else
                        {
                            // Remove expired key
                            _keyCache.TryRemove(keyId, out _);
                            cachedKey.Dispose();
                        }
                    }
                }

                // Not in cache, retrieve from storage
                byte[]? key = await _cryptoProvider.RetrieveKeyAsync(keyId, password);

                // If key was found, update the cache
                if (key != null)
                {
                    CacheKey(keyId, key);
                }

                if (key == null)
                    throw new FileNotFoundException();

                return key;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(KeyManager), $"Failed to retrieve key {keyId}: {ex.Message}");
                return null;
            }
        }

        /// <inheritdoc/>
        public async Task<bool> DeleteKeyAsync(string keyId, string? password = null)
        {
            if (string.IsNullOrEmpty(keyId))
                throw new ArgumentException("Key ID cannot be null or empty", nameof(keyId));

            // Get the key first to authenticate
            byte[]? success = RetrieveKeyAsync(keyId, password).GetAwaiter().GetResult();
            if (success == null)
            {
                return false;
            }

            try
            {
                // Remove from cache with secure disposal
                lock (_cacheLock)
                {
                    if (_keyCache.TryRemove(keyId, out CachedKey? cachedKey))
                    {
                        cachedKey.Dispose();
                    }
                }

                // Delete from storage
                return await _cryptoProvider.DeleteKeyAsync(keyId);
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(KeyManager), $"Failed to delete key {keyId}: {ex.Message}");
                return false;
            }
        }

        /// <inheritdoc/>
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

        /// <inheritdoc/>
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

        /// <inheritdoc/>
        public async Task<KeyPair> RotateKeyPairAsync(string keyId, KeyType keyType, string? password = null)
        {
            if (string.IsNullOrEmpty(keyId))
                throw new ArgumentException("Key ID cannot be null or empty", nameof(keyId));

            try
            {
                // Generate a new key pair
                KeyPair newKeyPair = keyType == KeyType.Ed25519 ? Sodium.GenerateEd25519KeyPair() : Sodium.GenerateX25519KeyPair();

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

        /// <inheritdoc/>
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
        /// Caches a key for faster access with secure handling.
        /// </summary>
        /// <param name="keyId">The identifier for the key.</param>
        /// <param name="key">The key to cache.</param>
        private void CacheKey(string keyId, byte[] key)
        {
            lock (_cacheLock)
            {
                // Remove existing cached key if present
                if (_keyCache.TryRemove(keyId, out CachedKey? existingKey))
                {
                    existingKey.Dispose();
                }

                // Store new cached key with expiration
                _keyCache[keyId] = new CachedKey(key, _cacheExpiration);
            }
        }

        /// <summary>
        /// Cleans up expired entries from the key cache.
        /// </summary>
        private void CleanupCache(object? state)
        {
            try
            {
                lock (_cacheLock)
                {
                    var expiredKeys = new List<string>();

                    // Find expired keys
                    foreach (var kvp in _keyCache)
                    {
                        if (kvp.Value.IsExpired)
                        {
                            expiredKeys.Add(kvp.Key);
                        }
                    }

                    // Remove and dispose expired keys
                    foreach (var keyId in expiredKeys)
                    {
                        if (_keyCache.TryRemove(keyId, out CachedKey? cachedKey))
                        {
                            cachedKey.Dispose();
                        }
                    }
                }
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

                // Clear and dispose the key cache securely
                lock (_cacheLock)
                {
                    foreach (var cachedKey in _keyCache.Values)
                    {
                        cachedKey.Dispose();
                    }
                    _keyCache.Clear();
                }

                // Dispose the key storage
                _keyStorage.Dispose();
            }

            _disposed = true;
        }
    }
}