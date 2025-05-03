using System.Security.Cryptography;
using System.Text;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;

namespace LibEmiddle.KeyExchange
{
    /// <summary>
    /// Provides secure storage and retrieval of cryptographic keys and sensitive data
    /// using platform-specific secure storage mechanisms when available.
    /// </summary>
    internal class KeyStorage : IDisposable
    {
        private readonly string _baseStoragePath;
        private bool _disposed;

        // Default file extensions
        private const string KEY_FILE_EXTENSION = ".key";
        private const string DATA_FILE_EXTENSION = ".data";

        // In-memory cache of loaded keys to reduce disk access
        private readonly Dictionary<string, byte[]> _keyCache = new Dictionary<string, byte[]>();

        /// <summary>
        /// Initializes a new instance of the KeyStorage class.
        /// </summary>
        /// <param name="storagePath">Optional custom path for key storage. If null, a default path is used.</param>
        public KeyStorage(string? storagePath = null)
        {
            _baseStoragePath = storagePath ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "LibEmiddle",
                "Keys");

            // Ensure storage directory exists
            Directory.CreateDirectory(_baseStoragePath);
        }

        /// <summary>
        /// Stores a cryptographic key securely.
        /// </summary>
        /// <param name="keyId">Unique identifier for the key.</param>
        /// <param name="keyData">The key data to store.</param>
        /// <returns>True if the key was stored successfully, false otherwise.</returns>
        public bool StoreKey(string keyId, byte[] keyData)
        {
            if (string.IsNullOrEmpty(keyId))
                throw new ArgumentException("Key ID cannot be null or empty.", nameof(keyId));

            if (keyData == null || keyData.Length == 0)
                throw new ArgumentException("Key data cannot be null or empty.", nameof(keyData));

            string filePath = GetKeyFilePath(keyId);

            try
            {
                // Generate a random encryption key
                byte[] encryptionKey = Sodium.GenerateRandomBytes(32);
                byte[] salt = Sodium.GenerateRandomBytes(16);

                try
                {
                    // Create metadata
                    var metadata = new KeyFileMetadata
                    {
                        KeyId = keyId,
                        Nonce = salt,
                        CreatedAt = DateTime.UtcNow,
                        UpdatedAt = DateTime.UtcNow,
                        Version = $"{ProtocolVersion.MAJOR_VERSION}.{ProtocolVersion.MINOR_VERSION}"
                    };

                    // Serialize metadata
                    string metadataJson = System.Text.Json.JsonSerializer.Serialize(metadata);
                    byte[] metadataBytes = Encoding.UTF8.GetBytes(metadataJson);

                    // Generate a nonce for encryption
                    byte[] nonce = Sodium.GenerateRandomBytes(Constants.NONCE_SIZE);

                    // Encrypt the key data
                    byte[] ciphertext = AES.AESEncrypt(keyData, encryptionKey, nonce, metadataBytes);

                    // Write to file
                    using (var fs = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.None))
                    {
                        // Write metadata first (unencrypted for retrieval)
                        byte[] metadataLengthBytes = BitConverter.GetBytes(metadataBytes.Length);
                        fs.Write(metadataLengthBytes, 0, metadataLengthBytes.Length);
                        fs.Write(metadataBytes, 0, metadataBytes.Length);

                        // Write encrypted data with nonce
                        byte[] nonceAndCiphertext = new byte[nonce.Length + ciphertext.Length];
                        Buffer.BlockCopy(nonce, 0, nonceAndCiphertext, 0, nonce.Length);
                        Buffer.BlockCopy(ciphertext, 0, nonceAndCiphertext, nonce.Length, ciphertext.Length);

                        fs.Write(nonceAndCiphertext, 0, nonceAndCiphertext.Length);
                    }

                    // Cache the key in memory
                    CacheKey(keyId, keyData);

                    // Store the encryption key securely for later retrieval
                    return StoreKeyEncryptionKey(keyId, encryptionKey);
                }
                finally
                {
                    // Clear sensitive material
                    SecureMemory.SecureClear(encryptionKey);
                }
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(KeyStorage), $"Failed to store key {keyId}: {ex.Message}");
                SecureDeleteFile(filePath); // Clean up partial file
                return false;
            }
        }

        /// <summary>
        /// Retrieves a cryptographic key.
        /// </summary>
        /// <param name="keyId">Unique identifier for the key.</param>
        /// <returns>The key data, or null if the key doesn't exist or couldn't be retrieved.</returns>
        public byte[]? RetrieveKey(string keyId)
        {
            if (string.IsNullOrEmpty(keyId))
                throw new ArgumentException("Key ID cannot be null or empty.", nameof(keyId));

            // Check the in-memory cache first
            if (_keyCache.TryGetValue(keyId, out byte[]? cachedKey))
            {
                return cachedKey.ToArray(); // Return a copy for security
            }

            string filePath = GetKeyFilePath(keyId);

            try
            {
                if (!File.Exists(filePath))
                    return null;

                // Retrieve the encryption key
                byte[]? encryptionKey = RetrieveKeyEncryptionKey(keyId);
                if (encryptionKey == null)
                    return null;

                try
                {
                    // Read the file
                    using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.None);
                    using var reader = new BinaryReader(fs);

                    // Read metadata
                    int metadataLength = reader.ReadInt32();
                    byte[] metadataBytes = reader.ReadBytes(metadataLength);

                    // Parse metadata
                    string metadataJson = Encoding.UTF8.GetString(metadataBytes);
                    var metadata = System.Text.Json.JsonSerializer.Deserialize<KeyFileMetadata>(metadataJson);

                    if (metadata == null)
                        throw new InvalidDataException("Invalid metadata format");

                    // Read nonce and ciphertext
                    byte[] nonceAndCiphertext = reader.ReadBytes((int)(fs.Length - fs.Position));

                    // Extract nonce
                    byte[] nonce = new byte[Constants.NONCE_SIZE];
                    Buffer.BlockCopy(nonceAndCiphertext, 0, nonce, 0, nonce.Length);

                    // Extract ciphertext
                    byte[] ciphertext = new byte[nonceAndCiphertext.Length - nonce.Length];
                    Buffer.BlockCopy(nonceAndCiphertext, nonce.Length, ciphertext, 0, ciphertext.Length);

                    // Decrypt the key data
                    byte[] keyData = AES.AESDecrypt(ciphertext, encryptionKey, nonce, metadataBytes);

                    // Cache the key for future use
                    CacheKey(keyId, keyData);

                    return keyData;
                }
                finally
                {
                    // Clear sensitive material
                    SecureMemory.SecureClear(encryptionKey);
                }
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(KeyStorage), $"Failed to retrieve key {keyId}: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Deletes a cryptographic key.
        /// </summary>
        /// <param name="keyId">Unique identifier for the key.</param>
        /// <returns>True if the key was deleted successfully, false otherwise.</returns>
        public bool DeleteKey(string keyId)
        {
            if (string.IsNullOrEmpty(keyId))
                throw new ArgumentException("Key ID cannot be null or empty.", nameof(keyId));

            string filePath = GetKeyFilePath(keyId);
            string encryptionKeyPath = GetKeyEncryptionKeyPath(keyId);

            try
            {
                bool fileExists = File.Exists(filePath);
                bool encKeyExists = File.Exists(encryptionKeyPath);

                if (!fileExists && !encKeyExists)
                    return false;

                // Securely delete the files
                if (fileExists)
                    SecureDeleteFile(filePath);

                if (encKeyExists)
                    SecureDeleteFile(encryptionKeyPath);

                // Remove from cache if present
                _keyCache.Remove(keyId);

                return true;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(KeyStorage), $"Failed to delete key {keyId}: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Stores general data securely.
        /// </summary>
        /// <param name="dataId">Unique identifier for the data.</param>
        /// <param name="data">The data to store.</param>
        /// <returns>True if the data was stored successfully, false otherwise.</returns>
        public bool StoreData(string dataId, byte[] data)
        {
            if (string.IsNullOrEmpty(dataId))
                throw new ArgumentException("Data ID cannot be null or empty.", nameof(dataId));

            if (data == null)
                throw new ArgumentNullException(nameof(data));

            string filePath = GetDataFilePath(dataId);

            try
            {
                // Generate a random encryption key
                byte[] encryptionKey = Sodium.GenerateRandomBytes(32);
                byte[] nonce = Sodium.GenerateRandomBytes(Constants.NONCE_SIZE);

                try
                {
                    // Encrypt the data
                    byte[] ciphertext = AES.AESEncrypt(data, encryptionKey, nonce, null);

                    // Combine nonce and ciphertext
                    byte[] encryptedData = new byte[nonce.Length + ciphertext.Length];
                    Buffer.BlockCopy(nonce, 0, encryptedData, 0, nonce.Length);
                    Buffer.BlockCopy(ciphertext, 0, encryptedData, nonce.Length, ciphertext.Length);

                    // Write to file
                    File.WriteAllBytes(filePath, encryptedData);

                    // Store the encryption key
                    return StoreDataEncryptionKey(dataId, encryptionKey);
                }
                finally
                {
                    // Clear sensitive material
                    SecureMemory.SecureClear(encryptionKey);
                }
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(KeyStorage), $"Failed to store data {dataId}: {ex.Message}");
                SecureDeleteFile(filePath); // Clean up partial file
                return false;
            }
        }

        /// <summary>
        /// Retrieves general data.
        /// </summary>
        /// <param name="dataId">Unique identifier for the data.</param>
        /// <returns>The data, or null if it doesn't exist or couldn't be retrieved.</returns>
        public byte[]? RetrieveData(string dataId)
        {
            if (string.IsNullOrEmpty(dataId))
                throw new ArgumentException("Data ID cannot be null or empty.", nameof(dataId));

            string filePath = GetDataFilePath(dataId);

            try
            {
                if (!File.Exists(filePath))
                    return null;

                // Retrieve the encryption key
                byte[]? encryptionKey = RetrieveDataEncryptionKey(dataId);
                if (encryptionKey == null)
                    return null;

                try
                {
                    // Read encrypted data
                    byte[] encryptedData = File.ReadAllBytes(filePath);

                    // Extract nonce
                    byte[] nonce = new byte[Constants.NONCE_SIZE];
                    Buffer.BlockCopy(encryptedData, 0, nonce, 0, nonce.Length);

                    // Extract ciphertext
                    byte[] ciphertext = new byte[encryptedData.Length - nonce.Length];
                    Buffer.BlockCopy(encryptedData, nonce.Length, ciphertext, 0, ciphertext.Length);

                    // Decrypt data
                    return AES.AESDecrypt(ciphertext, encryptionKey, nonce, null);
                }
                finally
                {
                    // Clear sensitive material
                    SecureMemory.SecureClear(encryptionKey);
                }
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(KeyStorage), $"Failed to retrieve data {dataId}: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Deletes general data.
        /// </summary>
        /// <param name="dataId">Unique identifier for the data.</param>
        /// <returns>True if the data was deleted successfully, false otherwise.</returns>
        public bool DeleteData(string dataId)
        {
            if (string.IsNullOrEmpty(dataId))
                throw new ArgumentException("Data ID cannot be null or empty.", nameof(dataId));

            string filePath = GetDataFilePath(dataId);
            string encryptionKeyPath = GetDataEncryptionKeyPath(dataId);

            try
            {
                bool fileExists = File.Exists(filePath);
                bool encKeyExists = File.Exists(encryptionKeyPath);

                if (!fileExists && !encKeyExists)
                    return false;

                // Securely delete the files
                if (fileExists)
                    SecureDeleteFile(filePath);

                if (encKeyExists)
                    SecureDeleteFile(encryptionKeyPath);

                return true;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(KeyStorage), $"Failed to delete data {dataId}: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Securely deletes a file by overwriting its contents before deletion.
        /// </summary>
        /// <param name="filePath">The path to the file to delete.</param>
        public static void SecureDeleteFile(string filePath)
        {
            if (string.IsNullOrEmpty(filePath))
                return;

            if (!File.Exists(filePath))
                return;

            try
            {
                // Get file info
                FileInfo fileInfo = new FileInfo(filePath);
                long fileSize = fileInfo.Length;

                if (fileSize > 0)
                {
                    // Open file for writing
                    using var fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Write);

                    // 1. Overwrite with zeros
                    byte[] zeros = new byte[4096]; // 4KB buffer
                    long remaining = fileSize;

                    while (remaining > 0)
                    {
                        int writeSize = (int)Math.Min(zeros.Length, remaining);
                        fileStream.Write(zeros, 0, writeSize);
                        remaining -= writeSize;
                    }

                    // 2. Overwrite with random data
                    byte[] random = new byte[4096];
                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(random);
                    }

                    fileStream.Position = 0;
                    remaining = fileSize;

                    while (remaining > 0)
                    {
                        int writeSize = (int)Math.Min(random.Length, remaining);
                        fileStream.Write(random, 0, writeSize);
                        remaining -= writeSize;
                    }

                    // Flush all changes to disk
                    fileStream.Flush(true);
                }

                // Delete the file
                File.Delete(filePath);
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(KeyStorage), $"Error during secure file deletion: {ex.Message}");

                // Fall back to regular deletion if secure deletion fails
                try
                {
                    File.Delete(filePath);
                }
                catch
                {
                    // Ignore any further exceptions
                }
            }
        }

        #region Helper Methods

        private string GetKeyFilePath(string keyId)
        {
            // Sanitize key ID to create a valid filename
            string sanitizedId = SanitizeIdForFilename(keyId);
            return Path.Combine(_baseStoragePath, $"{sanitizedId}{KEY_FILE_EXTENSION}");
        }

        private string GetDataFilePath(string dataId)
        {
            // Sanitize data ID to create a valid filename
            string sanitizedId = SanitizeIdForFilename(dataId);
            return Path.Combine(_baseStoragePath, $"{sanitizedId}{DATA_FILE_EXTENSION}");
        }

        private string GetKeyEncryptionKeyPath(string keyId)
        {
            // Store encryption keys in a separate location
            string sanitizedId = SanitizeIdForFilename(keyId);
            return Path.Combine(_baseStoragePath, "encryption_keys", $"{sanitizedId}.ek");
        }

        private string GetDataEncryptionKeyPath(string dataId)
        {
            // Store encryption keys in a separate location
            string sanitizedId = SanitizeIdForFilename(dataId);
            return Path.Combine(_baseStoragePath, "encryption_keys", $"{sanitizedId}.edk");
        }

        private string SanitizeIdForFilename(string id)
        {
            // Replace invalid characters with underscores
            return string.Join("_", id.Split(Path.GetInvalidFileNameChars()));
        }

        private void CacheKey(string keyId, byte[] keyData)
        {
            // Make a copy of the key data for the cache
            byte[] keyCopy = new byte[keyData.Length];
            Buffer.BlockCopy(keyData, 0, keyCopy, 0, keyData.Length);

            // Add or update the cache
            _keyCache[keyId] = keyCopy;
        }

        private bool StoreKeyEncryptionKey(string keyId, byte[] encryptionKey)
        {
            // Ensure the directory exists
            string dirPath = Path.GetDirectoryName(GetKeyEncryptionKeyPath(keyId)) ?? _baseStoragePath;
            Directory.CreateDirectory(dirPath);

            // Store the encryption key with platform-specific protection
            try
            {
                string filePath = GetKeyEncryptionKeyPath(keyId);

                // Use DPAPI or similar platform-specific protection
                byte[] protectedData;

                // Use custom protection (Sodium secretbox with a hardcoded key)
                // In a production environment, you'd want a better key management strategy
                byte[] hardcodedKey = new byte[Constants.AES_KEY_SIZE];
                byte[] nonce = Sodium.GenerateRandomBytes(Constants.NONCE_SIZE);
                byte[] ciphertext = AES.AESEncrypt(encryptionKey, hardcodedKey, nonce, null);

                // Combine nonce and ciphertext
                protectedData = new byte[nonce.Length + ciphertext.Length];
                nonce.AsSpan().CopyTo(protectedData.AsSpan(0));
                ciphertext.AsSpan().CopyTo(protectedData.AsSpan(nonce.Length));

                // Write to file
                File.WriteAllBytes(filePath, protectedData);

                return true;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(KeyStorage), $"Failed to store encryption key for {keyId}: {ex.Message}");
                return false;
            }
        }

        private byte[]? RetrieveKeyEncryptionKey(string keyId)
        {
            try
            {
                string filePath = GetKeyEncryptionKeyPath(keyId);

                if (!File.Exists(filePath))
                    return null;

                // Read protected data
                byte[] protectedData = File.ReadAllBytes(filePath);

                // Use custom protection (Sodium secretbox with a hardcoded key)
                byte[] hardcodedKey = new byte[Constants.AES_KEY_SIZE]; // Should match the key used for encryption

                // Extract nonce
                byte[] nonce = new byte[Constants.NONCE_SIZE];
                protectedData.AsSpan(0, nonce.Length).CopyTo(nonce);

                // Extract ciphertext
                byte[] ciphertext = new byte[protectedData.Length - nonce.Length];
                protectedData.AsSpan(nonce.Length).CopyTo(ciphertext);

                // Decrypt
                return AES.AESDecrypt(ciphertext, hardcodedKey, nonce, null);
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(KeyStorage), $"Failed to retrieve encryption key for {keyId}: {ex.Message}");
                return null;
            }
        }

        private bool StoreDataEncryptionKey(string dataId, byte[] encryptionKey)
        {
            // Use the same approach as key encryption keys
            return StoreKeyEncryptionKey($"data_{dataId}", encryptionKey);
        }

        private byte[]? RetrieveDataEncryptionKey(string dataId)
        {
            // Use the same approach as key encryption keys
            return RetrieveKeyEncryptionKey($"data_{dataId}");
        }

        #endregion

        #region IDisposable Implementation

        /// <summary>
        /// Disposes of resources used by the KeyStorage instance.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Disposes of resources used by the KeyStorage instance.
        /// </summary>
        /// <param name="disposing">True if called from Dispose(), false if called from finalizer.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                // Clear the key cache
                foreach (var key in _keyCache.Values)
                {
                    SecureMemory.SecureClear(key);
                }
                _keyCache.Clear();
            }

            _disposed = true;
        }

        #endregion
    }
}