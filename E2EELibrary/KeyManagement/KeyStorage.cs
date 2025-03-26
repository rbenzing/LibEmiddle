using System.Security.Cryptography;
using System.Text;
using E2EELibrary.Core;
using E2EELibrary.Encryption;
using E2EELibrary.Models;

namespace E2EELibrary.KeyManagement
{
    /// <summary>
    /// Provides functionality for securely storing and retrieving cryptographic keys
    /// </summary>
    public static class KeyStorage
    {
        /// <summary>
        /// Securely stores a key to a file with optional password protection and salt rotation
        /// </summary>
        /// <param name="key">Key to store</param>
        /// <param name="filePath">Path where the key will be stored</param>
        /// <param name="password">Optional password for additional encryption</param>
        /// <param name="saltRotationDays">Number of days after which the salt should be rotated (default: 30)</param>
        public static void StoreKeyToFile(byte[] key, string filePath, string? password = null, int saltRotationDays = 30)
        {
            if (key == null)
                throw new ArgumentException("Key cannot be null", nameof(key));
            if (key.Length == 0)
                throw new ArgumentException("Key cannot be empty", nameof(key));

            byte[] dataToStore = key;

            // If password is provided, encrypt the key before storing
            if (!string.IsNullOrEmpty(password))
            {
                // Generate salt with high entropy
                byte[] salt = new byte[32];
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(salt);
                }

                // Store creation timestamp for salt rotation
                long timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

                // Use Argon2id where available, fallback to PBKDF2 with high iteration count
                byte[] derivedKey;
                try
                {
                    // we use PBKDF2 with increased parameters
                    using var deriveBytes = new Rfc2898DeriveBytes(
                        password,
                        salt,
                        Constants.PBKDF2_ITERATIONS,
                        HashAlgorithmName.SHA256);

                    derivedKey = deriveBytes.GetBytes(Constants.AES_KEY_SIZE);
                }
                catch
                {
                    // Fallback to standard PBKDF2 if custom implementation fails
                    using var deriveBytes = new Rfc2898DeriveBytes(
                        password,
                        salt,
                        Constants.PBKDF2_ITERATIONS,
                        HashAlgorithmName.SHA256);

                    derivedKey = deriveBytes.GetBytes(Constants.AES_KEY_SIZE);
                }

                byte[] nonce = NonceGenerator.GenerateNonce();
                byte[] encryptedKey = AES.AESEncrypt(key, derivedKey, nonce);

                // Create metadata for salt rotation
                var metadata = new KeyFileMetadata
                {
                    Version = 1,
                    CreatedAt = timestamp,
                    RotationPeriodDays = saltRotationDays,
                    LastRotated = timestamp
                };

                // Serialize metadata
                string metadataJson = System.Text.Json.JsonSerializer.Serialize(metadata);
                byte[] metadataBytes = Encoding.UTF8.GetBytes(metadataJson);
                byte[] metadataLength = BitConverter.GetBytes(metadataBytes.Length);

                // Combine all components: 
                // [metadata length (4 bytes)][metadata][salt][nonce][encrypted key]
                byte[] result = new byte[
                    metadataLength.Length +
                    metadataBytes.Length +
                    salt.Length +
                    nonce.Length +
                    encryptedKey.Length
                ];

                int offset = 0;

                // Copy metadata length
                metadataLength.AsSpan().CopyTo(result.AsSpan(offset, metadataLength.Length));
                offset += metadataLength.Length;

                // Copy metadata bytes
                metadataBytes.AsSpan().CopyTo(result.AsSpan(offset, metadataBytes.Length));
                offset += metadataBytes.Length;

                // Copy salt
                salt.AsSpan().CopyTo(result.AsSpan(offset, salt.Length));
                offset += salt.Length;

                // Copy nonce
                nonce.AsSpan().CopyTo(result.AsSpan(offset, nonce.Length));
                offset += nonce.Length;

                // Copy encrypted key
                encryptedKey.AsSpan().CopyTo(result.AsSpan(offset, encryptedKey.Length));

                dataToStore = result;
            }

            File.WriteAllBytes(filePath, dataToStore);
        }

        /// <summary>
        /// Loads a key from a file, decrypting it if it was password-protected
        /// and handling salt rotation if needed
        /// </summary>
        /// <param name="filePath">Path to the stored key</param>
        /// <param name="password">Password if the key was encrypted</param>
        /// <param name="forceRotation">Force salt rotation regardless of time elapsed</param>
        /// <returns>The loaded key</returns>
        public static byte[] LoadKeyFromFile(string filePath, string? password = null, bool forceRotation = false)
        {
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException("Key file not found", filePath);
            }

            byte[] storedData = File.ReadAllBytes(filePath);

            // If no password, assume unencrypted key
            if (string.IsNullOrEmpty(password))
            {
                return storedData;
            }

            try
            {
                // Check if this is a new format key file (with metadata)
                if (storedData.Length >= 4)
                {
                    int metadataLength = BitConverter.ToInt32(storedData, 0);

                    // Basic sanity check for metadata length
                    if (metadataLength > 0 && metadataLength < 1024 && metadataLength <= storedData.Length - 4)
                    {
                        // This is a new format file with metadata
                        byte[] metadataBytes = new byte[metadataLength];
                        storedData.AsSpan(4, metadataLength).CopyTo(metadataBytes);

                        string metadataJson = Encoding.UTF8.GetString(metadataBytes);
                        var metadata = System.Text.Json.JsonSerializer.Deserialize<KeyFileMetadata>(metadataJson);

                        if (metadata != null)
                        {
                            // Check if salt rotation is needed
                            bool needsRotation = forceRotation;
                            long currentTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                            long daysSinceLastRotation = (currentTime - metadata.LastRotated) / (1000 * 60 * 60 * 24);

                            if (daysSinceLastRotation >= metadata.RotationPeriodDays)
                            {
                                needsRotation = true;
                            }

                            // Extract salt, nonce, and encrypted key
                            int offset = 4 + metadataLength;
                            byte[] salt = new byte[Constants.DEFAULT_SALT_SIZE]; // Using 32-byte salt in new format
                            byte[] nonce = new byte[Constants.NONCE_SIZE];
                            byte[] encryptedKey = new byte[storedData.Length - offset - salt.Length - nonce.Length];

                            // Copy salt data
                            storedData.AsSpan(offset, salt.Length).CopyTo(salt);
                            offset += salt.Length;

                            // Copy nonce data
                            storedData.AsSpan(offset, nonce.Length).CopyTo(nonce);
                            offset += nonce.Length;

                            // Copy encrypted key data
                            storedData.AsSpan(offset, encryptedKey.Length).CopyTo(encryptedKey);

                            // Derive key using the same parameters
                            byte[] derivedKey;
                            try
                            {
                                // Try to use Argon2id if available
                                // derivedKey = Argon2.DeriveKey(password, salt, iterations: 3, memory: 65536, parallelism: 4, keyLength: AES_KEY_SIZE);

                                using var deriveBytes = new Rfc2898DeriveBytes(
                                    password,
                                    salt,
                                    Constants.PBKDF2_ITERATIONS,
                                    HashAlgorithmName.SHA256);

                                derivedKey = deriveBytes.GetBytes(Constants.AES_KEY_SIZE);
                            }
                            catch
                            {
                                using var deriveBytes = new Rfc2898DeriveBytes(
                                    password,
                                    salt,
                                    Constants.PBKDF2_ITERATIONS,
                                    HashAlgorithmName.SHA256);

                                derivedKey = deriveBytes.GetBytes(Constants.AES_KEY_SIZE);
                            }

                            // Decrypt the key
                            byte[] decryptedKey = AES.AESDecrypt(encryptedKey, derivedKey, nonce);

                            // If rotation is needed, store the key with a new salt
                            if (needsRotation)
                            {
                                StoreKeyToFile(decryptedKey, filePath, password, metadata.RotationPeriodDays);
                            }

                            return decryptedKey;
                        }
                    }
                }

                // Fall back to old format (for backward compatibility)
                byte[] oldSalt = new byte[16];
                byte[] oldNonce = new byte[Constants.NONCE_SIZE];
                byte[] oldEncryptedKey = new byte[storedData.Length - oldSalt.Length - oldNonce.Length];

                // Create spans for the source and destination arrays
                ReadOnlySpan<byte> storedDataSpan = storedData.AsSpan();

                // Copy the salt, nonce, and encrypted key portions
                storedDataSpan.Slice(0, oldSalt.Length).CopyTo(oldSalt.AsSpan());
                storedDataSpan.Slice(oldSalt.Length, oldNonce.Length).CopyTo(oldNonce.AsSpan());
                storedDataSpan.Slice(oldSalt.Length + oldNonce.Length, oldEncryptedKey.Length).CopyTo(oldEncryptedKey.AsSpan());

                using var oldDeriveBytes = new Rfc2898DeriveBytes(
                    password,
                    oldSalt,
                    310000,
                    HashAlgorithmName.SHA256);

                byte[] oldDerivedKey = oldDeriveBytes.GetBytes(Constants.AES_KEY_SIZE);
                byte[] decryptedOldKey = AES.AESDecrypt(oldEncryptedKey, oldDerivedKey, oldNonce);

                // Automatically upgrade to new format with salt rotation
                StoreKeyToFile(decryptedOldKey, filePath, password);

                return decryptedOldKey;
            }
            catch (CryptographicException ex)
            {
                throw new CryptographicException("Failed to decrypt the key file. The password may be incorrect.", ex);
            }
            catch (Exception ex)
            {
                throw new InvalidDataException("The key file appears to be corrupted or invalid.", ex);
            }
        }
    }
}