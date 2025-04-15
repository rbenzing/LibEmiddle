using System.Security.Cryptography;
using System.Text;
using LibEmiddle.Core;
using LibEmiddle.Domain;

namespace LibEmiddle.Crypto
{
    /// <summary>
    /// Provides functionality for securely storing and retrieving cryptographic keys
    /// </summary>
    internal static class KeyStorage
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
                byte[] salt = Sodium.GenerateRandomBytes(Constants.DEFAULT_SALT_SIZE);
                RandomNumberGenerator.Fill(salt);

                // Store creation timestamp for salt rotation
                long timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

                // Derive encryption key from password
                byte[] derivedKey = DeriveKeyFromPassword(password, salt);

                // Generate a secure nonce
                byte[] nonce = NonceGenerator.GenerateNonce();

                // Encrypt the key
                byte[] encryptedKey = AES.AESEncrypt(key, derivedKey, nonce);

                // Securely clear derived key after use
                SecureMemory.SecureClear(derivedKey);

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

                // Calculate total size needed
                int totalSize = metadataLength.Length +
                                metadataBytes.Length +
                                salt.Length +
                                nonce.Length +
                                encryptedKey.Length;

                // Use SecureMemory to create a secure buffer for the output
                byte[] result = SecureMemory.CreateSecureBuffer(totalSize);

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

            // Write to file
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
                        byte[] metadataBytes = Sodium.GenerateRandomBytes(metadataLength);
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
                            byte[] salt = Sodium.GenerateRandomBytes(Constants.DEFAULT_SALT_SIZE); // Using constant for consistency
                            byte[] nonce = Sodium.GenerateRandomBytes(Constants.NONCE_SIZE);
                            byte[] encryptedKey = Sodium.GenerateRandomBytes(storedData.Length - offset - salt.Length - nonce.Length);

                            // Copy salt data - using spans for efficient memory handling
                            storedData.AsSpan(offset, salt.Length).CopyTo(salt.AsSpan());
                            offset += salt.Length;

                            // Copy nonce data
                            storedData.AsSpan(offset, nonce.Length).CopyTo(nonce.AsSpan());
                            offset += nonce.Length;

                            // Copy encrypted key data
                            storedData.AsSpan(offset, encryptedKey.Length).CopyTo(encryptedKey.AsSpan());

                            // Derive key using PBKDF2 with our standard parameters
                            byte[] derivedKey = DeriveKeyFromPassword(password, salt);

                            // Decrypt the key
                            byte[] decryptedKey = AES.AESDecrypt(encryptedKey, derivedKey, nonce);

                            // Securely clear the derived key when done with it
                            SecureMemory.SecureClear(derivedKey);

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
                byte[] oldSalt = Sodium.GenerateRandomBytes(16);
                byte[] oldNonce = Sodium.GenerateRandomBytes(Constants.NONCE_SIZE);
                byte[] oldEncryptedKey = Sodium.GenerateRandomBytes(storedData.Length - oldSalt.Length - oldNonce.Length);

                // Use spans for efficient memory copying
                storedData.AsSpan(0, oldSalt.Length).CopyTo(oldSalt.AsSpan());
                storedData.AsSpan(oldSalt.Length, oldNonce.Length).CopyTo(oldNonce.AsSpan());
                storedData.AsSpan(oldSalt.Length + oldNonce.Length, oldEncryptedKey.Length).CopyTo(oldEncryptedKey.AsSpan());

                // Derive key from password
                byte[] oldDerivedKey = DeriveKeyFromPassword(password, oldSalt);

                // Decrypt the key
                byte[] decryptedOldKey = AES.AESDecrypt(oldEncryptedKey, oldDerivedKey, oldNonce);

                // Securely clear the derived key
                SecureMemory.SecureClear(oldDerivedKey);

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

        /// <summary>
        /// Securely deletes a file
        /// </summary>
        /// <param name="filePath"></param>
        public static void SecureDeleteFile(string filePath)
        {
            if (!File.Exists(filePath))
                return;

            try
            {
                // Get file info to determine size
                var fileInfo = new FileInfo(filePath);
                long fileSize = fileInfo.Length;

                // Open the file for writing
                using (var fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Write))
                {
                    // Create a buffer of random data
                    byte[] randomBuffer = Sodium.GenerateRandomBytes(4096);

                    // Overwrite file with random data multiple times
                    for (int i = 0; i < 3; i++)
                    {
                        fileStream.Position = 0;

                        // Write in chunks
                        long remaining = fileSize;
                        while (remaining > 0)
                        {
                            int writeSize = (int)Math.Min(randomBuffer.Length, remaining);
                            fileStream.Write(randomBuffer, 0, writeSize);
                            remaining -= writeSize;
                        }

                        fileStream.Flush();
                    }

                    // Final pass with zeros
                    fileStream.Position = 0;
                    new Span<byte>(randomBuffer).Fill(0);

                    long remainingZero = fileSize;
                    while (remainingZero > 0)
                    {
                        int writeSize = (int)Math.Min(randomBuffer.Length, remainingZero);
                        fileStream.Write(randomBuffer, 0, writeSize);
                        remainingZero -= writeSize;
                    }

                    fileStream.Flush();

                    // Clear the buffer
                    SecureMemory.SecureClear(randomBuffer);
                }

                // Finally delete the file
                File.Delete(filePath);
            }
            catch (Exception ex)
            {
                // Log error but don't throw - best effort cleanup
                LoggingManager.LogError(nameof(KeyStorage), $"Error securely deleting file: {ex.Message}");

                // Try regular delete as fallback
                try { File.Delete(filePath); } catch { }
            }
        }

        /// <summary>
        /// Helper method to derive a key from a password using PBKDF2
        /// </summary>
        private static byte[] DeriveKeyFromPassword(string password, byte[] salt)
        {
            using var deriveBytes = new Rfc2898DeriveBytes(
                password,
                salt,
                Constants.PBKDF2_ITERATIONS,
                HashAlgorithmName.SHA256);

            return deriveBytes.GetBytes(Constants.AES_KEY_SIZE);
        }
    }
}