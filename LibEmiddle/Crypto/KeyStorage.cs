using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
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
        public static void StoreKeyToFile(ReadOnlySpan<byte> key, string filePath, string? password = null, int saltRotationDays = 30)
        {
            if (key.IsEmpty)
                throw new ArgumentException("Key cannot be empty", nameof(key));

            byte[] finalData;

            if (!string.IsNullOrEmpty(password))
            {
                // Generate salt and nonce
                byte[] salt = SecureMemory.CreateSecureBuffer(Constants.DEFAULT_SALT_SIZE);
                byte[] nonce = NonceGenerator.GenerateNonce();

                long timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                byte[] derivedKey = DeriveKeyFromPassword(password, salt);
                byte[] encryptedKey = AES.AESEncrypt(key.ToArray(), derivedKey, nonce);
                SecureMemory.SecureClear(derivedKey);

                var metadata = new KeyFileMetadata
                {
                    Version = 1,
                    CreatedAt = timestamp,
                    RotationPeriodDays = saltRotationDays,
                    LastRotated = timestamp
                };

                byte[] metadataBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(metadata));
                byte[] metadataLength = BitConverter.GetBytes(metadataBytes.Length);

                int totalSize =
                    metadataLength.Length +
                    metadataBytes.Length +
                    salt.Length +
                    nonce.Length +
                    encryptedKey.Length;

                finalData = new byte[totalSize];
                int offset = 0;

                metadataLength.CopyTo(finalData, offset); offset += metadataLength.Length;
                metadataBytes.CopyTo(finalData, offset); offset += metadataBytes.Length;
                salt.CopyTo(finalData, offset); offset += salt.Length;
                nonce.CopyTo(finalData, offset); offset += nonce.Length;
                encryptedKey.CopyTo(finalData, offset);

                // Optional: Secure clear temp buffers
                SecureMemory.SecureClear(encryptedKey);
                SecureMemory.SecureClear(salt);
                SecureMemory.SecureClear(nonce);
            }
            else
            {
                // Store plaintext key if no password
                finalData = key.ToArray(); // still make a copy to avoid writing read-only buffer
            }

            File.WriteAllBytes(filePath, finalData);
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
                throw new FileNotFoundException("Key file not found", filePath);

            byte[] storedData = File.ReadAllBytes(filePath);

            if (string.IsNullOrEmpty(password))
                return storedData; // Unencrypted key

            try
            {
                if (storedData.Length < sizeof(int))
                    throw new InvalidDataException("Invalid key file format: missing metadata length.");

                int metadataLength = BitConverter.ToInt32(storedData, 0);

                if (metadataLength <= 0 || metadataLength > 1024 || storedData.Length < metadataLength + 4)
                    throw new InvalidDataException("Invalid metadata length or truncated key file.");

                // Parse metadata
                Span<byte> metadataSpan = storedData.AsSpan(4, metadataLength);
                var metadata = JsonSerializer.Deserialize<KeyFileMetadata>(Encoding.UTF8.GetString(metadataSpan))
                               ?? throw new InvalidDataException("Invalid or missing key metadata.");

                // Calculate offsets
                int offset = 4 + metadataLength;
                Span<byte> saltSpan = storedData.AsSpan(offset, Constants.DEFAULT_SALT_SIZE);
                offset += Constants.DEFAULT_SALT_SIZE;

                Span<byte> nonceSpan = storedData.AsSpan(offset, Constants.NONCE_SIZE);
                offset += Constants.NONCE_SIZE;

                Span<byte> encryptedKeySpan = storedData.AsSpan(offset, storedData.Length - offset);

                // Derive encryption key
                byte[] derivedKey = DeriveKeyFromPassword(password, saltSpan.ToArray());
                byte[] decryptedKey = AES.AESDecrypt(encryptedKeySpan.ToArray(), derivedKey, nonceSpan.ToArray());
                SecureMemory.SecureClear(derivedKey);

                // Check if rotation is needed
                long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                long daysSinceRotation = (now - metadata.LastRotated) / (1000L * 60 * 60 * 24);
                bool needsRotation = forceRotation || daysSinceRotation >= metadata.RotationPeriodDays;

                if (needsRotation)
                {
                    StoreKeyToFile(decryptedKey, filePath, password, metadata.RotationPeriodDays);
                }

                return decryptedKey;
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
                    byte[] randomBuffer = SecureMemory.CreateSecureBuffer(4096);

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