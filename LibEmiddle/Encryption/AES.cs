using System.Security.Cryptography;
using System.Buffers;
using System.Text;
using E2EELibrary.Core;
using E2EELibrary.Models;

namespace E2EELibrary.Encryption
{
    /// <summary>
    /// Provides AES-GCM encryption and decryption functionality
    /// </summary>
    public class AES
    {
        /// <summary>
        /// Encrypts data using AES-GCM
        /// </summary>
        /// <param name="plaintext">Data to encrypt</param>
        /// <param name="key">Encryption key</param>
        /// <param name="nonce">Nonce for AES-GCM</param>
        /// <returns>Encrypted data with authentication tag</returns>
        public static byte[] AESEncrypt(byte[] plaintext, byte[] key, byte[] nonce)
        {
            if (plaintext == null)
                throw new ArgumentNullException(nameof(plaintext));
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (nonce == null)
                throw new ArgumentNullException(nameof(nonce));

            if (key.Length != Constants.AES_KEY_SIZE)
                throw new ArgumentException($"Key must be {Constants.AES_KEY_SIZE} bytes long", nameof(key));
            if (nonce.Length != Constants.NONCE_SIZE)
                throw new ArgumentException($"Nonce must be {Constants.NONCE_SIZE} bytes long", nameof(nonce));

            using var aes = new AesGcm(key, Constants.AUTH_TAG_SIZE);

            // Use our helper to get a buffer for ciphertext from the pool
            byte[] pooledCiphertext = SecureMemory.CreateSecureBuffer(plaintext.Length);

            try
            {
                // Create an auth tag array (small, so direct allocation is fine)
                byte[] tag = Sodium.GenerateRandomBytes(Constants.AUTH_TAG_SIZE);

                // Encrypt directly into these buffers
                aes.Encrypt(nonce, plaintext, pooledCiphertext, tag);

                // Combine ciphertext and tag for easier handling
                byte[] result = Sodium.GenerateRandomBytes(plaintext.Length + Constants.AUTH_TAG_SIZE);
                pooledCiphertext.AsSpan(0, pooledCiphertext.Length).CopyTo(result.AsSpan(0, plaintext.Length));
                tag.AsSpan(0, Constants.AUTH_TAG_SIZE).CopyTo(result.AsSpan(plaintext.Length, Constants.AUTH_TAG_SIZE));

                return result;
            }
            finally
            {
                // Return the rented buffer to the pool if it was pooled
                if (pooledCiphertext.Length > plaintext.Length)
                {
                    ArrayPool<byte>.Shared.Return(pooledCiphertext);
                }
            }
        }

        /// <summary>
        /// Decrypts data using AES-GCM
        /// </summary>
        /// <param name="ciphertextWithTag">Combined ciphertext and authentication tag</param>
        /// <param name="key">Decryption key</param>
        /// <param name="nonce">Nonce used for encryption</param>
        /// <returns>Decrypted data</returns>
        public static byte[] AESDecrypt(byte[] ciphertextWithTag, byte[] key, byte[] nonce)
        {
            if (ciphertextWithTag == null)
                throw new ArgumentNullException(nameof(ciphertextWithTag));
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (nonce == null)
                throw new ArgumentNullException(nameof(nonce));

            if (key.Length != Constants.AES_KEY_SIZE)
                throw new ArgumentException($"Key must be {Constants.AES_KEY_SIZE} bytes long", nameof(key));
            if (nonce.Length != Constants.NONCE_SIZE)
                throw new ArgumentException($"Nonce must be {Constants.NONCE_SIZE} bytes long", nameof(nonce));
            if (ciphertextWithTag.Length < Constants.AUTH_TAG_SIZE)
                throw new ArgumentException("Ciphertext too short to contain tag", nameof(ciphertextWithTag));

            using var aes = new AesGcm(key, Constants.AUTH_TAG_SIZE);

            // Extract ciphertext and tag
            int ciphertextLength = ciphertextWithTag.Length - Constants.AUTH_TAG_SIZE;

            // Use our helper to get a buffer for plaintext from the pool
            byte[] pooledPlaintext = SecureMemory.CreateSecureBuffer(ciphertextLength);

            try
            {
                // Extract ciphertext and tag directly into new arrays
                byte[] ciphertext = Sodium.GenerateRandomBytes(ciphertextLength);
                byte[] tag = Sodium.GenerateRandomBytes(Constants.AUTH_TAG_SIZE);
                Buffer.BlockCopy(ciphertextWithTag, 0, ciphertext, 0, ciphertextLength);
                Buffer.BlockCopy(ciphertextWithTag, ciphertextLength, tag, 0, Constants.AUTH_TAG_SIZE);

                try
                {
                    // Use the AesGcm Decrypt method with standard arrays
                    aes.Decrypt(nonce, ciphertext, tag, pooledPlaintext);

                    // If we got a pooled buffer that's larger than needed, we need to copy
                    // the result to a properly sized array
                    if (pooledPlaintext.Length > ciphertextLength)
                    {
                        byte[] result = Sodium.GenerateRandomBytes(ciphertextLength);
                        pooledPlaintext.AsSpan(0, pooledPlaintext.Length).CopyTo(result.AsSpan(0, ciphertextLength));

                        return result;
                    }
                    else
                    {
                        // If we got an exact-sized buffer, we can return it directly
                        return pooledPlaintext;
                    }
                }
                catch (CryptographicException ex)
                {
                    throw new CryptographicException("Authentication failed. The data may have been tampered with or the wrong key was used.", ex);
                }
            }
            finally
            {
                // Clear sensitive data before returning the buffer
                if (pooledPlaintext.Length > ciphertextLength)
                {
                    SecureMemory.SecureClear(pooledPlaintext);

                    // Return the pooled buffer if it was pooled
                    ArrayPool<byte>.Shared.Return(pooledPlaintext);
                }
            }
        }

        /// <summary>
        /// Encrypts a message with a simple API, including nonce generation
        /// </summary>
        /// <param name="message">Message to encrypt</param>
        /// <param name="key">AES-256 encryption key (32 bytes)</param>
        /// <returns>EncryptedMessage object containing ciphertext and nonce</returns>
        /// <exception cref="ArgumentException">Thrown when message is null or empty</exception>
        /// <exception cref="ArgumentNullException">Thrown when key is null</exception>
        /// <exception cref="ArgumentException">Thrown when key length is not 32 bytes</exception>
        public static EncryptedMessage Encrypt(string message, byte[] key)
        {
            if (string.IsNullOrEmpty(message))
                throw new ArgumentException("Message cannot be null or empty", nameof(message));
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (key.Length != Constants.AES_KEY_SIZE)
                throw new ArgumentException($"Key must be {Constants.AES_KEY_SIZE} bytes long", nameof(key));

            byte[] plaintext = Encoding.UTF8.GetBytes(message);
            byte[] nonce = NonceGenerator.GenerateNonce();
            byte[] ciphertext = AESEncrypt(plaintext, key, nonce);

            return new EncryptedMessage
            {
                Ciphertext = ciphertext,
                Nonce = nonce
            };
        }

        /// <summary>
        /// Decrypts a message with a simple API
        /// </summary>
        /// <param name="encryptedMessage">EncryptedMessage object</param>
        /// <param name="key">Decryption key</param>
        /// <returns>Decrypted message string</returns>
        public static string Decrypt(EncryptedMessage encryptedMessage, byte[] key)
        {
            if (encryptedMessage == null)
                throw new ArgumentNullException(nameof(encryptedMessage));
            if (encryptedMessage.Ciphertext == null)
                throw new ArgumentException("Ciphertext cannot be null", nameof(encryptedMessage));
            if (encryptedMessage.Nonce == null)
                throw new ArgumentException("Nonce cannot be null", nameof(encryptedMessage));
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (key.Length != Constants.AES_KEY_SIZE)
                throw new ArgumentException($"Key must be {Constants.AES_KEY_SIZE} bytes long", nameof(key));

            try
            {
                byte[] plaintext = AESDecrypt(encryptedMessage.Ciphertext, key, encryptedMessage.Nonce);

                // Validate the plaintext before converting to string
                if (plaintext == null || plaintext.Length == 0)
                {
                    throw new CryptographicException("Decryption produced empty plaintext");
                }

                // Check if the plaintext contains valid UTF-8 before conversion
                if (!Helpers.IsValidUtf8(plaintext))
                {
                    throw new FormatException("Decrypted content is not valid UTF-8");
                }

                return Encoding.UTF8.GetString(plaintext);
            }
            catch (CryptographicException ex)
            {
                throw new CryptographicException("Message decryption failed. The key may be incorrect.", ex);
            }
        }
    }
}