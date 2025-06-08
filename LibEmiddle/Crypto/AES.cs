using System.Security.Cryptography;
using System.Text;
using LibEmiddle.Core;
using LibEmiddle.Domain;

namespace LibEmiddle.Crypto
{
    /// <summary>
    /// Provides AES-GCM encryption and decryption functionality using libsodium
    /// with state precomputation for improved performance.
    /// </summary>
    internal static class AES
    {
        // Size of the AES-GCM state for precomputation
        private const int StateSize = 512; // Must be aligned to 16 bytes

        /// <summary>
        /// Encrypts data using AES-GCM with libsodium
        /// </summary>
        /// <param name="plaintext">Data to encrypt</param>
        /// <param name="key">Encryption key</param>
        /// <param name="nonce">Nonce for AES-GCM</param>
        /// <param name="additionalData">Optional authenticated additional data</param>
        /// <returns>Encrypted data with authentication tag</returns>
        public static byte[] AESEncrypt(
            byte[] plaintext,
            byte[] key,
            byte[] nonce,
            byte[]? additionalData = null)
        {
            ArgumentNullException.ThrowIfNull(plaintext, nameof(plaintext));
            ArgumentNullException.ThrowIfNull(key, nameof(key));
            ArgumentNullException.ThrowIfNull(nonce, nameof(nonce));

            if (key.Length != Constants.AES_KEY_SIZE)
                throw new ArgumentException($"Key must be {Constants.AES_KEY_SIZE} bytes long", nameof(key));
            if (nonce.Length != Constants.NONCE_SIZE)
                throw new ArgumentException($"Nonce must be {Constants.NONCE_SIZE} bytes long", nameof(nonce));

            // Prepare additional data if provided
            byte[] ad = additionalData ?? Array.Empty<byte>();

            // Allocate output buffer for ciphertext
            byte[] ciphertext = new byte[plaintext.Length + Constants.AUTH_TAG_SIZE];

            // Use unsafe and fixed for better performance and safety
            unsafe
            {
                // Stack allocate the state to avoid heap allocation
                Span<byte> stateBuffer = stackalloc byte[StateSize];

                fixed (byte* pState = stateBuffer)
                fixed (byte* pKey = key)
                fixed (byte* pPlaintext = plaintext)
                fixed (byte* pCiphertext = ciphertext)
                fixed (byte* pNonce = nonce)
                fixed (byte* pAd = ad)
                {
                    IntPtr state = (IntPtr)pState;

                    // Precompute the key expansion
                    int result = Sodium.crypto_aead_aes256gcm_beforenm(state, key);
                    if (result != 0)
                    {
                        throw new InvalidOperationException("Failed to initialize AES-GCM state");
                    }

                    // Encrypt using libsodium
                    result = Sodium.crypto_aead_aes256gcm_encrypt_afternm(
                        ciphertext, out ulong cipherLength,
                        plaintext, (ulong)plaintext.Length,
                        ad, (ulong)ad.Length,
                        null, // nsec is always null for AES-GCM
                        nonce,
                        state);

                    if (result != 0)
                    {
                        throw new InvalidOperationException("Encryption failed");
                    }

                    return ciphertext;
                }
            }
        }

        /// <summary>
        /// Decrypts data using AES-GCM with libsodium
        /// </summary>
        /// <param name="ciphertextWithTag">Combined ciphertext and authentication tag</param>
        /// <param name="key">Decryption key</param>
        /// <param name="nonce">Nonce used for encryption</param>
        /// <param name="additionalData">Optional authenticated additional data</param>
        /// <returns>Decrypted data</returns>
        public static byte[] AESDecrypt(
            byte[] ciphertextWithTag,
            byte[] key,
            byte[] nonce,
            byte[]? additionalData = null)
        {
            ArgumentNullException.ThrowIfNull(ciphertextWithTag, nameof(ciphertextWithTag));
            ArgumentNullException.ThrowIfNull(key, nameof(key));
            ArgumentNullException.ThrowIfNull(nonce, nameof(nonce));

            if (key.Length != Constants.AES_KEY_SIZE)
                throw new CryptographicException($"Key must be {Constants.AES_KEY_SIZE} bytes long");
            if (nonce.Length != Constants.NONCE_SIZE)
                throw new CryptographicException($"Nonce must be {Constants.NONCE_SIZE} bytes long");
            if (ciphertextWithTag.Length < Constants.AUTH_TAG_SIZE)
                throw new CryptographicException("Ciphertext too short to contain tag");

            // Prepare additional data if provided
            byte[] ad = additionalData ?? [];

            // Allocate output buffer for plaintext
            byte[] plaintext = new byte[ciphertextWithTag.Length - Constants.AUTH_TAG_SIZE];

            try
            {
                // Use unsafe and fixed for better performance and safety
                unsafe
                {
                    // Stack allocate the state to avoid heap allocation
                    Span<byte> stateBuffer = stackalloc byte[StateSize];

                    fixed (byte* pState = stateBuffer)
                    fixed (byte* pKey = key)
                    fixed (byte* pPlaintext = plaintext)
                    fixed (byte* pCiphertext = ciphertextWithTag)
                    fixed (byte* pNonce = nonce)
                    fixed (byte* pAd = ad)
                    {
                        IntPtr state = (IntPtr)pState;

                        // Precompute the key expansion
                        int result = Sodium.crypto_aead_aes256gcm_beforenm(state, key);
                        if (result != 0)
                        {
                            throw new InvalidOperationException("Failed to initialize AES-GCM state");
                        }

                        // Decrypt using libsodium
                        result = Sodium.crypto_aead_aes256gcm_decrypt_afternm(
                            plaintext, out ulong plaintextLength,
                            null, // nsec is always null for AES-GCM
                            ciphertextWithTag, (ulong)ciphertextWithTag.Length,
                            ad, (ulong)ad.Length,
                            nonce,
                            state);

                        if (result != 0)
                        {
                            throw new CryptographicException("Authentication failed. The data may have been tampered with or the wrong key was used.");
                        }

                        // Create a properly sized result array if needed
                        if (plaintextLength < (ulong)plaintext.Length)
                        {
                            byte[] resizedPlaintext = new byte[plaintextLength];
                            plaintext.AsSpan(0, (int)plaintextLength).CopyTo(resizedPlaintext);
                            SecureMemory.SecureClear(plaintext); // Clear the original buffer
                            return resizedPlaintext;
                        }

                        return plaintext;
                    }
                }
            }
            catch (CryptographicException)
            {
                // Rethrow cryptographic exceptions as they contain important security information
                throw;
            }
            catch (Exception ex)
            {
                // Wrap other exceptions with more context
                throw new InvalidOperationException("AES-GCM decryption failed", ex);
            }
        }

        /// <summary>
        /// Encrypts a message with a simple API, including nonce generation
        /// </summary>
        /// <param name="message">Message to encrypt</param>
        /// <param name="key">AES-256 encryption key (32 bytes)</param>
        /// <returns>EncryptedMessage object containing ciphertext and nonce</returns>
        public static EncryptedMessage Encrypt(string message, ReadOnlySpan<byte> key)
        {
            ArgumentException.ThrowIfNullOrEmpty(message, nameof(message));

            if (key.Length != Constants.AES_KEY_SIZE)
                throw new ArgumentException($"Key must be {Constants.AES_KEY_SIZE} bytes long", nameof(key));

            byte[] plaintext = Encoding.UTF8.GetBytes(message); // Changed from Encoding.Default
            byte[] nonce = Nonce.GenerateNonce();
            byte[] ciphertext = AESEncrypt(plaintext, key.ToArray(), nonce);

            return new EncryptedMessage
            {
                Ciphertext = ciphertext,
                Nonce = nonce,
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                MessageId = Guid.NewGuid().ToString(),
            };
        }

        /// <summary>
        /// Decrypts a message with a simple API
        /// </summary>
        /// <param name="encryptedMessage">EncryptedMessage object</param>
        /// <param name="key">Decryption key</param>
        /// <returns>Decrypted message string</returns>
        public static string Decrypt(EncryptedMessage encryptedMessage, ReadOnlySpan<byte> key)
        {
            ArgumentNullException.ThrowIfNull(encryptedMessage, nameof(encryptedMessage));
            ArgumentNullException.ThrowIfNull(encryptedMessage.Ciphertext, "Ciphertext cannot be null");
            ArgumentNullException.ThrowIfNull(encryptedMessage.Nonce, "Nonce cannot be null");
            ArgumentNullException.ThrowIfNull(key.ToArray(), nameof(key));

            if (key.Length != Constants.AES_KEY_SIZE)
                throw new ArgumentException($"Key must be {Constants.AES_KEY_SIZE} bytes long", nameof(key));

            try
            {
                byte[] plaintext = AESDecrypt(encryptedMessage.Ciphertext, key.ToArray(), encryptedMessage.Nonce);

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

                string result = Encoding.UTF8.GetString(plaintext);

                // Securely clear the plaintext as we no longer need it after conversion to string
                SecureMemory.SecureClear(plaintext);

                return result;
            }
            catch (CryptographicException ex)
            {
                throw new CryptographicException("Message decryption failed. The key may be incorrect.", ex);
            }
        }

        /// <summary>
        /// Separate encryption method for detached mode (separate ciphertext and tag)
        /// </summary>
        /// <param name="plaintext">Data to encrypt</param>
        /// <param name="key">Encryption key</param>
        /// <param name="nonce">Nonce for AES-GCM</param>
        /// <param name="tag">Output parameter for the authentication tag</param>
        /// <param name="additionalData">Optional authenticated additional data</param>
        /// <returns>Encrypted data without authentication tag</returns>
        /// <exception cref="ArgumentException">If inputs have invalid lengths or are empty.</exception>
        /// <exception cref="PlatformNotSupportedException">If AES-GCM or libsodium is unavailable.</exception>
        /// <exception cref="CryptographicException">If encryption fails or tag length mismatches.</exception>
        public static unsafe byte[] AESEncryptDetached(
            ReadOnlySpan<byte> plaintext,
            ReadOnlySpan<byte> key,
            ReadOnlySpan<byte> nonce,
            out byte[] tag,
            ReadOnlySpan<byte> additionalData = default)
        {
            // 1) Validate inputs
            if (plaintext.IsEmpty)
                throw new ArgumentNullException(nameof(plaintext));
            if (key.Length != Constants.AES_KEY_SIZE)
                throw new ArgumentException($"Key must be {Constants.AES_KEY_SIZE} bytes long", nameof(key));
            if (nonce.Length != Constants.NONCE_SIZE)
                throw new ArgumentException($"Nonce must be {Constants.NONCE_SIZE} bytes long", nameof(nonce));

            // 2) Stack-allocate state
            Span<byte> stateStorage = stackalloc byte[StateSize];

            // 3) Allocate output buffers
            byte[] ciphertext = new byte[plaintext.Length];
            tag = new byte[Constants.AUTH_TAG_SIZE];

            // 4) Expand key and encrypt
            fixed (byte* pState = stateStorage)
            {
                IntPtr statePtr = (IntPtr)pState;

                int rc = Sodium.crypto_aead_aes256gcm_beforenm(statePtr, key);
                if (rc != 0)
                    throw new InvalidOperationException("AES-GCM key schedule failed");

                rc = Sodium.crypto_aead_aes256gcm_encrypt_detached_afternm(
                    ciphertext,         // c
                    tag,                // mac
                    out ulong maclen,   // maclen_p
                    plaintext,          // m
                    (ulong)plaintext.Length,
                    additionalData,     // ad
                    (ulong)additionalData.Length,
                    null,               // nsec
                    nonce,              // npub
                    statePtr            // ctx
                );
                if (rc != 0 || maclen != (ulong)tag.Length)
                    throw new CryptographicException("AES-GCM detached encryption failed");
            }

            return ciphertext;
        }

        /// <summary>
        /// Decrypts data using AES-GCM in detached mode (separate ciphertext and tag)
        /// </summary>
        /// <param name="ciphertext">Encrypted data without authentication tag</param>
        /// <param name="tag">Authentication tag (16 bytes)</param>
        /// <param name="key">Decryption key (32 bytes for AES-256)</param>
        /// <param name="nonce">Nonce used for encryption (12 bytes)</param>
        /// <param name="additionalData">Optional authenticated additional data</param>
        /// <returns>Decrypted plaintext data</returns>
        /// <exception cref="ArgumentException">If inputs have invalid lengths or are empty.</exception>
        /// <exception cref="PlatformNotSupportedException">If AES-GCM or libsodium is unavailable.</exception>
        /// <exception cref="CryptographicException">If decryption fails or tag mismatch occurs.</exception>
        public static unsafe byte[] AESDecryptDetached(
            ReadOnlySpan<byte> ciphertext,
            ReadOnlySpan<byte> tag,
            ReadOnlySpan<byte> key,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> additionalData = default)
        {
            // 1) Validate inputs
            if (ciphertext.IsEmpty)
                throw new ArgumentNullException(nameof(ciphertext));
            if (tag.Length != Constants.AUTH_TAG_SIZE)
                throw new ArgumentException($"Tag must be {Constants.AUTH_TAG_SIZE} bytes long", nameof(tag));
            if (key.Length != Constants.AES_KEY_SIZE)
                throw new ArgumentException($"Key must be {Constants.AES_KEY_SIZE} bytes long", nameof(key));
            if (nonce.Length != Constants.NONCE_SIZE)
                throw new ArgumentException($"Nonce must be {Constants.NONCE_SIZE} bytes long", nameof(nonce));

            // 2) Stack-allocate state
            Span<byte> stateStorage = stackalloc byte[StateSize];

            // 3) Allocate plaintext buffer
            byte[] plaintext = new byte[ciphertext.Length];

            // 4) Expand key and decrypt
            fixed (byte* pState = stateStorage)
            {
                IntPtr statePtr = (IntPtr)pState;

                int rc = Sodium.crypto_aead_aes256gcm_beforenm(statePtr, key);
                if (rc != 0)
                    throw new InvalidOperationException("AES-GCM key schedule failed");

                rc = Sodium.crypto_aead_aes256gcm_decrypt_detached_afternm(
                    plaintext,            // m
                    out ulong mlen,       // mlen_p
                    null, // nsec
                    ciphertext,           // c
                    (ulong)ciphertext.Length,
                    tag,                  // mac
                    additionalData,       // ad
                    (ulong)additionalData.Length,
                    nonce,                // npub
                    statePtr             // ctx
                );
                if (rc != 0 || mlen != (ulong)plaintext.Length)
                    throw new CryptographicException("AES-GCM detached decryption failed");
            }

            return plaintext;
        }
    }
}