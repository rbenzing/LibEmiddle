using System.Runtime.InteropServices;
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
        /// Checks if AES-GCM is available on the current platform
        /// </summary>
        /// <returns>True if AES-GCM is available</returns>
        public static bool IsAesGcmAvailable()
        {
            Sodium.Initialize();
            return Sodium.crypto_aead_aes256gcm_is_available() == 1;
        }

        /// <summary>
        /// Encrypts data using AES-GCM with the built-in .NET implementation.
        /// </summary>
        /// <param name="plaintext">Data to encrypt.</param>
        /// <param name="key">Encryption key (32 bytes for AES-256).</param>
        /// <param name="nonce">Nonce (12 bytes recommended for AES-GCM).</param>
        /// <param name="additionalData">Optional authenticated additional data.</param>
        /// <returns>Encrypted data including the 16-byte authentication tag.</returns>
        /// <exception cref="ArgumentException">If key or nonce have invalid lengths.</exception>
        /// <exception cref="CryptographicException">If encryption fails.</exception>
        public static byte[] AESEncrypt(
            in ReadOnlySpan<byte> plaintext,
            in ReadOnlySpan<byte> key,
            in ReadOnlySpan<byte> nonce,
            in ReadOnlySpan<byte> additionalData = default)
        {
            // --- Argument Validation ---
            // Check lengths first (avoids exceptions in AesGcm constructor/Encrypt)
            if (key.Length != Constants.AES_KEY_SIZE)
                throw new ArgumentException($"Key must be {Constants.AES_KEY_SIZE} bytes long. Actual: {key.Length}", nameof(key));
            if (nonce.Length != Constants.NONCE_SIZE)
                throw new ArgumentException($"Nonce must be {Constants.NONCE_SIZE} bytes long for AES-GCM. Actual: {nonce.Length}", nameof(nonce));
            // Plaintext can be empty, additionalData can be empty (default)

            // --- Encryption ---
            // Allocate buffer for ciphertext + tag
            byte[] ciphertext = new byte[plaintext.Length + Constants.AUTH_TAG_SIZE];
            // Tag will be appended by AesGcm.Encrypt

            try
            {
                using (var aesGcm = new AesGcm(key, Constants.AUTH_TAG_SIZE)) // Specify tag size
                {
                    // Encrypt directly using spans
                    aesGcm.Encrypt(
                        nonce.ToArray(),
                        plaintext.ToArray(),
                        ciphertext.ToArray(), // Pass output buffer as Span<byte>
                        new byte[Constants.AUTH_TAG_SIZE],
                        associatedData: additionalData.ToArray() // Pass ReadOnlySpan<byte> directly
                       );
                }
                return ciphertext;
            }
            catch (CryptographicException ex) // Catch specific crypto errors
            {
                LoggingManager.LogError(nameof(AES), $"AES-GCM encryption failed: {ex.Message}");
                throw; // Re-throw to indicate failure
            }
            catch (Exception ex) // Catch unexpected errors
            {
                LoggingManager.LogError(nameof(AES), $"Unexpected error during AES-GCM encryption: {ex.Message}");
                throw new CryptographicException("Unexpected error during encryption.", ex);
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
            in ReadOnlySpan<byte> ciphertextWithTag,
            in ReadOnlySpan<byte> key,
            in ReadOnlySpan<byte> nonce,
            in ReadOnlySpan<byte> additionalData = default)
        {
            if (ciphertextWithTag.IsEmpty)
                throw new ArgumentException("Ciphertext cannot be empty", nameof(ciphertextWithTag));
            if (key.IsEmpty)
                throw new ArgumentException("Key cannot be empty", nameof(key));
            if (nonce.IsEmpty)
                throw new ArgumentException("Nonce cannot be empty", nameof(nonce));

            if (key.Length != Constants.AES_KEY_SIZE)
                throw new ArgumentException($"Key must be {Constants.AES_KEY_SIZE} bytes long", nameof(key));
            if (nonce.Length != Constants.NONCE_SIZE)
                throw new ArgumentException($"Nonce must be {Constants.NONCE_SIZE} bytes long", nameof(nonce));
            if (ciphertextWithTag.Length < Constants.AUTH_TAG_SIZE)
                throw new ArgumentException("Ciphertext too short to contain tag", nameof(ciphertextWithTag));

            // Initialize libsodium
            Sodium.Initialize();

            // Check if AES-GCM is available on this platform
            if (!IsAesGcmAvailable())
            {
                throw new PlatformNotSupportedException("AES-GCM is not available on this platform");
            }

            // Prepare additional data if provided
            ReadOnlySpan<byte> ad = additionalData;

            // Allocate output buffer for plaintext
            // Plaintext will be at most the size of ciphertext - authentication tag
            ReadOnlySpan<byte> plaintext = new byte[ciphertextWithTag.Length - Constants.AUTH_TAG_SIZE];

            // Allocate unmanaged memory for the state (must be 16-byte aligned)
            nint state = nint.Zero;

            try
            {
                // Precompute the key expansion
                int result = Sodium.crypto_aead_aes256gcm_beforenm(state, key.ToArray());
                if (result != 0)
                {
                    throw new InvalidOperationException("Failed to initialize AES-GCM state");
                }

                // Decrypt using libsodium
                result = Sodium.crypto_aead_aes256gcm_decrypt_afternm(
                    plaintext.ToArray(), out ulong plaintextLength,
                    null, // nsec is always null for AES-GCM
                    ciphertextWithTag.ToArray(), (ulong)ciphertextWithTag.Length,
                    ad.ToArray(), (ulong)ad.Length,
                    nonce.ToArray(),
                    state);

                if (result != 0)
                {
                    throw new CryptographicException(
                        "Authentication failed. The data may have been tampered with or the wrong key was used.");
                }

                // Create a properly sized result array if needed
                if (plaintextLength < (ulong)plaintext.Length)
                {
                    byte[] resizedPlaintext = new byte[plaintextLength];
                    plaintext.ToArray().AsSpan(0, (int)plaintextLength).CopyTo(resizedPlaintext);
                    return resizedPlaintext;
                }

                return plaintext.ToArray();
            }
            catch (DllNotFoundException)
            {
                throw new PlatformNotSupportedException("The libsodium library is not available");
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
            finally
            {
                // Free unmanaged memory - always check if it's allocated first
                if (state != nint.Zero)
                {
                    Marshal.FreeHGlobal(state);
                }
            }
        }

        /// <summary>
        /// Encrypts a message with a simple API, including nonce generation
        /// </summary>
        /// <param name="message">Message to encrypt</param>
        /// <param name="key">AES-256 encryption key (32 bytes)</param>
        /// <returns>EncryptedMessage object containing ciphertext and nonce</returns>
        public static EncryptedMessage Encrypt(string message, in ReadOnlySpan<byte> key)
        {
            ArgumentException.ThrowIfNullOrEmpty(message, nameof(message));
            ArgumentNullException.ThrowIfNull(key.ToString(), nameof(key));

            if (key.Length != Constants.AES_KEY_SIZE)
                throw new ArgumentException($"Key must be {Constants.AES_KEY_SIZE} bytes long", nameof(key));

            byte[] plaintext = Encoding.UTF8.GetBytes(message);
            byte[] nonce = NonceGenerator.GenerateNonce();
            byte[] ciphertext = AESEncrypt(plaintext, key, nonce);

            return new EncryptedMessage
            {
                Ciphertext = ciphertext,
                Nonce = nonce,
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                MessageId = Guid.NewGuid()
            };
        }

        /// <summary>
        /// Decrypts a message with a simple API
        /// </summary>
        /// <param name="encryptedMessage">EncryptedMessage object</param>
        /// <param name="key">Decryption key</param>
        /// <returns>Decrypted message string</returns>
        public static string Decrypt(EncryptedMessage encryptedMessage, in ReadOnlySpan<byte> key)
        {
            ArgumentNullException.ThrowIfNull(encryptedMessage, nameof(encryptedMessage));
            ArgumentNullException.ThrowIfNull(encryptedMessage.Ciphertext, "Ciphertext cannot be null");
            ArgumentNullException.ThrowIfNull(encryptedMessage.Nonce, "Nonce cannot be null");
            ArgumentNullException.ThrowIfNull(key.ToString(), nameof(key));

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
        public static ReadOnlySpan<byte> AESEncryptDetached(
            ReadOnlySpan<byte> plaintext,
            in ReadOnlySpan<byte> key,
            in ReadOnlySpan<byte> nonce, 
            out byte[] tag,
            in ReadOnlySpan<byte> additionalData = default)
        {
            ArgumentNullException.ThrowIfNull(plaintext.ToArray());
            ArgumentNullException.ThrowIfNull(key.ToArray());
            ArgumentNullException.ThrowIfNull(nonce.ToArray());

            if (key.Length != Constants.AES_KEY_SIZE)
                throw new ArgumentException($"Key must be {Constants.AES_KEY_SIZE} bytes long", nameof(key));
            if (nonce.Length != Constants.NONCE_SIZE)
                throw new ArgumentException($"Nonce must be {Constants.NONCE_SIZE} bytes long", nameof(nonce));

            // Initialize libsodium
            Sodium.Initialize();

            // Check if AES-GCM is available on this platform
            if (!IsAesGcmAvailable())
            {
                throw new PlatformNotSupportedException("AES-GCM is not available on this platform");
            }

            // Prepare additional data if provided
            ReadOnlySpan<byte> ad = additionalData;

            // Allocate unmanaged memory for the state (must be 16-byte aligned)
            nint state = nint.Zero;

            try
            {
                // Allocate state memory
                state = Marshal.AllocHGlobal(StateSize);
                if (state == nint.Zero)
                    throw new OutOfMemoryException("Failed to allocate memory for AES-GCM state");

                // Precompute the key expansion
                int result = Sodium.crypto_aead_aes256gcm_beforenm(state, key.ToArray());
                if (result != 0)
                {
                    throw new InvalidOperationException("Failed to initialize AES-GCM state");
                }

                // Allocate output buffer for ciphertext (same size as plaintext)
                ReadOnlySpan<byte> ciphertext = new byte[plaintext.Length];

                // Allocate tag buffer
                tag = new byte[Constants.AUTH_TAG_SIZE];

                // Encrypt using libsodium in detached mode
                result = Sodium.crypto_aead_aes256gcm_encrypt_detached_afternm(
                    ciphertext.ToArray(),
                    tag, out ulong tagLength,
                    plaintext.ToArray(), (ulong)plaintext.Length,
                    ad.ToArray(), (ulong)ad.Length,
                    null, // nsec is always null for AES-GCM
                    nonce.ToArray(),
                    state);

                if (result != 0)
                {
                    throw new InvalidOperationException("Encryption failed");
                }

                return ciphertext;
            }
            catch (DllNotFoundException)
            {
                throw new PlatformNotSupportedException("The libsodium library is not available");
            }
            finally
            {
                // Free unmanaged memory
                if (state != nint.Zero)
                    Marshal.FreeHGlobal(state);
            }
        }

        /// <summary>
        /// Separate decryption method for detached mode (separate ciphertext and tag)
        /// </summary>
        /// <param name="ciphertext">Encrypted data without authentication tag</param>
        /// <param name="tag">Authentication tag</param>
        /// <param name="key">Decryption key</param>
        /// <param name="nonce">Nonce used for encryption</param>
        /// <param name="additionalData">Optional authenticated additional data</param>
        /// <returns>Decrypted data</returns>
        public static ReadOnlySpan<byte> AESDecryptDetached(
            in ReadOnlySpan<byte> ciphertext, 
            in ReadOnlySpan<byte> tag, 
            in ReadOnlySpan<byte> key, 
            in ReadOnlySpan<byte> nonce, 
            in ReadOnlySpan<byte> additionalData = default)
        {
            ArgumentNullException.ThrowIfNull(ciphertext.ToArray());
            ArgumentNullException.ThrowIfNull(tag.ToArray());
            ArgumentNullException.ThrowIfNull(key.ToArray());
            ArgumentNullException.ThrowIfNull(nonce.ToArray());

            if (key.Length != Constants.AES_KEY_SIZE)
                throw new ArgumentException($"Key must be {Constants.AES_KEY_SIZE} bytes long", nameof(key));
            if (nonce.Length != Constants.NONCE_SIZE)
                throw new ArgumentException($"Nonce must be {Constants.NONCE_SIZE} bytes long", nameof(nonce));
            if (tag.Length != Constants.AUTH_TAG_SIZE)
                throw new ArgumentException($"Tag must be {Constants.AUTH_TAG_SIZE} bytes long", nameof(tag));

            // Initialize libsodium
            Sodium.Initialize();

            // Check if AES-GCM is available on this platform
            if (!IsAesGcmAvailable())
            {
                throw new PlatformNotSupportedException("AES-GCM is not available on this platform");
            }

            // Prepare additional data if provided
            ReadOnlySpan<byte> ad = additionalData;

            // Allocate unmanaged memory for the state (must be 16-byte aligned)
            nint state = nint.Zero;

            try
            {
                // Allocate state memory
                state = Marshal.AllocHGlobal(StateSize);
                if (state == nint.Zero)
                    throw new OutOfMemoryException("Failed to allocate memory for AES-GCM state");

                // Precompute the key expansion
                int result = Sodium.crypto_aead_aes256gcm_beforenm(state, key.ToArray());
                if (result != 0)
                {
                    throw new InvalidOperationException("Failed to initialize AES-GCM state");
                }

                // Allocate output buffer for plaintext (same size as ciphertext)
                ReadOnlySpan<byte> plaintext = new byte[ciphertext.Length];

                // Decrypt using libsodium in detached mode
                result = Sodium.crypto_aead_aes256gcm_decrypt_detached_afternm(
                    plaintext.ToArray(),
                    null, // nsec is always null for AES-GCM
                    ciphertext.ToArray(), (ulong)ciphertext.Length,
                    tag.ToArray(),
                    ad.ToArray(), (ulong)ad.Length,
                    nonce.ToArray(),
                    state);

                if (result != 0)
                {
                    throw new CryptographicException(
                        "Authentication failed. The data may have been tampered with or the wrong key was used.");
                }

                return plaintext;
            }
            catch (DllNotFoundException)
            {
                throw new PlatformNotSupportedException("The libsodium library is not available");
            }
            finally
            {
                // Free unmanaged memory
                if (state != nint.Zero)
                    Marshal.FreeHGlobal(state);
            }
        }

        /// <summary>
        /// AES-GCM Context for reusing the same expanded key
        /// </summary>
        public sealed class AesGcmContext : IDisposable
        {
            private nint _state;
            private bool _disposed;

            /// <summary>
            /// Creates a new AES-GCM context with the specified key
            /// </summary>
            /// <param name="key">The encryption/decryption key</param>
            public AesGcmContext(ReadOnlySpan<byte> key)
            {
                ArgumentNullException.ThrowIfNull(key.ToArray(), nameof(key));
                if (key.Length != Constants.AES_KEY_SIZE)
                    throw new ArgumentException($"Key must be {Constants.AES_KEY_SIZE} bytes long", nameof(key));

                // Initialize libsodium
                Sodium.Initialize();

                // Check if AES-GCM is available on this platform
                if (!IsAesGcmAvailable())
                {
                    throw new PlatformNotSupportedException("AES-GCM is not available on this platform");
                }

                // Allocate unmanaged memory for the state (must be 16-byte aligned)
                _state = Marshal.AllocHGlobal(StateSize);
                if (_state == nint.Zero)
                    throw new OutOfMemoryException("Failed to allocate memory for AES-GCM state");

                try
                {
                    // Precompute the key expansion
                    int result = Sodium.crypto_aead_aes256gcm_beforenm(_state, key.ToArray());

                    // Clear the key copy after use
                    SecureMemory.SecureClear(key.ToArray());

                    if (result != 0)
                    {
                        throw new InvalidOperationException("Failed to initialize AES-GCM state");
                    }
                }
                catch
                {
                    // Free resources on failure
                    Marshal.FreeHGlobal(_state);
                    _state = nint.Zero;
                    throw;
                }
            }

            /// <summary>
            /// Encrypts data using the precomputed key
            /// </summary>
            /// <param name="plaintext">Data to encrypt</param>
            /// <param name="nonce">Nonce for AES-GCM</param>
            /// <param name="additionalData">Optional authenticated additional data</param>
            /// <returns>Encrypted data with authentication tag</returns>
            public ReadOnlySpan<byte> Encrypt(
                ReadOnlySpan<byte> plaintext,
                ReadOnlySpan<byte> nonce,
                ReadOnlySpan<byte> additionalData = default)
            {
                ThrowIfDisposed();

                ArgumentNullException.ThrowIfNull(plaintext.ToArray());
                ArgumentNullException.ThrowIfNull(nonce.ToArray());

                if (nonce.Length != Constants.NONCE_SIZE)
                    throw new ArgumentException($"Nonce must be {Constants.NONCE_SIZE} bytes long", nameof(nonce));

                // Prepare additional data if provided
                ReadOnlySpan<byte> ad = additionalData;

                // Allocate output buffer for ciphertext
                ReadOnlySpan<byte> ciphertext = new byte[plaintext.Length + Constants.AUTH_TAG_SIZE];

                try
                {
                    // Encrypt using libsodium
                    int result = Sodium.crypto_aead_aes256gcm_encrypt_afternm(
                        ciphertext.ToArray(), out ulong cipherLength,
                        plaintext.ToArray(), (ulong)plaintext.Length,
                        ad.ToArray(), (ulong)ad.Length,
                        null, // nsec is always null for AES-GCM
                        nonce.ToArray(),
                        _state);

                    if (result != 0)
                    {
                        throw new InvalidOperationException("Encryption failed");
                    }

                    return ciphertext;
                }
                finally
                {
                    // free memory || secure clear
                }
            }

            /// <summary>
            /// Decrypts data using the precomputed key
            /// </summary>
            /// <param name="ciphertextWithTag">Combined ciphertext and authentication tag</param>
            /// <param name="nonce">Nonce used for encryption</param>
            /// <param name="additionalData">Optional authenticated additional data</param>
            /// <returns>Decrypted data</returns>
            public byte[] Decrypt(
                ReadOnlySpan<byte> ciphertextWithTag,
                ReadOnlySpan<byte> nonce,
                ReadOnlySpan<byte> additionalData = default)
            {
                ThrowIfDisposed();

                ArgumentNullException.ThrowIfNull(ciphertextWithTag.ToArray());
                ArgumentNullException.ThrowIfNull(nonce.ToArray());

                if (nonce.Length != Constants.NONCE_SIZE)
                    throw new ArgumentException($"Nonce must be {Constants.NONCE_SIZE} bytes long", nameof(nonce));
                if (ciphertextWithTag.Length < Constants.AUTH_TAG_SIZE)
                    throw new ArgumentException("Ciphertext too short to contain tag", nameof(ciphertextWithTag));

                // Prepare additional data if provided
                ReadOnlySpan<byte> ad = additionalData;

                // Allocate output buffer for plaintext
                ReadOnlySpan<byte> plaintext = new byte[ciphertextWithTag.Length - Constants.AUTH_TAG_SIZE];

                try
                {
                    // Decrypt using libsodium
                    int result = Sodium.crypto_aead_aes256gcm_decrypt_afternm(
                        plaintext.ToArray(), out ulong plaintextLength,
                        null, // nsec is always null for AES-GCM
                        ciphertextWithTag.ToArray(), (ulong)ciphertextWithTag.Length,
                        ad.ToArray(), (ulong)ad.Length,
                        nonce.ToArray(),
                        _state);

                    if (result != 0)
                    {
                        throw new CryptographicException(
                            "Authentication failed. The data may have been tampered with or the wrong key was used.");
                    }

                    // Create a properly sized result array if needed
                    if (plaintextLength < (ulong)plaintext.Length)
                    {
                        byte[] resizedPlaintext = new byte[plaintextLength];
                        plaintext.ToArray().AsSpan(0, (int)plaintextLength).CopyTo(resizedPlaintext);
                        return resizedPlaintext;
                    }

                    return plaintext.ToArray();
                }
                finally
                {
                    // free memory || secure clear
                }
            }

            /// <summary>
            /// Disposes the context and frees unmanaged resources
            /// </summary>
            public void Dispose()
            {
                if (!_disposed)
                {
                    // Free unmanaged memory
                    if (_state != nint.Zero)
                    {
                        Marshal.FreeHGlobal(_state);
                        _state = nint.Zero;
                    }
                    _disposed = true;
                }
            }

            private void ThrowIfDisposed()
            {
                if (_disposed)
                {
                    throw new ObjectDisposedException(nameof(AesGcmContext));
                }
            }
        }
    }
}