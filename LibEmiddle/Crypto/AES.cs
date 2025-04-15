using System.Runtime.InteropServices;
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
        /// Encrypts data using AES-GCM with libsodium
        /// </summary>
        /// <param name="plaintext">Data to encrypt</param>
        /// <param name="key">Encryption key</param>
        /// <param name="nonce">Nonce for AES-GCM</param>
        /// <param name="additionalData">Optional authenticated additional data</param>
        /// <returns>Encrypted data with authentication tag</returns>
        public static byte[] AESEncrypt(byte[] plaintext, byte[] key, byte[] nonce, byte[]? additionalData = null)
        {
            ArgumentNullException.ThrowIfNull(plaintext, nameof(plaintext));
            ArgumentNullException.ThrowIfNull(key, nameof(key));
            ArgumentNullException.ThrowIfNull(nonce, nameof(nonce));

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
            byte[] ad = additionalData ?? Array.Empty<byte>();

            // Allocate output buffer for ciphertext
            byte[] ciphertext = new byte[plaintext.Length + Constants.AUTH_TAG_SIZE];

            // Allocate unmanaged memory for the state (must be 16-byte aligned)
            nint state = nint.Zero;

            // Pin the managed buffers so GC doesn't move them
            GCHandle plaintextHandle = default;
            GCHandle ciphertextHandle = default;
            GCHandle keyHandle = default;
            GCHandle nonceHandle = default;
            GCHandle adHandle = default;

            try
            {
                // Allocate state memory
                state = Marshal.AllocHGlobal(StateSize);
                if (state == nint.Zero)
                    throw new OutOfMemoryException("Failed to allocate memory for AES-GCM state");

                // Pin all the buffers we need to pass to native code
                plaintextHandle = GCHandle.Alloc(plaintext, GCHandleType.Pinned);
                ciphertextHandle = GCHandle.Alloc(ciphertext, GCHandleType.Pinned);
                keyHandle = GCHandle.Alloc(key, GCHandleType.Pinned);
                nonceHandle = GCHandle.Alloc(nonce, GCHandleType.Pinned);
                adHandle = GCHandle.Alloc(ad, GCHandleType.Pinned);

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
            catch (DllNotFoundException)
            {
                throw new PlatformNotSupportedException("The libsodium library is not available");
            }
            finally
            {
                // Free unmanaged memory
                if (state != nint.Zero)
                    Marshal.FreeHGlobal(state);

                // Unpin all managed buffers
                if (plaintextHandle.IsAllocated) plaintextHandle.Free();
                if (ciphertextHandle.IsAllocated) ciphertextHandle.Free();
                if (keyHandle.IsAllocated) keyHandle.Free();
                if (nonceHandle.IsAllocated) nonceHandle.Free();
                if (adHandle.IsAllocated) adHandle.Free();
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
        public static byte[] AESDecrypt(byte[] ciphertextWithTag, byte[] key, byte[] nonce, byte[]? additionalData = null)
        {
            ArgumentNullException.ThrowIfNull(ciphertextWithTag, nameof(ciphertextWithTag));
            ArgumentNullException.ThrowIfNull(key, nameof(key));
            ArgumentNullException.ThrowIfNull(nonce, nameof(nonce));

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
            byte[] ad = additionalData ?? Array.Empty<byte>();

            // Allocate output buffer for plaintext
            // Plaintext will be at most the size of ciphertext - authentication tag
            byte[] plaintext = new byte[ciphertextWithTag.Length - Constants.AUTH_TAG_SIZE];

            // Allocate unmanaged memory for the state (must be 16-byte aligned)
            nint state = nint.Zero;

            // Pin the managed buffers so GC doesn't move them
            GCHandle plaintextHandle = default;
            GCHandle ciphertextHandle = default;
            GCHandle keyHandle = default;
            GCHandle nonceHandle = default;
            GCHandle adHandle = default;

            try
            {
                // Allocate the state memory
                state = Marshal.AllocHGlobal(StateSize);
                if (state == nint.Zero)
                    throw new OutOfMemoryException("Failed to allocate memory for AES-GCM state");

                // Pin all the buffers we need to pass to native code
                plaintextHandle = GCHandle.Alloc(plaintext, GCHandleType.Pinned);
                ciphertextHandle = GCHandle.Alloc(ciphertextWithTag, GCHandleType.Pinned);
                keyHandle = GCHandle.Alloc(key, GCHandleType.Pinned);
                nonceHandle = GCHandle.Alloc(nonce, GCHandleType.Pinned);
                adHandle = GCHandle.Alloc(ad, GCHandleType.Pinned);

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
                    throw new System.Security.Cryptography.CryptographicException(
                        "Authentication failed. The data may have been tampered with or the wrong key was used.");
                }

                // Create a properly sized result array if needed
                if (plaintextLength < (ulong)plaintext.Length)
                {
                    byte[] resizedPlaintext = new byte[plaintextLength];
                    plaintext.AsSpan(0, (int)plaintextLength).CopyTo(resizedPlaintext);
                    return resizedPlaintext;
                }

                return plaintext;
            }
            catch (DllNotFoundException)
            {
                throw new PlatformNotSupportedException("The libsodium library is not available");
            }
            catch (System.Security.Cryptography.CryptographicException)
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

                // Unpin all managed buffers
                if (plaintextHandle.IsAllocated) plaintextHandle.Free();
                if (ciphertextHandle.IsAllocated) ciphertextHandle.Free();
                if (keyHandle.IsAllocated) keyHandle.Free();
                if (nonceHandle.IsAllocated) nonceHandle.Free();
                if (adHandle.IsAllocated) adHandle.Free();
            }
        }

        /// <summary>
        /// Encrypts a message with a simple API, including nonce generation
        /// </summary>
        /// <param name="message">Message to encrypt</param>
        /// <param name="key">AES-256 encryption key (32 bytes)</param>
        /// <returns>EncryptedMessage object containing ciphertext and nonce</returns>
        public static EncryptedMessage Encrypt(string message, byte[] key)
        {
            ArgumentException.ThrowIfNullOrEmpty(message, nameof(message));
            ArgumentNullException.ThrowIfNull(key, nameof(key));
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
        public static string Decrypt(EncryptedMessage encryptedMessage, byte[] key)
        {
            ArgumentNullException.ThrowIfNull(encryptedMessage, nameof(encryptedMessage));
            ArgumentNullException.ThrowIfNull(encryptedMessage.Ciphertext, "Ciphertext cannot be null");
            ArgumentNullException.ThrowIfNull(encryptedMessage.Nonce, "Nonce cannot be null");
            ArgumentNullException.ThrowIfNull(key, nameof(key));
            if (key.Length != Constants.AES_KEY_SIZE)
                throw new ArgumentException($"Key must be {Constants.AES_KEY_SIZE} bytes long", nameof(key));

            try
            {
                byte[] plaintext = AESDecrypt(encryptedMessage.Ciphertext, key, encryptedMessage.Nonce);

                // Validate the plaintext before converting to string
                if (plaintext == null || plaintext.Length == 0)
                {
                    throw new System.Security.Cryptography.CryptographicException("Decryption produced empty plaintext");
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
            catch (System.Security.Cryptography.CryptographicException ex)
            {
                throw new System.Security.Cryptography.CryptographicException("Message decryption failed. The key may be incorrect.", ex);
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
        public static byte[] AESEncryptDetached(byte[] plaintext, byte[] key, byte[] nonce, out byte[] tag, byte[]? additionalData = null)
        {
            ArgumentNullException.ThrowIfNull(plaintext);
            ArgumentNullException.ThrowIfNull(key);
            ArgumentNullException.ThrowIfNull(nonce);

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
            byte[] ad = additionalData ?? Array.Empty<byte>();

            // Allocate unmanaged memory for the state (must be 16-byte aligned)
            nint state = nint.Zero;

            // Pin the managed buffers so GC doesn't move them
            GCHandle plaintextHandle = default;
            GCHandle keyHandle = default;
            GCHandle nonceHandle = default;
            GCHandle adHandle = default;

            try
            {
                // Allocate state memory
                state = Marshal.AllocHGlobal(StateSize);
                if (state == nint.Zero)
                    throw new OutOfMemoryException("Failed to allocate memory for AES-GCM state");

                // Precompute the key expansion
                int result = Sodium.crypto_aead_aes256gcm_beforenm(state, key);
                if (result != 0)
                {
                    throw new InvalidOperationException("Failed to initialize AES-GCM state");
                }

                // Allocate output buffer for ciphertext (same size as plaintext)
                byte[] ciphertext = new byte[plaintext.Length];

                // Allocate tag buffer
                tag = new byte[Constants.AUTH_TAG_SIZE];

                // Pin all the buffers we need to pass to native code
                plaintextHandle = GCHandle.Alloc(plaintext, GCHandleType.Pinned);
                keyHandle = GCHandle.Alloc(key, GCHandleType.Pinned);
                nonceHandle = GCHandle.Alloc(nonce, GCHandleType.Pinned);
                adHandle = GCHandle.Alloc(ad, GCHandleType.Pinned);

                // Encrypt using libsodium in detached mode
                result = Sodium.crypto_aead_aes256gcm_encrypt_detached_afternm(
                    ciphertext,
                    tag, out ulong tagLength,
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
            catch (DllNotFoundException)
            {
                throw new PlatformNotSupportedException("The libsodium library is not available");
            }
            finally
            {
                // Free unmanaged memory
                if (state != nint.Zero)
                    Marshal.FreeHGlobal(state);

                // Unpin all managed buffers
                if (plaintextHandle.IsAllocated) plaintextHandle.Free();
                if (keyHandle.IsAllocated) keyHandle.Free();
                if (nonceHandle.IsAllocated) nonceHandle.Free();
                if (adHandle.IsAllocated) adHandle.Free();
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
        public static byte[] AESDecryptDetached(byte[] ciphertext, byte[] tag, byte[] key, byte[] nonce, byte[]? additionalData = null)
        {
            ArgumentNullException.ThrowIfNull(ciphertext);
            ArgumentNullException.ThrowIfNull(tag);
            ArgumentNullException.ThrowIfNull(key);
            ArgumentNullException.ThrowIfNull(nonce);

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
            byte[] ad = additionalData ?? Array.Empty<byte>();

            // Allocate unmanaged memory for the state (must be 16-byte aligned)
            nint state = nint.Zero;

            // Pin the managed buffers so GC doesn't move them
            GCHandle plaintextHandle = default;
            GCHandle ciphertextHandle = default;
            GCHandle tagHandle = default;
            GCHandle keyHandle = default;
            GCHandle nonceHandle = default;
            GCHandle adHandle = default;

            try
            {
                // Allocate state memory
                state = Marshal.AllocHGlobal(StateSize);
                if (state == nint.Zero)
                    throw new OutOfMemoryException("Failed to allocate memory for AES-GCM state");

                // Precompute the key expansion
                int result = Sodium.crypto_aead_aes256gcm_beforenm(state, key);
                if (result != 0)
                {
                    throw new InvalidOperationException("Failed to initialize AES-GCM state");
                }

                // Allocate output buffer for plaintext (same size as ciphertext)
                byte[] plaintext = new byte[ciphertext.Length];

                // Pin all the buffers we need to pass to native code
                plaintextHandle = GCHandle.Alloc(plaintext, GCHandleType.Pinned);
                ciphertextHandle = GCHandle.Alloc(ciphertext, GCHandleType.Pinned);
                tagHandle = GCHandle.Alloc(tag, GCHandleType.Pinned);
                keyHandle = GCHandle.Alloc(key, GCHandleType.Pinned);
                nonceHandle = GCHandle.Alloc(nonce, GCHandleType.Pinned);
                adHandle = GCHandle.Alloc(ad, GCHandleType.Pinned);

                // Decrypt using libsodium in detached mode
                result = Sodium.crypto_aead_aes256gcm_decrypt_detached_afternm(
                    plaintext,
                    null, // nsec is always null for AES-GCM
                    ciphertext, (ulong)ciphertext.Length,
                    tag,
                    ad, (ulong)ad.Length,
                    nonce,
                    state);

                if (result != 0)
                {
                    throw new System.Security.Cryptography.CryptographicException("Authentication failed. The data may have been tampered with or the wrong key was used.");
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

                // Unpin all managed buffers
                if (plaintextHandle.IsAllocated) plaintextHandle.Free();
                if (ciphertextHandle.IsAllocated) ciphertextHandle.Free();
                if (tagHandle.IsAllocated) tagHandle.Free();
                if (keyHandle.IsAllocated) keyHandle.Free();
                if (nonceHandle.IsAllocated) nonceHandle.Free();
                if (adHandle.IsAllocated) adHandle.Free();
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
            public AesGcmContext(byte[] key)
            {
                ArgumentNullException.ThrowIfNull(key);
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
                    // Create a copy of the key to avoid modifying the original
                    byte[] keyCopy = new byte[key.Length];
                    key.CopyTo(keyCopy, 0);

                    // Precompute the key expansion
                    int result = Sodium.crypto_aead_aes256gcm_beforenm(_state, keyCopy);

                    // Clear the key copy after use
                    SecureMemory.SecureClear(keyCopy);

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
            public byte[] Encrypt(byte[] plaintext, byte[] nonce, byte[]? additionalData = null)
            {
                ThrowIfDisposed();
                ArgumentNullException.ThrowIfNull(plaintext);
                ArgumentNullException.ThrowIfNull(nonce);
                if (nonce.Length != Constants.NONCE_SIZE)
                    throw new ArgumentException($"Nonce must be {Constants.NONCE_SIZE} bytes long", nameof(nonce));

                // Prepare additional data if provided
                byte[] ad = additionalData ?? Array.Empty<byte>();

                // Allocate output buffer for ciphertext
                byte[] ciphertext = new byte[plaintext.Length + Constants.AUTH_TAG_SIZE];

                // Pin the managed buffers so GC doesn't move them
                GCHandle plaintextHandle = default;
                GCHandle ciphertextHandle = default;
                GCHandle nonceHandle = default;
                GCHandle adHandle = default;

                try
                {
                    // Pin all the buffers we need to pass to native code
                    plaintextHandle = GCHandle.Alloc(plaintext, GCHandleType.Pinned);
                    ciphertextHandle = GCHandle.Alloc(ciphertext, GCHandleType.Pinned);
                    nonceHandle = GCHandle.Alloc(nonce, GCHandleType.Pinned);
                    adHandle = GCHandle.Alloc(ad, GCHandleType.Pinned);

                    // Encrypt using libsodium
                    int result = Sodium.crypto_aead_aes256gcm_encrypt_afternm(
                        ciphertext, out ulong cipherLength,
                        plaintext, (ulong)plaintext.Length,
                        ad, (ulong)ad.Length,
                        null, // nsec is always null for AES-GCM
                        nonce,
                        _state);

                    if (result != 0)
                    {
                        throw new InvalidOperationException("Encryption failed");
                    }

                    return ciphertext;
                }
                finally
                {
                    // Unpin all managed buffers
                    if (plaintextHandle.IsAllocated) plaintextHandle.Free();
                    if (ciphertextHandle.IsAllocated) ciphertextHandle.Free();
                    if (nonceHandle.IsAllocated) nonceHandle.Free();
                    if (adHandle.IsAllocated) adHandle.Free();
                }
            }

            /// <summary>
            /// Decrypts data using the precomputed key
            /// </summary>
            /// <param name="ciphertextWithTag">Combined ciphertext and authentication tag</param>
            /// <param name="nonce">Nonce used for encryption</param>
            /// <param name="additionalData">Optional authenticated additional data</param>
            /// <returns>Decrypted data</returns>
            public byte[] Decrypt(byte[] ciphertextWithTag, byte[] nonce, byte[]? additionalData = null)
            {
                ThrowIfDisposed();
                ArgumentNullException.ThrowIfNull(ciphertextWithTag);
                ArgumentNullException.ThrowIfNull(nonce);
                if (nonce.Length != Constants.NONCE_SIZE)
                    throw new ArgumentException($"Nonce must be {Constants.NONCE_SIZE} bytes long", nameof(nonce));
                if (ciphertextWithTag.Length < Constants.AUTH_TAG_SIZE)
                    throw new ArgumentException("Ciphertext too short to contain tag", nameof(ciphertextWithTag));

                // Prepare additional data if provided
                byte[] ad = additionalData ?? Array.Empty<byte>();

                // Allocate output buffer for plaintext
                byte[] plaintext = new byte[ciphertextWithTag.Length - Constants.AUTH_TAG_SIZE];

                // Pin the managed buffers so GC doesn't move them
                GCHandle plaintextHandle = default;
                GCHandle ciphertextHandle = default;
                GCHandle nonceHandle = default;
                GCHandle adHandle = default;

                try
                {
                    // Pin all the buffers we need to pass to native code
                    plaintextHandle = GCHandle.Alloc(plaintext, GCHandleType.Pinned);
                    ciphertextHandle = GCHandle.Alloc(ciphertextWithTag, GCHandleType.Pinned);
                    nonceHandle = GCHandle.Alloc(nonce, GCHandleType.Pinned);
                    adHandle = GCHandle.Alloc(ad, GCHandleType.Pinned);

                    // Decrypt using libsodium
                    int result = Sodium.crypto_aead_aes256gcm_decrypt_afternm(
                        plaintext, out ulong plaintextLength,
                        null, // nsec is always null for AES-GCM
                        ciphertextWithTag, (ulong)ciphertextWithTag.Length,
                        ad, (ulong)ad.Length,
                        nonce,
                        _state);

                    if (result != 0)
                    {
                        throw new System.Security.Cryptography.CryptographicException("Authentication failed. The data may have been tampered with or the wrong key was used.");
                    }

                    // Create a properly sized result array if needed
                    if (plaintextLength < (ulong)plaintext.Length)
                    {
                        byte[] resizedPlaintext = new byte[plaintextLength];
                        plaintext.AsSpan(0, (int)plaintextLength).CopyTo(resizedPlaintext);
                        return resizedPlaintext;
                    }

                    return plaintext;
                }
                finally
                {
                    // Unpin all managed buffers
                    if (plaintextHandle.IsAllocated) plaintextHandle.Free();
                    if (ciphertextHandle.IsAllocated) ciphertextHandle.Free();
                    if (nonceHandle.IsAllocated) nonceHandle.Free();
                    if (adHandle.IsAllocated) adHandle.Free();
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