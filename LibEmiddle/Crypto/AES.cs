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
                    throw new CryptographicException(
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
        public static EncryptedMessage Encrypt(string message, ReadOnlySpan<byte> key)
        {
            ArgumentException.ThrowIfNullOrEmpty(message, nameof(message));
            ArgumentNullException.ThrowIfNull(key.ToArray(), nameof(key));
            if (key.Length != Constants.AES_KEY_SIZE)
                throw new ArgumentException($"Key must be {Constants.AES_KEY_SIZE} bytes long", nameof(key));

            byte[] plaintext = Encoding.UTF8.GetBytes(message);
            byte[] nonce = NonceGenerator.GenerateNonce();
            byte[] ciphertext = AESEncrypt(plaintext, key.ToArray(), nonce);

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

            // 2) Initialize Sodium and check availability
            Sodium.Initialize();
            if (!IsAesGcmAvailable())
                throw new PlatformNotSupportedException("AES-GCM not supported on this platform");

            // 3) Stack-allocate state
            Span<byte> stateStorage = stackalloc byte[StateSize];

            // 4) Allocate output buffers
            byte[] ciphertext = new byte[plaintext.Length];
            tag = new byte[Constants.AUTH_TAG_SIZE];

            // 5) Expand key and encrypt
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

            // 2) Initialize Sodium and check availability
            Sodium.Initialize();
            if (!IsAesGcmAvailable())
                throw new PlatformNotSupportedException("AES-GCM not supported on this platform");

            // 3) Stack-allocate state
            Span<byte> stateStorage = stackalloc byte[StateSize];

            // 4) Allocate plaintext buffer
            byte[] plaintext = new byte[ciphertext.Length];

            // 5) Expand key and decrypt
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

        /// <summary>
        /// Context for multiple operations under the same key (amortized key schedule).
        /// </summary>
        public sealed unsafe class AesGcmContext : IDisposable
        {
            private readonly IntPtr _state;
            private bool _disposed;

            public AesGcmContext(ReadOnlySpan<byte> key)
            {
                ArgumentNullException.ThrowIfNull(key.ToArray(), nameof(key));
                if (key.Length != Constants.AES_KEY_SIZE)
                    throw new ArgumentException($"Key must be {Constants.AES_KEY_SIZE} bytes", nameof(key));

                Sodium.Initialize();
                if (!IsAesGcmAvailable())
                    throw new PlatformNotSupportedException("AES-GCM unavailable");

                // Allocate unmanaged state
                _state = Marshal.AllocHGlobal(StateSize);
                if (_state == IntPtr.Zero)
                    throw new OutOfMemoryException("Unable to allocate AES-GCM state");

                // Precompute key schedule
                fixed (byte* pKey = key)
                {
                    if (Sodium.crypto_aead_aes256gcm_beforenm(_state, new ReadOnlySpan<byte>(pKey, key.Length)) != 0)
                    {
                        Marshal.FreeHGlobal(_state);
                        throw new InvalidOperationException("Failed AES-GCM key schedule");
                    }
                }
            }

            /// <summary>
            /// Encrypts data using the precomputed key, in detached mode.
            /// </summary>
            public byte[] EncryptDetached(
                ReadOnlySpan<byte> plaintext,
                ReadOnlySpan<byte> key,
                ReadOnlySpan<byte> nonce,
                out byte[] tag,
                ReadOnlySpan<byte> additionalData = default)
            {
                ThrowIfDisposed();
                ArgumentNullException.ThrowIfNull(plaintext.ToArray(), nameof(plaintext));

                if (nonce.Length != Constants.NONCE_SIZE)
                    throw new ArgumentException($"Nonce must be {Constants.NONCE_SIZE} bytes", nameof(nonce));
                if (key.Length != Constants.AES_KEY_SIZE)
                    throw new ArgumentException($"Key must be {Constants.AES_KEY_SIZE} bytes", nameof(key));

                return AESEncryptDetached(
                    plaintext,
                    key,
                    nonce,
                    out tag,
                    additionalData);
            }

            /// <summary>
            /// Decrypts data using the precomputed key, in detached mode.
            /// </summary>
            public byte[] DecryptDetached(
                ReadOnlySpan<byte> ciphertext,
                ReadOnlySpan<byte> tag,
                ReadOnlySpan<byte> key,
                ReadOnlySpan<byte> nonce,
                ReadOnlySpan<byte> additionalData = default)
            {
                ThrowIfDisposed();
                ArgumentNullException.ThrowIfNull(ciphertext.ToArray(), nameof(ciphertext));

                if (tag.Length != Constants.AUTH_TAG_SIZE)
                    throw new ArgumentException($"Tag must be {Constants.AUTH_TAG_SIZE} bytes", nameof(tag));
                if (nonce.Length != Constants.NONCE_SIZE)
                    throw new ArgumentException($"Nonce must be {Constants.NONCE_SIZE} bytes", nameof(nonce));
                if (key.Length != Constants.AES_KEY_SIZE)
                    throw new ArgumentException($"Key must be {Constants.AES_KEY_SIZE} bytes", nameof(key));

                return AESDecryptDetached(
                    ciphertext,
                    tag,
                    key,
                    nonce,
                    additionalData);
            }

            public void Dispose()
            {
                if (!_disposed)
                {
                    Marshal.FreeHGlobal(_state);
                    _disposed = true;
                }
            }

            private void ThrowIfDisposed()
            {
                if (_disposed) throw new ObjectDisposedException(nameof(AesGcmContext));
            }
        }
    }
}