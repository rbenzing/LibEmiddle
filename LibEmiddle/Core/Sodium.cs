﻿using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using LibEmiddle.Domain;
using System.Threading;

namespace LibEmiddle.Core
{
    /// <summary>
    /// Provides a native interface to the libsodium cryptographic library.
    /// This class ensures the library is properly initialized before use.
    /// </summary>
    public static partial class Sodium
    {
        // Version constants for libsodium
        private const string SODIUM_VERSION_STRING = "1.0.20";
        private const int SODIUM_LIBRARY_VERSION_MAJOR = 10;
        private const int SODIUM_LIBRARY_VERSION_MINOR = 3;

        private static int s_initialized;
        private static bool s_loadAttempted;
        private static string s_libraryPath = string.Empty;

        // Library name based on platform
        private const string LibraryName =
#if NET
            "libsodium";
#elif WIN32
            "libsodium.dll";
#elif LINUX
            "libsodium.so";
#elif OSX
            "libsodium.dylib";
#else
            "libsodium";
#endif

        static Sodium()
        {
            try
            {
                // Try to load the library from platform-specific locations
                if (!TryLoadNativeLibrary())
                {
                    throw new DllNotFoundException("Could not load libsodium native library");
                }
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(Sodium), $"Error loading libsodium: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Initializes the libsodium library. This method is thread-safe and ensures
        /// that initialization happens only once.
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Initialize()
        {
            if (s_initialized == 0)
            {
                InitializeCore();
            }
        }

        /// <summary>
        /// Core initialization logic for the libsodium library.
        /// </summary>
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static void InitializeCore()
        {
            try
            {
                // Make version check more lenient - allow newer versions
                int major = sodium_library_version_major();
                int minor = sodium_library_version_minor();

                if (major < SODIUM_LIBRARY_VERSION_MAJOR ||
                    (major == SODIUM_LIBRARY_VERSION_MAJOR && minor < SODIUM_LIBRARY_VERSION_MINOR))
                {
                    string? version = Marshal.PtrToStringAnsi(sodium_version_string());
                    throw new InvalidOperationException($"Sodium library version too old. Expected at least: {SODIUM_VERSION_STRING}, Actual: {version}");
                }

                // Log the actual version for diagnostic purposes
                string? actualVersion = Marshal.PtrToStringAnsi(sodium_version_string());
                LoggingManager.LogInformation(nameof(Sodium), $"Loaded libsodium version: {actualVersion} (major={major}, minor={minor})");

                // Set misuse handler using Marshal for pointer conversion
                IntPtr handlerPtr = Marshal.GetFunctionPointerForDelegate(new InternalErrorCallback(InternalError));
                if (sodium_set_misuse_handler(handlerPtr) != 0)
                {
                    throw new InvalidOperationException("Failed to set Sodium misuse handler.");
                }

                // sodium_init() returns 0 on success, -1 on failure, and 1 if the
                // library had already been initialized.
                int result = sodium_init();
                if (result < 0)
                {
                    throw new InvalidOperationException("Failed to initialize Sodium library.");
                }
            }
            catch (DllNotFoundException e)
            {
                throw new PlatformNotSupportedException($"The Sodium library is not available on this platform. Attempted to load from: {s_libraryPath}", e);
            }
            catch (BadImageFormatException e)
            {
                throw new PlatformNotSupportedException($"The Sodium library format is incompatible with this platform. Attempted to load from: {s_libraryPath}", e);
            }

            Interlocked.Exchange(ref s_initialized, 1);
        }

        private static bool TryLoadNativeLibrary()
        {
            if (s_loadAttempted)
                return true;

            s_loadAttempted = true;

            try
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    if (RuntimeInformation.ProcessArchitecture == Architecture.X64)
                        return LoadLibraryFromPath("runtimes/win-x64/native/libsodium.dll");
                    else if (RuntimeInformation.ProcessArchitecture == Architecture.X86)
                        return LoadLibraryFromPath("runtimes/win-x86/native/libsodium.dll");
                    else if (RuntimeInformation.ProcessArchitecture == Architecture.Arm64)
                        return LoadLibraryFromPath("runtimes/win-arm64/native/libsodium.dll");
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                {
                    if (RuntimeInformation.ProcessArchitecture == Architecture.X64)
                        return LoadLibraryFromPath("runtimes/linux-x64/native/libsodium.so");
                    else if (RuntimeInformation.ProcessArchitecture == Architecture.Arm64)
                        return LoadLibraryFromPath("runtimes/linux-arm64/native/libsodium.so");
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                {
                    if (RuntimeInformation.ProcessArchitecture == Architecture.X64)
                        return LoadLibraryFromPath("runtimes/osx-x64/native/libsodium.dylib");
                    else if (RuntimeInformation.ProcessArchitecture == Architecture.Arm64)
                        return LoadLibraryFromPath("runtimes/osx-arm64/native/libsodium.dylib");
                }
            }
            catch (Exception ex)
            {
                LoggingManager.LogWarning(nameof(Sodium), $"Warning: Could not explicitly load the library: {ex.Message}");
                // Continue to default loading mechanism
            }

            // Fall back to default loading mechanism - we've marked the load as attempted,
            // so the DllImport attributes will try to load the library by name
            return true;
        }

        private static bool LoadLibraryFromPath(string relativePath)
        {
            try
            {
                s_libraryPath = Path.Combine(AppContext.BaseDirectory, relativePath);

                if (File.Exists(s_libraryPath))
                {
                    // Use .NET Core 3.0+ API
                    IntPtr handle = NativeLibrary.Load(s_libraryPath);

                    // If we get here, the library loaded successfully
                    LoggingManager.LogInformation(nameof(Sodium), $"Successfully loaded libsodium from: {s_libraryPath}");
                    return true;
                }
                else
                {
                    LoggingManager.LogError(nameof(Sodium), $"Library file not found at: {s_libraryPath}");
                }
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(Sodium), $"Failed to load library from {s_libraryPath}: {ex.Message}");
            }

            return false;
        }

        // Define delegate for internal error callback
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void InternalErrorCallback();

        /// <summary>
        /// Handler for internal libsodium errors.
        /// </summary>
        private static void InternalError()
        {
            throw new InvalidOperationException("Sodium internal error: The library detected a misuse of a function.");
        }

        #region Native library imports

        [LibraryImport(LibraryName, EntryPoint = "sodium_init")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        private static partial int sodium_init();

        [LibraryImport(LibraryName, EntryPoint = "sodium_version_string")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        private static partial IntPtr sodium_version_string();

        [LibraryImport(LibraryName, EntryPoint = "sodium_library_version_major")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        private static partial int sodium_library_version_major();

        [LibraryImport(LibraryName, EntryPoint = "sodium_library_version_minor")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        private static partial int sodium_library_version_minor();

        [LibraryImport(LibraryName, EntryPoint = "sodium_set_misuse_handler")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        private static partial int sodium_set_misuse_handler(IntPtr handler);

        #endregion

        #region AES encryption

        /// <summary>
        /// Returns 1 if AES-GCM is available on the processor, 0 otherwise.
        /// </summary>
        /// <returns>1 if AES-GCM is available, 0 otherwise</returns>
        [LibraryImport(LibraryName, EntryPoint = "crypto_aead_aes256gcm_is_available")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int crypto_aead_aes256gcm_is_available();

        /// <summary>
        /// Checks if AES-GCM is available on the current platform.
        /// </summary>
        /// <returns>True if AES-GCM is available, false otherwise.</returns>
        public static bool IsAesGcmAvailable()
        {
            Initialize();
            return crypto_aead_aes256gcm_is_available() == 1;
        }

        /// <summary>
        /// Initializes a context by expanding the key and always returns 0.
        /// </summary>
        [LibraryImport(LibraryName, EntryPoint = "crypto_aead_aes256gcm_beforenm")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int crypto_aead_aes256gcm_beforenm(
            IntPtr state,
            ReadOnlySpan<byte> key);

        /// <summary>
        /// Encrypts a message using a previously initialized AES-GCM context.
        /// </summary>
        [LibraryImport(LibraryName, EntryPoint = "crypto_aead_aes256gcm_encrypt_afternm")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int crypto_aead_aes256gcm_encrypt_afternm(
            Span<byte> cipher, out ulong cipherLength,
            ReadOnlySpan<byte> message, ulong messageLength,
            ReadOnlySpan<byte> additionalData, ulong additionalDataLength,
            Span<byte> nsec, // Always null for AES-GCM
            ReadOnlySpan<byte> nonce,
            IntPtr state);

        /// <summary>
        /// Decrypts a message using a previously initialized AES-GCM context.
        /// </summary>
        [LibraryImport(LibraryName, EntryPoint = "crypto_aead_aes256gcm_decrypt_afternm")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int crypto_aead_aes256gcm_decrypt_afternm(
            Span<byte> message, out ulong messageLength,
            Span<byte> nsec, // Always null for AES-GCM
            ReadOnlySpan<byte> cipher, ulong cipherLength,
            ReadOnlySpan<byte> additionalData, ulong additionalDataLength,
            ReadOnlySpan<byte> nonce,
            IntPtr state);

        /// <summary>
        /// Encrypts a message using a previously initialized AES-GCM context with detached authentication tag.
        /// </summary>
        [LibraryImport(LibraryName, EntryPoint = "crypto_aead_aes256gcm_encrypt_detached_afternm")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int crypto_aead_aes256gcm_encrypt_detached_afternm(
            Span<byte> cipher,
            Span<byte> tag, out ulong tagLength,
            ReadOnlySpan<byte> message, ulong messageLength,
            ReadOnlySpan<byte> additionalData, ulong additionalDataLength,
            Span<byte> nsec, // Always null for AES-GCM
            ReadOnlySpan<byte> nonce,
            IntPtr state);

        /// <summary>
        /// Decrypts a message using a previously initialized AES-GCM context with detached authentication tag.
        /// </summary>
        [LibraryImport(LibraryName, EntryPoint = "crypto_aead_aes256gcm_decrypt_detached_afternm")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int crypto_aead_aes256gcm_decrypt_detached_afternm(
            Span<byte> message,
            Span<byte> nsec, // Always null for AES-GCM
            ReadOnlySpan<byte> cipher, ulong cipherLength,
            ReadOnlySpan<byte> tag,
            ReadOnlySpan<byte> additionalData, ulong additionalDataLength,
            ReadOnlySpan<byte> nonce,
            IntPtr state);

        #endregion

        #region Memory operations

        /// <summary>
        /// Returns a pointer to securely allocated memory.
        /// </summary>
        [LibraryImport(LibraryName, EntryPoint = "sodium_malloc")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial IntPtr sodium_malloc(nuint size);

        /// <summary>
        /// Free the securely allocated memory.
        /// </summary>
        [LibraryImport(LibraryName, EntryPoint = "sodium_free")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial void sodium_free(IntPtr ptr);

        /// <summary>
        /// Locks the memory to avoid swapping it to disk.
        /// </summary>
        [LibraryImport(LibraryName, EntryPoint = "sodium_mlock")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int sodium_mlock(IntPtr addr, nuint len);

        /// <summary>
        /// Unlocks previously locked memory.
        /// </summary>
        [LibraryImport(LibraryName, EntryPoint = "sodium_munlock")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int sodium_munlock(IntPtr addr, nuint len);

        /// <summary>
        /// Securely zeroes a memory region.
        /// </summary>
        [LibraryImport(LibraryName, EntryPoint = "sodium_memzero")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial void sodium_memzero(IntPtr buffer, nuint length);

        /// <summary>
        /// Compares two memory regions in constant time.
        /// </summary>
        [LibraryImport(LibraryName, EntryPoint = "sodium_memcmp")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int sodium_memcmp(IntPtr b1, IntPtr b2, nuint length);

        /// <summary>
        /// Generates random bytes.
        /// </summary>
        [LibraryImport(LibraryName, EntryPoint = "randombytes_buf")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial void randombytes_buf(IntPtr buffer, nuint size);

        /// <summary>
        /// Fills a span with cryptographically secure random bytes.
        /// </summary>
        /// <param name="buffer">The buffer to fill with random bytes.</param>
        public static void RandomFill(Span<byte> buffer)
        {
            if (buffer.IsEmpty)
                throw new ArgumentException("Buffer cannot be empty", nameof(buffer));

            Initialize();

            unsafe
            {
                fixed (byte* ptr = buffer)
                {
                    randombytes_buf((IntPtr)ptr, (nuint)buffer.Length);
                }
            }
        }

        #endregion

        #region X25519 Key Exchange Functions

        /// <summary>
        /// Computes HMAC-SHA256 on the input data.
        /// </summary>
        [LibraryImport(LibraryName, EntryPoint = "crypto_auth_hmacsha256")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int crypto_auth_hmacsha256(
            Span<byte> output,
            ReadOnlySpan<byte> message,
            nuint messageLength,
            ReadOnlySpan<byte> key);

        /// <summary>
        /// Computes an HMAC-SHA256 of a message with the given key.
        /// </summary>
        /// <param name="message">The message to authenticate.</param>
        /// <param name="key">The key to use (32 bytes recommended).</param>
        /// <returns>The 32-byte HMAC output.</returns>
        public static byte[] ComputeHmacSha256(ReadOnlySpan<byte> message, ReadOnlySpan<byte> key)
        {
            if (key.Length != Constants.AES_KEY_SIZE)
                throw new ArgumentException($"Key must be {Constants.AES_KEY_SIZE} bytes long.", nameof(key));

            Initialize();

            byte[] output = new byte[Constants.AES_KEY_SIZE]; // SHA256 hash is 32 bytes
            int result = crypto_auth_hmacsha256(output, message, (nuint)message.Length, key);

            if (result != 0)
                throw new InvalidOperationException("HMAC computation failed.");

            return output;
        }

        /// <summary>
        /// Creates a master key (PRK) using HKDF-SHA256 extract.
        /// </summary>
        [LibraryImport(LibraryName, EntryPoint = "crypto_kdf_hkdf_sha256_extract")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int crypto_kdf_hkdf_sha256_extract(
            Span<byte> prk,
            ReadOnlySpan<byte> salt, nuint saltLength,
            ReadOnlySpan<byte> ikm, nuint ikmLength);

        /// <summary>
        /// Performs HKDF extraction to create a pseudorandom key.
        /// </summary>
        /// <param name="salt">Optional salt (can be null).</param>
        /// <param name="inputKeyMaterial">Input keying material.</param>
        /// <returns>32-byte PRK (pseudorandom key).</returns>
        public static byte[] HkdfExtract(ReadOnlySpan<byte> salt, ReadOnlySpan<byte> inputKeyMaterial)
        {
            Initialize();

            byte[] prk = new byte[32]; // SHA256 hash is 32 bytes
            int result = crypto_kdf_hkdf_sha256_extract(
                prk,
                salt, (uint)salt.Length,
                inputKeyMaterial, (uint)inputKeyMaterial.Length);

            if (result != 0)
                throw new InvalidOperationException("HKDF extraction failed.");

            return prk;
        }

        /// <summary>
        /// A standard alternative to crypto_kdf_derive_from_key(). It is slower, but 
        /// the context can be of any size.
        /// </summary>
        /// <param name="output"></param>
        /// <param name="outputLength"></param>
        /// <param name="info"></param>
        /// <param name="infoLength"></param>
        /// <param name="prk"></param>
        /// <returns></returns>
        [LibraryImport(LibraryName, EntryPoint = "crypto_kdf_hkdf_sha256_expand")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int crypto_kdf_hkdf_sha256_expand(
            Span<byte> output,
            nuint outputLength,
            ReadOnlySpan<byte> info,
            nuint infoLength,
            ReadOnlySpan<byte> prk);

        /// <summary>
        /// Performs HKDF expansion to derive keys.
        /// </summary>
        /// <param name="prk">The pseudorandom key from extraction step.</param>
        /// <param name="info">Optional context and application information.</param>
        /// <param name="outputLength">Desired output length.</param>
        /// <returns>Output key material of the specified length.</returns>
        public static byte[] HkdfExpand(ReadOnlySpan<byte> prk, ReadOnlySpan<byte> info, int outputLength)
        {
            if (outputLength <= 0)
                throw new ArgumentException("Output length must be positive", nameof(outputLength));

            Initialize();

            byte[] output = new byte[outputLength];
            int result = crypto_kdf_hkdf_sha256_expand(
                output, (uint)outputLength,
                info, (uint)info.Length,
                prk);

            if (result != 0)
                throw new InvalidOperationException("HKDF expand failed.");

            return output;
        }

        /// <summary>
        /// Derives a key using HKDF (both extract and expand operations).
        /// </summary>
        /// <param name="inputKeyMaterial">Input keying material.</param>
        /// <param name="salt">Optional salt (can be null).</param>
        /// <param name="info">Optional context and application information.</param>
        /// <param name="outputLength">Desired output length.</param>
        /// <returns>Derived key of the specified length.</returns>
        public static byte[] HkdfDerive(ReadOnlySpan<byte> inputKeyMaterial, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> info, int outputLength = 32)
        {
            byte[] prk = HkdfExtract(salt, inputKeyMaterial);
            try
            {
                return HkdfExpand(prk, info, outputLength);
            }
            finally
            {
                SecureMemory.SecureClear(prk);
            }
        }

        #endregion

        #region Signing & Verifying PreKeys

        /// <summary>
        /// Signs the message m, whose length is mlen bytes, using the secret key sk 
        /// and puts the signature into sig, which can be up to crypto_sign_BYTES bytes
        /// long.
        /// </summary>
        /// <param name="signature"></param>
        /// <param name="signatureLength"></param>
        /// <param name="message"></param>
        /// <param name="messageLength"></param>
        /// <param name="secretKey"></param>
        /// <returns></returns>
        [LibraryImport(LibraryName, EntryPoint = "crypto_sign_detached")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int crypto_sign_detached(
            Span<byte> signature, out nuint signatureLength,
            ReadOnlySpan<byte> message, nuint messageLength,
            ReadOnlySpan<byte> secretKey);

        /// <summary>
        /// Verifies that sig is a valid signature for the message m, whose length is mlen 
        /// bytes, using the signer’s public key pk.
        /// </summary>
        /// <param name="signature"></param>
        /// <param name="message"></param>
        /// <param name="messageLength"></param>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        [LibraryImport(LibraryName, EntryPoint = "crypto_sign_verify_detached")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int crypto_sign_verify_detached(
            ReadOnlySpan<byte> signature,
            ReadOnlySpan<byte> message, nuint messageLength,
            ReadOnlySpan<byte> publicKey);

        /// <summary>
        /// Randomly generates a secret key and a corresponding public key.
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="secretKey"></param>
        /// <returns></returns>
        [LibraryImport(LibraryName, EntryPoint = "crypto_sign_keypair")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int crypto_sign_keypair(
            Span<byte> publicKey,
            Span<byte> secretKey);

        #endregion

        #region Utility Functions

        /// <summary>
        /// Fills a buffer with random bytes using libsodium's cryptographically secure random number generator.
        /// </summary>
        /// <param name="size">Size of the buffer to create and fill.</param>
        /// <returns>A buffer filled with random bytes.</returns>
        /// <exception cref="ArgumentException">If size is less than or equal to zero.</exception>
        public static byte[] GenerateRandomBytes(uint size)
        {
            if (size <= 0)
                throw new ArgumentException("Size must be positive", nameof(size));

            Initialize();

            byte[] buffer = new byte[size];
            RandomFill(buffer);
            return buffer;
        }

        /// <summary>
        /// Computes a shared secret using X25519 key exchange.
        /// </summary>
        [LibraryImport(LibraryName, EntryPoint = "crypto_scalarmult_curve25519")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int crypto_scalarmult_curve25519(
            Span<byte> q,
            ReadOnlySpan<byte> n,
            ReadOnlySpan<byte> p);

        /// <summary>
        /// Computes a shared secret using X25519 key exchange.
        /// </summary>
        /// <param name="secretKey">Your private X25519 key (32 bytes).</param>
        /// <param name="publicKey">Peer's public X25519 key (32 bytes).</param>
        /// <returns>The 32-byte shared secret.</returns>
        /// <exception cref="ArgumentException">If keys are invalid size.</exception>
        /// <exception cref="InvalidOperationException">If DH calculation fails.</exception>
        public static byte[] ScalarMult(ReadOnlySpan<byte> secretKey, ReadOnlySpan<byte> publicKey)
        {
            if (secretKey.Length != Constants.X25519_KEY_SIZE)
                throw new ArgumentException($"Secret key must be {Constants.X25519_KEY_SIZE} bytes.", nameof(secretKey));
            if (publicKey.Length != Constants.X25519_KEY_SIZE)
                throw new ArgumentException($"Public key must be {Constants.X25519_KEY_SIZE} bytes.", nameof(publicKey));

            Initialize();

            byte[] sharedSecret = new byte[Constants.X25519_KEY_SIZE];
            int result = crypto_scalarmult_curve25519(sharedSecret, secretKey, publicKey);

            if (result != 0)
                throw new InvalidOperationException("X25519 key exchange failed.");

            return sharedSecret;
        }

        /// <summary>
        /// Computes the public key from a private key using X25519.
        /// </summary>
        [LibraryImport(LibraryName, EntryPoint = "crypto_scalarmult_curve25519_base")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int crypto_scalarmult_curve25519_base(
            Span<byte> q,
            ReadOnlySpan<byte> n);

        /// <summary>
        /// Computes the public key from a private key using X25519.
        /// </summary>
        /// <param name="secretKey">The 32-byte X25519 private key.</param>
        /// <returns>The 32-byte X25519 public key.</returns>
        /// <exception cref="ArgumentException">If the key is invalid size.</exception>
        /// <exception cref="InvalidOperationException">If calculation fails.</exception>
        public static byte[] ScalarMultBase(ReadOnlySpan<byte> secretKey)
        {
            if (secretKey.Length != Constants.X25519_KEY_SIZE)
                throw new ArgumentException($"Secret key must be {Constants.X25519_KEY_SIZE} bytes.", nameof(secretKey));

            Initialize();

            byte[] publicKey = new byte[Constants.X25519_KEY_SIZE];
            int result = crypto_scalarmult_curve25519_base(publicKey, secretKey);

            if (result != 0)
                throw new InvalidOperationException("X25519 public key generation failed.");

            return publicKey;
        }

        /// <summary>
        /// Converts an Ed25519 public key to an X25519 public key.
        /// </summary>
        [LibraryImport(LibraryName, EntryPoint = "crypto_sign_ed25519_pk_to_curve25519")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int crypto_sign_ed25519_pk_to_curve25519(
            Span<byte> x25519PublicKey,
            ReadOnlySpan<byte> ed25519PublicKey);

        /// <summary>
        /// Converts an Ed25519 public key to an X25519 public key.
        /// </summary>
        /// <param name="ed25519PublicKey">The Ed25519 public key (32 bytes).</param>
        /// <returns>The converted X25519 public key (32 bytes).</returns>
        public static byte[] ConvertEd25519PublicKeyToX25519(ReadOnlySpan<byte> ed25519PublicKey)
        {
            if (ed25519PublicKey.Length != Constants.ED25519_PUBLIC_KEY_SIZE)
                throw new ArgumentException($"Ed25519 public key must be {Constants.ED25519_PUBLIC_KEY_SIZE} bytes.", nameof(ed25519PublicKey));

            Initialize();

            byte[] x25519PublicKey = new byte[Constants.X25519_KEY_SIZE];
            int result = crypto_sign_ed25519_pk_to_curve25519(x25519PublicKey, ed25519PublicKey);

            if (result != 0)
                throw new InvalidOperationException("Failed to convert Ed25519 public key to X25519.");

            return x25519PublicKey;
        }

        /// <summary>
        /// Converts an Ed25519 secret key to an X25519 secret key.
        /// </summary>
        [LibraryImport(LibraryName, EntryPoint = "crypto_sign_ed25519_sk_to_curve25519")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int crypto_sign_ed25519_sk_to_curve25519(
            Span<byte> x25519PrivateKey,
            ReadOnlySpan<byte> ed25519PrivateKey);

        /// <summary>
        /// Converts an Ed25519 private key to an X25519 private key.
        /// </summary>
        /// <param name="ed25519PrivateKey">The Ed25519 private key (64 bytes).</param>
        /// <returns>The converted X25519 private key (32 bytes).</returns>
        public static byte[] ConvertEd25519PrivateKeyToX25519(ReadOnlySpan<byte> ed25519PrivateKey)
        {
            if (ed25519PrivateKey.Length != Constants.ED25519_PRIVATE_KEY_SIZE)
                throw new ArgumentException($"Ed25519 private key must be {Constants.ED25519_PRIVATE_KEY_SIZE} bytes.", nameof(ed25519PrivateKey));

            Initialize();

            byte[] x25519PrivateKey = new byte[Constants.X25519_KEY_SIZE];
            int result = crypto_sign_ed25519_sk_to_curve25519(x25519PrivateKey, ed25519PrivateKey);

            if (result != 0)
                throw new InvalidOperationException("Failed to convert Ed25519 private key to X25519.");

            return x25519PrivateKey;
        }

        /// <summary>
        /// Generates an Ed25519 key pair.
        /// </summary>
        [LibraryImport(LibraryName, EntryPoint = "crypto_sign_ed25519_keypair")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int crypto_sign_ed25519_keypair(
            Span<byte> publicKey,
            Span<byte> secretKey);

        /// <summary>
        /// Generates an Ed25519 key pair.
        /// </summary>
        /// <returns>A key pair with public and private keys.</returns>
        public static KeyPair GenerateEd25519KeyPair()
        {
            Initialize();

            byte[] publicKey = new byte[Constants.ED25519_PUBLIC_KEY_SIZE];
            byte[] privateKey = new byte[Constants.ED25519_PRIVATE_KEY_SIZE];

            int result = crypto_sign_ed25519_keypair(publicKey, privateKey);
            if (result != 0)
                throw new InvalidOperationException("Ed25519 key pair generation failed.");

            return new KeyPair(publicKey, privateKey);
        }

        /// <summary>
        /// Generates an Ed25519 key pair deterministically from a 32-byte seed.
        /// </summary>
        [LibraryImport(LibraryName, EntryPoint = "crypto_sign_ed25519_seed_keypair")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int crypto_sign_ed25519_seed_keypair(
            Span<byte> publicKey,
            Span<byte> secretKey,
            ReadOnlySpan<byte> seed);

        /// <summary>
        /// Generates an Ed25519 key pair from a seed.
        /// </summary>
        /// <param name="seed">The 32-byte seed.</param>
        /// <returns>A key pair with public and private keys.</returns>
        public static KeyPair GenerateEd25519KeyPairFromSeed(ReadOnlySpan<byte> seed)
        {
            if (seed.Length != 32)
                throw new ArgumentException("Seed must be 32 bytes.", nameof(seed));

            Initialize();

            byte[] publicKey = new byte[Constants.ED25519_PUBLIC_KEY_SIZE];
            byte[] privateKey = new byte[Constants.ED25519_PRIVATE_KEY_SIZE];

            int result = crypto_sign_ed25519_seed_keypair(publicKey, privateKey, seed);
            if (result != 0)
                throw new InvalidOperationException("Ed25519 key pair generation from seed failed.");

            return new KeyPair(publicKey, privateKey);
        }

        /// <summary>
        /// Randomly generates a secret key and the corresponding public key.
        /// </summary>
        [LibraryImport(LibraryName, EntryPoint = "crypto_box_keypair")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int crypto_box_keypair(
            Span<byte> publicKey,
            Span<byte> secretKey);

        /// <summary>
        /// Generates an X25519 key pair.
        /// </summary>
        /// <returns>A key pair with public and private keys.</returns>
        public static KeyPair GenerateX25519KeyPair()
        {
            Initialize();

            byte[] publicKey = new byte[Constants.X25519_KEY_SIZE];
            byte[] privateKey = new byte[Constants.X25519_KEY_SIZE];

            int result = crypto_box_keypair(publicKey, privateKey);
            if (result != 0)
                throw new InvalidOperationException("X25519 key pair generation failed.");

            return new KeyPair(publicKey, privateKey);
        }

        /// <summary>
        /// Checks that p represents a point on the edwards25519 curve, in canonical form, 
        /// on the main subgroup, and that the point doesn’t have a small order.
        /// </summary>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        [LibraryImport(LibraryName, EntryPoint = "crypto_core_ed25519_is_valid_point")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int crypto_core_ed25519_is_valid_point(
            ReadOnlySpan<byte> publicKey);

        /// <summary>
        /// Validates an Ed25519 public key.
        /// </summary>
        /// <param name="publicKey">The public key to validate.</param>
        /// <returns>True if the key is valid, false otherwise.</returns>
        public static bool ValidateEd25519PublicKey(ReadOnlySpan<byte> publicKey)
        {
            if (publicKey.Length != Constants.ED25519_PUBLIC_KEY_SIZE)
                return false;

            Initialize();

            int result = crypto_core_ed25519_is_valid_point(publicKey);
            return result == 1;
        }

        /// <summary>
        /// Signs a message using Ed25519.
        /// </summary>
        [LibraryImport(LibraryName, EntryPoint = "crypto_sign_ed25519_detached")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int crypto_sign_ed25519_detached(
            Span<byte> signature, out ulong signatureLength,
            ReadOnlySpan<byte> message, ulong messageLength,
            ReadOnlySpan<byte> secretKey);

        /// <summary>
        /// Signs a message using Ed25519.
        /// </summary>
        /// <param name="message">The message to sign.</param>
        /// <param name="privateKey">The Ed25519 private key (64 bytes).</param>
        /// <returns>The 64-byte signature.</returns>
        public static byte[] SignDetached(ReadOnlySpan<byte> message, ReadOnlySpan<byte> privateKey)
        {
            if (privateKey.Length != Constants.ED25519_PRIVATE_KEY_SIZE)
                throw new ArgumentException($"Private key must be {Constants.ED25519_PRIVATE_KEY_SIZE} bytes.", nameof(privateKey));

            Initialize();

            byte[] signature = new byte[Constants.ED25519_PRIVATE_KEY_SIZE];
            int result = crypto_sign_ed25519_detached(
                signature, 
                out _, 
                message, 
                (ulong)message.Length, 
                privateKey);

            if (result != 0)
                throw new InvalidOperationException("Signing operation failed.");

            return signature;
        }

        /// <summary>
        /// Verifies a message signature using Ed25519.
        /// </summary>
        [LibraryImport(LibraryName, EntryPoint = "crypto_sign_ed25519_verify_detached")]
        [UnmanagedCallConv(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static partial int crypto_sign_ed25519_verify_detached(
            ReadOnlySpan<byte> signature,
            ReadOnlySpan<byte> message, ulong messageLength,
            ReadOnlySpan<byte> publicKey);

        /// <summary>
        /// Verifies an Ed25519 signature.
        /// </summary>
        /// <param name="signature">The signature to verify (64 bytes).</param>
        /// <param name="message">The original message that was signed.</param>
        /// <param name="publicKey">The signer's Ed25519 public key (32 bytes).</param>
        /// <returns>True if the signature is valid, false otherwise.</returns>
        public static bool VerifyDetached(ReadOnlySpan<byte> signature, ReadOnlySpan<byte> message, ReadOnlySpan<byte> publicKey)
        {
            if (signature.Length != Constants.ED25519_PRIVATE_KEY_SIZE)
                throw new ArgumentException($"Signature must be {Constants.ED25519_PRIVATE_KEY_SIZE} bytes.", nameof(signature));

            if (publicKey.Length != Constants.ED25519_PUBLIC_KEY_SIZE)
                throw new ArgumentException($"Public key must be {Constants.ED25519_PUBLIC_KEY_SIZE} bytes.", nameof(publicKey));

            Initialize();

            int result = crypto_sign_ed25519_verify_detached(signature, message, (nuint)message.Length, publicKey);
            return result == 0;
        }

        /// <summary>
        /// Computes a shared secret using X25519 key exchange.
        /// </summary>
        /// <param name="output">The shared secret output (32 bytes).</param>
        /// <param name="privateKey">Your private X25519 key (32 bytes).</param>
        /// <param name="peerPublicKey">Peer's public X25519 key (32 bytes).</param>
        public static void ComputeSharedSecret(
            Span<byte> output, 
            ReadOnlySpan<byte> privateKey, 
            ReadOnlySpan<byte> peerPublicKey)
        {
            if (output.Length != Constants.X25519_KEY_SIZE || privateKey.Length != Constants.X25519_KEY_SIZE || peerPublicKey.Length != Constants.X25519_KEY_SIZE)
                throw new ArgumentException($"All buffers must be exactly {Constants.X25519_KEY_SIZE} bytes.");

            // Call underlying DllImport using stack-allocated temporary arrays
            byte[] q = new byte[Constants.X25519_KEY_SIZE];
            byte[] n = privateKey.ToArray();
            byte[] p = peerPublicKey.ToArray();

            int result = crypto_scalarmult_curve25519(q, n, p);
            if (result != 0)
                throw new InvalidOperationException("X25519 key agreement failed.");

            q.CopyTo(output);
        }

        /// <summary>
        /// Computes the X25519 public key corresponding to a private key.
        /// </summary>
        /// <param name="output">The generated public key (32 bytes).</param>
        /// <param name="privateKey">The private key to derive from (32 bytes).</param>
        public static void ComputePublicKey(Span<byte> output, ReadOnlySpan<byte> privateKey)
        {
            const int KeySize = Constants.X25519_KEY_SIZE;

            if (output.Length != KeySize || privateKey.Length != KeySize)
                throw new ArgumentException($"Both buffers must be exactly {KeySize} bytes.");

            int result = Sodium.crypto_scalarmult_curve25519_base(output, privateKey);

            if (result != 0)
                throw new InvalidOperationException("Failed to compute X25519 public key.");
        }

        /// <summary>
        /// Securely compares two spans of bytes in constant time to prevent timing attacks.
        /// </summary>
        /// <param name="a">First span to compare.</param>
        /// <param name="b">Second span to compare.</param>
        /// <returns>True if spans are identical, false otherwise.</returns>
        public static bool ConstantTimeEquals(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
        {
            if (a.Length != b.Length)
                return false;

            if (a.Length == 0)
                return true;

            Initialize();

            unsafe
            {
                fixed (byte* aPtr = a)
                fixed (byte* bPtr = b)
                {
                    return sodium_memcmp((IntPtr)aPtr, (IntPtr)bPtr, (nuint)a.Length) == 0;
                }
            }
        }

        /// <summary>
        /// Creates a secure memory buffer that is protected from being swapped to disk.
        /// </summary>
        /// <param name="size">Size of the buffer in bytes.</param>
        /// <returns>A handle to the secure memory.</returns>
        public static IntPtr SecureAlloc(uint size)
        {
            if (size <= 0)
                throw new ArgumentException("Size must be positive", nameof(size));

            Initialize();

            IntPtr ptr = sodium_malloc(size);
            if (ptr == IntPtr.Zero)
                throw new OutOfMemoryException("Failed to allocate secure memory.");

            return ptr;
        }

        /// <summary>
        /// Securely frees memory allocated with SecureAlloc.
        /// </summary>
        /// <param name="ptr">Pointer to the memory to free.</param>
        public static void SecureFree(IntPtr ptr)
        {
            if (ptr == IntPtr.Zero)
                return;

            Initialize();
            sodium_free(ptr);
        }

        /// <summary>
        /// Securely zeros a memory region.
        /// </summary>
        /// <param name="buffer">Pointer to the memory region.</param>
        /// <param name="length">Length of the memory region.</param>
        public static void SecureZero(IntPtr buffer, uint length)
        {
            if (buffer == IntPtr.Zero || length <= 0)
                return;

            Initialize();
            sodium_memzero(buffer, (nuint)length);
        }

        /// <summary>
        /// Locks memory to prevent it from being swapped to disk.
        /// </summary>
        /// <param name="buffer">Pointer to the memory region.</param>
        /// <param name="length">Length of the memory region.</param>
        /// <returns>True if successful, false otherwise.</returns>
        public static bool LockMemory(IntPtr buffer, uint length)
        {
            if (buffer == IntPtr.Zero || length <= 0)
                return false;

            Initialize();
            return sodium_mlock(buffer, (nuint)length) == 0;
        }

        /// <summary>
        /// Unlocks previously locked memory and zeros it.
        /// </summary>
        /// <param name="buffer">Pointer to the memory region.</param>
        /// <param name="length">Length of the memory region.</param>
        /// <returns>True if successful, false otherwise.</returns>
        public static bool UnlockMemory(IntPtr buffer, int length)
        {
            if (buffer == IntPtr.Zero || length <= 0)
                return false;

            Initialize();
            return sodium_munlock(buffer, (uint)length) == 0;
        }

        #endregion
    }
}