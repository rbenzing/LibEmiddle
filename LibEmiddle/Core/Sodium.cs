using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace E2EELibrary.Core
{
    /// <summary>
    /// Provides a native interface to the libsodium cryptographic library.
    /// This class ensures the library is properly initialized before use.
    /// </summary>
    public static class Sodium
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
        private static unsafe void InitializeCore()
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

        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        private static extern int sodium_init();

        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr sodium_version_string();

        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        private static extern int sodium_library_version_major();

        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        private static extern int sodium_library_version_minor();

        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        private static extern int sodium_set_misuse_handler(IntPtr handler);

        #endregion

        #region AES encryption

        /// <summary>
        /// Returns a 0 or 1 when AES-GCM is available on the processor.
        /// </summary>
        /// <returns></returns>
        [DllImport(Sodium.LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_aead_aes256gcm_is_available();

        /// <summary>
        /// Initializes a context ctx by expanding the key k and always returns 0.
        /// </summary>
        /// <param name="state"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        [DllImport(Sodium.LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_aead_aes256gcm_beforenm(IntPtr state, byte[] key);

        /// <summary>
        /// The crypto_aead_aes256gcm_encrypt_afternm() and crypto_aead_aes256gcm_decrypt_afternm() 
        /// functions are identical to crypto_aead_aes256gcm_encrypt() and 
        /// crypto_aead_aes256gcm_decrypt(), but accept a previously initialized 
        /// context ctx instead of a key.
        /// </summary>
        [DllImport(Sodium.LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_aead_aes256gcm_encrypt_afternm(
            byte[] cipher, out ulong cipherLength,
            byte[] message, ulong messageLength,
            byte[] additionalData, ulong additionalDataLength,
            byte[]? nsec, // Always null for AES-GCM
            byte[] nonce,
            IntPtr state);

        /// <summary>
        /// The crypto_aead_aes256gcm_encrypt_afternm() and crypto_aead_aes256gcm_decrypt_afternm() 
        /// functions are identical to crypto_aead_aes256gcm_encrypt() and 
        /// crypto_aead_aes256gcm_decrypt(), but accept a previously initialized 
        /// context ctx instead of a key.
        /// </summary>
        [DllImport(Sodium.LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_aead_aes256gcm_decrypt_afternm(
            byte[] message, out ulong messageLength,
            byte[]? nsec, // Always null for AES-GCM
            byte[] cipher, ulong cipherLength,
            byte[] additionalData, ulong additionalDataLength,
            byte[] nonce,
            IntPtr state);

        /// <summary>
        /// Function is identical to crypto_aead_aes256gcm_encrypt_detached() and 
        /// crypto_aead_aes256gcm_decrypt_detached(), but accept a previously 
        /// initialized context ctx instead of a key.
        /// </summary>
        [DllImport(Sodium.LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_aead_aes256gcm_encrypt_detached_afternm(
            byte[] cipher,
            byte[] tag, out ulong tagLength,
            byte[] message, ulong messageLength,
            byte[] additionalData, ulong additionalDataLength,
            byte[]? nsec, // Always null for AES-GCM
            byte[] nonce,
            IntPtr state);

        /// <summary>
        /// Function is identical to crypto_aead_aes256gcm_encrypt_detached() and 
        /// crypto_aead_aes256gcm_decrypt_detached(), but accept a previously 
        /// initialized context ctx instead of a key.
        /// </summary>
        [DllImport(Sodium.LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_aead_aes256gcm_decrypt_detached_afternm(
            byte[] message,
            byte[]? nsec, // Always null for AES-GCM
            byte[] cipher, ulong cipherLength,
            byte[] tag,
            byte[] additionalData, ulong additionalDataLength,
            byte[] nonce,
            IntPtr state);

        #endregion

        #region Memory operations

        /// <summary>
        /// Returns a pointer from which exactly size contiguous bytes of memory can be
        /// accessed. Like normal malloc, NULL may be returned and errno set if it is 
        /// not possible to allocate enough memory.
        /// </summary>
        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr sodium_malloc(UIntPtr size);

        /// <summary>
        /// Free the allocated region
        /// </summary>
        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void sodium_free(IntPtr ptr);

        /// <summary>
        /// Locks at least len bytes of memory starting at addr. This can help avoid swapping 
        /// sensitive data to disk.
        /// </summary>
        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int sodium_mlock(IntPtr addr, UIntPtr len);

        /// <summary>
        /// Called after locked memory is not being used anymore. It will zero len bytes starting at 
        /// addr before flagging the pages as swappable again. 
        /// </summary>
        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int sodium_munlock(IntPtr addr, UIntPtr len);

        /// <summary>
        /// Securely zeros out a memory region.
        /// </summary>
        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void sodium_memzero(IntPtr buffer, UIntPtr length);

        /// <summary>
        /// Securely compares two memory regions in constant time.
        /// </summary>
        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int sodium_memcmp(IntPtr b1, IntPtr b2, UIntPtr length);

        /// <summary>
        /// Generates random bytes suitable for cryptographic use.
        /// </summary>
        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        private static extern void randombytes_buf(IntPtr buffer, UIntPtr size);

        #endregion

        #region X25519 Key Exchange Functions

        /// <summary>
        /// Computes HMAC-SHA256 on the input data
        /// </summary>
        /// <param name="output"></param>
        /// <param name="outputLength"></param>
        /// <param name="info"></param>
        /// <param name="infoLength"></param>
        /// <param name="prk"></param>
        /// <returns></returns>
        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_auth_hmacsha256(
            byte[] output, UIntPtr outputLength,
            byte[] info, UIntPtr infoLength,
            byte[] prk);


        /// <summary>
        /// Creates a master key (prk) given an optional salt salt (which can be NULL, or 
        /// salt_len bytes), and input keying material ikm of size ikm_len bytes.
        /// </summary>
        /// <param name="prk"></param>
        /// <param name="salt"></param>
        /// <param name="saltLength"></param>
        /// <param name="ikm"></param>
        /// <param name="ikmLength"></param>
        /// <returns></returns>
        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_kdf_hkdf_sha256_extract(
            byte[] prk,
            byte[]? salt, UIntPtr saltLength,
            byte[] ikm, UIntPtr ikmLength);

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
        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_kdf_hkdf_sha256_expand(
            byte[] output, UIntPtr outputLength,
            byte[] info, UIntPtr infoLength,
            byte[] prk);

        /// <summary>
        /// Computes a shared secret using X25519 key exchange.
        /// </summary>
        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_scalarmult_curve25519(byte[] q, byte[] n, byte[] p);

        /// <summary>
        /// Computes the public key from a private key using X25519.
        /// </summary>
        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_scalarmult_curve25519_base(byte[] q, byte[] n);

        #endregion

        #region X25519 Key Generation

        /// <summary>
        /// Checks that p represents a point on the edwards25519 curve, in canonical form, 
        /// on the main subgroup, and that the point doesn’t have a small order.
        /// </summary>
        /// <param name="p"></param>
        /// <returns></returns>
        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_core_ed25519_is_valid_point(byte[] p);

        /// <summary>
        /// Randomly generates a secret key and the corresponding public key.
        /// </summary>
        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_box_keypair(byte[] publicKey, byte[] secretKey);

        #endregion

        #region Ed25519 Digital Signature Functions

        /// <summary>
        /// Signs a message using Ed25519.
        /// </summary>
        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_sign_ed25519_detached(
            byte[] signature, out ulong signatureLength,
            byte[] message, ulong messageLength,
            byte[] secretKey);

        /// <summary>
        /// Verifies a message signature using Ed25519.
        /// </summary>
        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_sign_ed25519_verify_detached(
            byte[] signature,
            byte[] message, ulong messageLength,
            byte[] publicKey);

        /// <summary>
        /// Generates an Ed25519 key pair.
        /// </summary>
        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_sign_ed25519_keypair(byte[] publicKey, byte[] secretKey);

        /// <summary>
        /// Generates an Ed25519 key pair deterministically from a 32-byte seed.
        /// </summary>
        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_sign_ed25519_seed_keypair(byte[] publicKey, byte[] secretKey, byte[] seed);

        /// <summary>
        /// Converts an Ed25519 public key to an X25519 public key.
        /// </summary>
        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_sign_ed25519_pk_to_curve25519(byte[] curve25519_pk, byte[] ed25519_pk);

        /// <summary>
        /// Converts an Ed25519 secret key to an X25519 secret key.
        /// </summary>
        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_sign_ed25519_sk_to_curve25519(byte[] curve25519_sk, byte[] ed25519_sk);

        #endregion

        #region Public Key Authentication

        /// <summary>
        /// Randomly generates a secret key and a corresponding public key.
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="secretKey"></param>
        /// <returns></returns>
        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_sign_keypair(byte[] publicKey, byte[] secretKey);

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
        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_sign_detached(
            byte[] signature, out ulong signatureLength,
            byte[] message, ulong messageLength,
            byte[] secretKey);

        /// <summary>
        /// Verifies that sig is a valid signature for the message m, whose length is mlen 
        /// bytes, using the signer’s public key pk.
        /// </summary>
        /// <param name="signature"></param>
        /// <param name="message"></param>
        /// <param name="messageLength"></param>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_sign_verify_detached(
            byte[] signature,
            byte[] message, ulong messageLength,
            byte[] publicKey);

        #endregion

        #region Utility Functions

        /// <summary>
        /// Fills a buffer with random bytes using libsodium's cryptographically secure random number generator.
        /// </summary>
        /// <param name="buffer">The buffer to fill with random data.</param>
        public static void RandomBytes(byte[] buffer)
        {
            if (buffer == null)
                throw new ArgumentNullException(nameof(buffer));

            Initialize();

            // Use Marshal for safe pointer handling
            GCHandle bufferHandle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            try
            {
                randombytes_buf(bufferHandle.AddrOfPinnedObject(), (UIntPtr)buffer.Length);
            }
            finally
            {
                bufferHandle.Free();
            }
        }

        /// <summary>
        /// Generates a buffer with random bytes.
        /// </summary>
        public static byte[] GenerateRandomBytes(int size)
        {
            if (size <= 0)
                throw new ArgumentException("Size must be positive", nameof(size));

            Initialize();

            byte[] buffer = new byte[size];

            // Use Marshal for safe pointer handling
            GCHandle bufferHandle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            try
            {
                randombytes_buf(bufferHandle.AddrOfPinnedObject(), (UIntPtr)size);
            }
            finally
            {
                bufferHandle.Free();
            }

            return buffer;
        }

        /// <summary>
        /// Computes a shared secret using X25519.
        /// </summary>
        /// <param name="secretKey">The secret key.</param>
        /// <param name="publicKey">The public key.</param>
        /// <returns>The shared secret.</returns>
        public static byte[] ScalarMult(byte[] secretKey, byte[] publicKey)
        {
            if (secretKey == null)
                throw new ArgumentNullException(nameof(secretKey));
            if (publicKey == null)
                throw new ArgumentNullException(nameof(publicKey));

            Initialize();

            byte[] sharedSecret = GenerateRandomBytes(Constants.AES_KEY_SIZE);
            int result = crypto_scalarmult_curve25519(sharedSecret, secretKey, publicKey);

            if (result != 0)
                throw new InvalidOperationException("X25519 key exchange failed.");

            return sharedSecret;
        }

        /// <summary>
        /// Computes the public key from a private key using X25519.
        /// </summary>
        /// <param name="secretKey">The secret key.</param>
        /// <returns>The public key.</returns>
        public static byte[] ScalarMultBase(byte[] secretKey)
        {
            if (secretKey == null)
                throw new ArgumentNullException(nameof(secretKey));

            Initialize();

            byte[] publicKey = GenerateRandomBytes(Constants.AES_KEY_SIZE);
            int result = crypto_scalarmult_curve25519_base(publicKey, secretKey);

            if (result != 0)
                throw new InvalidOperationException("X25519 public key generation failed.");

            return publicKey;
        }

        #endregion
    }
}