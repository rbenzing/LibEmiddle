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
        private const string SODIUM_VERSION_STRING = "1.0.18";
        private const int SODIUM_LIBRARY_VERSION_MAJOR = 10;
        private const int SODIUM_LIBRARY_VERSION_MINOR = 3;

        private static int s_initialized;

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
                if (sodium_library_version_major() != SODIUM_LIBRARY_VERSION_MAJOR ||
                    sodium_library_version_minor() != SODIUM_LIBRARY_VERSION_MINOR)
                {
                    string? version = Marshal.PtrToStringAnsi(sodium_version_string());
                    throw (version != null && version != SODIUM_VERSION_STRING)
                        ? new InvalidOperationException($"Sodium library version mismatch. Expected: {SODIUM_VERSION_STRING}, Actual: {version}")
                        : new InvalidOperationException("Failed to initialize Sodium library due to version mismatch.");
                }

                if (sodium_set_misuse_handler(&InternalError) != 0)
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
                throw new PlatformNotSupportedException("The Sodium library is not available on this platform.", e);
            }
            catch (BadImageFormatException e)
            {
                throw new PlatformNotSupportedException("The Sodium library format is incompatible with this platform.", e);
            }

            Interlocked.Exchange(ref s_initialized, 1);
        }

        /// <summary>
        /// Handler for internal libsodium errors.
        /// </summary>
        [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvCdecl) })]
        private static void InternalError()
        {
            throw new InvalidOperationException("Sodium internal error: The library detected a misuse of a function.");
        }

        #region Native library imports

        [DllImport("libsodium", CallingConvention = CallingConvention.Cdecl)]
        private static extern int sodium_init();

        [DllImport("libsodium", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr sodium_version_string();

        [DllImport("libsodium", CallingConvention = CallingConvention.Cdecl)]
        private static extern int sodium_library_version_major();

        [DllImport("libsodium", CallingConvention = CallingConvention.Cdecl)]
        private static extern int sodium_library_version_minor();

        [DllImport("libsodium", CallingConvention = CallingConvention.Cdecl)]
        private static extern unsafe int sodium_set_misuse_handler(delegate* unmanaged[Cdecl]<void> handler);

        #endregion

        #region Common libsodium operations

        /// <summary>
        /// Securely zeros out a memory region.
        /// </summary>
        /// <param name="buffer">The memory region to zero.</param>
        /// <param name="length"></param>
        [DllImport("libsodium", CallingConvention = CallingConvention.Cdecl)]
        public static extern void sodium_memzero(IntPtr buffer, UIntPtr length);

        /// <summary>
        /// Securely compares two memory regions in constant time.
        /// </summary>
        /// <param name="b1">First memory region.</param>
        /// <param name="b2">Second memory region.</param>
        /// <param name="length">Length to compare.</param>
        /// <returns>0 if the regions are equal, non-zero otherwise.</returns>
        [DllImport("libsodium", CallingConvention = CallingConvention.Cdecl)]
        public static extern int sodium_memcmp(IntPtr b1, IntPtr b2, UIntPtr length);

        /// <summary>
        /// Generates random bytes suitable for cryptographic use.
        /// </summary>
        /// <param name="buffer">The buffer to fill with random bytes.</param>
        /// <param name="size">The number of bytes to fill.</param>
        [DllImport("libsodium", CallingConvention = CallingConvention.Cdecl)]
        public static extern void randombytes_buf(IntPtr buffer, UIntPtr size);

        #endregion

        // Additional libsodium functions used throughout your project

        #region X25519 Key Exchange Functions

        /// <summary>
        /// Computes a shared secret using X25519 key exchange.
        /// </summary>
        [DllImport("libsodium", CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_scalarmult_curve25519(byte[] q, byte[] n, byte[] p);

        /// <summary>
        /// Computes the public key from a private key using X25519.
        /// </summary>
        [DllImport("libsodium", CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_scalarmult_curve25519_base(byte[] q, byte[] n);

        #endregion

        #region Ed25519 Digital Signature Functions

        /// <summary>
        /// Signs a message using Ed25519.
        /// </summary>
        [DllImport("libsodium", CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_sign_ed25519_detached(
            byte[] signature, out ulong signatureLength,
            byte[] message, ulong messageLength,
            byte[] secretKey);

        /// <summary>
        /// Verifies a message signature using Ed25519.
        /// </summary>
        [DllImport("libsodium", CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_sign_ed25519_verify_detached(
            byte[] signature,
            byte[] message, ulong messageLength,
            byte[] publicKey);

        /// <summary>
        /// Generates an Ed25519 key pair.
        /// </summary>
        [DllImport("libsodium", CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_sign_ed25519_keypair(byte[] publicKey, byte[] secretKey);

        /// <summary>
        /// Converts an Ed25519 public key to an X25519 public key.
        /// </summary>
        [DllImport("libsodium", CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_sign_ed25519_pk_to_curve25519(byte[] curve25519_pk, byte[] ed25519_pk);

        /// <summary>
        /// Converts an Ed25519 secret key to an X25519 secret key.
        /// </summary>
        [DllImport("libsodium", CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_sign_ed25519_sk_to_curve25519(byte[] curve25519_sk, byte[] ed25519_sk);

        #endregion

        #region Public Key Authentication

        [DllImport("libsodium", CallingConvention = CallingConvention.Cdecl)]
        private static extern int crypto_sign_keypair(byte[] publicKey, byte[] secretKey);

        [DllImport("libsodium", CallingConvention = CallingConvention.Cdecl)]
        private static extern int crypto_sign_detached(
            byte[] signature, out ulong signatureLength,
            byte[] message, ulong messageLength,
            byte[] secretKey);

        [DllImport("libsodium", CallingConvention = CallingConvention.Cdecl)]
        private static extern int crypto_sign_verify_detached(
            byte[] signature,
            byte[] message, ulong messageLength,
            byte[] publicKey);

        #endregion

        #region Utility Functions

        /// <summary>
        /// Fills a buffer with random bytes.
        /// </summary>
        /// <param name="buffer">The buffer to fill with random data.</param>
        public static void RandomBytes(byte[] buffer)
        {
            if (buffer == null)
                throw new ArgumentNullException(nameof(buffer));

            Initialize();

            unsafe
            {
                fixed (byte* ptr = buffer)
                {
                    randombytes_buf((IntPtr)ptr, (UIntPtr)buffer.Length);
                }
            }
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

            byte[] sharedSecret = new byte[32];
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

            byte[] publicKey = new byte[32];
            int result = crypto_scalarmult_curve25519_base(publicKey, secretKey);

            if (result != 0)
                throw new InvalidOperationException("X25519 public key generation failed.");

            return publicKey;
        }

        #endregion
    }
}