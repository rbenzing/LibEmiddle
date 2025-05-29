using System.Security.Cryptography;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using LibEmiddle.Domain;

namespace LibEmiddle.Core;

/// <summary>
/// Provides a native interface to the libsodium cryptographic library.
/// This class ensures the library is properly initialized before use.
/// </summary>
public sealed partial class Sodium
{
    // Version constants for libsodium
    private const string SODIUM_VERSION_STRING = "1.0.20";
    private const int SODIUM_LIBRARY_VERSION_MAJOR = 10;
    private const int SODIUM_LIBRARY_VERSION_MINOR = 3;
    private static readonly InternalErrorCallback s_internalErrorCallback = new InternalErrorCallback(InternalError);

    private static int s_initialized;
    private static bool s_loadAttempted;
    private static string s_libraryPath = string.Empty;
    private static readonly object s_initLock = new();

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

    public Sodium()
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
    public static void Initialize()
    {
        if (Volatile.Read(ref s_initialized) != 0)
            return;

        lock (s_initLock)
        {
            if (Volatile.Read(ref s_initialized) != 0)
                return;

            InitializeCore();
        }
    }

    /// <summary>
    /// Core initialization logic for the libsodium library.
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void InitializeCore()
    {
        IntPtr versionPtr = IntPtr.Zero;

        try
        {
            // Make version check more lenient - allow newer versions
            int major = sodium_library_version_major();
            int minor = sodium_library_version_minor();

            versionPtr = sodium_version_string();

            if (major < SODIUM_LIBRARY_VERSION_MAJOR ||
                (major == SODIUM_LIBRARY_VERSION_MAJOR && minor < SODIUM_LIBRARY_VERSION_MINOR))
            {
                string? version = Marshal.PtrToStringAnsi(versionPtr);
                throw new InvalidOperationException($"Sodium library version too old. Expected at least: {SODIUM_VERSION_STRING}, Actual: {version}");
            } else
            {
                // Log the actual version for diagnostic purposes
                string? actualVersion = Marshal.PtrToStringAnsi(versionPtr);
                LoggingManager.LogInformation(nameof(Sodium), $"Loaded libsodium version: {actualVersion} (major={major}, minor={minor})");
            }

            // Set misuse handler using Marshal for pointer conversion
            IntPtr functionPointer = Marshal.GetFunctionPointerForDelegate(s_internalErrorCallback);
            if (sodium_set_misuse_handler(functionPointer) != 0)
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

            Volatile.Write(ref s_initialized, 1);
        }
        catch (DllNotFoundException e)
        {
            throw new PlatformNotSupportedException($"The Sodium library is not available on this platform. Attempted to load from: {s_libraryPath}", e);
        }
        catch (BadImageFormatException e)
        {
            throw new PlatformNotSupportedException($"The Sodium library format is incompatible with this platform. Attempted to load from: {s_libraryPath}", e);
        }
    }

    private static bool TryLoadNativeLibrary()
    {
        if (Volatile.Read(ref s_loadAttempted))
            return true;

        lock (s_initLock)
        {
            if (Volatile.Read(ref s_loadAttempted))
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
                LoggingManager.LogError(nameof(Sodium), $"Failed to load native library: {ex.Message}");
                throw new DllNotFoundException($"Could not load libsodium native library: {ex.Message}", ex);
            }

            // Fall back to default loading mechanism
            LoggingManager.LogWarning(nameof(Sodium), "No platform-specific library found, attempting default load mechanism");
            return true;
        }
    }

    private static bool LoadLibraryFromPath(string relativePath)
    {
        IntPtr handle = IntPtr.Zero;
        try
        {
            s_libraryPath = Path.Combine(AppContext.BaseDirectory, relativePath);

            if (File.Exists(s_libraryPath))
            {
                // Use .NET Core 3.0+ API with proper error handling
                handle = NativeLibrary.Load(s_libraryPath);

                if (handle == IntPtr.Zero)
                {
                    LoggingManager.LogError(nameof(Sodium), $"NativeLibrary.Load returned null handle for: {s_libraryPath}");
                    return false;
                }

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

            // Attempt to free the handle if it was partially loaded
            if (handle != IntPtr.Zero)
            {
                try
                {
                    NativeLibrary.Free(handle);
                }
                catch
                {
                    // Best effort cleanup
                }
            }
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
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial int sodium_init();

    [LibraryImport(LibraryName, EntryPoint = "sodium_version_string")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial IntPtr sodium_version_string();

    [LibraryImport(LibraryName, EntryPoint = "sodium_library_version_major")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial int sodium_library_version_major();

    [LibraryImport(LibraryName, EntryPoint = "sodium_library_version_minor")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial int sodium_library_version_minor();

    [LibraryImport(LibraryName, EntryPoint = "sodium_set_misuse_handler")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial int sodium_set_misuse_handler(IntPtr handler);

    #endregion

    #region AES encryption

    /// <summary>
    /// Returns 1 if AES-GCM is available on the processor, 0 otherwise.
    /// </summary>
    /// <returns>1 if AES-GCM is available, 0 otherwise</returns>
    [LibraryImport(LibraryName, EntryPoint = "crypto_aead_aes256gcm_is_available")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
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
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_aead_aes256gcm_beforenm(
        IntPtr state,
        ReadOnlySpan<byte> key);

    /// <summary>
    /// Encrypts a message using a previously initialized AES-GCM context.
    /// </summary>
    [LibraryImport(LibraryName, EntryPoint = "crypto_aead_aes256gcm_encrypt_afternm")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
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
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_aead_aes256gcm_decrypt_afternm(
        Span<byte> message,
        out ulong messageLength,
        Span<byte> nsec, // Always null for AES-GCM
        ReadOnlySpan<byte> cipher,
        ulong cipherLength,
        ReadOnlySpan<byte> additionalData,
        ulong additionalDataLength,
        ReadOnlySpan<byte> nonce,
        IntPtr state);

    /// <summary>
    /// Encrypts a message using a previously initialized AES-GCM context with detached authentication tag.
    /// </summary>
    [LibraryImport(LibraryName, EntryPoint = "crypto_aead_aes256gcm_encrypt_detached_afternm")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_aead_aes256gcm_encrypt_detached_afternm(
        Span<byte> c,          // unsigned char *c
        Span<byte> mac,        // unsigned char *mac
        out ulong maclen_p,   // unsigned long long *maclen_p
        ReadOnlySpan<byte> m,          // const unsigned char *m
        ulong mlen,       // unsigned long long mlen
        ReadOnlySpan<byte> ad,         // const unsigned char *ad
        ulong adlen,      // unsigned long long adlen
        ReadOnlySpan<byte> nsec,       // const unsigned char *nsec (always null)
        ReadOnlySpan<byte> npub,       // const unsigned char *npub (nonce)
        IntPtr ctx);         // const crypto_aead_aes256gcm_state *ctx

    /// <summary>
    /// Encrypts a message using a previously initialized AES-GCM context with detached authentication tag.
    /// </summary>
    [LibraryImport(LibraryName, EntryPoint = "crypto_aead_aes256gcm_decrypt_detached_afternm")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_aead_aes256gcm_decrypt_detached_afternm(
        Span<byte> m,          // unsigned char *m
        out ulong mlen_p,     // unsigned long long *mlen_p
        Span<byte> nsec,       // unsigned char *nsec (always null)
        ReadOnlySpan<byte> c,          // const unsigned char *c
        ulong clen,       // unsigned long long clen
        ReadOnlySpan<byte> mac,        // const unsigned char *mac
        ReadOnlySpan<byte> ad,         // const unsigned char *ad
        ulong adlen,      // unsigned long long adlen
        ReadOnlySpan<byte> npub,       // const unsigned char *npub (nonce)
        IntPtr ctx);         // const crypto_aead_aes256gcm_state *ctx

    #endregion

    #region Memory operations

    /// <summary>
    /// Returns a pointer to securely allocated memory.
    /// </summary>
    [LibraryImport(LibraryName, EntryPoint = "sodium_malloc")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial IntPtr sodium_malloc(nuint size);

    /// <summary>
    /// Free the securely allocated memory.
    /// </summary>
    [LibraryImport(LibraryName, EntryPoint = "sodium_free")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial void sodium_free(IntPtr ptr);

    /// <summary>
    /// Locks the memory to avoid swapping it to disk.
    /// </summary>
    [LibraryImport(LibraryName, EntryPoint = "sodium_mlock")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int sodium_mlock(IntPtr addr, nuint len);

    /// <summary>
    /// Unlocks previously locked memory.
    /// </summary>
    [LibraryImport(LibraryName, EntryPoint = "sodium_munlock")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int sodium_munlock(IntPtr addr, nuint len);

    /// <summary>
    /// Securely zeroes a memory region.
    /// </summary>
    [LibraryImport(LibraryName, EntryPoint = "sodium_memzero")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial void sodium_memzero(IntPtr buffer, nuint length);

    /// <summary>
    /// Compares two memory regions in constant time.
    /// </summary>
    [LibraryImport(LibraryName, EntryPoint = "sodium_memcmp")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int sodium_memcmp(IntPtr b1, IntPtr b2, nuint length);

    /// <summary>
    /// Generates random bytes.
    /// </summary>
    [LibraryImport(LibraryName, EntryPoint = "randombytes_buf")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
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
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
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
    public static byte[] GenerateHmacSha256(ReadOnlySpan<byte> message, ReadOnlySpan<byte> key)
    {
        if (key.Length != Constants.AES_KEY_SIZE)
            throw new ArgumentException($"Key must be {Constants.AES_KEY_SIZE} bytes long.", nameof(key));

        Initialize();

        byte[] output = new byte[Constants.AES_KEY_SIZE]; // SHA256 hash is 32 bytes

        try
        {
            int result = crypto_auth_hmacsha256(output, message, (nuint)message.Length, key);

            if (result != 0)
                throw new CryptographicException("Libsodium HMAC-SHA256 computation failed.");

            return output;
        }
        catch
        {
            // Ensure output is cleared on any exception
            SecureMemory.SecureClear(output);
            throw;
        }
    }

    /// <summary>
    /// Creates a master key (PRK) using HKDF-SHA256 extract.
    /// </summary>
    [LibraryImport(LibraryName, EntryPoint = "crypto_kdf_hkdf_sha256_extract")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_kdf_hkdf_sha256_extract(Span<byte> prk,
        ReadOnlySpan<byte> salt,
        nuint saltLength,
        ReadOnlySpan<byte> ikm,
        nuint ikmLength);

    /// <summary>
    /// Performs HKDF extraction to create a pseudorandom key.
    /// </summary>
    /// <param name="salt">Optional salt (can be null).</param>
    /// <param name="inputKeyMaterial">Input keying material.</param>
    /// <param name="outputPrk">The derived PRK.</param>
    /// <returns>32-byte PRK (pseudorandom key).</returns>
    private static void HkdfExtract(ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> inputKeyMaterial,
        Span<byte> outputPrk)
    {
        if (outputPrk.Length != 32)
            throw new ArgumentException("Output buffer must be 32 bytes for SHA256 PRK.");

        if (inputKeyMaterial.IsEmpty)
            inputKeyMaterial = Encoding.UTF8.GetBytes(ProtocolVersion.FULL_VERSION);

        Initialize();

        int result = crypto_kdf_hkdf_sha256_extract(
            outputPrk,
            salt,
            (nuint)salt.Length,
            inputKeyMaterial,
            (nuint)inputKeyMaterial.Length);

        if (result != 0)
            throw new InvalidOperationException("HKDF extraction failed.");
    }

    /// <summary>
    /// A standard alternative to crypto_kdf_derive_from_key(). It is slower, but 
    /// the context can be of any size.
    /// </summary>
    [LibraryImport(LibraryName, EntryPoint = "crypto_kdf_hkdf_sha256_expand")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_kdf_hkdf_sha256_expand(Span<byte> output,
        nuint outputLength,
        ReadOnlySpan<byte> info,
        nuint infoLength,
        ReadOnlySpan<byte> prk);

    /// <summary>
    /// Performs HKDF expansion to derive keys.
    /// </summary>
    /// <param name="prk">The pseudorandom key from extraction step.</param>
    /// <param name="info">Optional context and application information.</param>
    /// <param name="output">Desired output.</param>
    /// <returns>Output key material of the specified length.</returns>
    private static void HkdfExpand(ReadOnlySpan<byte> prk,
        ReadOnlySpan<byte> info,
        Span<byte> output)
    {
        if (output.Length <= 0)
            throw new ArgumentException("Output buffer must not be empty.", nameof(output));

        Initialize();

        int result = crypto_kdf_hkdf_sha256_expand(
            output,
            (nuint)output.Length,
            info,
            (nuint)info.Length,
            prk);

        if (result != 0)
            throw new InvalidOperationException("HKDF expand failed.");
    }

    /// <summary>
    /// Derives a key using HKDF (both extract and expand operations).
    /// </summary>
    /// <param name="inputKeyMaterial">Input keying material.</param>
    /// <param name="salt">Optional salt (can be null).</param>
    /// <param name="info">Optional context and application information.</param>
    /// <param name="outputLength">The length of the PRK.</param>
    /// <returns>Derived key of the specified length.</returns>
    public static byte[] HkdfDerive(ReadOnlySpan<byte> inputKeyMaterial,
        ReadOnlySpan<byte> salt = default,
        ReadOnlySpan<byte> info = default,
        int outputLength = 32)
    {
        if (outputLength <= 0)
            throw new ArgumentOutOfRangeException(nameof(outputLength), "Output length must be positive.");

        // Allocate heap buffer for PRK (SHA-256 output = 32 bytes)
        byte[] prk = new byte[Constants.AES_KEY_SIZE];
        byte[]? output = null;

        try
        {
            // Fill PRK buffer securely
            HkdfExtract(salt, inputKeyMaterial, prk);

            // Allocate final output buffer
            output = new byte[outputLength];

            // Expand with PRK
            HkdfExpand(prk, info, output);

            // Transfer ownership to caller
            var result = output;
            output = null;
            return result;
        }
        finally
        {
            SecureMemory.SecureClear(prk);
            if (output != null)
                SecureMemory.SecureClear(output);
        }
    }

    #endregion

    #region Signing & Verifying PreKeys

    /// <summary>
    /// Signs the message m, whose length is mlen bytes, using the secret key sk 
    /// and puts the signature into sig, which can be up to crypto_sign_BYTES bytes long.
    /// </summary>
    [LibraryImport(LibraryName, EntryPoint = "crypto_sign")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_sign(
        Span<byte> signature, out nuint signatureLength,
        ReadOnlySpan<byte> message, nuint messageLength,
        ReadOnlySpan<byte> secretKey);

    /// <summary>
    /// Signs a message using Ed25519.
    /// DEPRECATED: Use SignDetached instead for better performance and security.
    /// </summary>
    /// <param name="message">The message to sign.</param>
    /// <param name="privateKey">The private key (64 bytes).</param>
    /// <returns>The signature (64 bytes).</returns>
    [Obsolete("Use SignDetached instead for better performance and security.")]
    public static byte[] Sign(ReadOnlySpan<byte> message, ReadOnlySpan<byte> privateKey)
    {
        if (message.IsEmpty)
            throw new ArgumentException("Message cannot be empty", nameof(message));
        if (privateKey.Length != Constants.ED25519_PRIVATE_KEY_SIZE)
            throw new ArgumentException($"Private key must be {Constants.ED25519_PRIVATE_KEY_SIZE} bytes. Length: {privateKey.Length}", nameof(privateKey));

        Initialize();

        byte[] signature = new byte[Constants.ED25519_PRIVATE_KEY_SIZE];

        try
        {
            int result = crypto_sign(
                signature,
                out nuint signatureLength,
                message,
                (nuint)message.Length,
                privateKey);

            if (result != 0 || signatureLength != (nuint)signature.Length)
            {
                throw new InvalidOperationException("Failed to create signature.");
            }

            return signature;
        }
        catch
        {
            SecureMemory.SecureClear(signature);
            throw;
        }
    }

    /// <summary>
    /// Verifies that sig is a valid signature for the message m, whose length is mlen 
    /// bytes, using the signer's public key pk.
    /// DEPRECATED: Use SignVerifyDetached instead for better performance.
    /// </summary>
    [LibraryImport(LibraryName, EntryPoint = "crypto_sign_verify")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_sign_verify(
        ReadOnlySpan<byte> signature,
        ReadOnlySpan<byte> message, nuint messageLength,
        ReadOnlySpan<byte> publicKey);

    /// <summary>
    /// Verifies a signature using Ed25519.
    /// DEPRECATED: Use SignVerifyDetached instead for better performance.
    /// </summary>
    /// <param name="signature">The signature to verify.</param>
    /// <param name="message">The original message.</param>
    /// <param name="publicKey">The public key (32 bytes).</param>
    /// <returns>True if the signature is valid, false otherwise.</returns>
    [Obsolete("Use SignVerifyDetached instead for better performance.")]
    public static bool SignVerify(ReadOnlySpan<byte> signature, ReadOnlySpan<byte> message, ReadOnlySpan<byte> publicKey)
    {
        if (signature.Length != Constants.ED25519_PRIVATE_KEY_SIZE)
            throw new ArgumentException($"Signature must be {Constants.ED25519_PRIVATE_KEY_SIZE} bytes.", nameof(signature));
        if (message.IsEmpty)
            throw new ArgumentException("Message cannot be empty", nameof(message));
        if (publicKey.Length != Constants.ED25519_PUBLIC_KEY_SIZE)
            throw new ArgumentException($"Public key must be {Constants.ED25519_PUBLIC_KEY_SIZE} bytes.", nameof(publicKey));

        Initialize();

        int result = crypto_sign_verify(
            signature,
            message,
            (nuint)message.Length,
            publicKey);

        return result == 0;
    }

    /// <summary>
    /// Randomly generates a secret key and a corresponding public key.
    /// </summary>
    [LibraryImport(LibraryName, EntryPoint = "crypto_sign_keypair")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_sign_keypair(
        Span<byte> publicKey,
        Span<byte> secretKey);

    /// <summary>
    /// Generates a new Ed25519 key pair for signing.
    /// </summary>
    /// <returns>A new key pair.</returns>
    public static KeyPair GenerateSigningKeyPair()
    {
        Initialize();

        byte[] publicKey = new byte[Constants.ED25519_PUBLIC_KEY_SIZE];
        byte[] privateKey = new byte[Constants.ED25519_PRIVATE_KEY_SIZE];

        try
        {
            int result = crypto_sign_keypair(publicKey, privateKey);

            if (result != 0)
            {
                throw new CryptographicException("Failed to generate Ed25519 key pair.");
            }

            return new KeyPair(publicKey, privateKey);
        }
        catch
        {
            // Clear sensitive data on error
            SecureMemory.SecureClear(publicKey);
            SecureMemory.SecureClear(privateKey);
            throw;
        }
    }

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
        try
        {
            RandomFill(buffer);
            return buffer;
        }
        catch
        {
            SecureMemory.SecureClear(buffer);
            throw;
        }
    }

    /// <summary>
    /// Computes a shared secret using X25519 key exchange.
    /// </summary>
    [LibraryImport(LibraryName, EntryPoint = "crypto_scalarmult_curve25519")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
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
    /// <exception cref="CryptographicException">If DH calculation fails.</exception>
    public static byte[] ScalarMult(ReadOnlySpan<byte> secretKey, ReadOnlySpan<byte> publicKey)
    {
        if (secretKey.Length != Constants.X25519_KEY_SIZE)
            throw new ArgumentException($"Secret key must be {Constants.X25519_KEY_SIZE} bytes.", nameof(secretKey));
        if (publicKey.Length != Constants.X25519_KEY_SIZE)
            throw new ArgumentException($"Public key must be {Constants.X25519_KEY_SIZE} bytes.", nameof(publicKey));

        Initialize();

        byte[] sharedSecret = new byte[Constants.X25519_KEY_SIZE];

        try
        {
            int result = crypto_scalarmult_curve25519(sharedSecret, secretKey, publicKey);

            if (result != 0)
                throw new CryptographicException("Libsodium X25519 key exchange failed.");

            return sharedSecret;
        }
        catch
        {
            SecureMemory.SecureClear(sharedSecret);
            throw;
        }
    }

    /// <summary>
    /// Computes the public key from a private key using X25519.
    /// </summary>
    [LibraryImport(LibraryName, EntryPoint = "crypto_scalarmult_curve25519_base")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_scalarmult_curve25519_base(
        Span<byte> q,
        ReadOnlySpan<byte> n);

    /// <summary>
    /// Computes the public key from a private key using X25519.
    /// </summary>
    /// <param name="privateKey">The 32-byte X25519 private key.</param>
    /// <returns>The 32-byte X25519 public key.</returns>
    /// <exception cref="ArgumentException">If the key is invalid size.</exception>
    /// <exception cref="CryptographicException">If calculation fails.</exception>
    public static byte[] ScalarMultBase(ReadOnlySpan<byte> privateKey)
    {
        if (privateKey.Length != Constants.X25519_KEY_SIZE)
            throw new ArgumentException($"Secret key must be {Constants.X25519_KEY_SIZE} bytes.", nameof(privateKey));

        Initialize();

        byte[] publicKey = new byte[Constants.X25519_KEY_SIZE];

        try
        {
            int result = crypto_scalarmult_curve25519_base(publicKey, privateKey);

            if (result != 0)
                throw new CryptographicException("Libsodium X25519 public key generation failed.");

            return publicKey;
        }
        catch
        {
            SecureMemory.SecureClear(publicKey);
            throw;
        }
    }

    /// <summary>
    /// Hash a password string
    /// </summary>
    [LibraryImport(LibraryName, EntryPoint = "crypto_pwhash_str",
               StringMarshalling = StringMarshalling.Utf8)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_pwhash_str(
        Span<byte> outHashed,
        string password,             // marshalled as UTF-8
        nuint passwordLen,
        ulong opsLimit,
        nuint memLimit);

    /// <summary>
    /// Computes an Argon2id hash from a password.
    /// </summary>
    /// <param name="password">The password to hash.</param>
    /// <returns>The hashed password string.</returns>
    public static string Argon2id(string password)
    {
        if (string.IsNullOrEmpty(password))
            throw new ArgumentException("Password cannot be null or empty", nameof(password));

        Initialize();

        Span<byte> buf = stackalloc byte[128];

        try
        {
            int rc = crypto_pwhash_str(buf,
                password,
                (nuint)Encoding.UTF8.GetByteCount(password),
                4,  // opslimit 4-10 passes
                (nuint)(256 * 1024 * 1024) // 256MB memory limit
            );

            if (rc != 0)
                throw new InvalidOperationException("crypto_pwhash_str failed.");

            // Find the null terminator
            int len = buf.IndexOf((byte)0);
            return Encoding.UTF8.GetString(buf[..(len < 0 ? 128 : len)]);
        }
        finally
        {
            SecureMemory.SecureClear(buf);
        }
    }

    /// <summary>
    /// Verify a hashed password string
    /// </summary>
    [LibraryImport(LibraryName, EntryPoint = "crypto_pwhash_str_verify",
               StringMarshalling = StringMarshalling.Utf8)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_pwhash_str_verify(
        ReadOnlySpan<byte> hashed,      // zero-terminated
        string password,
        nuint passwordLen);

    /// <summary>
    /// Verify an Argon2id hash string.
    /// </summary>
    /// <param name="hash">The hash to verify.</param>
    /// <param name="password">The password to check.</param>
    /// <returns>True if the password matches the hash.</returns>
    public static bool VerifyArgon2id(string hash, string password)
    {
        if (string.IsNullOrEmpty(hash))
            throw new ArgumentException("Hash cannot be null or empty", nameof(hash));
        if (string.IsNullOrEmpty(password))
            throw new ArgumentException("Password cannot be null or empty", nameof(password));

        Initialize();

        Span<byte> buf = stackalloc byte[128];
        int rc = 1; // 1 = false

        try
        {
            int written = Encoding.UTF8.GetBytes(hash, buf);
            if (written >= buf.Length)
                throw new ArgumentException("Hash too long", nameof(hash));

            buf[written] = 0; // NUL-terminate

            rc = crypto_pwhash_str_verify(
                buf[..(written + 1)], // include NUL
                password,
                (nuint)Encoding.UTF8.GetByteCount(password));
        }
        finally
        {
            SecureMemory.SecureClear(buf);
        }

        return rc == 0;
    }
    /// <summary>
    /// Converts an Ed25519 public key to an X25519 public key.
    /// </summary>
    [LibraryImport(LibraryName, EntryPoint = "crypto_sign_ed25519_pk_to_curve25519")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
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

        try
        {
            int result = crypto_sign_ed25519_pk_to_curve25519(x25519PublicKey, ed25519PublicKey);

            if (result != 0)
                throw new CryptographicException("Failed to convert Ed25519 public key to X25519.");

            return x25519PublicKey;
        }
        catch
        {
            SecureMemory.SecureClear(x25519PublicKey);
            throw;
        }
    }

    /// <summary>
    /// Converts an Ed25519 secret key to an X25519 public key.
    /// </summary>
    [LibraryImport(LibraryName, EntryPoint = "crypto_sign_ed25519_sk_to_pk")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_sign_ed25519_sk_to_pk(
        Span<byte> ed25519PublicKey,
        ReadOnlySpan<byte> signedKey);

    public static Span<byte> ConvertEd25519PrivateKeyToX25519PublicKey(ReadOnlySpan<byte> signedKey)
    {
        if (signedKey.Length != Constants.ED25519_PRIVATE_KEY_SIZE)
            throw new ArgumentException($"Ed25519 private key must be {Constants.ED25519_PRIVATE_KEY_SIZE} bytes.", nameof(signedKey));

        Initialize();

        // First extract the Ed25519 public key from the private key
        Span<byte> ed25519PublicKey = stackalloc byte[Constants.ED25519_PUBLIC_KEY_SIZE];
        Span<byte> x25519PublicKey = stackalloc byte[Constants.X25519_KEY_SIZE];

        try
        {
            int result = crypto_sign_ed25519_sk_to_pk(ed25519PublicKey, signedKey);

            if (result != 0)
                throw new CryptographicException("Failed to extract Ed25519 public key from private key.");

            // Then convert the Ed25519 public key to X25519 public key
            result = crypto_sign_ed25519_pk_to_curve25519(x25519PublicKey, ed25519PublicKey);

            if (result != 0)
                throw new CryptographicException("Failed to convert Ed25519 public key to X25519.");

            // Clear the intermediate Ed25519 public key
            SecureMemory.SecureClear(ed25519PublicKey);

            // Return a heap-allocated copy since we can't return stack memory
            return x25519PublicKey.ToArray();
        }
        catch
        {
            SecureMemory.SecureClear(ed25519PublicKey);
            SecureMemory.SecureClear(x25519PublicKey);
            throw;
        }
    }

    /// <summary>
    /// Converts an Ed25519 secret key to an X25519 secret key.
    /// </summary>
    [LibraryImport(LibraryName, EntryPoint = "crypto_sign_ed25519_sk_to_curve25519")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
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

        try
        {
            int result = crypto_sign_ed25519_sk_to_curve25519(x25519PrivateKey, ed25519PrivateKey);

            if (result != 0)
                throw new CryptographicException("Failed to convert Ed25519 private key to X25519.");

            return x25519PrivateKey;
        }
        catch
        {
            SecureMemory.SecureClear(x25519PrivateKey);
            throw;
        }
    }

    /// <summary>
    /// Generates an Ed25519 key pair.
    /// </summary>
    [LibraryImport(LibraryName, EntryPoint = "crypto_sign_ed25519_keypair")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
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

        try
        {
            int result = crypto_sign_ed25519_keypair(publicKey, privateKey);
            if (result != 0)
                throw new CryptographicException("Ed25519 key pair generation failed.");

            return new KeyPair(publicKey, privateKey);
        }
        catch
        {
            SecureMemory.SecureClear(publicKey);
            SecureMemory.SecureClear(privateKey);
            throw;
        }
    }

    /// <summary>
    /// Generates an Ed25519 key pair deterministically from a 32-byte seed.
    /// </summary>
    [LibraryImport(LibraryName, EntryPoint = "crypto_sign_ed25519_seed_keypair")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
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

        try
        {
            int result = crypto_sign_ed25519_seed_keypair(publicKey, privateKey, seed);
            if (result != 0)
                throw new CryptographicException("Ed25519 key pair generation from seed failed.");

            return new KeyPair(publicKey, privateKey);
        }
        catch
        {
            SecureMemory.SecureClear(publicKey);
            SecureMemory.SecureClear(privateKey);
            throw;
        }
    }

    /// <summary>
    /// Randomly generates a secret key and the corresponding public key.
    /// </summary>
    [LibraryImport(LibraryName, EntryPoint = "crypto_box_keypair")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
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

        try
        {
            int result = crypto_box_keypair(publicKey, privateKey);
            if (result != 0)
                throw new CryptographicException("X25519 key pair generation failed.");

            return new KeyPair(publicKey, privateKey);
        }
        catch
        {
            SecureMemory.SecureClear(publicKey);
            SecureMemory.SecureClear(privateKey);
            throw;
        }
    }

    /// <summary>
    /// Checks that p represents a point on the edwards25519 curve, in canonical form, 
    /// on the main subgroup, and that the point doesn't have a small order.
    /// </summary>
    [LibraryImport(LibraryName, EntryPoint = "crypto_core_ed25519_is_valid_point")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_core_ed25519_is_valid_point(
        ReadOnlySpan<byte> publicKey);

    /// <summary>
    /// Validates an Ed25519 public key.
    /// </summary>
    /// <param name="ed25519PublicKey">The public key to validate.</param>
    /// <returns>True if the key is valid, false otherwise.</returns>
    public static bool ValidateEd25519PublicKey(ReadOnlySpan<byte> ed25519PublicKey)
    {
        if (ed25519PublicKey.Length != Constants.ED25519_PUBLIC_KEY_SIZE)
            return false;

        Initialize();

        try
        {
            int result = crypto_core_ed25519_is_valid_point(ed25519PublicKey);
            return result == 1;
        }
        catch
        {
            // If validation throws, consider the key invalid
            return false;
        }
    }

    /// <summary>
    /// Validates an X25519 public key to ensure it's not an invalid or dangerous value
    /// </summary>
    /// <param name="x25519PublicKey">X25519 public key to validate</param>
    /// <returns>True if the key is valid.</returns>
    public static bool ValidateX25519PublicKey(byte[] x25519PublicKey)
    {
        if (x25519PublicKey == null || x25519PublicKey.Length != Constants.X25519_KEY_SIZE)
        {
            return false;
        }

        // Check for all-zero key, which is invalid for X25519
        bool allZeros = true;
        for (int i = 0; i < x25519PublicKey.Length; i++)
        {
            if (x25519PublicKey[i] != 0)
            {
                allZeros = false;
                break;
            }
        }

        if (allZeros)
        {
            return false;
        }

        // Check for other known weak keys
        // Low order points that should be rejected
        byte[][] lowOrderPoints =
        [
            // Point at infinity
            new byte[32] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
            // y = 1 (order 4)
            new byte[32] { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
            // Low order point (order 8)
            new byte[32] { 224, 235, 122, 124, 59, 65, 184, 174, 22, 86, 227, 250, 241, 159, 196, 106, 218, 9, 141, 235, 156, 50, 177, 253, 134, 98, 5, 22, 95, 73, 184, 0 },
        ];

        foreach (var lowOrderPoint in lowOrderPoints)
        {
            if (x25519PublicKey.SequenceEqual(lowOrderPoint))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Signs a message using Ed25519.
    /// </summary>
    [LibraryImport(LibraryName, EntryPoint = "crypto_sign_detached")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_sign_detached(
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
        if (message.IsEmpty)
            throw new ArgumentException("Message cannot be empty", nameof(message));

        if (privateKey.Length != Constants.ED25519_PRIVATE_KEY_SIZE)
            throw new ArgumentException($"Private key must be {Constants.ED25519_PRIVATE_KEY_SIZE} bytes.", nameof(privateKey));

        Initialize();

        byte[] signature = new byte[Constants.ED25519_PRIVATE_KEY_SIZE];

        try
        {
            int result = crypto_sign_detached(
                signature,
                out ulong actualLength,
                message,
                (ulong)message.Length,
                privateKey);

            if (result != 0 || actualLength != Constants.ED25519_PRIVATE_KEY_SIZE)
                throw new InvalidOperationException("Signing operation failed.");

            return signature;
        }
        catch
        {
            SecureMemory.SecureClear(signature);
            throw;
        }
    }
    /// <summary>
    /// Verifies a message signature using Ed25519.
    /// </summary>
    [LibraryImport(LibraryName, EntryPoint = "crypto_sign_verify_detached")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_sign_verify_detached(
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
    public static bool SignVerifyDetached(ReadOnlySpan<byte> signature, ReadOnlySpan<byte> message, ReadOnlySpan<byte> publicKey)
    {
        if (signature.Length != Constants.ED25519_PRIVATE_KEY_SIZE)
            throw new ArgumentException($"Signature must be {Constants.ED25519_PRIVATE_KEY_SIZE} bytes.", nameof(signature));

        if (publicKey.Length != Constants.ED25519_PUBLIC_KEY_SIZE)
            throw new ArgumentException($"Public key must be {Constants.ED25519_PUBLIC_KEY_SIZE} bytes.", nameof(publicKey));

        if (message.IsEmpty)
            throw new ArgumentException("Message cannot be empty", nameof(message));

        Initialize();

        try
        {
            int result = crypto_sign_verify_detached(signature, message, (ulong)message.Length, publicKey);
            return result == 0;
        }
        catch
        {
            // If verification throws, consider it invalid
            return false;
        }
    }

    /// <summary>
    /// Computes a shared secret using X25519 key exchange.
    /// </summary>
    /// <param name="output">The shared secret output (32 bytes).</param>
    /// <param name="privateKey">Your private X25519 key (32 bytes).</param>
    /// <param name="peerPublicKey">Peer's public X25519 key (32 bytes).</param>
    public void ComputeSharedSecret(
        Span<byte> output,
        ReadOnlySpan<byte> privateKey,
        ReadOnlySpan<byte> peerPublicKey)
    {
        if (output.Length != Constants.X25519_KEY_SIZE || privateKey.Length != Constants.X25519_KEY_SIZE || peerPublicKey.Length != Constants.X25519_KEY_SIZE)
            throw new ArgumentException($"All buffers must be exactly {Constants.X25519_KEY_SIZE} bytes.");

        Initialize();

        int result = crypto_scalarmult_curve25519(output, privateKey, peerPublicKey);
        if (result != 0)
            throw new InvalidOperationException("X25519 key agreement failed.");
    }

    /// <summary>
    /// Computes the X25519 public key corresponding to a private key.
    /// </summary>
    /// <param name="output">The generated X25519 public key (32 bytes).</param>
    /// <param name="privateKey">The X25519 private key to compute from (32 bytes).</param>
    public static void ComputePublicKey(Span<byte> output, ReadOnlySpan<byte> privateKey)
    {
        if (privateKey.Length != Constants.X25519_KEY_SIZE)
        {
            throw new ArgumentException($"Private key must be {Constants.X25519_KEY_SIZE} bytes long.", nameof(privateKey));
        }
        if (output.Length != Constants.X25519_KEY_SIZE)
        {
            throw new ArgumentException($"Output buffer must be {Constants.X25519_KEY_SIZE} bytes long.", nameof(output));
        }

        Initialize();

        try
        {
            int result = crypto_scalarmult_curve25519_base(output, privateKey);

            if (result != 0)
                throw new CryptographicException("Libsodium failed to compute X25519 public key.");
        }
        catch (Exception e) when (e is not CryptographicException && e is not ArgumentException)
        {
            // Wrap unexpected exceptions
            throw new CryptographicException($"An error occurred during public key computation: {e.Message}", e);
        }
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
    public static void SecureZero(IntPtr buffer, nuint length)
    {
        if (buffer == IntPtr.Zero || length <= 0)
            return;

        Initialize();

        sodium_memzero(buffer, length);
    }

    /// <summary>
    /// Locks memory to prevent it from being swapped to disk.
    /// </summary>
    /// <param name="buffer">Pointer to the memory region.</param>
    /// <param name="length">Length of the memory region.</param>
    /// <returns>True if successful, false otherwise.</returns>
    public static bool LockMemory(IntPtr buffer, nuint length)
    {
        if (buffer == IntPtr.Zero || length <= 0)
            return false;

        Initialize();

        return sodium_mlock(buffer, length) == 0;
    }

    /// <summary>
    /// Unlocks previously locked memory and zeros it.
    /// </summary>
    /// <param name="buffer">Pointer to the memory region.</param>
    /// <param name="length">Length of the memory region.</param>
    /// <returns>True if successful, false otherwise.</returns>
    public static bool UnlockMemory(IntPtr buffer, nuint length)
    {
        if (buffer == IntPtr.Zero || length <= 0)
            return false;

        Initialize();

        // First zero the memory before unlocking
        sodium_memzero(buffer, length);

        return sodium_munlock(buffer, length) == 0;
    }

    #endregion
}