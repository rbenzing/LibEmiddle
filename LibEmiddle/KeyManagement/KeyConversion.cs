using System.Security.Cryptography;
using E2EELibrary.Core;

namespace E2EELibrary.KeyManagement
{
    /// <summary>
    /// Provides functionality for converting between different key formats.
    /// </summary>
    public static class KeyConversion
    {
        /// <summary>
        /// Converts an Ed25519 public key to an X25519 public key using libsodium's cryptographically secure conversion.
        /// </summary>
        /// <param name="ed25519PublicKey">Ed25519 public key to convert (32 bytes)</param>
        /// <returns>Converted X25519 public key (32 bytes)</returns>
        /// <exception cref="ArgumentNullException">Thrown when input key is null</exception>
        /// <exception cref="ArgumentException">Thrown when input key has an invalid length</exception>
        /// <exception cref="CryptographicException">Thrown when key conversion fails</exception>
        public static byte[] ConvertEd25519PublicKeyToX25519(byte[] ed25519PublicKey)
        {
            // Null check with descriptive message
            ArgumentNullException.ThrowIfNull(nameof(ed25519PublicKey),
                "Ed25519 public key cannot be null.");

            // Validate key length explicitly
            if (ed25519PublicKey.Length != Constants.ED25519_PUBLIC_KEY_SIZE)
            {
                throw new ArgumentException(
                    $"Invalid Ed25519 public key length. " +
                    $"Expected {Constants.ED25519_PUBLIC_KEY_SIZE} bytes, " +
                    $"got {ed25519PublicKey.Length} bytes.",
                    nameof(ed25519PublicKey));
            }

            Sodium.Initialize();

            try
            {
                // Use libsodium's secure conversion method
                byte[] x25519PublicKey = Sodium.GenerateRandomBytes(Constants.X25519_KEY_SIZE);
                int conversionResult = Sodium.crypto_sign_ed25519_pk_to_curve25519(x25519PublicKey, ed25519PublicKey);

                if (conversionResult != 0)
                {
                    throw new CryptographicException("Failed to convert Ed25519 public key to X25519.");
                }

                // Additional validation of converted key
                if (!KeyValidation.ValidateX25519PublicKey(x25519PublicKey))
                {
                    throw new CryptographicException("Converted X25519 public key failed validation.");
                }

                return x25519PublicKey;
            }
            catch (DllNotFoundException ex)
            {
                throw new PlatformNotSupportedException(
                    "Libsodium library is not available for key conversion.",
                    ex);
            }
        }

        /// <summary>
        /// Derives a public X25519 key from an Ed25519 private key.
        /// </summary>
        /// <param name="ed25519PrivateKey">Ed25519 private key (32 or 64 bytes)</param>
        /// <returns>Derived X25519 public key (32 bytes)</returns>
        public static byte[] DeriveX25519PublicKeyFromEd25519(byte[] ed25519PrivateKey)
        {
            byte[] x25519PrivateKey = DeriveX25519PrivateKeyFromEd25519(ed25519PrivateKey);

            try
            {
                return Sodium.ScalarMultBase(x25519PrivateKey);
            }
            finally
            {
                // Securely clear the temporary private key
                SecureMemory.SecureClear(x25519PrivateKey);
            }
        }

        /// <summary>
        /// Derives an X25519 private key from an Ed25519 private key using secure cryptographic methods.
        /// </summary>
        /// <param name="ed25519PrivateKey">Ed25519 private key (32 or 64 bytes)</param>
        /// <returns>Derived X25519 private key (32 bytes)</returns>
        /// <exception cref="ArgumentNullException">Thrown when input key is null</exception>
        /// <exception cref="ArgumentException">Thrown when input key has an invalid length</exception>
        /// <exception cref="CryptographicException">Thrown when key derivation fails</exception>
        public static byte[] DeriveX25519PrivateKeyFromEd25519(byte[] ed25519PrivateKey)
        {
            ArgumentNullException.ThrowIfNull(nameof(ed25519PrivateKey),
                "Ed25519 private key cannot be null.");

            // Handle different input key lengths
            byte[] sourceKey;
            if (ed25519PrivateKey.Length == Constants.X25519_KEY_SIZE)
            {
                // If already 32 bytes, create a secure copy
                sourceKey = Sodium.GenerateRandomBytes(Constants.X25519_KEY_SIZE);
                ed25519PrivateKey.AsSpan(0, Constants.X25519_KEY_SIZE).CopyTo(sourceKey.AsSpan());
            }
            else if (ed25519PrivateKey.Length == Constants.ED25519_PRIVATE_KEY_SIZE)
            {
                // Extract seed from 64-byte Ed25519 private key
                sourceKey = Sodium.GenerateRandomBytes(Constants.X25519_KEY_SIZE);
                ed25519PrivateKey.AsSpan(0, Constants.X25519_KEY_SIZE).CopyTo(sourceKey.AsSpan());
            }
            else
            {
                throw new ArgumentException(
                    $"Invalid Ed25519 private key length. " +
                    $"Expected {Constants.X25519_KEY_SIZE} or {Constants.ED25519_PRIVATE_KEY_SIZE} bytes, " +
                    $"got {ed25519PrivateKey.Length} bytes.",
                    nameof(ed25519PrivateKey));
            }

            try
            {
                // Derive X25519 private key following RFC 7748
                byte[] hash = SHA512.HashData(sourceKey);

                // Clamp the key as per X25519 requirements
                hash[0] &= 248;   // Clear lowest 3 bits
                hash[31] &= 127;  // Clear highest bit
                hash[31] |= 64;   // Set second highest bit

                // Generate final X25519 private key
                byte[] x25519Private = Sodium.GenerateRandomBytes(Constants.X25519_KEY_SIZE);
                hash.AsSpan(0, Constants.X25519_KEY_SIZE).CopyTo(x25519Private.AsSpan());

                return x25519Private;
            }
            catch (Exception ex)
            {
                throw new CryptographicException(
                    "Failed to derive X25519 private key from Ed25519 key.",
                    ex);
            }
            finally
            {
                // Securely clear sensitive key material
                SecureMemory.SecureClear(sourceKey);
            }
        }

        /// <summary>
        /// Implements HKDF (RFC 5869) using libsodium's crypto_kdf_hkdf_sha256_* functions
        /// </summary>
        /// <param name="inputKeyMaterial">Initial key material</param>
        /// <param name="salt">Optional salt (can be null)</param>
        /// <param name="info">Context and application specific information</param>
        /// <param name="outputLength">Desired output key material length</param>
        /// <returns>Derived key material</returns>
        public static byte[] HkdfDerive(
            byte[] inputKeyMaterial,
            byte[]? salt = null,
            byte[]? info = null,
            int outputLength = 32)
        {
            // Use empty byte array if salt is null
            salt ??= new byte[32];

            // Use empty byte array if info is null
            info ??= Array.Empty<byte>();

            // Allocate buffer for PRK (pseudorandom key)
            byte[] prk = new byte[32];

            // Extract step
            int extractResult = Sodium.crypto_kdf_hkdf_sha256_extract(
                prk,
                salt,
                (UIntPtr)salt.Length,
                inputKeyMaterial,
                (UIntPtr)inputKeyMaterial.Length
            );

            if (extractResult != 0)
                throw new CryptographicException("HKDF extract failed");

            // Allocate output buffer
            byte[] output = new byte[outputLength];

            // Expand step
            int expandResult = Sodium.crypto_kdf_hkdf_sha256_expand(
                output,
                (UIntPtr)outputLength,
                info,
                (UIntPtr)(info?.Length ?? 0),
                prk
            );

            if (expandResult != 0)
                throw new CryptographicException("HKDF expand failed");

            return output;
        }
    }
}
