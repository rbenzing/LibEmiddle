using System.Security.Cryptography;
using LibEmiddle.Core;
using LibEmiddle.Domain;

namespace LibEmiddle.Crypto
{
    /// <summary>
    /// Provides functionality for converting between different key formats.
    /// </summary>
    internal static class KeyConversion
    {
        /// <summary>
        /// Derives an X25519 private key from an Ed25519 private key using secure cryptographic methods.
        /// </summary>
        /// <param name="ed25519PrivateKey">Ed25519 private key (32 or 64 bytes)</param>
        /// <returns>Derived X25519 private key (32 bytes)</returns>
        /// <exception cref="ArgumentNullException">Thrown when input key is null</exception>
        /// <exception cref="ArgumentException">Thrown when input key has an invalid length</exception>
        /// <exception cref="CryptographicException">Thrown when key derivation fails</exception>
        public static byte[] DeriveX25519PrivateKeyFromEd25519(ReadOnlySpan<byte> ed25519PrivateKey)
        {
            if (ed25519PrivateKey.IsEmpty)
                throw new ArgumentException("Ed25519 private key cannot be empty.", nameof(ed25519PrivateKey));

            // Handle different input key lengths
            Span<byte> sourceKey;
            if (ed25519PrivateKey.Length == Constants.X25519_KEY_SIZE)
            {
                // If already 32 bytes, create a secure copy
                sourceKey = SecureMemory.CreateSecureBuffer(Constants.X25519_KEY_SIZE);
                ed25519PrivateKey.Slice(0, Constants.X25519_KEY_SIZE).CopyTo(sourceKey);
            }
            else if (ed25519PrivateKey.Length == Constants.ED25519_PRIVATE_KEY_SIZE)
            {
                // Extract seed from 64-byte Ed25519 private key
                sourceKey = SecureMemory.CreateSecureBuffer(Constants.X25519_KEY_SIZE);
                ed25519PrivateKey.Slice(0, Constants.X25519_KEY_SIZE).CopyTo(sourceKey);
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
                byte[] x25519Private = SecureMemory.CreateSecureBuffer(Constants.X25519_KEY_SIZE);
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
            ReadOnlySpan<byte> inputKeyMaterial,
            ReadOnlySpan<byte> salt = default,
            ReadOnlySpan<byte> info = default,
            int outputLength = 32)
        {
            // Allocate buffer for PRK (pseudorandom key)
            byte[] prk = SecureMemory.CreateSecureBuffer(32);

            // Extract step
            int extractResult = Sodium.crypto_kdf_hkdf_sha256_extract(
                prk,
                salt.IsEmpty ? null : salt.ToArray(),
                (uint)salt.Length,
                inputKeyMaterial.ToArray(),
                (uint)inputKeyMaterial.Length
            );

            if (extractResult != 0)
                throw new CryptographicException("HKDF extract failed");

            // Allocate output buffer
            byte[] output = new byte[outputLength];

            // Expand step
            int expandResult = Sodium.crypto_kdf_hkdf_sha256_expand(
                output,
                (uint)outputLength,
                info.ToArray(),
                (uint)(info.Length),
                prk
            );

            if (expandResult != 0)
                throw new CryptographicException("HKDF expand failed");

            return output;
        }

        /// <summary>
        /// Exports a key to a secure Base64 string representation
        /// </summary>
        /// <param name="key">The key to export</param>
        /// <returns>Base64 encoded string representation of the key</returns>
        public static string ExportKeyToBase64(ReadOnlySpan<byte> key)
        {
            return Convert.ToBase64String(key);
        }

        /// <summary>
        /// Imports a key from a Base64 string representation
        /// </summary>
        /// <param name="base64Key">Base64 encoded key</param>
        /// <returns>Byte array representation of the key</returns>
        public static byte[] ImportKeyFromBase64(string base64Key)
        {
            return Convert.FromBase64String(base64Key);
        }
    }
}
