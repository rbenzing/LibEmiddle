using System;
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
        /// Converts an Ed25519 public key to an X25519 public key using libsodium's conversion.
        /// If conversion fails, it returns the original key assuming it's already in X25519 format.
        /// </summary>
        /// <param name="ed25519PublicKey">Ed25519 public key (32 bytes)</param>
        /// <returns>X25519 public key (32 bytes)</returns>
        public static byte[] ConvertEd25519PublicKeyToX25519(byte[] ed25519PublicKey)
        {
            if (ed25519PublicKey == null)
                throw new ArgumentNullException(nameof(ed25519PublicKey));

            // It is common for an Ed25519 public key to be 32 bytes.
            if (ed25519PublicKey.Length != Constants.ED25519_PUBLIC_KEY_SIZE)
                throw new ArgumentException($"Invalid Ed25519 public key length: {ed25519PublicKey.Length}.", nameof(ed25519PublicKey));

            // Attempt to convert using libsodium's function.
            byte[] x25519PublicKey = Sodium.ConvertEd25519PublicKeyToCurve25519(ed25519PublicKey);

            return x25519PublicKey;
        }

        /// <summary>
        /// Derives an X25519 public key from an Ed25519 private key.
        /// </summary>
        /// <param name="ed25519PrivateKey">Ed25519 private key</param>
        /// <returns>X25519 public key</returns>
        public static byte[] DeriveX25519PublicKeyFromEd25519(byte[] ed25519PrivateKey)
        {
            ArgumentNullException.ThrowIfNull(ed25519PrivateKey, nameof(ed25519PrivateKey));

            byte[] x25519Private = DeriveX25519PrivateKey(ed25519PrivateKey);
            return Sodium.ScalarMultBase(x25519Private);
        }

        /// <summary>
        /// Derives an X25519 private key from an Ed25519 private key.
        /// </summary>
        /// <param name="ed25519PrivateKey">Ed25519 private key</param>
        /// <returns>X25519 private key</returns>
        public static byte[] DeriveX25519PrivateKeyFromEd25519(byte[] ed25519PrivateKey)
        {
            ArgumentNullException.ThrowIfNull(ed25519PrivateKey, nameof(ed25519PrivateKey));

            return DeriveX25519PrivateKey(ed25519PrivateKey);
        }

        /// <summary>
        /// Derives an X25519 private key from an Ed25519 key using proper conversion methods.
        /// </summary>
        /// <param name="ed25519PrivateKey">Ed25519 private key (32 or 64 bytes)</param>
        /// <returns>X25519 private key (32 bytes)</returns>
        private static byte[] DeriveX25519PrivateKey(byte[] ed25519PrivateKey)
        {
            ArgumentNullException.ThrowIfNull(ed25519PrivateKey, nameof(ed25519PrivateKey));

            // If already 32 bytes, assume it is already a seed or an X25519 key.
            if (ed25519PrivateKey.Length == Constants.X25519_KEY_SIZE)
            {
                byte[] copy = Sodium.GenerateRandomBytes(Constants.X25519_KEY_SIZE);
                ed25519PrivateKey.AsSpan(0, Constants.X25519_KEY_SIZE).CopyTo(copy.AsSpan());
                return copy;
            }

            // If it's a 64-byte Ed25519 private key, extract the seed (first 32 bytes).
            if (ed25519PrivateKey.Length == Constants.ED25519_PRIVATE_KEY_SIZE)
            {
                byte[] seed = Sodium.GenerateRandomBytes(Constants.X25519_KEY_SIZE);
                ed25519PrivateKey.AsSpan(0, Constants.X25519_KEY_SIZE).CopyTo(seed);

                // Derive the X25519 private key from the seed following RFC 7748.
                byte[] hash = SHA512.HashData(seed);

                // Clamp the key as required for X25519.
                hash[0] &= 248;  // Clear the lowest 3 bits.
                hash[31] &= 127; // Clear the highest bit.
                hash[31] |= 64;  // Set the second highest bit.

                byte[] x25519Private = Sodium.GenerateRandomBytes(Constants.X25519_KEY_SIZE);
                hash.AsSpan(0, Constants.X25519_KEY_SIZE).CopyTo(x25519Private);
                return x25519Private;
            }

            throw new ArgumentException($"Invalid Ed25519 private key length: {ed25519PrivateKey.Length}. Expected 32 or 64 bytes.");
        }
    }
}
