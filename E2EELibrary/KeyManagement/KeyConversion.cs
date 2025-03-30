using System.Security.Cryptography;
using E2EELibrary.Core;

namespace E2EELibrary.KeyManagement
{
    /// <summary>
    /// Provides functionality for converting between different key formats
    /// </summary>
    public static class KeyConversion
    {
        /// <summary>
        /// Derives an X25519 public key from an Ed25519 key pair
        /// </summary>
        /// <param name="ed25519PrivateKey">Ed25519 private key</param>
        /// <returns>X25519 public key</returns>
        public static byte[] DeriveX25519PublicKeyFromEd25519(byte[] ed25519PrivateKey)
        {
            // Validate input
            ArgumentNullException.ThrowIfNull(ed25519PrivateKey, nameof(ed25519PrivateKey));

            // Derive X25519 private key
            byte[] x25519Private = DeriveX25519PrivateKey(ed25519PrivateKey);

            // Compute corresponding X25519 public key
            return Sodium.ScalarMultBase(x25519Private);
        }

        /// <summary>
        /// Derives an X25519 private key for controlled use cases
        /// </summary>
        /// <param name="ed25519PrivateKey">Ed25519 private key</param>
        /// <returns>X25519 private key</returns>
        public static byte[] DeriveX25519PrivateKeyFromEd25519(byte[] ed25519PrivateKey)
        {
            // Validate input and call the existing private method
            ArgumentNullException.ThrowIfNull(ed25519PrivateKey, nameof(ed25519PrivateKey));

            return DeriveX25519PrivateKey(ed25519PrivateKey);
        }

        /// <summary>
        /// Derives an X25519 private key from an Ed25519 key using proper conversion methods
        /// </summary>
        /// <param name="ed25519PrivateKey">Ed25519 private key (32 or 64 bytes)</param>
        /// <returns>X25519 private key (32 bytes)</returns>
        private static byte[] DeriveX25519PrivateKey(byte[] ed25519PrivateKey)
        {
            // Validate input and call the existing private method
            ArgumentNullException.ThrowIfNull(ed25519PrivateKey, nameof(ed25519PrivateKey));

            // If already 32 bytes, it might be a seed or an X25519 key already
            if (ed25519PrivateKey.Length == Constants.X25519_KEY_SIZE)
            {
                // Create a copy to prevent external modification
                byte[] copy = new byte[Constants.X25519_KEY_SIZE];
                ed25519PrivateKey.AsSpan(0, Constants.X25519_KEY_SIZE).CopyTo(copy.AsSpan());
                return copy;
            }

            // If it's a 64-byte Ed25519 private key, extract the seed (first 32 bytes)
            if (ed25519PrivateKey.Length == Constants.ED25519_PRIVATE_KEY_SIZE)
            {
                // Extract the seed (first 32 bytes) which is the standard approach
                byte[] seed = new byte[Constants.X25519_KEY_SIZE];
                ed25519PrivateKey.AsSpan(0, Constants.X25519_KEY_SIZE).CopyTo(seed);

                // Derive the X25519 private key from the seed
                // This follows the standard conversion as specified in RFC 7748
                byte[] hash = SHA512.HashData(seed);

                // Properly clamp the key as required for X25519 per RFC 7748
                hash[0] &= 248;  // Clear the lowest 3 bits
                hash[31] &= 127; // Clear the highest bit
                hash[31] |= 64;  // Set the second highest bit

                byte[] x25519Private = new byte[Constants.X25519_KEY_SIZE];
                hash.AsSpan(0, Constants.X25519_KEY_SIZE).CopyTo(x25519Private);
                return x25519Private;
                
            }

            throw new ArgumentException($"Invalid Ed25519 private key length: {ed25519PrivateKey.Length}. Expected 32 or 64 bytes.");
        }
    }
}