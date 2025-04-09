using System.Security.Cryptography;
using E2EELibrary.Core;

namespace E2EELibrary.KeyManagement
{
    /// <summary>
    /// Provides functionality for generating cryptographic keys.
    /// </summary>
    public static class KeyGenerator
    {
        /// <summary>
        /// Generates a sender key for group messaging
        /// </summary>
        /// <returns>Random sender key</returns>
        public static byte[] GenerateSenderKey()
        {
            byte[] senderKey = Sodium.GenerateRandomBytes(Constants.AES_KEY_SIZE);
            RandomNumberGenerator.Fill(senderKey);
            return senderKey;
        }

        /// <summary>
        /// HMAC-SHA256 on the input data (normalizedPublicKey) using the provided key (existingSharedKey).
        /// </summary>
        /// <param name="existingSharedKey">The shared key (32 bytes required).</param>
        /// <param name="normalizedPublicKey">The data to be HMACed.</param>
        /// <returns>The 32-byte HMAC-SHA256 result.</returns>
        public static byte[] GenerateHmacSha256(byte[] existingSharedKey, byte[] normalizedPublicKey)
        {
            // Ensure the existingSharedKey is of the required length.
            if (existingSharedKey.Length != Constants.AES_KEY_SIZE)
            {
                throw new ArgumentException($"Key must be {Constants.AES_KEY_SIZE} bytes long.", nameof(existingSharedKey));
            }

            Sodium.Initialize();

            byte[] output = new byte[Constants.AES_KEY_SIZE];
            int ret = Sodium.crypto_auth_hmacsha256(
                output, (UIntPtr)output.Length,
                normalizedPublicKey, (UIntPtr)normalizedPublicKey.Length,
                existingSharedKey);

            if (ret != 0)
            {
                throw new InvalidOperationException($"crypto_auth_hmacsha256 failed with return value {ret}");
            }

            return output;
        }

        /// <summary>
        /// Generates a standard Ed25519 key pair using libsodium.
        /// </summary>
        public static (byte[] publicKey, byte[] privateKey) GenerateEd25519KeyPair()
        {
            Sodium.Initialize();

            byte[] publicKey = Sodium.GenerateRandomBytes(32);
            byte[] privateKey = Sodium.GenerateRandomBytes(64);

            int result = Sodium.crypto_sign_ed25519_keypair(publicKey, privateKey);
            if (result != 0)
            {
                throw new InvalidOperationException("Ed25519 key pair generation failed.");
            }
            return (publicKey, privateKey);
        }

        /// <summary>
        /// Deterministically generates an Ed25519 key pair from a 32-byte seed.
        /// This method is useful for edge-case testing with minimal or maximal entropy.
        /// </summary>
        public static (byte[] publicKey, byte[] privateKey) GenerateEd25519KeyPairFromSeed(byte[] seed)
        {
            if (seed == null || seed.Length != 32)
                throw new ArgumentException("Seed must be 32 bytes.", nameof(seed));

            byte[] publicKey = Sodium.GenerateRandomBytes(32);
            byte[] privateKey = Sodium.GenerateRandomBytes(64);

            Sodium.Initialize();

            int result = Sodium.crypto_sign_ed25519_seed_keypair(publicKey, privateKey, seed);
            if (result != 0)
                throw new InvalidOperationException("Ed25519 seeded key pair generation failed.");

            return (publicKey, privateKey);
        }

        /// <summary>
        /// Generates an X25519 key pair using libsodium's crypto_box_keypair
        /// </summary>
        public static (byte[] publicKey, byte[] privateKey) GenerateX25519KeyPair()
        {
            Sodium.Initialize();

            byte[] publicKey = Sodium.GenerateRandomBytes(Constants.X25519_KEY_SIZE);
            byte[] privateKey = Sodium.GenerateRandomBytes(Constants.X25519_KEY_SIZE);

            Sodium.Initialize();

            int result = Sodium.crypto_box_keypair(publicKey, privateKey);
            if (result != 0)
                throw new InvalidOperationException("X25519 key pair generation failed.");

            return (publicKey, privateKey);
        }
    }
}