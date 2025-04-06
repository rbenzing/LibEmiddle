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
        /// Generates a standard Ed25519 key pair using libsodium.
        /// </summary>
        public static (byte[] publicKey, byte[] privateKey) GenerateEd25519KeyPair()
        {
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
            // Call libsodium’s seeded keypair generation.
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

            int result = Sodium.crypto_box_keypair(publicKey, privateKey);
            if (result != 0)
                throw new InvalidOperationException("X25519 key pair generation failed.");

            return (publicKey, privateKey);
        }
    }
}