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
            byte[] senderKey = new byte[Constants.AES_KEY_SIZE];
            RandomNumberGenerator.Fill(senderKey);
            return senderKey;
        }

        /// <summary>
        /// Generates a standard Ed25519 key pair using libsodium.
        /// </summary>
        public static (byte[] publicKey, byte[] privateKey) GenerateEd25519KeyPair()
        {
            byte[] publicKey = new byte[32];
            byte[] privateKey = new byte[64];
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
            byte[] publicKey = new byte[32];
            byte[] privateKey = new byte[64];
            // Call libsodium’s seeded keypair generation.
            int result = Sodium.crypto_sign_ed25519_seed_keypair(publicKey, privateKey, seed);
            if (result != 0)
                throw new InvalidOperationException("Ed25519 seeded key pair generation failed.");
            return (publicKey, privateKey);
        }

        /// <summary>
        /// Generates an X25519 key pair.
        /// </summary>
        public static (byte[] publicKey, byte[] privateKey) GenerateX25519KeyPair()
        {
            byte[] privateKey = new byte[32];
            RandomNumberGenerator.Fill(privateKey);
            // Clamp the private key as per RFC 7748.
            privateKey[0] &= 248;
            privateKey[31] &= 127;
            privateKey[31] |= 64;
            byte[] publicKey = Sodium.ScalarMultBase(privateKey);
            return (publicKey, privateKey);
        }
    }
}