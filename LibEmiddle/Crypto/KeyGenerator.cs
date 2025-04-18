using System.Security.Cryptography;
using LibEmiddle.Core;
using LibEmiddle.Domain;

namespace LibEmiddle.Crypto
{
    /// <summary>
    /// Provides functionality for generating cryptographic keys.
    /// </summary>
    internal static class KeyGenerator
    {
        /// <summary>
        /// Generates a sender key for group messaging
        /// </summary>
        /// <returns>Random sender key</returns>
        public static byte[] GenerateInitialChainKey()
        {
            byte[] senderKey = SecureMemory.CreateSecureBuffer(Constants.AES_KEY_SIZE);
            RandomNumberGenerator.Fill(senderKey);
            return senderKey;
        }

        /// <summary>
        /// HMAC-SHA256 on the input data (normalizedPublicKey) using the provided key (existingSharedKey).
        /// </summary>
        /// <param name="existingSharedKey">The shared key (32 bytes required).</param>
        /// <param name="normalizedPublicKey">The data to be HMACed.</param>
        /// <returns>The 32-byte HMAC-SHA256 result.</returns>
        public static byte[] GenerateHmacSha256(ReadOnlySpan<byte> existingSharedKey, ReadOnlySpan<byte> normalizedPublicKey)
        {
            // Ensure the existingSharedKey is of the required length.
            if (existingSharedKey.Length != Constants.AES_KEY_SIZE)
            {
                throw new ArgumentException($"Key must be {Constants.AES_KEY_SIZE} bytes long.", nameof(existingSharedKey));
            }

            Sodium.Initialize();

            byte[] output = new byte[Constants.AES_KEY_SIZE];
            int ret = Sodium.crypto_auth_hmacsha256(
                output,
                normalizedPublicKey.ToArray(),
                (UIntPtr)normalizedPublicKey.Length,
                existingSharedKey.ToArray());

            if (ret != 0)
            {
                throw new InvalidOperationException($"crypto_auth_hmacsha256 failed with return value {ret}");
            }

            return output;
        }

        /// <summary>
        /// Generates a standard Ed25519 key pair using libsodium.
        /// </summary>
        public static KeyPair GenerateEd25519KeyPair()
        {
            Sodium.Initialize();

            byte[] publicKey = SecureMemory.CreateSecureBuffer(32);
            byte[] privateKey = SecureMemory.CreateSecureBuffer(64);

            int result = Sodium.crypto_sign_ed25519_keypair(publicKey, privateKey);
            if (result != 0)
            {
                throw new InvalidOperationException("Ed25519 key pair generation failed.");
            }
            return new KeyPair(publicKey, privateKey);
        }

        /// <summary>
        /// Deterministically generates an Ed25519 key pair from a 32-byte seed.
        /// This method is useful for edge-case testing with minimal or maximal entropy.
        /// </summary>
        public static KeyPair GenerateEd25519KeyPairFromSeed(ReadOnlySpan<byte> seed)
        {
            if (seed == null || seed.Length != Constants.DEFAULT_SALT_SIZE)
                throw new ArgumentException("Seed must be 32 bytes.", nameof(seed));

            byte[] publicKey = SecureMemory.CreateSecureBuffer(Constants.ED25519_PUBLIC_KEY_SIZE);
            byte[] privateKey = SecureMemory.CreateSecureBuffer(Constants.ED25519_PRIVATE_KEY_SIZE);

            Sodium.Initialize();

            int result = Sodium.crypto_sign_ed25519_seed_keypair(publicKey, privateKey, seed.ToArray());
            if (result != 0)
                throw new InvalidOperationException("Ed25519 seeded key pair generation failed.");

            return new KeyPair(publicKey, privateKey);
        }

        /// <summary>
        /// Generates an X25519 key pair using libsodium's crypto_box_keypair
        /// </summary>
        public static KeyPair GenerateX25519KeyPair()
        {
            Sodium.Initialize();

            byte[] publicKey = SecureMemory.CreateSecureBuffer(Constants.X25519_KEY_SIZE);
            byte[] privateKey = SecureMemory.CreateSecureBuffer(Constants.X25519_KEY_SIZE);

            Sodium.Initialize();

            int result = Sodium.crypto_box_keypair(publicKey, privateKey);
            if (result != 0)
                throw new InvalidOperationException("X25519 key pair generation failed.");

            return new KeyPair(publicKey, privateKey);
        }
    }
}