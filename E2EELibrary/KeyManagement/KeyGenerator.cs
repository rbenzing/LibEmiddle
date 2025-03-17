using System.Security.Cryptography;
using Sodium;
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
        /// Generates an Ed25519 key pair for digital signatures
        /// </summary>
        /// <returns>Tuple containing (publicKey, privateKey) where privateKey is 64 bytes</returns>
        public static (byte[] publicKey, byte[] privateKey) GenerateEd25519KeyPair()
        {
            // Generate a full Ed25519 key pair.
            var edKeyPair = PublicKeyAuth.GenerateKeyPair();
            return (edKeyPair.PublicKey, edKeyPair.PrivateKey);
        }

        /// <summary>
        /// Generates an X25519 key pair for secure key exchange in 32 bytes
        /// </summary>
        /// <returns>Tuple containing (publicKey, privateKey)</returns>
        public static (byte[] publicKey, byte[] privateKey) GenerateX25519KeyPair()
        {
            // Generate a full Ed25519 key pair first.
            var edKeyPair = PublicKeyAuth.GenerateKeyPair();

            // Derive a proper 32-byte X25519 private key from the Ed25519 private key.
            byte[] x25519Private = KeyConversion.DeriveX25519PrivateKeyFromEd25519(edKeyPair.PrivateKey);

            try
            {
                // Compute the corresponding X25519 public key.
                byte[] x25519Public = ScalarMult.Base(x25519Private);

                // Validate the generated public key
                if (!KeyValidation.ValidateX25519PublicKey(x25519Public))
                {
                    throw new CryptographicException("Generated X25519 public key failed validation");
                }

                return (x25519Public, x25519Private);
            }
            catch (Exception ex)
            {
                // Clear sensitive data on exception
                SecureMemory.SecureClear(x25519Private);
                throw new CryptographicException("Failed to generate X25519 key pair", ex);
            }
        }
    }
}