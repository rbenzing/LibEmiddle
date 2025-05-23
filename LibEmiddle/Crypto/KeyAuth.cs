﻿using LibEmiddle.Core;

namespace LibEmiddle.Crypto
{
    /// <summary>
    /// Provides Ed25519 public-key authentication functionality.
    /// </summary>
    public static class KeyAuth
    {
        private const int ED25519_PUBLICKEYBYTES = 32;
        private const int ED25519_SECRETKEYBYTES = 64;
        private const int ED25519_BYTES = 64;

        /// <summary>
        /// Represents a key pair for Ed25519 signatures.
        /// </summary>
        public class KeyPair
        {
            /// <summary>
            /// The public key (32 bytes).
            /// </summary>
            public byte[] PublicKey { get; }

            /// <summary>
            /// The private key (64 bytes).
            /// </summary>
            public byte[] PrivateKey { get; }

            /// <summary>
            /// Creates a new key pair instance.
            /// </summary>
            /// <param name="publicKey">The public key.</param>
            /// <param name="privateKey">The private key.</param>
            public KeyPair(byte[] publicKey, byte[] privateKey)
            {
                PublicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
                PrivateKey = privateKey ?? throw new ArgumentNullException(nameof(privateKey));
            }
        }

        /// <summary>
        /// Generates a new Ed25519 key pair for signing.
        /// </summary>
        /// <returns>A new key pair.</returns>
        public static KeyPair GenerateKeyPair()
        {
            Sodium.Initialize();

            byte[] publicKey = Sodium.GenerateRandomBytes(ED25519_PUBLICKEYBYTES);
            byte[] privateKey = Sodium.GenerateRandomBytes(ED25519_SECRETKEYBYTES);
            
            int result = Sodium.crypto_sign_keypair(
                publicKey,
                privateKey
            );
            if (result != 0)
            {
                throw new InvalidOperationException("Failed to generate Ed25519 key pair.");
            }
 
            return new KeyPair(publicKey, privateKey);
        }

        /// <summary>
        /// Signs a message using Ed25519.
        /// </summary>
        /// <param name="message">The message to sign.</param>
        /// <param name="privateKey">The private key (64 bytes).</param>
        /// <returns>The signature (64 bytes).</returns>
        public static byte[] SignDetached(byte[] message, byte[] privateKey)
        {
            if (message == null)
                throw new ArgumentNullException(nameof(message));
            if (privateKey == null)
                throw new ArgumentNullException(nameof(privateKey));
            if (privateKey.Length != ED25519_SECRETKEYBYTES)
                throw new ArgumentException($"Private key must be {ED25519_SECRETKEYBYTES} bytes.", nameof(privateKey));

            Sodium.Initialize();

            byte[] signature = Sodium.GenerateRandomBytes(ED25519_BYTES);
            
            int result = Sodium.crypto_sign_detached(
                signature,
                out ulong signatureLength,
                message,
                (ulong)message.Length,
                privateKey);

            if (result != 0 && signatureLength > 0)
            {
                throw new InvalidOperationException("Failed to create signature.");
            }

            return signature;
        }

        /// <summary>
        /// Verifies a signature using Ed25519.
        /// </summary>
        /// <param name="signature">The signature to verify.</param>
        /// <param name="message">The original message.</param>
        /// <param name="publicKey">The public key (32 bytes).</param>
        /// <returns>True if the signature is valid, false otherwise.</returns>
        public static bool VerifyDetached(byte[] signature, byte[] message, byte[] publicKey)
        {
            if (signature == null)
                throw new ArgumentNullException(nameof(signature));
            if (message == null)
                throw new ArgumentNullException(nameof(message));
            if (publicKey == null)
                throw new ArgumentNullException(nameof(publicKey));
            if (signature.Length != ED25519_BYTES)
                throw new ArgumentException($"Signature must be {ED25519_BYTES} bytes.", nameof(signature));
            if (publicKey.Length != ED25519_PUBLICKEYBYTES)
                throw new ArgumentException($"Public key must be {ED25519_PUBLICKEYBYTES} bytes.", nameof(publicKey));

            Sodium.Initialize();

            int result = Sodium.crypto_sign_verify_detached(
                        signature,
                        message,
                        (ulong)message.Length,
                        publicKey);

            return result == 0;
                
        }
    }
}