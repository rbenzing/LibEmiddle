using LibEmiddle.Core;
using LibEmiddle.Domain;

namespace LibEmiddle.Crypto
{
    /// <summary>
    /// Provides Ed25519 public-key authentication functionality.
    /// </summary>
    internal static class KeyAuth
    {
        /// <summary>
        /// Generates a new Ed25519 key pair for signing.
        /// </summary>
        /// <returns>A new key pair.</returns>
        public static KeyPair GenerateSigningKeyPair()
        {
            Sodium.Initialize();

            byte[] publicKey = Sodium.GenerateRandomBytes(Constants.ED25519_PUBLIC_KEY_SIZE);
            byte[] privateKey = Sodium.GenerateRandomBytes(Constants.ED25519_PRIVATE_KEY_SIZE);
            
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
        public static byte[] SignDetached(in ReadOnlySpan<byte> message, in ReadOnlySpan<byte> privateKey)
        {
            if (message == null)
                throw new ArgumentNullException(nameof(message));
            if (privateKey == null)
                throw new ArgumentNullException(nameof(privateKey));
            if (privateKey.Length != Constants.ED25519_PRIVATE_KEY_SIZE)
                throw new ArgumentException($"Private key must be {Constants.ED25519_PRIVATE_KEY_SIZE} bytes. Length: {privateKey.Length}", nameof(privateKey));

            Sodium.Initialize();

            byte[] signature = Sodium.GenerateRandomBytes(Constants.ED25519_PRIVATE_KEY_SIZE);
            
            int result = Sodium.crypto_sign_detached(
                signature,
                out ulong signatureLength,
                message.ToArray(),
                (ulong)message.Length,
                privateKey.ToArray());

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
        public static bool VerifyDetached(in ReadOnlySpan<byte> signature, in ReadOnlySpan<byte> message, in ReadOnlySpan<byte> publicKey)
        {
            if (signature == null)
                throw new ArgumentNullException(nameof(signature));
            if (message == null)
                throw new ArgumentNullException(nameof(message));
            if (publicKey == null)
                throw new ArgumentNullException(nameof(publicKey));
            if (signature.Length != Constants.ED25519_PRIVATE_KEY_SIZE)
                throw new ArgumentException($"Signature must be {Constants.ED25519_PRIVATE_KEY_SIZE} bytes.", nameof(signature));
            if (publicKey.Length != Constants.ED25519_PUBLIC_KEY_SIZE)
                throw new ArgumentException($"Public key must be {Constants.ED25519_PUBLIC_KEY_SIZE} bytes.", nameof(publicKey));

            Sodium.Initialize();

            int result = Sodium.crypto_sign_verify_detached(
                        signature.ToArray(),
                        message.ToArray(),
                        (ulong)message.Length,
                        publicKey.ToArray());

            return result == 0;
                
        }
    }
}