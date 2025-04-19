using System.Text;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;

namespace LibEmiddle.Messaging.Transport
{
    /// <summary>
    /// Provides functionality for authenticating and verifying message integrity.
    /// </summary>
    public static class MessageSigning
    {
        /// <summary>
        /// Signs a message using Ed25519
        /// </summary>
        /// <param name="message">Message to sign</param>
        /// <param name="privateKey">Private key for signing (64 bytes Ed25519)</param>
        /// <returns>Signature</returns>
        public static byte[] SignMessage(ReadOnlySpan<byte> message, ReadOnlySpan<byte> privateKey)
        {
            ArgumentNullException.ThrowIfNull(message.ToArray(), nameof(message));
            ArgumentNullException.ThrowIfNull(privateKey.ToArray(), nameof(privateKey));

            // Ed25519 private keys should be 64 bytes
            if (privateKey.Length != Constants.ED25519_PRIVATE_KEY_SIZE)
            {
                throw new ArgumentException("Invalid private key.", nameof(privateKey));
            }

            return KeyAuth.SignDetached(message, privateKey);
        }

        /// <summary>
        /// Verifies an Ed25519 signature
        /// </summary>
        /// <param name="message">Original message</param>
        /// <param name="signature">Signature to verify (64 bytes Ed25519)</param>
        /// <param name="publicKey">Public key of signer (32 bytes Ed25519)</param>
        /// <returns>True if signature is valid</returns>
        public static bool VerifySignature(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKey)
        {
            ArgumentNullException.ThrowIfNull(message.ToArray(), nameof(message));
            ArgumentNullException.ThrowIfNull(signature.ToArray(), nameof(signature));
            ArgumentNullException.ThrowIfNull(publicKey.ToArray(), nameof(publicKey));

            // Use Ed25519 validation here.
            if (!Sodium.ValidateEd25519PublicKey(publicKey))
            {
                throw new ArgumentException("Invalid public key.", nameof(publicKey));
            }

            return KeyAuth.VerifyDetached(signature, message, publicKey);
        }

        /// <summary>
        /// Signs a text message with a simpler API
        /// </summary>
        /// <param name="message">Message to sign</param>
        /// <param name="privateKey">Private key for signing (64 bytes Ed25519)</param>
        /// <returns>Signature as Base64 string</returns>
        public static string SignTextMessage(string message, ReadOnlySpan<byte> privateKey)
        {
            if (string.IsNullOrEmpty(message))
                throw new ArgumentException("Message cannot be null or empty", nameof(message));

            ArgumentNullException.ThrowIfNull(privateKey.ToArray(), nameof(privateKey));

            ReadOnlySpan<byte> messageBytes = Encoding.UTF8.GetBytes(message);
            ReadOnlySpan<byte> signature = SignMessage(messageBytes, privateKey);
            return Convert.ToBase64String(signature);
        }

        /// <summary>
        /// Verifies a signed text message
        /// </summary>
        /// <param name="message">Original message</param>
        /// <param name="signatureBase64">Signature as Base64 string</param>
        /// <param name="publicKey">Public key of signer (32 bytes X25519)</param>
        /// <returns>True if signature is valid</returns>
        public static bool VerifyTextMessage(string message, string signatureBase64, byte[] publicKey)
        {
            ArgumentNullException.ThrowIfNull(message, nameof(message));
            ArgumentNullException.ThrowIfNull(signatureBase64, nameof(signatureBase64));
            ArgumentNullException.ThrowIfNull(publicKey, nameof(publicKey));

            try
            {
                byte[] messageBytes = Encoding.UTF8.GetBytes(message);
                byte[] signature = Convert.FromBase64String(signatureBase64);
                return VerifySignature(messageBytes, signature, publicKey);
            }
            catch (FormatException)
            {
                // Invalid Base64
                return false;
            }
        }

        /// <summary>
        /// Signs a message object after normalizing it to a canonical representation
        /// </summary>
        /// <typeparam name="T">Type of object to sign</typeparam>
        /// <param name="data">Data object to sign</param>
        /// <param name="privateKey">Private key for signing (64 bytes Ed25519)</param>
        /// <returns>Signature as a byte array</returns>
        public static ReadOnlySpan<byte> SignObject<T>(T data, ReadOnlySpan<byte> privateKey)
        {
            // Normalize the object by serializing with our standard options
            string json = JsonSerialization.Serialize(data);

            // Sign the canonical representation
            ReadOnlySpan<byte> messageBytes = Encoding.UTF8.GetBytes(json);
            return SignMessage(messageBytes, privateKey);
        }

        /// <summary>
        /// Verifies a signature for a message object after normalizing it
        /// </summary>
        /// <typeparam name="T">Type of object that was signed</typeparam>
        /// <param name="data">Data object to verify</param>
        /// <param name="signature">Signature to verify</param>
        /// <param name="publicKey">Public key of the signer</param>
        /// <returns>True if the signature is valid</returns>
        public static bool VerifyObject<T>(T data, byte[] signature, byte[] publicKey)
        {
            // Normalize the object by serializing with our standard options
            string json = JsonSerialization.Serialize(data);

            // Verify the signature against the canonical representation
            byte[] messageBytes = Encoding.UTF8.GetBytes(json);
            return VerifySignature(messageBytes, signature, publicKey);
        }
    }
}