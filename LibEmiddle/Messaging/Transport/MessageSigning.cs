﻿using System.Security.Cryptography;
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
        public static byte[] SignMessage(byte[] message, byte[] privateKey)
        {
            ArgumentNullException.ThrowIfNull(message, nameof(message));
            ArgumentNullException.ThrowIfNull(privateKey, nameof(privateKey));

            // Ed25519 private keys should be 64 bytes, but we can handle 32-byte keys by expanding them
            if (privateKey.Length == Constants.X25519_KEY_SIZE)
            {
                // For 32-byte keys, we need to expand them to 64 bytes for Ed25519 signing
                byte[] expandedKey = new byte[Constants.ED25519_PRIVATE_KEY_SIZE];

                // Copy the first 32 bytes to the expanded key
                privateKey.AsSpan(0, Constants.X25519_KEY_SIZE).CopyTo(expandedKey.AsSpan(0, Constants.X25519_KEY_SIZE));

                // Fill the second half with derivable data
                using (var sha256 = SHA256.Create())
                {
                    byte[] secondHalf = sha256.ComputeHash(privateKey);
                    secondHalf.AsSpan(0, Constants.X25519_KEY_SIZE)
                        .CopyTo(expandedKey.AsSpan(Constants.X25519_KEY_SIZE, Constants.X25519_KEY_SIZE));
                }

                return KeyAuth.SignDetached(message, expandedKey);
            }

            return KeyAuth.SignDetached(message, privateKey);
        }

        /// <summary>
        /// Verifies an Ed25519 signature
        /// </summary>
        /// <param name="message">Original message</param>
        /// <param name="signature">Signature to verify</param>
        /// <param name="publicKey">Public key of signer</param>
        /// <returns>True if signature is valid</returns>
        public static bool VerifySignature(byte[] message, byte[] signature, byte[] publicKey)
        {
            ArgumentNullException.ThrowIfNull(message, nameof(message));
            ArgumentNullException.ThrowIfNull(signature, nameof(signature));
            ArgumentNullException.ThrowIfNull(publicKey, nameof(publicKey));

            return KeyAuth.VerifyDetached(signature, message, publicKey);
        }

        /// <summary>
        /// Signs a text message with a simpler API
        /// </summary>
        /// <param name="message">Message to sign</param>
        /// <param name="privateKey">Private key for signing</param>
        /// <returns>Signature as Base64 string</returns>
        public static string SignTextMessage(string message, byte[] privateKey)
        {
            if (string.IsNullOrEmpty(message))
                throw new ArgumentException("Message cannot be null or empty", nameof(message));

            ArgumentNullException.ThrowIfNull(privateKey, nameof(privateKey));

            byte[] messageBytes = Encoding.UTF8.GetBytes(message);
            byte[] signature = SignMessage(messageBytes, privateKey);
            return Convert.ToBase64String(signature);
        }

        /// <summary>
        /// Verifies a signed text message
        /// </summary>
        /// <param name="message">Original message</param>
        /// <param name="signatureBase64">Signature as Base64 string</param>
        /// <param name="publicKey">Public key of signer</param>
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
        /// <param name="privateKey">Private key for signing</param>
        /// <returns>Signature as a byte array</returns>
        public static byte[] SignObject<T>(T data, byte[] privateKey)
        {
            // Normalize the object by serializing with our standard options
            string json = JsonSerialization.Serialize(data);

            // Sign the canonical representation
            byte[] messageBytes = Encoding.UTF8.GetBytes(json);
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