using System.Security.Cryptography;
using System.Text;
using E2EELibrary.Communication;
using E2EELibrary.KeyManagement;
using E2EELibrary.KeyExchange;
using E2EELibrary.Models;
using E2EELibrary.Encryption;

namespace E2EELibrary.MultiDevice
{
    /// <summary>
    /// Provides functionality for linking multiple devices and sharing encryption keys between them.
    /// </summary>
    public static class DeviceLinking
    {
        /// <summary>
        /// Derives a shared key for a new device in a multi-device setup
        /// </summary>
        /// <param name="existingSharedKey">Existing device's shared key</param>
        /// <param name="newDevicePublicKey">New device's public key</param>
        /// <returns>Shared key for the new device</returns>
        public static byte[] DeriveSharedKeyForNewDevice(byte[] existingSharedKey, byte[] newDevicePublicKey)
        {
            using var hmac = new HMACSHA256(existingSharedKey);

            ArgumentNullException.ThrowIfNull(hmac, nameof(hmac));

            return hmac.ComputeHash(newDevicePublicKey);
        }

        /// <summary>
        /// Creates a device link message for establishing multi-device sync
        /// </summary>
        /// <param name="mainDeviceKeyPair">Main device's key pair</param>
        /// <param name="newDevicePublicKey">New device's public key</param>
        /// <returns>Encrypted device link message</returns>
        public static EncryptedMessage CreateDeviceLinkMessage(
    (byte[] publicKey, byte[] privateKey) mainDeviceKeyPair,
    byte[] newDevicePublicKey)
        {
            // Derive the X25519 private key from the full Ed25519 private key for key exchange.
            byte[] mainDeviceX25519Private = KeyConversion.DeriveX25519PrivateKeyFromEd25519(mainDeviceKeyPair.privateKey);
            // newDevicePublicKey is assumed to be a 32-byte X25519 public key.
            byte[] sharedSecret = X3DHExchange.X3DHKeyExchange(newDevicePublicKey, mainDeviceX25519Private);

            // Sign the new device's public key using the full Ed25519 private key.
            byte[] signature = MessageSigning.SignMessage(newDevicePublicKey, mainDeviceKeyPair.privateKey);

            var linkMessage = new DeviceLinkMessage
            {
                MainDevicePublicKey = mainDeviceKeyPair.publicKey,
                Signature = signature
            };

            string json = System.Text.Json.JsonSerializer.Serialize(new
            {
                mainDevicePublicKey = Convert.ToBase64String(linkMessage.MainDevicePublicKey),
                signature = Convert.ToBase64String(linkMessage.Signature)
            });
            byte[] plaintext = Encoding.UTF8.GetBytes(json);
            byte[] nonce = NonceGenerator.GenerateNonce();
            byte[] ciphertext = AES.AESEncrypt(plaintext, sharedSecret, nonce);
            return new EncryptedMessage
            {
                Ciphertext = ciphertext,
                Nonce = nonce
            };
        }

        /// <summary>
        /// Processes a device link message on the new device
        /// </summary>
        /// <param name="encryptedMessage">Encrypted link message</param>
        /// <param name="newDeviceKeyPair">New device's key pair</param>
        /// <param name="mainDevicePublicKey">Main device's public key</param>
        /// <returns>Main device public key if verification succeeds</returns>
        public static byte[]? ProcessDeviceLinkMessage(
            EncryptedMessage encryptedMessage,
            (byte[] publicKey, byte[] privateKey) newDeviceKeyPair,
            byte[] mainDevicePublicKey)
        {
            // Input validation
            ArgumentNullException.ThrowIfNull(encryptedMessage, nameof(encryptedMessage));
            ArgumentNullException.ThrowIfNull(newDeviceKeyPair.publicKey, nameof(newDeviceKeyPair.publicKey));
            ArgumentNullException.ThrowIfNull(newDeviceKeyPair.privateKey, nameof(newDeviceKeyPair.privateKey));
            ArgumentNullException.ThrowIfNull(mainDevicePublicKey, nameof(mainDevicePublicKey));
            ArgumentNullException.ThrowIfNull(encryptedMessage.Ciphertext, nameof(encryptedMessage.Ciphertext));
            ArgumentNullException.ThrowIfNull(encryptedMessage.Nonce, nameof(encryptedMessage.Nonce));

            try
            {
                // Generate shared secret
                byte[] sharedSecret = X3DHExchange.X3DHKeyExchange(mainDevicePublicKey, newDeviceKeyPair.privateKey);

                // Decrypt
                byte[] plaintext = AES.AESDecrypt(encryptedMessage.Ciphertext, sharedSecret, encryptedMessage.Nonce);
                string json = Encoding.UTF8.GetString(plaintext);

                // Deserialize
                var data = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(json);

                ArgumentNullException.ThrowIfNull(data);

                if (!data.ContainsKey("mainDevicePublicKey") || !data.ContainsKey("signature"))
                {
                    return null; // Required fields missing
                }

                byte[] mainPubKey = Convert.FromBase64String(data["mainDevicePublicKey"]);
                byte[] signature = Convert.FromBase64String(data["signature"]);

                // Verify signature
                if (MessageSigning.VerifySignature(newDeviceKeyPair.publicKey, signature, mainPubKey))
                {
                    return mainPubKey;
                }
            }
            catch (Exception ex)
            {
                // Log the exception in production environment
                Console.WriteLine($"Error processing device link message: {ex.Message}");
                // In production, consider using a proper logging framework
            }

            return null;
        }
    }
}