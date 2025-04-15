using System.Security.Cryptography;
using System.Text;
using LibEmiddle.KeyExchange;
using LibEmiddle.Core;
using LibEmiddle.Messaging.Transport;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;

namespace LibEmiddle.MultiDevice
{
    /// <summary>
    /// Provides functionality for linking multiple devices and sharing encryption keys between them.
    /// </summary>
    public static class DeviceLinking
    {
        // Maximum allowed difference (in milliseconds) between the message timestamp and the current time.
        private const long AllowedTimestampSkewMilliseconds = 300000; // 5 minutes

        /// <summary>
        /// Derives a shared key for a new device when the caller provides an Ed25519 public key.
        /// The method converts the Ed25519 key to its X25519 representation before computing the shared key.
        /// </summary>
        /// <param name="existingSharedKey">Existing device's shared key</param>
        /// <param name="newDevicePublicKey">New device's Ed25519 public key (32 bytes)</param>
        /// <returns>Shared key for the new device</returns>
        public static byte[] DeriveSharedKeyForNewDevice(byte[] existingSharedKey, byte[] newDevicePublicKey)
        {
            if (existingSharedKey == null)
                throw new ArgumentNullException(nameof(existingSharedKey));
            if (newDevicePublicKey == null)
                throw new ArgumentNullException(nameof(newDevicePublicKey));

            byte[] normalizedPublicKey;
            try
            {
                // Try to convert assuming it is a valid Ed25519 public key.
                normalizedPublicKey = KeyConversion.ConvertEd25519PublicKeyToX25519(newDevicePublicKey);
            }
            catch (Exception)
            {
                // If conversion fails, assume the key is already in X25519 form.
                bool validKey = KeyValidation.ValidateX25519PublicKey(newDevicePublicKey);
                if (!validKey)
                {
                    throw new CryptographicException(nameof(newDevicePublicKey), "Public key is invalid.");
                }
                normalizedPublicKey = newDevicePublicKey;
            }

            return KeyConversion.HkdfDerive(
                existingSharedKey,
                normalizedPublicKey,
                Encoding.UTF8.GetBytes("DeviceLinkKeyDerivation") // Must match the X25519 overload below.
            );
        }

        /// <summary>
        /// Derives a shared key for a new device when the caller provides an X25519 public key.
        /// No conversion is performed.
        /// </summary>
        /// <param name="existingSharedKey">Existing device's shared key</param>
        /// <param name="x25519PublicKey">New device's X25519 public key (32 bytes)</param>
        /// <returns>Shared key for the new device</returns>
        public static byte[] DeriveSharedKeyForNewDeviceX25519(byte[] existingSharedKey, byte[] x25519PublicKey)
        {
            if (existingSharedKey == null)
                throw new ArgumentNullException(nameof(existingSharedKey));
            if (x25519PublicKey == null)
                throw new ArgumentNullException(nameof(x25519PublicKey));

            return KeyConversion.HkdfDerive(
                existingSharedKey,
                x25519PublicKey,
                Encoding.UTF8.GetBytes("DeviceLinkKeyDerivation")
            );
        }

        /// <summary>
        /// Creates a device link message for establishing multi-device sync.
        /// (Implementation remains unchanged for brevity.)
        /// </summary>
        public static EncryptedMessage CreateDeviceLinkMessage(
            KeyPair mainDeviceKeyPair,
            byte[] newDevicePublicKey)
        {
            // Validate that the main device key pair is in Ed25519 format.
            if (mainDeviceKeyPair.PublicKey == null)
                throw new ArgumentNullException(nameof(mainDeviceKeyPair.PublicKey));
            if (mainDeviceKeyPair.PrivateKey == null)
                throw new ArgumentNullException(nameof(mainDeviceKeyPair.PrivateKey));
            if (mainDeviceKeyPair.PublicKey.Length != Constants.ED25519_PUBLIC_KEY_SIZE ||
                mainDeviceKeyPair.PrivateKey.Length != Constants.ED25519_PRIVATE_KEY_SIZE)
            {
                throw new ArgumentException("Main device key pair must be an Ed25519 key pair.", nameof(mainDeviceKeyPair));
            }
            if (newDevicePublicKey == null)
                throw new ArgumentNullException(nameof(newDevicePublicKey));

            // Convert main device's Ed25519 private key to X25519.
            byte[] mainDeviceX25519Private = KeyConversion.DeriveX25519PrivateKeyFromEd25519(mainDeviceKeyPair.PrivateKey);
            // Compute the main device's X25519 public key.
            byte[] mainDeviceX25519Public = Sodium.ScalarMultBase(mainDeviceX25519Private);
            // Convert new device's Ed25519 public key to X25519.
            byte[] newDeviceX25519Public = KeyConversion.ConvertEd25519PublicKeyToX25519(newDevicePublicKey);

            // Compute the shared secret using X3DH.
            byte[] sharedSecret = X3DHExchange.PerformX25519DH(newDeviceX25519Public, mainDeviceX25519Private);

            // Sign the new device's original Ed25519 public key using the main device's Ed25519 private key.
            byte[] signature = MessageSigning.SignMessage(newDevicePublicKey, mainDeviceKeyPair.PrivateKey);

            // Build the payload.
            var payload = new
            {
                mainDevicePublicKey = Convert.ToBase64String(mainDeviceKeyPair.PublicKey),
                signature = Convert.ToBase64String(signature)
            };
            string json = System.Text.Json.JsonSerializer.Serialize(payload);
            byte[] plaintext = Encoding.UTF8.GetBytes(json);
            byte[] nonce = NonceGenerator.GenerateNonce();
            byte[] ciphertext = AES.AESEncrypt(plaintext, sharedSecret, nonce);

            return new EncryptedMessage
            {
                Ciphertext = ciphertext,
                Nonce = nonce,
                SenderDHKey = mainDeviceX25519Public,
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                MessageNumber = 0,
                SessionId = null
            };
        }

        /// <summary>
        /// Processes a device link message on the new device.
        /// (Implementation remains unchanged for brevity.)
        /// </summary>
        public static byte[]? ProcessDeviceLinkMessage(
            EncryptedMessage encryptedMessage,
            KeyPair newDeviceKeyPair,
            byte[] mainDevicePublicKey)
        {
            if (encryptedMessage == null)
                throw new ArgumentNullException(nameof(encryptedMessage));
            // Instead of throwing for missing fields, treat them as invalid and return null.
            if (encryptedMessage.Ciphertext == null ||
                encryptedMessage.Nonce == null ||
                encryptedMessage.SenderDHKey == null)
            {
                LoggingManager.LogWarning(nameof(DeviceLinking), "Device link message missing required fields (ciphertext, nonce, or SenderDHKey).");
                return null;
            }
            if (newDeviceKeyPair.PublicKey == null)
                throw new ArgumentNullException(nameof(newDeviceKeyPair.PublicKey));
            if (newDeviceKeyPair.PrivateKey == null)
                throw new ArgumentNullException(nameof(newDeviceKeyPair.PrivateKey));
            if (mainDevicePublicKey == null)
                throw new ArgumentNullException(nameof(mainDevicePublicKey));

            try
            {
                // Check replay protection using the timestamp.
                long currentTimestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                if (Math.Abs(currentTimestamp - encryptedMessage.Timestamp) > AllowedTimestampSkewMilliseconds)
                {
                    LoggingManager.LogWarning(nameof(DeviceLinking), "Device link message rejected due to timestamp outside allowed window.");
                    return null;
                }

                // Convert the new device's Ed25519 private key to X25519.
                byte[] newDeviceX25519Private = KeyConversion.DeriveX25519PrivateKeyFromEd25519(newDeviceKeyPair.PrivateKey);

                // Retrieve the main device's X25519 public key from SenderDHKey.
                byte[] mainDeviceX25519Public = encryptedMessage.SenderDHKey;
                if (mainDeviceX25519Public.Length != Constants.X25519_KEY_SIZE)
                {
                    throw new ArgumentException("Invalid main device X25519 public key length in SenderDHKey");
                }

                // Compute the shared secret.
                byte[] sharedSecret = X3DHExchange.PerformX25519DH(mainDeviceX25519Public, newDeviceX25519Private);

                // Decrypt the ciphertext.
                byte[] plaintext = AES.AESDecrypt(encryptedMessage.Ciphertext, sharedSecret, encryptedMessage.Nonce);
                string json = Encoding.UTF8.GetString(plaintext);

                // Deserialize the payload.
                var data = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(json);
                if (data == null || !data.ContainsKey("mainDevicePublicKey") || !data.ContainsKey("signature"))
                {
                    LoggingManager.LogWarning(nameof(DeviceLinking), "Device link message payload missing required fields.");
                    return null;
                }

                byte[] mainDeviceEd25519Public = Convert.FromBase64String(data["mainDevicePublicKey"]);
                byte[] signature = Convert.FromBase64String(data["signature"]);

                // Ensure that the main device public key from the payload matches the expected one.
                if (!mainDeviceEd25519Public.SequenceEqual(mainDevicePublicKey))
                {
                    LoggingManager.LogWarning(nameof(DeviceLinking), "Device link message rejected due to mismatched main device public key.");
                    return null;
                }

                // Verify that the main device signed the new device's original Ed25519 public key.
                if (MessageSigning.VerifySignature(newDeviceKeyPair.PublicKey, signature, mainDeviceEd25519Public))
                {
                    return mainDeviceEd25519Public;
                }
                else
                {
                    LoggingManager.LogWarning(nameof(DeviceLinking), "Device link message signature verification failed.");
                    return null;
                }
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(DeviceLinking), $"Error processing device link message: {ex}");
                return null;
            }
        }
    }
}