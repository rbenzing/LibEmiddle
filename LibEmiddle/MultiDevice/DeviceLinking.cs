using System.Security.Cryptography;
using System.Text;
using E2EELibrary.Communication;
using E2EELibrary.KeyManagement;
using E2EELibrary.KeyExchange;
using E2EELibrary.Models;
using E2EELibrary.Encryption;
using E2EELibrary.Core;

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
            ArgumentNullException.ThrowIfNull(existingSharedKey, nameof(existingSharedKey));
            ArgumentNullException.ThrowIfNull(newDevicePublicKey, nameof(newDevicePublicKey));

            // Ensure consistent key format for HMAC input
            byte[] normalizedKey;

            // Handle Ed25519 keys (32 bytes)
            if (newDevicePublicKey.Length == Constants.ED25519_PUBLIC_KEY_SIZE)
            {
                try
                {
                    // Convert Ed25519 to X25519 if necessary
                    normalizedKey = KeyConversion.DeriveX25519PublicKeyFromEd25519(newDevicePublicKey);
                }
                catch
                {
                    // If conversion fails, use the key as-is
                    normalizedKey = newDevicePublicKey;
                }
            }
            // Already a X25519 key or other format
            else if (newDevicePublicKey.Length == Constants.X25519_KEY_SIZE)
            {
                // Use a copy to prevent modifying the original
                normalizedKey = new byte[newDevicePublicKey.Length];
                newDevicePublicKey.AsSpan().CopyTo(normalizedKey.AsSpan());
            }
            else
            {
                // For any other key size, use as-is (with copy)
                normalizedKey = new byte[newDevicePublicKey.Length];
                newDevicePublicKey.AsSpan().CopyTo(normalizedKey.AsSpan());
            }

            using var hmac = new HMACSHA256(existingSharedKey);
            return hmac.ComputeHash(normalizedKey);
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
            try
            {
                // Derive main device's X25519 private key from its Ed25519 private key.
                byte[] mainDeviceX25519Private;
                if (mainDeviceKeyPair.privateKey.Length == Constants.ED25519_PRIVATE_KEY_SIZE)
                {
                    mainDeviceX25519Private = KeyConversion.DeriveX25519PrivateKeyFromEd25519(mainDeviceKeyPair.privateKey);
                }
                else if (mainDeviceKeyPair.privateKey.Length == Constants.X25519_KEY_SIZE)
                {
                    mainDeviceX25519Private = new byte[Constants.X25519_KEY_SIZE];
                    Buffer.BlockCopy(mainDeviceKeyPair.privateKey, 0, mainDeviceX25519Private, 0, Constants.X25519_KEY_SIZE);
                }
                else
                {
                    throw new ArgumentException($"Invalid private key length: {mainDeviceKeyPair.privateKey.Length}");
                }

                // Compute the corresponding X25519 public key using RFC 7748.
                byte[] mainDeviceX25519Public = Sodium.ScalarMultBase(mainDeviceX25519Private);

                // Convert new device public key to X25519 if needed.
                byte[] newDeviceX25519Public;
                if (newDevicePublicKey.Length == Constants.ED25519_PUBLIC_KEY_SIZE)
                {
                    newDeviceX25519Public = KeyConversion.DeriveX25519PublicKeyFromEd25519(newDevicePublicKey);
                }
                else if (newDevicePublicKey.Length == Constants.X25519_KEY_SIZE)
                {
                    newDeviceX25519Public = new byte[Constants.X25519_KEY_SIZE];
                    Buffer.BlockCopy(newDevicePublicKey, 0, newDeviceX25519Public, 0, Constants.X25519_KEY_SIZE);
                }
                else
                {
                    throw new ArgumentException($"Invalid public key length: {newDevicePublicKey.Length}");
                }

                // Perform X25519 key exchange to derive the shared secret.
                byte[] sharedSecret = Sodium.ScalarMult(mainDeviceX25519Private, newDeviceX25519Public);

                try
                {
                    // Sign the new device's public key using the main device's original Ed25519 private key.
                    byte[] signature = MessageSigning.SignMessage(newDevicePublicKey, mainDeviceKeyPair.privateKey);

                    // Construct the payload including:
                    // - The main device's original Ed25519 public key (for later signature verification)
                    // - The derived X25519 public key (for key exchange)
                    // - The signature over the new device's public key.
                    var payload = new
                    {
                        mainDevicePublicKey = Convert.ToBase64String(mainDeviceKeyPair.publicKey),
                        mainDeviceX25519PublicKey = Convert.ToBase64String(mainDeviceX25519Public),
                        signature = Convert.ToBase64String(signature)
                    };

                    string json = System.Text.Json.JsonSerializer.Serialize(payload);
                    byte[] plaintext = Encoding.UTF8.GetBytes(json);
                    byte[] nonce = NonceGenerator.GenerateNonce(); // Ensure uniqueness per RFC/NIST guidance.
                    byte[] ciphertext = AES.AESEncrypt(plaintext, sharedSecret, nonce);

                    return new EncryptedMessage
                    {
                        Ciphertext = ciphertext,
                        Nonce = nonce
                    };
                }
                finally
                {
                    // Securely clear sensitive material.
                    Array.Clear(mainDeviceX25519Private, 0, mainDeviceX25519Private.Length);
                    Array.Clear(sharedSecret, 0, sharedSecret.Length);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error in CreateDeviceLinkMessage: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Processes a device link message on the new device
        /// </summary>
        /// <param name="encryptedMessage">Encrypted link message</param>
        /// <param name="newDeviceKeyPair">New device's key pair</param>
        /// <param name="mainDeviceX25519Public">Main device's public key</param>
        /// <returns>Main device public key if verification succeeds</returns>
        public static byte[]? ProcessDeviceLinkMessage(
        EncryptedMessage encryptedMessage,
        (byte[] publicKey, byte[] privateKey) newDeviceKeyPair,
        byte[] mainDeviceX25519Public)
        {
            try
            {
                // Derive new device's X25519 private key.
                byte[] newDeviceX25519Private;
                if (newDeviceKeyPair.privateKey.Length == Constants.ED25519_PRIVATE_KEY_SIZE)
                {
                    newDeviceX25519Private = KeyConversion.DeriveX25519PrivateKeyFromEd25519(newDeviceKeyPair.privateKey);
                }
                else if (newDeviceKeyPair.privateKey.Length == Constants.X25519_KEY_SIZE)
                {
                    newDeviceX25519Private = new byte[Constants.X25519_KEY_SIZE];
                    Buffer.BlockCopy(newDeviceKeyPair.privateKey, 0, newDeviceX25519Private, 0, Constants.X25519_KEY_SIZE);
                }
                else
                {
                    throw new ArgumentException($"Invalid private key length: {newDeviceKeyPair.privateKey.Length}");
                }

                // Compute the shared secret using the new device's X25519 private key and the supplied main device X25519 public key.
                byte[] sharedSecret = Sodium.ScalarMult(newDeviceX25519Private, mainDeviceX25519Public);

                try
                {
                    if (encryptedMessage.Ciphertext == null || encryptedMessage.Nonce == null)
                    {
                        Console.WriteLine("Encrypted message has null ciphertext or nonce");
                        return null;
                    }

                    // Decrypt the ciphertext using AES-GCM.
                    byte[] decryptedPlaintext = AES.AESDecrypt(encryptedMessage.Ciphertext, sharedSecret, encryptedMessage.Nonce);
                    string json = Encoding.UTF8.GetString(decryptedPlaintext);

                    // Deserialize the JSON payload.
                    var data = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(json);
                    if (data == null ||
                        !data.ContainsKey("mainDevicePublicKey") ||
                        !data.ContainsKey("mainDeviceX25519PublicKey") ||
                        !data.ContainsKey("signature"))
                    {
                        return null;
                    }

                    // Retrieve the main device's public keys and signature.
                    byte[] payloadMainDeviceEd25519 = Convert.FromBase64String(data["mainDevicePublicKey"]);
                    byte[] payloadMainDeviceX25519 = Convert.FromBase64String(data["mainDeviceX25519PublicKey"]);
                    byte[] signature = Convert.FromBase64String(data["signature"]);

                    // Validate that the supplied mainDeviceX25519Public matches the one sent in the payload.
                    if (!payloadMainDeviceX25519.SequenceEqual(mainDeviceX25519Public))
                    {
                        throw new CryptographicException("Main device X25519 public key mismatch.");
                    }

                    // Verify the signature using the main device's original Ed25519 public key.
                    if (MessageSigning.VerifySignature(newDeviceKeyPair.publicKey, signature, payloadMainDeviceEd25519))
                    {
                        return payloadMainDeviceEd25519;
                    }
                    else
                    {
                        Console.WriteLine("Signature verification failed");
                        return null;
                    }
                }
                finally
                {
                    // Securely clear sensitive material.
                    Array.Clear(newDeviceX25519Private, 0, newDeviceX25519Private.Length);
                    Array.Clear(sharedSecret, 0, sharedSecret.Length);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error in ProcessDeviceLinkMessage: {ex.Message}");
                throw;
            }
        }

    }
}