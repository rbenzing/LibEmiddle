using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using LibEmiddle.Core;
using LibEmiddle.Domain;
using LibEmiddle.Abstractions;
using LibEmiddle.Crypto;
using System.Security;

namespace LibEmiddle.MultiDevice;

public partial class DeviceManager
{
    /// <summary>
    /// Creates a sync message for a specific device using secure encryption.
    /// </summary>
    /// <param name="syncData">The data to synchronize</param>
    /// <param name="deviceKey">The target device's public key</param>
    /// <param name="senderX25519Private">The sender's X25519 private key</param>
    /// <returns>An encrypted message containing the sync data</returns>
    private EncryptedMessage CreateSyncMessageForDevice(byte[] syncData, byte[] deviceKey, byte[] senderX25519Private)
    {
        // Perform key exchange
        byte[] sharedSecret = _cryptoProvider.ScalarMult(senderX25519Private, deviceKey);

        try
        {
            // Sign the sync data
            byte[] signature = _cryptoProvider.Sign(syncData, _deviceKeyPair.PrivateKey);

            // Create sync message with timestamp for replay protection
            var syncMessage = new DeviceSyncMessage
            {
                SenderPublicKey = _deviceKeyPair.PublicKey,
                Data = syncData,
                Signature = signature,
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                Version = ProtocolVersion.FULL_VERSION
            };

            // Serialize with protocol version
            string json = JsonSerializer.Serialize(new
            {
                senderPublicKey = Convert.ToBase64String(syncMessage.SenderPublicKey ?? Array.Empty<byte>()),
                data = Convert.ToBase64String(syncMessage.Data ?? Array.Empty<byte>()),
                signature = Convert.ToBase64String(syncMessage.Signature ?? Array.Empty<byte>()),
                timestamp = syncMessage.Timestamp,
                protocolVersion = syncMessage.Version
            });

            // Encrypt
            byte[] plaintext = Encoding.UTF8.GetBytes(json);
            byte[] nonce = Nonce.GenerateNonce();
            byte[] ciphertext = AES.AESEncrypt(plaintext, sharedSecret, nonce);

            // Create encrypted message
            return new EncryptedMessage
            {
                Ciphertext = ciphertext,
                Nonce = nonce,
                Timestamp = syncMessage.Timestamp,
                MessageId = Guid.NewGuid().ToString()
            };
        }
        finally
        {
            // Securely clear shared secret after use
            SecureMemory.SecureClear(sharedSecret);
        }
    }

    /// <summary>
    /// Attempts to process a sync message from a specific device.
    /// </summary>
    /// <param name="encryptedMessage">The encrypted sync message</param>
    /// <param name="deviceKey">The sender device's public key</param>
    /// <returns>The decrypted sync data if successful, null otherwise</returns>
    private byte[]? TryProcessSyncMessageFromDevice(EncryptedMessage encryptedMessage, byte[] deviceKey)
    {
        // Basic null checks
        if (encryptedMessage?.Ciphertext == null || encryptedMessage.Nonce == null)
            return null;

        byte[]? x25519Private = null;
        byte[]? sharedSecret = null;

        try
        {
            // Prepare receiver's private key (this device)
            x25519Private = _cryptoProvider.ConvertEd25519PrivateKeyToX25519(_deviceKeyPair.PrivateKey);

            if (x25519Private == null || x25519Private.Length != Constants.X25519_KEY_SIZE)
                return null;

            // Get shared secret
            sharedSecret = _cryptoProvider.ScalarMult(x25519Private, deviceKey);

            // Decrypt message
            byte[] plaintext;
            try
            {
                plaintext = AES.AESDecrypt(encryptedMessage.Ciphertext, sharedSecret, encryptedMessage.Nonce);
            }
            catch
            {
                // Decryption failed - likely incorrect keys or tampered message
                return null;
            }

            // Parse and validate the sync message
            string json = Encoding.UTF8.GetString(plaintext);
            var jsonObj = JsonDocument.Parse(json);
            var root = jsonObj.RootElement;

            // Extract and validate fields
            if (!root.TryGetProperty("data", out var dataElement) ||
                dataElement.ValueKind != JsonValueKind.String)
            {
                return null;
            }

            string? dataBase64 = dataElement.GetString();
            if (string.IsNullOrEmpty(dataBase64))
                return null;

            byte[] syncData = Convert.FromBase64String(dataBase64);

            // Create and validate the sync message
            var syncMessage = new DeviceSyncMessage();

            if (root.TryGetProperty("senderPublicKey", out var senderElement) &&
                senderElement.ValueKind == JsonValueKind.String)
            {
                string? senderBase64 = senderElement.GetString();
                if (!string.IsNullOrEmpty(senderBase64))
                {
                    syncMessage.SenderPublicKey = Convert.FromBase64String(senderBase64);
                }
            }

            if (root.TryGetProperty("signature", out var signatureElement) &&
                signatureElement.ValueKind == JsonValueKind.String)
            {
                string? signatureBase64 = signatureElement.GetString();
                if (!string.IsNullOrEmpty(signatureBase64))
                {
                    syncMessage.Signature = Convert.FromBase64String(signatureBase64);
                }
            }

            if (root.TryGetProperty("timestamp", out var timestampElement) &&
                timestampElement.ValueKind == JsonValueKind.Number)
            {
                syncMessage.Timestamp = timestampElement.GetInt64();
            }

            syncMessage.Data = syncData;

            // Validate the sync message using the validator
            // We need to validate against the original Ed25519 key, not the normalized X25519 key
            // The sync message contains the Ed25519 sender key, so we need to convert the X25519 device key back
            // or find the original Ed25519 key that corresponds to this X25519 key
            if (syncMessage.SenderPublicKey != null)
            {
                // Check if the sender's Ed25519 key normalizes to the same X25519 key as the device key
                byte[]? normalizedSenderKey = NormalizeDeviceKey(syncMessage.SenderPublicKey);
                bool isValidSender = false;

                if (normalizedSenderKey != null)
                {
                    try
                    {
                        isValidSender = SecureMemory.SecureCompare(normalizedSenderKey, deviceKey);
                    }
                    finally
                    {
                        SecureMemory.SecureClear(normalizedSenderKey);
                    }
                }

                if (!isValidSender)
                {
                    LoggingManager.LogWarning(nameof(DeviceManager),
                        "Sync message sender does not match expected device");
                    return null;
                }

                // Now validate the message signature using the sender's Ed25519 key
                if (!_syncMessageValidator.ValidateSyncMessage(syncMessage, syncMessage.SenderPublicKey))
                {
                    LoggingManager.LogWarning(nameof(DeviceManager),
                        "Sync message validation failed");
                    return null;
                }
            }

            return syncData;
        }
        catch (Exception ex)
        {
            LoggingManager.LogWarning(nameof(DeviceManager),
                $"Error processing sync message: {ex.Message}");
            return null;
        }
        finally
        {
            // Clean up sensitive data
            if (x25519Private != null)
                SecureMemory.SecureClear(x25519Private);
            if (sharedSecret != null)
                SecureMemory.SecureClear(sharedSecret);
        }
    }

    /// <summary>
    /// Checks if two device keys represent the same device.
    /// </summary>
    /// <param name="key1">First device key</param>
    /// <param name="key2">Second device key</param>
    /// <returns>True if the keys represent the same device</returns>
    private static bool IsSameDeviceKey(byte[] key1, byte[] key2)
    {
        if (key1 == null || key2 == null || key1.Length != key2.Length)
            return false;

        return SecureMemory.SecureCompare(key1, key2);
    }

    /// <summary>
    /// Validates that an encrypted message has the required fields.
    /// </summary>
    /// <param name="message">The message to validate</param>
    /// <returns>True if the message is valid</returns>
    private static bool IsValidEncryptedMessage(EncryptedMessage message)
    {
        return message.Ciphertext != null &&
               message.Ciphertext.Length > 0 &&
               message.Nonce != null &&
               message.Nonce.Length == Constants.NONCE_SIZE;
    }

    /// <summary>
    /// Normalizes a device key to X25519 format for consistent storage and lookup.
    /// Delegates to <see cref="KeyConversion.ConvertEd25519PublicKeyToX25519"/> for shared logic.
    /// </summary>
    /// <param name="deviceKey">The device key to normalize</param>
    /// <returns>The normalized X25519 key, or null if invalid</returns>
    private static byte[]? NormalizeDeviceKey(byte[] deviceKey)
    {
        try
        {
            return KeyConversion.ConvertEd25519PublicKeyToX25519(deviceKey);
        }
        catch (Exception ex)
        {
            LoggingManager.LogWarning(nameof(DeviceManager),
                $"Error normalizing device key: {ex.Message}");
            return null;
        }
    }
}
