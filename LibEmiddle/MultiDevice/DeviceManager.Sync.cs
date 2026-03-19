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
    /// <inheritdoc/>
    public Dictionary<string, EncryptedMessage> CreateSyncMessages(byte[] syncData)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(syncData, nameof(syncData));

        var result = new Dictionary<string, EncryptedMessage>();

        // Basic sanity check
        if (_linkedDevices.Count == 0)
            return result;

        // Make a secure copy of the sync data to avoid external modification during processing
        using var secureSyncData = new SecureMemory.SecureArray<byte>(syncData);
        byte[]? senderX25519Private = null;

        try
        {
            senderX25519Private = _cryptoProvider.ConvertEd25519PrivateKeyToX25519(_deviceKeyPair.PrivateKey);

            // Thread safety for linked devices access
            foreach (var deviceEntry in _linkedDevices)
            {
                string deviceId = deviceEntry.Key;
                DeviceInfo deviceInfo = deviceEntry.Value;
                byte[] deviceKey = deviceInfo.PublicKey;

                try
                {
                    // Create the sync message for this device
                    EncryptedMessage message = CreateSyncMessageForDevice(
                        secureSyncData.Value,
                        deviceKey,
                        senderX25519Private);

                    // Add to result dictionary
                    result[deviceId] = message;
                }
                catch (Exception ex)
                {
                    // Log the error but continue processing other devices
                    LoggingManager.LogWarning(nameof(DeviceManager),
                        $"Error creating sync message for device {deviceId}: {ex.Message}");
                }
            }
        }
        finally
        {
            // Securely clear the private key copy when done
            if (senderX25519Private != null)
            {
                SecureMemory.SecureClear(senderX25519Private);
            }
        }

        return result;
    }

    /// <inheritdoc/>
    public Task<byte[]?> ProcessSyncMessageAsync(EncryptedMessage encryptedMessage, byte[]? senderHint = null)
    {
        return Task.Run(() => ProcessSyncMessage(encryptedMessage, senderHint));
    }

    /// <inheritdoc/>
    public byte[]? ProcessSyncMessage(EncryptedMessage encryptedMessage, byte[]? senderHint = null)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(encryptedMessage, nameof(encryptedMessage));

        // Validate the encrypted message
        if (!IsValidEncryptedMessage(encryptedMessage))
        {
            LoggingManager.LogWarning(nameof(DeviceManager), "Invalid encrypted message format");
            return null;
        }

        // If we have a sender hint, try that device first
        if (senderHint != null)
        {
            byte[]? normalizedHint = NormalizeDeviceKey(senderHint);
            if (normalizedHint != null)
            {
                try
                {
                    string senderKeyBase64 = Convert.ToBase64String(normalizedHint);

                    if (_linkedDevices.TryGetValue(senderKeyBase64, out var deviceInfo))
                    {
                        byte[]? result = TryProcessSyncMessageFromDevice(encryptedMessage, deviceInfo.PublicKey);
                        if (result != null)
                            return result;
                    }
                }
                finally
                {
                    SecureMemory.SecureClear(normalizedHint);
                }
            }
        }

        // Otherwise try all linked devices
        foreach (var deviceEntry in _linkedDevices)
        {
            DeviceInfo deviceInfo = deviceEntry.Value;
            byte[] deviceKey = deviceInfo.PublicKey;

            // Skip the hint device if we already tried it
            if (senderHint != null && IsSameDeviceKey(deviceKey, senderHint))
                continue;

            // Create a fresh copy of the message for each attempt
            var messageCopy = new EncryptedMessage
            {
                Ciphertext = encryptedMessage.Ciphertext?.ToArray(),
                Nonce = encryptedMessage.Nonce?.ToArray(),
                SenderMessageNumber = encryptedMessage.SenderMessageNumber,
                SenderDHKey = encryptedMessage.SenderDHKey?.ToArray(),
                Timestamp = encryptedMessage.Timestamp,
                MessageId = encryptedMessage.MessageId,
                SessionId = encryptedMessage.SessionId
            };

            byte[]? result = TryProcessSyncMessageFromDevice(messageCopy, deviceKey);
            if (result != null)
                return result;
        }

        LoggingManager.LogInformation(nameof(DeviceManager),
            "Could not process sync message with any linked device key");
        return null;
    }
}
