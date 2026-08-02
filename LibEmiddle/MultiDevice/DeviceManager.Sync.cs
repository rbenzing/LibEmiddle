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

        // Tracks which stored device keys we have already attempted, so the fallback loop does
        // not retry them. Keyed by the dictionary key (base64 X25519), which is unambiguous.
        var attempted = new HashSet<string>(StringComparer.Ordinal);

        // If we have a sender hint, try that device first.
        //
        // Linked devices are stored under their X25519 public key. Callers may hand us either the
        // X25519 key or the Ed25519 identity key, and the two formats are indistinguishable by
        // inspection, so try the hint verbatim BEFORE attempting an Ed25519->X25519 conversion.
        // Sniffing first is not safe: about one in eight X25519 keys also validates as an Ed25519
        // point, so conversion would silently yield a different key and the lookup would miss at
        // random. Trying the raw bytes first makes the common case deterministic.
        if (senderHint != null && senderHint.Length == Constants.X25519_KEY_SIZE)
        {
            string rawHintBase64 = Convert.ToBase64String(senderHint);
            if (_linkedDevices.TryGetValue(rawHintBase64, out var rawDeviceInfo))
            {
                attempted.Add(rawHintBase64);

                byte[]? result = TryProcessSyncMessageFromDevice(encryptedMessage, rawDeviceInfo.PublicKey);
                if (result != null)
                    return result;
            }
        }

        // The hint was not a stored X25519 key; treat it as an Ed25519 identity key and convert.
        if (senderHint != null && attempted.Count == 0)
        {
            byte[]? normalizedHint = NormalizeDeviceKey(senderHint);
            if (normalizedHint != null)
            {
                try
                {
                    string senderKeyBase64 = Convert.ToBase64String(normalizedHint);

                    if (_linkedDevices.TryGetValue(senderKeyBase64, out var deviceInfo))
                    {
                        attempted.Add(senderKeyBase64);

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

            // Skip only devices we have actually already attempted above. Comparing the stored
            // key against the raw hint here used to skip the one device that could decrypt the
            // message whenever the caller passed an X25519 hint.
            if (!attempted.Add(deviceEntry.Key))
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
