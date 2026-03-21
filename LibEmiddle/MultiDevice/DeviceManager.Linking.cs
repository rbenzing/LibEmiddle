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
    public EncryptedMessage CreateDeviceLinkMessage(byte[] newDevicePublicKey)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(newDevicePublicKey, nameof(newDevicePublicKey));

        // Check if device was previously revoked
        if (IsDeviceRevoked(newDevicePublicKey))
            throw new SecurityException("Cannot add a previously revoked device");

        try
        {
            return _deviceLinkingService.CreateDeviceLinkMessage(_deviceKeyPair, newDevicePublicKey);
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(DeviceManager), $"Failed to create device link message: {ex.Message}");
            throw;
        }
    }

    /// <inheritdoc/>
    public bool ProcessDeviceLinkMessage(
        EncryptedMessage encryptedMessage,
        byte[] expectedMainDevicePublicKey)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(encryptedMessage, nameof(encryptedMessage));
        ArgumentNullException.ThrowIfNull(expectedMainDevicePublicKey, nameof(expectedMainDevicePublicKey));

        // Check if device was previously revoked
        if (IsDeviceRevoked(expectedMainDevicePublicKey))
        {
            LoggingManager.LogWarning(nameof(DeviceManager),
                "Cannot process link message from a revoked device");
            return false;
        }

        try
        {
            // Process the device link message using the service
            byte[]? mainDevicePublicKey = _deviceLinkingService.ProcessDeviceLinkMessage(
                encryptedMessage,
                _deviceKeyPair,
                expectedMainDevicePublicKey);

            if (mainDevicePublicKey == null)
                return false;

            // Link was successful, add the device to our linked devices
            AddLinkedDevice(mainDevicePublicKey);
            return true;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(DeviceManager), $"Failed to process device link message: {ex.Message}");
            return false;
        }
    }

    /// <inheritdoc/>
    public DeviceRevocationMessage CreateDeviceRevocationMessage(byte[] devicePublicKey, string? reason = null)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(devicePublicKey, nameof(devicePublicKey));

        // Delegate to the linking service for creating the revocation message
        var revocationMessage = _deviceLinkingService.CreateDeviceRevocationMessage(
            _deviceKeyPair, devicePublicKey, reason);

        // Record the revocation locally
        ProcessDeviceRevocationMessage(revocationMessage);

        return revocationMessage;
    }

    /// <inheritdoc/>
    public bool ProcessDeviceRevocationMessage(DeviceRevocationMessage revocationMessage)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(revocationMessage, nameof(revocationMessage));
        ArgumentNullException.ThrowIfNull(revocationMessage.RevokedDevicePublicKey, nameof(revocationMessage.RevokedDevicePublicKey));
        EnsureStorageLoadedAsync().GetAwaiter().GetResult();

        try
        {
            // Check if we've already processed this revocation message
            if (_processedRevocations.ContainsKey(revocationMessage.Id))
            {
                // Already processed, but return success
                return true;
            }

            // Verify the revocation using the linking service
            if (!_deviceLinkingService.VerifyDeviceRevocationMessage(revocationMessage, _deviceKeyPair.PublicKey))
            {
                LoggingManager.LogWarning(nameof(DeviceManager),
                    "Revocation message signature verification failed");
                return false;
            }

            // The revocation message contains the device key in normalized X25519 format
            // We need to use this exact key to find the device in our dictionary
            string deviceId = Convert.ToBase64String(revocationMessage.RevokedDevicePublicKey);

            // Remove the device from linked devices if present
            if (_linkedDevices.TryRemove(deviceId, out var deviceInfo))
            {
                LoggingManager.LogInformation(nameof(DeviceManager),
                    $"Revoked linked device {deviceId}: {revocationMessage.Reason ?? "No reason provided"}");

                // Securely clear the device info
                if (deviceInfo.PublicKey != null)
                {
                    SecureMemory.SecureClear(deviceInfo.PublicKey);
                }

                // Persist the updated list to disk (fire-and-forget, best-effort).
                PersistDevicesFireAndForget();
            }
            else
            {
                // Device not found in linked devices - this could happen if:
                // 1. Device was already removed
                // 2. Device was never linked to this manager
                // 3. There's a key normalization mismatch
                LoggingManager.LogDebug(nameof(DeviceManager),
                    $"Device {deviceId} not found in linked devices during revocation processing");
            }

            // Store the revocation message to prevent replay attacks
            _processedRevocations[revocationMessage.Id] = revocationMessage;

            return true;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(DeviceManager),
                $"Error processing device revocation message: {ex.Message}");
            return false;
        }
    }

    /// <inheritdoc/>
    public bool IsDeviceRevoked(byte[] devicePublicKey)
    {
        if (devicePublicKey == null)
            return false;

        byte[]? normalizedKey = NormalizeDeviceKey(devicePublicKey);
        if (normalizedKey == null)
            return false;

        try
        {
            string deviceId = Convert.ToBase64String(normalizedKey);

            // Check all processed revocations to see if this device was revoked
            foreach (var revocation in _processedRevocations.Values)
            {
                if (revocation.RevokedDevicePublicKey == null)
                    continue;

                string revokedId = Convert.ToBase64String(revocation.RevokedDevicePublicKey);
                if (revokedId == deviceId)
                    return true;
            }

            return false;
        }
        catch (Exception ex)
        {
            LoggingManager.LogWarning(nameof(DeviceManager),
                $"Error in IsDeviceRevoked: {ex.Message}");
            return false;
        }
        finally
        {
            // Always securely clear sensitive key material
            if (normalizedKey != null)
            {
                SecureMemory.SecureClear(normalizedKey);
            }
        }
    }

    /// <inheritdoc/>
    public List<byte[]> GetRevokedDeviceKeys()
    {
        ThrowIfDisposed();

        var revokedKeys = new List<byte[]>();

        foreach (var revocation in _processedRevocations.Values)
        {
            if (revocation.RevokedDevicePublicKey != null)
            {
                // Make a copy to prevent external modification
                revokedKeys.Add(revocation.RevokedDevicePublicKey.ToArray());
            }
        }

        return revokedKeys;
    }

    /// <inheritdoc/>
    public string ExportRevocations()
    {
        ThrowIfDisposed();

        var revocations = _processedRevocations.Values.ToList();
        return JsonSerialization.Serialize(revocations);
    }

    /// <inheritdoc/>
    public int ImportRevocations(string serializedRevocations)
    {
        ThrowIfDisposed();

        if (string.IsNullOrEmpty(serializedRevocations))
            return 0;

        try
        {
            var revocations = JsonSerialization.Deserialize<List<DeviceRevocationMessage>>(serializedRevocations);
            if (revocations == null)
                return 0;

            int importedCount = 0;

            foreach (var revocation in revocations)
            {
                // Verify and process each revocation
                if (revocation.IsValid() && ProcessDeviceRevocationMessage(revocation))
                {
                    importedCount++;
                }
            }

            return importedCount;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(DeviceManager),
                $"Error importing revocations: {ex.Message}");
            return 0;
        }
    }
}
