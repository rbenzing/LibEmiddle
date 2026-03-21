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
    public int GetLinkedDeviceCount()
    {
        ThrowIfDisposed();
        EnsureStorageLoadedAsync().GetAwaiter().GetResult();
        return _linkedDevices.Count;
    }

    /// <inheritdoc/>
    public void AddLinkedDevice(byte[] devicePublicKey)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(devicePublicKey, nameof(devicePublicKey));
        EnsureStorageLoadedAsync().GetAwaiter().GetResult();

        // Check if device was previously revoked
        if (IsDeviceRevoked(devicePublicKey))
            throw new SecurityException("Cannot add a previously revoked device");

        byte[]? normalizedKey = null;
        try
        {
            normalizedKey = NormalizeDeviceKey(devicePublicKey);
            if (normalizedKey == null)
            {
                throw new ArgumentException(
                    $"Device public key must be {Constants.X25519_KEY_SIZE} or {Constants.ED25519_PUBLIC_KEY_SIZE} bytes",
                    nameof(devicePublicKey));
            }

            // Add to dictionary using Base64 representation of the key as dictionary key
            string keyBase64 = Convert.ToBase64String(normalizedKey);

            // Check if device is already added
            if (_linkedDevices.TryGetValue(keyBase64, out _))
            {
                LoggingManager.LogDebug(nameof(DeviceManager), $"Device {keyBase64} is already linked");
                return;
            }

            // Create a new device info record with current timestamp
            var deviceInfo = new DeviceInfo
            {
                PublicKey = normalizedKey,
                LinkedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
            };

            _linkedDevices.TryAdd(keyBase64, deviceInfo);

            LoggingManager.LogInformation(nameof(DeviceManager), $"Successfully linked device {keyBase64}");

            // Persist the updated list to disk (fire-and-forget, best-effort).
            PersistDevicesFireAndForget();
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(DeviceManager),
                $"Failed to add linked device: {ex.Message}");

            // Clear the normalized key if we didn't store it successfully
            if (normalizedKey != null)
            {
                SecureMemory.SecureClear(normalizedKey);
            }
        }
        finally
        {
            normalizedKey = null;
        }
    }

    /// <inheritdoc/>
    public bool RemoveLinkedDevice(byte[] devicePublicKey)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(devicePublicKey, nameof(devicePublicKey));
        EnsureStorageLoadedAsync().GetAwaiter().GetResult();

        byte[]? normalizedKey = null;
        try
        {
            normalizedKey = NormalizeDeviceKey(devicePublicKey);
            if (normalizedKey == null)
            {
                throw new ArgumentException(
                    $"Device public key must be {Constants.X25519_KEY_SIZE} or {Constants.ED25519_PUBLIC_KEY_SIZE} bytes",
                    nameof(devicePublicKey));
            }

            // Use Base64 representation as dictionary key
            string keyBase64 = Convert.ToBase64String(normalizedKey);

            // Try to remove and securely clear the device info
            if (_linkedDevices.TryRemove(keyBase64, out DeviceInfo? deviceInfo))
            {
                if (deviceInfo?.PublicKey != null)
                {
                    SecureMemory.SecureClear(deviceInfo.PublicKey);
                }

                LoggingManager.LogInformation(nameof(DeviceManager), $"Removed linked device {keyBase64}");

                // Persist the updated list to disk (fire-and-forget, best-effort).
                PersistDevicesFireAndForget();

                return true;
            }

            LoggingManager.LogInformation(nameof(DeviceManager), $"Device {keyBase64} not found in linked devices");
            return false;
        }
        finally
        {
            // Always securely clear the temporary key
            if (normalizedKey != null)
            {
                SecureMemory.SecureClear(normalizedKey);
            }
        }
    }

    /// <inheritdoc/>
    public bool IsDeviceLinked(ReadOnlySpan<byte> devicePublicKey)
    {
        ThrowIfDisposed();

        if (devicePublicKey.IsEmpty)
            return false;

        EnsureStorageLoadedAsync().GetAwaiter().GetResult();

        byte[]? normalizedKey = null;
        try
        {
            normalizedKey = NormalizeDeviceKey(devicePublicKey.ToArray());
            if (normalizedKey == null)
                return false;

            string keyBase64 = Convert.ToBase64String(normalizedKey);
            return _linkedDevices.ContainsKey(keyBase64);
        }
        catch (Exception ex)
        {
            LoggingManager.LogWarning(nameof(DeviceManager),
                $"Error in IsDeviceLinked: {ex.Message}");
            return false;
        }
        finally
        {
            if (normalizedKey != null)
            {
                SecureMemory.SecureClear(normalizedKey);
            }
        }
    }

    /// <inheritdoc/>
    public string ExportLinkedDevices()
    {
        ThrowIfDisposed();

        var linkedDevicesList = new List<LinkedDeviceInfo>();

        foreach (var kvp in _linkedDevices)
        {
            // Create a serializable representation
            var deviceInfo = new LinkedDeviceInfo
            {
                Id = kvp.Key,
                PublicKey = Convert.ToBase64String(kvp.Value.PublicKey),
                LinkedAt = kvp.Value.LinkedAt
            };

            linkedDevicesList.Add(deviceInfo);
        }

        return JsonSerialization.Serialize(linkedDevicesList);
    }

    /// <inheritdoc/>
    public int ImportLinkedDevices(string serializedDevices)
    {
        ThrowIfDisposed();

        if (string.IsNullOrEmpty(serializedDevices))
            return 0;

        try
        {
            var devicesList = JsonSerialization.Deserialize<List<LinkedDeviceInfo>>(serializedDevices);
            if (devicesList == null)
                return 0;

            int importedCount = 0;

            foreach (var deviceInfo in devicesList)
            {
                // Skip if already exists
                if (_linkedDevices.ContainsKey(deviceInfo.Id))
                    continue;

                // Check if device has been revoked
                try
                {
                    byte[] publicKey = Convert.FromBase64String(deviceInfo.PublicKey);

                    if (IsDeviceRevoked(publicKey))
                    {
                        LoggingManager.LogWarning(nameof(DeviceManager),
                            $"Skipping import of revoked device: {deviceInfo.Id}");
                        continue;
                    }

                    // Recreate the device info
                    var newDeviceInfo = new DeviceInfo
                    {
                        PublicKey = publicKey,
                        LinkedAt = deviceInfo.LinkedAt
                    };

                    // Add to linked devices
                    if (_linkedDevices.TryAdd(deviceInfo.Id, newDeviceInfo))
                    {
                        importedCount++;
                    }
                }
                catch (Exception ex)
                {
                    LoggingManager.LogWarning(nameof(DeviceManager),
                        $"Error importing device {deviceInfo.Id}: {ex.Message}");
                    // Continue with next device
                }
            }

            return importedCount;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(DeviceManager),
                $"Error importing linked devices: {ex.Message}");
            return 0;
        }
    }
}
