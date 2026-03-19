using System.Security.Cryptography;
using LibEmiddle.Abstractions;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;
using LibEmiddle.KeyManagement;
using LibEmiddle.Messaging.Group;
using LibEmiddle.MultiDevice;
using LibEmiddle.Protocol;
using LibEmiddle.Sessions;
using LibEmiddle.Messaging.Transport;
using LibEmiddle.Messaging.Chat;
using LibEmiddle.Diagnostics;

namespace LibEmiddle.API;

public sealed partial class LibEmiddleClient
{
    /// <summary>
    /// Creates a device link message for adding a new device.
    /// </summary>
    /// <param name="newDevicePublicKey">The new device's public key</param>
    /// <returns>An encrypted message for device linking</returns>
    public EncryptedMessage CreateDeviceLinkMessage(byte[] newDevicePublicKey)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentNullException.ThrowIfNull(newDevicePublicKey);

        try
        {
            return _deviceManager.CreateDeviceLinkMessage(newDevicePublicKey);
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Failed to create device link message: {ex.Message}");
            throw;
        }
    }

    /// <summary>
    /// Processes a device link message from the main device.
    /// </summary>
    /// <param name="encryptedMessage">The encrypted device link message</param>
    /// <param name="expectedMainDevicePublicKey">Expected public key of the main device</param>
    /// <returns>True if the device was successfully linked</returns>
    public bool ProcessDeviceLinkMessage(
        EncryptedMessage encryptedMessage,
        byte[] expectedMainDevicePublicKey)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentNullException.ThrowIfNull(encryptedMessage);
        ArgumentNullException.ThrowIfNull(expectedMainDevicePublicKey);

        try
        {
            return _deviceManager.ProcessDeviceLinkMessage(encryptedMessage, expectedMainDevicePublicKey);
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Failed to process device link message: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Creates sync messages for all linked devices.
    /// </summary>
    /// <param name="syncData">The data to synchronize</param>
    /// <returns>Dictionary of device IDs to encrypted sync messages</returns>
    public Dictionary<string, EncryptedMessage> CreateSyncMessages(byte[] syncData)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentNullException.ThrowIfNull(syncData);

        try
        {
            return _deviceManager.CreateSyncMessages(syncData);
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Failed to create sync messages: {ex.Message}");
            throw;
        }
    }

    /// <summary>
    /// Gets the number of linked devices.
    /// </summary>
    /// <returns>Number of linked devices</returns>
    public int GetLinkedDeviceCount()
    {
        ThrowIfDisposed();
        EnsureInitialized();

        try
        {
            return _deviceManager.GetLinkedDeviceCount();
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient), $"Failed to get linked device count: {ex.Message}");
            return 0;
        }
    }

    /// <summary>
    /// Removes a linked device from the device manager.
    /// </summary>
    /// <param name="devicePublicKey">The public key of the device to remove</param>
    /// <returns>True if the device was removed successfully</returns>
    public bool RemoveLinkedDevice(byte[] devicePublicKey)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentNullException.ThrowIfNull(devicePublicKey);

        try
        {
            var result = _deviceManager.RemoveLinkedDevice(devicePublicKey);
            if (result)
            {
                LoggingManager.LogInformation(nameof(LibEmiddleClient),
                    $"Removed linked device {Convert.ToBase64String(devicePublicKey).Substring(0, 8)}");
            }
            return result;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient), $"Failed to remove linked device: {ex.Message}");
            return false;
        }
    }
}
