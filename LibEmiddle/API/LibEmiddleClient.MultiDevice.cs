using System.Security.Cryptography;
using LibEmiddle.Abstractions;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;
using LibEmiddle.Domain.Exceptions;
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

    /// <summary>
    /// Sends an encrypted message to a specific linked device.
    /// </summary>
    /// <param name="deviceId">
    /// The base-64–encoded X25519 public key identifying the target device,
    /// as stored in the <see cref="DeviceManager"/>.
    /// </param>
    /// <param name="message">The pre-encrypted message to route to the device.</param>
    /// <returns>A task that completes when the message has been accepted by the transport.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="deviceId"/> is null or empty, or <paramref name="message"/> is null.
    /// </exception>
    /// <exception cref="LibEmiddleException">
    /// Thrown with <see cref="LibEmiddleErrorCode.DeviceNotFound"/> when the device is not linked,
    /// or with <see cref="LibEmiddleErrorCode.TransportError"/> when transport delivery fails.
    /// </exception>
    public async Task SendToDeviceAsync(string deviceId, EncryptedMessage message)
    {
        ThrowIfDisposed();
        EnsureInitialized();

        if (string.IsNullOrEmpty(deviceId))
            throw new ArgumentException("Device ID cannot be null or empty.", nameof(deviceId));

        ArgumentNullException.ThrowIfNull(message);

        // Resolve the device ID to a public key byte array and confirm the device is linked.
        byte[] devicePublicKey;
        try
        {
            devicePublicKey = Convert.FromBase64String(deviceId);
        }
        catch (FormatException ex)
        {
            throw new ArgumentException($"Device ID '{deviceId}' is not valid base-64.", nameof(deviceId), ex);
        }

        if (!_deviceManager.IsDeviceLinked(devicePublicKey))
        {
            LoggingManager.LogWarning(nameof(LibEmiddleClient),
                $"SendToDeviceAsync: device '{deviceId[..Math.Min(8, deviceId.Length)]}...' is not in the linked-device list.");
            throw new LibEmiddleException(
                $"Device '{deviceId}' is not linked to this client.",
                LibEmiddleErrorCode.DeviceNotFound);
        }

        // Stamp device routing information into the message headers so the
        // receiving side can route or filter by device ID without decrypting.
        var routedMessage = message.Clone();
        routedMessage.Headers ??= new Dictionary<string, string>();
        routedMessage.Headers["X-Device-Id"] = deviceId;
        routedMessage.Headers["X-Sender-Device-Id"] = Convert.ToBase64String(_identityKeyPair.PublicKey);

        // Wrap in a MailboxMessage addressed to the target device's public key.
        var mailboxMessage = new MailboxMessage(
            recipientKey: devicePublicKey,
            senderKey: _identityKeyPair.PublicKey,
            payload: routedMessage)
        {
            Type = MessageType.DeviceSync,
            Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
        };

        bool sent;
        try
        {
            sent = await _transport.SendMessageAsync(mailboxMessage).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"SendToDeviceAsync: transport threw while sending to device '{deviceId[..Math.Min(8, deviceId.Length)]}...': {ex.Message}");
            throw new LibEmiddleException(
                $"Transport error while sending to device '{deviceId}'.",
                LibEmiddleErrorCode.TransportError,
                ex);
        }

        if (!sent)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"SendToDeviceAsync: transport returned false for device '{deviceId[..Math.Min(8, deviceId.Length)]}...'.");
            throw new LibEmiddleException(
                $"Transport failed to deliver message to device '{deviceId}'.",
                LibEmiddleErrorCode.TransportError);
        }

        LoggingManager.LogInformation(nameof(LibEmiddleClient),
            $"SendToDeviceAsync: message sent to device '{deviceId[..Math.Min(8, deviceId.Length)]}...'.");
    }
}
