using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using LibEmiddle.Core;
using LibEmiddle.Domain;
using LibEmiddle.Abstractions;
using LibEmiddle.Crypto;
using System.Security;

namespace LibEmiddle.MultiDevice;

/// <summary>
/// Manages multi-device sessions for securely synchronizing cryptographic state across
/// multiple devices belonging to the same user identity.
/// 
/// <para>
/// Provides functionality for linking, unlinking, and synchronizing data between devices,
/// as well as managing device revocation to ensure security across a user's device ecosystem.
/// Implements RFC-compliant procedures for the Signal protocol's multi-device specification.
/// </para>
/// </summary>
public class DeviceManager : IDeviceManager, IDisposable
{
    private readonly KeyPair _deviceKeyPair;
    private readonly IDeviceLinkingService _deviceLinkingService;
    private readonly ICryptoProvider _cryptoProvider;
    private readonly ISyncMessageValidator _syncMessageValidator;

    // Device storage with thread-safe dictionaries
    private readonly ConcurrentDictionary<string, DeviceInfo> _linkedDevices =
        new(StringComparer.Ordinal);

    // Store revocation messages we've processed for replay protection
    private readonly ConcurrentDictionary<string, DeviceRevocationMessage> _processedRevocations =
        new();

    // Use a separate sync lock for import/export operations
    private readonly SemaphoreSlim _stateLock = new(1, 1);

    // Track if we're disposed
    private bool _disposed = false;

    /// <summary>
    /// Creates a new multi-device manager with the specified dependencies.
    /// </summary>
    /// <param name="deviceKeyPair">This device's Ed25519 identity key pair</param>
    /// <param name="deviceLinkingService">Service for handling device linking operations</param>
    /// <param name="cryptoProvider">Cryptographic provider implementation</param>
    /// <param name="syncMessageValidator">Optional validator for sync messages</param>
    /// <exception cref="ArgumentNullException">Thrown when required parameters are null</exception>
    /// <exception cref="ArgumentException">Thrown when device key pair is invalid</exception>
    public DeviceManager(
        KeyPair deviceKeyPair,
        IDeviceLinkingService deviceLinkingService,
        ICryptoProvider cryptoProvider,
        ISyncMessageValidator? syncMessageValidator = null)
    {
        if (deviceKeyPair.PublicKey == null || deviceKeyPair.PublicKey.Length == 0)
            throw new ArgumentException("Device public key cannot be null or empty", nameof(deviceKeyPair));

        if (deviceKeyPair.PrivateKey == null || deviceKeyPair.PrivateKey.Length == 0)
            throw new ArgumentException("Device private key cannot be null or empty", nameof(deviceKeyPair));

        // Create a deep copy of the key pair to prevent external modification
        _deviceKeyPair = new KeyPair(
            SecureMemory.SecureCopy(deviceKeyPair.PublicKey) ?? throw new ArgumentNullException(nameof(deviceKeyPair.PublicKey)),
            SecureMemory.SecureCopy(deviceKeyPair.PrivateKey) ?? throw new ArgumentNullException(nameof(deviceKeyPair.PrivateKey))
        );

        _deviceLinkingService = deviceLinkingService ?? throw new ArgumentNullException(nameof(deviceLinkingService));
        _cryptoProvider = cryptoProvider ?? throw new ArgumentNullException(nameof(cryptoProvider));
        _syncMessageValidator = syncMessageValidator ?? new SyncMessageValidator(cryptoProvider);
    }

    /// <inheritdoc/>
    public int GetLinkedDeviceCount()
    {
        ThrowIfDisposed();
        return _linkedDevices.Count;
    }

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
    public void AddLinkedDevice(byte[] devicePublicKey)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(devicePublicKey, nameof(devicePublicKey));

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

            // Set to null so we don't clear the normalized key as it's now stored in the dictionary
            normalizedKey = null;
        }
        finally
        {
            // Clear the normalized key if we didn't store it successfully
            if (normalizedKey != null)
            {
                SecureMemory.SecureClear(normalizedKey);
            }
        }
    }

    /// <inheritdoc/>
    public bool RemoveLinkedDevice(byte[] devicePublicKey)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(devicePublicKey, nameof(devicePublicKey));

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

            // Mark the device as revoked
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

    #region Private methods

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
            if (syncMessage.SenderPublicKey != null &&
                !_syncMessageValidator.ValidateSyncMessage(syncMessage, syncMessage.SenderPublicKey))
            {
                LoggingManager.LogWarning(nameof(DeviceManager),
                    "Sync message validation failed");
                return null;
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
    /// </summary>
    /// <param name="deviceKey">The device key to normalize</param>
    /// <returns>The normalized X25519 key, or null if invalid</returns>
    private byte[]? NormalizeDeviceKey(byte[] deviceKey)
    {
        try
        {
            // Handle X25519 format (common case)
            if (deviceKey.Length == Constants.X25519_KEY_SIZE)
            {
                // Validate X25519 public key
                if (!_cryptoProvider.ValidateX25519PublicKey(deviceKey))
                {
                    return null;
                }
                return (byte[])deviceKey.Clone();
            }
            // Handle Ed25519 format
            else if (deviceKey.Length == Constants.ED25519_PUBLIC_KEY_SIZE)
            {
                return _cryptoProvider.ConvertEd25519PublicKeyToX25519(deviceKey);
            }
            else
            {
                // Invalid key size
                return null;
            }
        }
        catch (Exception ex)
        {
            LoggingManager.LogWarning(nameof(DeviceManager),
                $"Error normalizing device key: {ex.Message}");
            return null;
        }
    }

    #endregion

    #region Dispose

    /// <summary>
    /// Throws an ObjectDisposedException if this object has been disposed.
    /// </summary>
    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(DeviceManager));
        }
    }

    /// <summary>
    /// Disposes of resources used by the DeviceManager.
    /// </summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Disposes of resources used by the DeviceManager.
    /// </summary>
    /// <param name="disposing">True if disposing, false if finalizing</param>
    protected virtual void Dispose(bool disposing)
    {
        if (_disposed) return;

        if (disposing)
        {
            // Dispose of managed resources
            _stateLock.Dispose();

            // Clear any sensitive data
            foreach (var device in _linkedDevices.Values)
            {
                if (device.PublicKey != null)
                {
                    SecureMemory.SecureClear(device.PublicKey);
                }
            }

            // Clear collections
            _linkedDevices.Clear();
            _processedRevocations.Clear();

            // Clear device key pair
            if (_deviceKeyPair.PublicKey != null)
                SecureMemory.SecureClear(_deviceKeyPair.PublicKey);
            if (_deviceKeyPair.PrivateKey != null)
                SecureMemory.SecureClear(_deviceKeyPair.PrivateKey);
        }

        _disposed = true;
    }

    #endregion
}