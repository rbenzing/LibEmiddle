using System.Collections.Concurrent;
using System.Security;
using System.Text;
using System.Text.Json;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.Abstractions;

namespace LibEmiddle.MultiDevice
{
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
    public class DeviceManager : IDisposable
    {
        private readonly KeyPair _deviceKeyPair;
        private readonly IDeviceLinkingService _deviceLinkingService;
        private readonly ICryptoProvider _cryptoProvider;

        // Device storage with thread-safe dictionaries
        private readonly ConcurrentDictionary<string, DeviceInfo> _linkedDevices =
            new ConcurrentDictionary<string, DeviceInfo>(StringComparer.Ordinal);

        // Store revocation messages we've processed for replay protection
        private readonly ConcurrentDictionary<string, DeviceRevocationMessage> _processedRevocations =
            new ConcurrentDictionary<string, DeviceRevocationMessage>();

        // Store revoked devices with their revocation timestamp
        private readonly ConcurrentDictionary<string, long> _revokedDevices =
            new ConcurrentDictionary<string, long>();

        // Use a separate sync lock for import/export operations
        private readonly SemaphoreSlim _stateLock = new SemaphoreSlim(1, 1);

        // Track if we're disposed
        private bool _disposed = false;

        /// <summary>
        /// Creates a new multi-device manager with the specified identity key pair.
        /// </summary>
        /// <param name="deviceKeyPair">This device's Ed25519 identity key pair</param>
        /// <param name="cryptoProvider">Optional cryptographic provider implementation</param>
        /// <param name="deviceLinkingService">Optional device linking service implementation</param>
        public DeviceManager(
            KeyPair deviceKeyPair,
            ICryptoProvider? cryptoProvider = null,
            IDeviceLinkingService? deviceLinkingService = null)
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

            // Initialize dependencies (with default implementations if not provided)
            _cryptoProvider = cryptoProvider ?? new CryptoProvider();
            _deviceLinkingService = deviceLinkingService ?? new DeviceLinkingService(_cryptoProvider);
        }

        /// <summary>
        /// Gets the number of linked devices registered with this device manager.
        /// </summary>
        /// <returns>The count of unique linked devices</returns>
        public int GetLinkedDeviceCount()
        {
            ThrowIfDisposed();
            return _linkedDevices.Count;
        }

        /// <summary>
        /// Creates a device link message for establishing multi-device sync with a new device.
        /// 
        /// <para>
        /// This method creates a secure message that can be transmitted to a new device to establish
        /// a trusted relationship between the current device and the new device. The message includes
        /// the necessary cryptographic material to verify identity and establish a secure channel.
        /// </para>
        /// </summary>
        /// <param name="newDevicePublicKey">The public key of the new device to link</param>
        /// <returns>An encrypted message containing linking information</returns>
        /// <exception cref="ArgumentNullException">Thrown if newDevicePublicKey is null</exception>
        /// <exception cref="ArgumentException">Thrown if newDevicePublicKey is invalid</exception>
        /// <exception cref="SecurityException">Thrown if trying to link a revoked device</exception>
        public EncryptedMessage CreateDeviceLinkMessage(byte[] newDevicePublicKey)
        {
            ThrowIfDisposed();

            if (newDevicePublicKey == null)
                throw new ArgumentNullException(nameof(newDevicePublicKey));

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

        /// <summary>
        /// Processes a device link message received from another device.
        /// 
        /// <para>
        /// Verifies and processes a device link message received from another device (typically the main
        /// device sending a link to this device). If the message is valid and properly signed, it establishes
        /// a trusted link with the sending device.
        /// </para>
        /// </summary>
        /// <param name="encryptedMessage">The device link message to process</param>
        /// <param name="expectedMainDevicePublicKey">The expected public key of the main device</param>
        /// <returns>True if the linking was successful, false otherwise</returns>
        /// <exception cref="ArgumentNullException">Thrown if parameters are null</exception>
        /// <exception cref="SecurityException">Thrown if trying to link a revoked device</exception>
        public bool ProcessDeviceLinkMessage(
            EncryptedMessage encryptedMessage,
            byte[] expectedMainDevicePublicKey)
        {
            ThrowIfDisposed();

            if (encryptedMessage == null)
                throw new ArgumentNullException(nameof(encryptedMessage));

            if (expectedMainDevicePublicKey == null)
                throw new ArgumentNullException(nameof(expectedMainDevicePublicKey));

            // Check if device was previously revoked
            if (IsDeviceRevoked(expectedMainDevicePublicKey))
            {
                LoggingManager.LogWarning(nameof(DeviceManager),
                    "Cannot process link message from a revoked device");
                return false;
            }

            try
            {
                // Process the device link message
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

        /// <summary>
        /// Adds a linked device to the device manager.
        /// 
        /// <para>
        /// Records a new device as being linked to this device for synchronization purposes.
        /// The device key is normalized to ensure consistent lookup regardless of the key format.
        /// </para>
        /// </summary>
        /// <param name="devicePublicKey">Public key of the device to link</param>
        /// <exception cref="ArgumentNullException">Thrown if devicePublicKey is null</exception>
        /// <exception cref="ArgumentException">Thrown if devicePublicKey has invalid format</exception>
        /// <exception cref="SecurityException">Thrown if trying to add a revoked device</exception>
        public void AddLinkedDevice(byte[] devicePublicKey)
        {
            ThrowIfDisposed();

            if (devicePublicKey == null)
                throw new ArgumentNullException(nameof(devicePublicKey));

            // Check if device was previously revoked
            if (IsDeviceRevoked(devicePublicKey))
                throw new SecurityException("Cannot add a previously revoked device");

            byte[]? normalizedKey = null;
            try
            {
                // Handle X25519 format (common case)
                if (devicePublicKey.Length == Constants.X25519_KEY_SIZE)
                {
                    // Validate X25519 public key
                    if (!_cryptoProvider.ValidateX25519PublicKey(devicePublicKey))
                    {
                        throw new ArgumentException("Invalid X25519 public key", nameof(devicePublicKey));
                    }
                    normalizedKey = (byte[])devicePublicKey.Clone();
                }
                // Handle Ed25519 format
                else if (devicePublicKey.Length == Constants.ED25519_PUBLIC_KEY_SIZE)
                {
                    normalizedKey = _cryptoProvider.ConvertEd25519PublicKeyToX25519(devicePublicKey);
                }
                else
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

        /// <summary>
        /// Removes a linked device from the device manager.
        /// 
        /// <para>
        /// Removes a device from the list of linked devices. This does not revoke the device,
        /// it simply removes it from the local list of linked devices.
        /// </para>
        /// </summary>
        /// <param name="devicePublicKey">Public key of the device to remove</param>
        /// <returns>True if the device was found and removed, false otherwise</returns>
        /// <exception cref="ArgumentNullException">Thrown if devicePublicKey is null</exception>
        public bool RemoveLinkedDevice(byte[] devicePublicKey)
        {
            ThrowIfDisposed();

            if (devicePublicKey == null)
                throw new ArgumentNullException(nameof(devicePublicKey));

            byte[]? normalizedKey = null;
            try
            {
                // Handle X25519 format (common case)
                if (devicePublicKey.Length == Constants.X25519_KEY_SIZE)
                {
                    normalizedKey = (byte[])devicePublicKey.Clone();
                }
                // Handle Ed25519 format
                else if (devicePublicKey.Length == Constants.ED25519_PUBLIC_KEY_SIZE)
                {
                    normalizedKey = _cryptoProvider.ConvertEd25519PublicKeyToX25519(devicePublicKey);
                }
                else
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
                    if (deviceInfo != null && deviceInfo.PublicKey != null)
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

        /// <summary>
        /// Checks if a device is already linked to this device.
        /// </summary>
        /// <param name="devicePublicKey">Public key of the device to check</param>
        /// <returns>True if the device is linked, false otherwise</returns>
        public bool IsDeviceLinked(ReadOnlySpan<byte> devicePublicKey)
        {
            ThrowIfDisposed();

            if (devicePublicKey.IsEmpty)
                return false;

            byte[]? normalizedKey = null;
            try
            {
                // Handle X25519 format (common case)
                if (devicePublicKey.Length == Constants.X25519_KEY_SIZE)
                {
                    normalizedKey = devicePublicKey.ToArray();
                }
                // Handle Ed25519 format
                else if (devicePublicKey.Length == Constants.ED25519_PUBLIC_KEY_SIZE)
                {
                    normalizedKey = _cryptoProvider.ConvertEd25519PublicKeyToX25519(devicePublicKey.ToArray());
                }
                else
                {
                    return false; // Invalid key length
                }

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

        /// <summary>
        /// Creates encrypted sync messages for all linked devices.
        /// 
        /// <para>
        /// Encrypts the provided data uniquely for each linked device, enabling secure
        /// synchronization of data across all devices linked to this user's identity.
        /// </para>
        /// </summary>
        /// <param name="syncData">Data to synchronize with other devices</param>
        /// <returns>Dictionary mapping device identifiers to encrypted messages</returns>
        /// <exception cref="ArgumentNullException">Thrown if syncData is null</exception>
        public Dictionary<string, EncryptedMessage> CreateSyncMessages(byte[] syncData)
        {
            ThrowIfDisposed();

            if (syncData == null)
                throw new ArgumentNullException(nameof(syncData));

            var result = new Dictionary<string, EncryptedMessage>();

            // Basic sanity check
            if (_linkedDevices.Count == 0)
                return result;

            // Make a secure copy of the sync data to avoid external modification during processing
            using (var secureSyncData = new SecureMemory.SecureArray<byte>(syncData))
            {
                // Prepare the sender's private key in X25519 format
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
            }

            return result;
        }

        /// <summary>
        /// Creates a revocation message for a device.
        /// </summary>
        /// <param name="devicePublicKey">Public key of the device to revoke</param>
        /// <param name="reason">Optional reason for revocation</param>
        /// <returns>A signed revocation message</returns>
        /// <exception cref="ArgumentNullException">If devicePublicKey is null</exception>
        /// <exception cref="InvalidOperationException">If attempting to revoke self</exception>
        /// <exception cref="ArgumentException">If devicePublicKey has invalid format</exception>
        public DeviceRevocationMessage CreateDeviceRevocationMessage(byte[] devicePublicKey, string? reason = null)
        {
            ThrowIfDisposed();

            ArgumentNullException.ThrowIfNull(devicePublicKey, nameof(devicePublicKey));

            // Prevent revoking our own device
            if (devicePublicKey.Length == _deviceKeyPair.PublicKey.Length &&
                SecureMemory.SecureCompare(devicePublicKey, _deviceKeyPair.PublicKey))
            {
                throw new InvalidOperationException("Cannot revoke your own device");
            }

            // Create the revocation message
            try
            {
                var revocationMessage = _deviceLinkingService.CreateDeviceRevocationMessage(
                    _deviceKeyPair, devicePublicKey, reason);

                // Record the revocation locally
                ProcessDeviceRevocationMessage(revocationMessage);

                return revocationMessage;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(DeviceManager),
                    $"Failed to create device revocation message: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Processes a device revocation message, marking the device as revoked if validated.
        /// </summary>
        /// <param name="revocationMessage">The revocation message to process</param>
        /// <returns>True if the revocation message was valid and processed</returns>
        /// <exception cref="ArgumentNullException">Thrown if revocationMessage is null</exception>
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

                // First verify the revocation with our identity key as the trusted key
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

        /// <summary>
        /// Checks if a device has been revoked.
        /// </summary>
        /// <param name="devicePublicKey">Public key of the device to check</param>
        /// <returns>True if the device was revoked</returns>
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

        /// <summary>
        /// Gets a list of all revoked device public keys.
        /// </summary>
        /// <returns>A list of revoked device public keys (in normalized X25519 format)</returns>
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

        /// <summary>
        /// Exports the device revocations for persistence.
        /// </summary>
        /// <returns>Serialized representation of all processed revocations</returns>
        public string ExportRevocations()
        {
            ThrowIfDisposed();

            var revocations = _processedRevocations.Values.ToList();
            return JsonSerialization.Serialize(revocations);
        }

        /// <summary>
        /// Imports device revocations from a serialized representation.
        /// </summary>
        /// <param name="serializedRevocations">The serialized revocations</param>
        /// <returns>The number of imported revocations</returns>
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

        /// <summary>
        /// Creates a sync message for a specific device.
        /// </summary>
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
                    // Add protocol version information
                    Version = ProtocolVersion.FULL_VERSION
                };

                // Serialize with protocol version
                string json = System.Text.Json.JsonSerializer.Serialize(new
                {
                    senderPublicKey = Convert.ToBase64String(syncMessage.SenderPublicKey ?? Array.Empty<byte>()),
                    data = Convert.ToBase64String(syncMessage.Data ?? Array.Empty<byte>()),
                    signature = Convert.ToBase64String(syncMessage.Signature ?? Array.Empty<byte>()),
                    timestamp = syncMessage.Timestamp,
                    protocolVersion = syncMessage.Version
                });

                // Encrypt
                byte[] plaintext = Encoding.Default.GetBytes(json);
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
        /// Processes a sync message received from another device.
        /// 
        /// <para>
        /// Attempts to decrypt and validate a sync message, extracting the synchronized data
        /// if the message is valid and from a trusted linked device.
        /// </para>
        /// </summary>
        /// <param name="encryptedMessage">Encrypted sync message to process</param>
        /// <param name="senderHint">Optional hint about which device sent the message</param>
        /// <returns>The synchronized data if successful, null otherwise</returns>
        /// <exception cref="ArgumentNullException">Thrown if encryptedMessage is null</exception>
        public byte[]? ProcessSyncMessage(EncryptedMessage encryptedMessage, byte[]? senderHint = null)
        {
            ThrowIfDisposed();

            if (encryptedMessage == null)
                throw new ArgumentNullException(nameof(encryptedMessage));

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

        /// <summary>
        /// Attempts to process a sync message from a specific device.
        /// </summary>
        private byte[]? TryProcessSyncMessageFromDevice(EncryptedMessage encryptedMessage, byte[] deviceKey)
        {
            // Basic null checks
            if (encryptedMessage?.Ciphertext == null || encryptedMessage.Nonce == null)
                return null;

            try
            {
                // Step 1: Prepare keys
                byte[]? x25519Private = null;
                try
                {
                    // Prepare receiver's private key (this device)
                    x25519Private = _cryptoProvider.ConvertEd25519PrivateKeyToX25519(_deviceKeyPair.PrivateKey);

                    if (x25519Private == null || x25519Private.Length != Constants.X25519_KEY_SIZE)
                        return null;

                    // Step 2: Get shared secret
                    byte[] sharedSecret = _cryptoProvider.ScalarMult(x25519Private, deviceKey);
                    try
                    {
                        // Step 3: Decrypt message
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

                        // Step 4: Parse JSON
                        string json = Encoding.UTF8.GetString(plaintext);
                        var jsonObj = JsonDocument.Parse(json);
                        var root = jsonObj.RootElement;

                        // Step 5: Extract fields
                        if (!root.TryGetProperty("data", out var dataElement) ||
                            dataElement.ValueKind != JsonValueKind.String)
                        {
                            return null;
                        }

                        string? dataBase64 = dataElement.GetString();
                        if (string.IsNullOrEmpty(dataBase64))
                            return null;

                        // Step 6: Decode the data
                        byte[] syncData = Convert.FromBase64String(dataBase64);

                        // Step 7: Verify the signature if present
                        if (root.TryGetProperty("signature", out var signatureElement) &&
                            root.TryGetProperty("senderPublicKey", out var senderElement) &&
                            signatureElement.ValueKind == JsonValueKind.String &&
                            senderElement.ValueKind == JsonValueKind.String)
                        {
                            string? signatureBase64 = signatureElement.GetString();
                            string? senderBase64 = senderElement.GetString();

                            if (!string.IsNullOrEmpty(signatureBase64) && !string.IsNullOrEmpty(senderBase64))
                            {
                                byte[] signature = Convert.FromBase64String(signatureBase64);
                                byte[] senderPublicKey = Convert.FromBase64String(senderBase64);

                                // Verify the signature
                                if (!_cryptoProvider.VerifySignature(syncData, signature, senderPublicKey))
                                {
                                    LoggingManager.LogWarning(nameof(DeviceManager),
                                        "Sync message signature verification failed");
                                    return null;
                                }
                            }
                        }

                        return syncData;
                    }
                    finally
                    {
                        // Clear sensitive data
                        if (sharedSecret != null)
                            SecureMemory.SecureClear(sharedSecret);
                    }
                }
                finally
                {
                    // Clean up sensitive data
                    if (x25519Private != null)
                        SecureMemory.SecureClear(x25519Private);
                }
            }
            catch (Exception ex)
            {
                LoggingManager.LogWarning(nameof(DeviceManager),
                    $"Error processing sync message: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Exports linked devices to a serialized representation for persistence.
        /// </summary>
        /// <returns>A JSON serialized representation of linked devices.</returns>
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

        /// <summary>
        /// Imports linked devices from a serialized representation.
        /// </summary>
        /// <param name="serializedDevices">The serialized devices data.</param>
        /// <returns>The number of imported devices.</returns>
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

        /// <summary>
        /// Checks if two device keys represent the same device.
        /// </summary>
        private bool IsSameDeviceKey(byte[] key1, byte[] key2)
        {
            if (key1 == null || key2 == null || key1.Length != key2.Length)
                return false;

            return SecureMemory.SecureCompare(key1, key2);
        }

        /// <summary>
        /// Validates that an encrypted message has the required fields.
        /// </summary>
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

        /// <summary> Cleans up resources. </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary> Cleans up resources. </summary>
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

                // Clear revocations 
                _processedRevocations.Clear();
            }

            _disposed = true;
        }
    }

    /// <summary>
    /// Stores information about a linked device.
    /// </summary>
    internal class DeviceInfo
    {
        /// <summary>
        /// The device's public key (X25519 format).
        /// </summary>
        public byte[] PublicKey { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// When the device was linked (milliseconds since epoch).
        /// </summary>
        public long LinkedAt { get; set; }
    }
}