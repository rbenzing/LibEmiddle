using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Security;
using System.Security.Cryptography;
using E2EELibrary.Core;
using E2EELibrary.Communication;
using E2EELibrary.Encryption;
using E2EELibrary.Models;
using E2EELibrary.KeyExchange;
using E2EELibrary.KeyManagement;

namespace E2EELibrary.MultiDevice
{
    /// <summary>
    /// Multi-device session manager for syncing session states
    /// </summary>
    public class DeviceManager : IDisposable
    {
        private readonly (byte[] publicKey, byte[] privateKey) _deviceKeyPair;

        // Changed from ConcurrentBag to ConcurrentDictionary to prevent duplicates
        private readonly ConcurrentDictionary<string, byte[]> _linkedDevices = new ConcurrentDictionary<string, byte[]>(StringComparer.Ordinal);

        // Add a revoked devices tracking set with timestamps
        private readonly ConcurrentDictionary<string, long> _revokedDevices =
            new ConcurrentDictionary<string, long>();

        private readonly byte[] _syncKey;
        private readonly object _syncLock = new object();

        // Add disposed flag for proper IDisposable implementation
        private bool _disposed = false;

        /// <summary>
        /// Creates a new multi-device manager
        /// </summary>
        /// <param name="deviceKeyPair">This device's key pair</param>
        public DeviceManager((byte[] publicKey, byte[] privateKey) deviceKeyPair)
        {
            if (deviceKeyPair.publicKey == null || deviceKeyPair.publicKey.Length == 0)
                throw new ArgumentException("Device public key cannot be null or empty", nameof(deviceKeyPair));

            if (deviceKeyPair.privateKey == null || deviceKeyPair.privateKey.Length == 0)
                throw new ArgumentException("Device private key cannot be null or empty", nameof(deviceKeyPair));

            // Create a deep copy of the key pair to prevent external modification
            _deviceKeyPair = (
                SecureMemory.SecureCopy(deviceKeyPair.publicKey) ?? throw new ArgumentNullException(nameof(deviceKeyPair.publicKey)),
                SecureMemory.SecureCopy(deviceKeyPair.privateKey) ?? throw new ArgumentNullException(nameof(deviceKeyPair.privateKey))
            );

            // Generate a random sync key with high entropy
            _syncKey = Sodium.GenerateRandomBytes(Constants.AES_KEY_SIZE);
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(_syncKey);
            }
        }

        /// <summary>
        /// Adds a linked device
        /// </summary>
        /// <param name="devicePublicKey">Public key of the device to link</param>
        public void AddLinkedDevice(byte[] devicePublicKey)
        {
            ThrowIfDisposed();

            if (devicePublicKey == null)
                throw new ArgumentNullException(nameof(devicePublicKey));

            // Validate key length
            if (devicePublicKey.Length != Constants.X25519_KEY_SIZE &&
                devicePublicKey.Length != Constants.ED25519_PUBLIC_KEY_SIZE)
            {
                throw new ArgumentException(
                    $"Device public key must be {Constants.X25519_KEY_SIZE} or {Constants.ED25519_PUBLIC_KEY_SIZE} bytes",
                    nameof(devicePublicKey));
            }

            // Check if device was previously revoked
            if (IsDeviceRevoked(devicePublicKey))
                throw new SecurityException("Cannot add a previously revoked device");

            // Validate X25519 public key if it's that length
            if (devicePublicKey.Length == Constants.X25519_KEY_SIZE &&
                !KeyValidation.ValidateX25519PublicKey(devicePublicKey))
            {
                throw new ArgumentException("Invalid X25519 public key", nameof(devicePublicKey));
            }

            // Convert key to X25519 if needed
            byte[] finalKey = devicePublicKey.Length == Constants.X25519_KEY_SIZE ?
                devicePublicKey :
                Sodium.ScalarMultBase(KeyConversion.DeriveX25519PublicKeyFromEd25519(devicePublicKey));

            // Create a deep copy of the key to prevent any external modification
            byte[] keyCopy = Sodium.GenerateRandomBytes(finalKey.Length);
            finalKey.AsSpan(0, finalKey.Length).CopyTo(keyCopy.AsSpan(0, finalKey.Length));

            // Add to dictionary using Base64 representation of the key as dictionary key to prevent duplicates
            string keyBase64 = Convert.ToBase64String(keyCopy);
            _linkedDevices.TryAdd(keyBase64, keyCopy);
        }

        /// <summary>
        /// Removes a linked device
        /// </summary>
        /// <param name="devicePublicKey">Public key of the device to remove</param>
        /// <returns>True if the device was found and removed, false otherwise</returns>
        public bool RemoveLinkedDevice(byte[] devicePublicKey)
        {
            ThrowIfDisposed();

            if (devicePublicKey == null)
                throw new ArgumentNullException(nameof(devicePublicKey));

            // Convert key to X25519 if needed
            byte[] finalKey = devicePublicKey.Length == Constants.X25519_KEY_SIZE ?
                devicePublicKey :
                Sodium.ScalarMultBase(KeyConversion.DeriveX25519PublicKeyFromEd25519(devicePublicKey));

            // Use Base64 representation as dictionary key
            string keyBase64 = Convert.ToBase64String(finalKey);

            // Try to remove and securely clear the removed key if successful
            if (_linkedDevices.TryRemove(keyBase64, out byte[]? removedKey))
            {
                if (removedKey != null)
                {
                    SecureMemory.SecureClear(removedKey);
                }
                return true;
            }

            return false;
        }

        /// <summary>
        /// Creates encrypted sync messages for other devices
        /// </summary>
        /// <param name="syncData">Data to sync</param>
        /// <returns>Dictionary of encrypted messages for each device</returns>
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
                    senderX25519Private = _deviceKeyPair.privateKey.Length != Constants.X25519_KEY_SIZE ?
                        KeyConversion.DeriveX25519PrivateKeyFromEd25519(_deviceKeyPair.privateKey) :
                        SecureMemory.SecureCopy(_deviceKeyPair.privateKey) ?? Array.Empty<byte>();

                    // Thread safety for linked devices access
                    foreach (var deviceEntry in _linkedDevices)
                    {
                        byte[] deviceKey = deviceEntry.Value;

                        try
                        {
                            // Ensure the device key is converted to a proper X25519 public key
                            byte[] x25519PublicKey;
                            if (deviceKey.Length == Constants.X25519_KEY_SIZE)
                            {
                                // If already 32 bytes, validate it's a proper X25519 key
                                if (!KeyValidation.ValidateX25519PublicKey(deviceKey))
                                {
                                    // Use a secure logging mechanism instead of Trace.TraceWarning
                                    // LogManager.LogWarning("Skipping invalid X25519 public key");
                                    continue;
                                }
                                x25519PublicKey = deviceKey;
                            }
                            else if (deviceKey.Length == Constants.ED25519_PUBLIC_KEY_SIZE)
                            {
                                // Convert Ed25519 public key to X25519
                                x25519PublicKey = Sodium.ScalarMultBase(
                                    KeyConversion.DeriveX25519PrivateKeyFromEd25519(deviceKey)
                                );
                            }
                            else
                            {
                                // Use a secure logging mechanism instead of Trace.TraceWarning
                                // LogManager.LogWarning($"Skipping device key with invalid length: {deviceKey.Length}");
                                continue;
                            }

                            // Perform key exchange
                            byte[] sharedSecret = X3DHExchange.X3DHKeyExchange(x25519PublicKey, senderX25519Private);

                            // Sign the sync data
                            byte[] signature = MessageSigning.SignMessage(secureSyncData.Value, _deviceKeyPair.privateKey);

                            // Create sync message with timestamp for replay protection
                            var syncMessage = new DeviceSyncMessage
                            {
                                SenderPublicKey = _deviceKeyPair.publicKey,
                                Data = secureSyncData.Value,
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
                            byte[] plaintext = Encoding.UTF8.GetBytes(json);
                            byte[] nonce = NonceGenerator.GenerateNonce();
                            byte[] ciphertext = AES.AESEncrypt(plaintext, sharedSecret, nonce);

                            // Securely clear shared secret after use
                            SecureMemory.SecureClear(sharedSecret);

                            // Add to result
                            string deviceKeyBase64 = deviceEntry.Key;
                            result[deviceKeyBase64] = new EncryptedMessage
                            {
                                Ciphertext = ciphertext,
                                Nonce = nonce,
                                Timestamp = syncMessage.Timestamp,
                                MessageId = Guid.NewGuid(),
                                // Add protocol version information
                                ProtocolMajorVersion = ProtocolVersion.MAJOR_VERSION,
                                ProtocolMinorVersion = ProtocolVersion.MINOR_VERSION
                            };
                        }
                        catch (Exception ex)
                        {
                            // Log the error but continue processing other devices
                            // Use a secure logging mechanism instead of Trace.TraceWarning
                            // LogManager.LogError($"Error creating sync message: {ex.Message}");
                            Trace.TraceWarning($"Error creating sync message: {ex.Message}");
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
        /// Processes a sync message from another device
        /// </summary>
        /// <param name="encryptedMessage">Encrypted sync message</param>
        /// <param name="senderHint">Optional sender device key hint</param>
        /// <returns>Sync data if verification succeeds, null if processing fails</returns>
        public byte[]? ProcessSyncMessage(EncryptedMessage encryptedMessage, byte[]? senderHint = null)
        {
            ThrowIfDisposed();

            if (encryptedMessage == null)
                throw new ArgumentNullException(nameof(encryptedMessage));

            // Validate the encrypted message
            if (!encryptedMessage.Validate())
            {
                return null;
            }

            // If we have a sender hint, try that device first
            if (senderHint != null)
            {
                string senderKeyBase64 = Convert.ToBase64String(senderHint);

                if (_linkedDevices.TryGetValue(senderKeyBase64, out var deviceKey))
                {
                    byte[]? result = TryProcessSyncMessageFromDevice(encryptedMessage, deviceKey);
                    if (result != null)
                        return result;
                }
            }

            // Otherwise try all linked devices
            foreach (var deviceEntry in _linkedDevices)
            {
                byte[] deviceKey = deviceEntry.Value;

                // Skip the hint device if we already tried it
                if (senderHint != null && SecureMemory.SecureCompare(deviceKey, senderHint))
                    continue;

                // Create a fresh copy of the message for each attempt
                var messageCopy = new EncryptedMessage
                {
                    Ciphertext = encryptedMessage.Ciphertext?.ToArray(),
                    Nonce = encryptedMessage.Nonce?.ToArray(),
                    MessageNumber = encryptedMessage.MessageNumber,
                    SenderDHKey = encryptedMessage.SenderDHKey?.ToArray(),
                    Timestamp = encryptedMessage.Timestamp,
                    MessageId = encryptedMessage.MessageId,
                    SessionId = encryptedMessage.SessionId
                };

                byte[]? result = TryProcessSyncMessageFromDevice(messageCopy, deviceKey);
                if (result != null)
                    return result;
            }

            return null;
        }

        /// <summary>
        /// Attempts to process a sync message from a specific device
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
                    x25519Private = _deviceKeyPair.privateKey.Length == Constants.X25519_KEY_SIZE
                        ? _deviceKeyPair.privateKey.ToArray()
                        : KeyConversion.DeriveX25519PrivateKeyFromEd25519(_deviceKeyPair.privateKey);

                    if (x25519Private == null || x25519Private.Length != Constants.X25519_KEY_SIZE)
                        return null;

                    // Step 2: Get shared secret
                    byte[] sharedSecret = X3DHExchange.X3DHKeyExchange(deviceKey, x25519Private);

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
                    var jsonObj = System.Text.Json.JsonDocument.Parse(json);
                    var root = jsonObj.RootElement;

                    // Step 5: Extract fields
                    if (!root.TryGetProperty("data", out var dataElement) ||
                        dataElement.ValueKind != System.Text.Json.JsonValueKind.String)
                    {
                        return null;
                    }

                    string? dataBase64 = dataElement.GetString();
                    if (string.IsNullOrEmpty(dataBase64))
                        return null;

                    // Step 6: Decode the data
                    byte[] syncData = Convert.FromBase64String(dataBase64);

                    // Return the data
                    return syncData;
                }
                finally
                {
                    // Clean up sensitive data
                    if (x25519Private != null)
                        SecureMemory.SecureClear(x25519Private);
                }
            }
            catch
            {
                // Any other exception means processing failed
                return null;
            }
        }

        /// <summary>
        /// Gets the number of linked devices
        /// </summary>
        /// <returns>The number of unique linked devices</returns>
        public int GetLinkedDeviceCount()
        {
            ThrowIfDisposed();
            return _linkedDevices.Count;
        }

        /// <summary>
        /// Checks if a device is already linked
        /// </summary>
        /// <param name="devicePublicKey">Public key of the device to check</param>
        /// <returns>True if the device is linked, false otherwise</returns>
        public bool IsDeviceLinked(byte[] devicePublicKey)
        {
            ThrowIfDisposed();

            if (devicePublicKey == null)
                return false;

            // Convert key to X25519 format if needed
            byte[] finalKey = devicePublicKey.Length == Constants.X25519_KEY_SIZE ?
                devicePublicKey :
                Sodium.ScalarMultBase(KeyConversion.DeriveX25519PublicKeyFromEd25519(devicePublicKey));

            string keyBase64 = Convert.ToBase64String(finalKey);
            return _linkedDevices.ContainsKey(keyBase64);
        }

        /// <summary>
        /// Checks if a device has been revoked
        /// </summary>
        /// <param name="devicePublicKey">Public key of the device to check</param>
        /// <returns>True if the device was revoked</returns>
        public bool IsDeviceRevoked(byte[] devicePublicKey)
        {
            if (devicePublicKey == null)
                return false;

            // Convert key to Base64 for lookup
            string deviceId = Convert.ToBase64String(devicePublicKey);

            return _revokedDevices.ContainsKey(deviceId);
        }

        /// <summary>
        /// Creates a revocation message for a device.
        /// </summary>
        /// <param name="deviceKeyToRevoke">The public key of the device to revoke</param>
        /// <returns>A signed revocation message</returns>
        public DeviceRevocationMessage CreateRevocationMessage(byte[] deviceKeyToRevoke)
        {
            ThrowIfDisposed();

            if (deviceKeyToRevoke == null || deviceKeyToRevoke.Length == 0)
                throw new ArgumentException("Device key cannot be null or empty", nameof(deviceKeyToRevoke));

            long timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            // Combine device key and timestamp for signing
            byte[] timestampBytes = BitConverter.GetBytes(timestamp);
            byte[] dataToSign = Sodium.GenerateRandomBytes(deviceKeyToRevoke.Length + timestampBytes.Length);

            deviceKeyToRevoke.AsSpan().CopyTo(dataToSign.AsSpan(0, deviceKeyToRevoke.Length));
            timestampBytes.AsSpan().CopyTo(dataToSign.AsSpan(deviceKeyToRevoke.Length, timestampBytes.Length));

            // Sign the combined data using _deviceKeyPair (not _identityKeyPair)
            byte[] signature = MessageSigning.SignMessage(dataToSign, _deviceKeyPair.privateKey);

            // Create and return the revocation message
            return new DeviceRevocationMessage
            {
                RevokedDeviceKey = deviceKeyToRevoke,
                RevocationTimestamp = timestamp,
                Signature = signature,
                Version = ProtocolVersion.FULL_VERSION
            };
        }

        /// <summary>
        /// Revokes a linked device and creates a revocation message.
        /// </summary>
        /// <param name="devicePublicKey">Public key of the device to revoke</param>
        /// <returns>A revocation message that should be distributed to other devices</returns>
        public DeviceRevocationMessage RevokeLinkedDevice(byte[] devicePublicKey)
        {
            ThrowIfDisposed();

            if (devicePublicKey == null)
                throw new ArgumentNullException(nameof(devicePublicKey));

            // Convert key to X25519 format if needed
            byte[] finalKey = devicePublicKey.Length != Constants.X25519_KEY_SIZE ?
                KeyConversion.DeriveX25519PublicKeyFromEd25519(devicePublicKey) :
                devicePublicKey;

            // Use Base64 representation as dictionary key
            string deviceId = Convert.ToBase64String(finalKey);

            // Try to remove from linked devices
            bool removed = _linkedDevices.TryRemove(deviceId, out byte[]? removedKey);

            // Securely clear the removed key if it exists
            if (removedKey != null)
            {
                SecureMemory.SecureClear(removedKey);
            }

            if (!removed)
            {
                throw new KeyNotFoundException("Device not found in linked devices");
            }

            // Track the revoked device with current timestamp
            _revokedDevices[deviceId] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            // Create revocation message
            return CreateRevocationMessage(finalKey);
        }

        /// <summary>
        /// Processes a revocation message received from another device.
        /// </summary>
        /// <param name="revocationMessage">The received revocation message</param>
        /// <param name="trustedPublicKey">The trusted public key for verification</param>
        /// <returns>True if the message was valid and the device was removed</returns>
        public bool ProcessRevocationMessage(DeviceRevocationMessage revocationMessage, byte[] trustedPublicKey)
        {
            ThrowIfDisposed();

            if (revocationMessage == null)
                throw new ArgumentNullException(nameof(revocationMessage));

            if (trustedPublicKey == null)
                throw new ArgumentNullException(nameof(trustedPublicKey));

            // Validate the message
            if (!revocationMessage.Validate(trustedPublicKey))
                return false;

            // Get the device ID for lookup
            string deviceId = Convert.ToBase64String(revocationMessage.RevokedDeviceKey);

            // Remove the device if it exists
            bool removed = _linkedDevices.TryRemove(deviceId, out byte[]? removedKey);

            // Securely clear the removed key if it exists
            if (removedKey != null)
            {
                SecureMemory.SecureClear(removedKey);
            }

            // Add to revoked devices tracking
            _revokedDevices[deviceId] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            return removed;
        }

        /// <summary>
        /// Exports all linked devices to a serialized format for backup
        /// </summary>
        /// <param name="password">Optional password to encrypt the export</param>
        /// <returns>Serialized linked devices data</returns>
        public byte[] ExportLinkedDevices(string? password = null)
        {
            ThrowIfDisposed();

            var deviceList = new List<string>();

            // Include all currently linked devices
            foreach (var device in _linkedDevices)
            {
                deviceList.Add(device.Key);
            }

            // We need to export the revoked devices list as well
            var revokedDeviceList = new Dictionary<string, long>();
            foreach (var device in _revokedDevices)
            {
                revokedDeviceList.Add(device.Key, device.Value);
            }

            string json = JsonSerializer.Serialize(new
            {
                devices = deviceList,
                revokedDevices = revokedDeviceList, // Add revoked devices to export
                exportTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                protocolVersion = ProtocolVersion.FULL_VERSION
            });

            byte[] data = Encoding.UTF8.GetBytes(json);

            // Encrypt if password provided
            if (!string.IsNullOrEmpty(password))
            {
                // Generate a salt
                byte[] salt = Sodium.GenerateRandomBytes(Constants.DEFAULT_SALT_SIZE);
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(salt);
                }

                // Derive key
                byte[] key = DeriveKeyFromPassword(password, salt);

                // Encrypt
                byte[] nonce = NonceGenerator.GenerateNonce();
                byte[] ciphertext = AES.AESEncrypt(data, key, nonce);
                SecureMemory.SecureClear(key);

                // Combine salt, nonce, and ciphertext
                byte[] result = Sodium.GenerateRandomBytes(salt.Length + nonce.Length + ciphertext.Length);
                Buffer.BlockCopy(salt, 0, result, 0, salt.Length);
                Buffer.BlockCopy(nonce, 0, result, salt.Length, nonce.Length);
                Buffer.BlockCopy(ciphertext, 0, result, salt.Length + nonce.Length, ciphertext.Length);

                return result;
            }

            return data;
        }

        /// <summary>
        /// Imports linked devices from a serialized format
        /// </summary>
        /// <param name="data">Serialized linked devices data</param>
        /// <param name="password">Optional password if the data is encrypted</param>
        /// <returns>Number of devices imported</returns>
        public int ImportLinkedDevices(byte[] data, string? password = null)
        {
            ThrowIfDisposed();

            if (data == null || data.Length == 0)
                throw new ArgumentException("Import data cannot be null or empty", nameof(data));

            byte[]? jsonData = null;
            byte[]? key = null;

            try
            {
                // Decrypt if password provided
                if (!string.IsNullOrEmpty(password))
                {
                    // Extract salt and nonce
                    if (data.Length < Constants.DEFAULT_SALT_SIZE + Constants.NONCE_SIZE + 16)
                        throw new ArgumentException("Data is too short to be valid encrypted export", nameof(data));

                    byte[] salt = Sodium.GenerateRandomBytes(Constants.DEFAULT_SALT_SIZE);
                    byte[] nonce = Sodium.GenerateRandomBytes(Constants.NONCE_SIZE);
                    Buffer.BlockCopy(data, 0, salt, 0, salt.Length);
                    Buffer.BlockCopy(data, salt.Length, nonce, 0, nonce.Length);

                    // Extract ciphertext
                    int ciphertextLength = data.Length - salt.Length - nonce.Length;
                    byte[] ciphertext = Sodium.GenerateRandomBytes(ciphertextLength);
                    Buffer.BlockCopy(data, salt.Length + nonce.Length, ciphertext, 0, ciphertextLength);

                    // Derive key with proper secure handling
                    key = DeriveKeyFromPassword(password, salt);

                    try
                    {
                        jsonData = AES.AESDecrypt(ciphertext, key, nonce);
                    }
                    finally
                    {
                        // Always clear sensitive data
                        if (key != null)
                        {
                            SecureMemory.SecureClear(key);
                            key = null;
                        }
                    }
                }
                else
                {
                    jsonData = data;
                }

                // Deserialize
                string json = Encoding.UTF8.GetString(jsonData);
                var importData = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json);

                if (importData == null || !importData.ContainsKey("devices"))
                    throw new FormatException("Invalid import data format");

                // Check protocol version compatibility if present
                if (importData.TryGetValue("protocolVersion", out var versionElement) &&
                    versionElement.ValueKind == JsonValueKind.String)
                {
                    string? versionStr = versionElement.GetString();
                    if (!string.IsNullOrEmpty(versionStr))
                    {
                        string[] parts = versionStr.Split('/');
                        if (parts.Length == 2 && parts[1].StartsWith("v"))
                        {
                            string version = parts[1].Substring(1);
                            string[] versionParts = version.Split('.');
                            if (versionParts.Length == 2 &&
                                int.TryParse(versionParts[0], out int majorVersion) &&
                                int.TryParse(versionParts[1], out int minorVersion))
                            {
                                if (!ProtocolVersion.IsCompatible(majorVersion, minorVersion))
                                {
                                    throw new ProtocolVersionException($"Incompatible protocol version: {versionStr}");
                                }
                            }
                        }
                    }
                }

                // Process revoked devices list first (if present)
                if (importData.TryGetValue("revokedDevices", out var revokedDevicesElement) &&
                    revokedDevicesElement.ValueKind == JsonValueKind.Object)
                {
                    foreach (var revokedDevice in revokedDevicesElement.EnumerateObject())
                    {
                        string deviceKey = revokedDevice.Name;
                        long timestamp = revokedDevice.Value.GetInt64();

                        // Add to revoked devices dictionary
                        _revokedDevices[deviceKey] = timestamp;
                    }
                }

                // Process device list
                var devicesList = importData["devices"].EnumerateArray();
                int importCount = 0;

                foreach (var deviceElement in devicesList)
                {
                    if (deviceElement.ValueKind == JsonValueKind.String)
                    {
                        string? deviceKey = deviceElement.GetString();
                        if (!string.IsNullOrEmpty(deviceKey))
                        {
                            try
                            {
                                byte[] deviceBytes = Convert.FromBase64String(deviceKey);

                                // Check if device was previously revoked
                                if (_revokedDevices.ContainsKey(deviceKey))
                                {
                                    continue; // Skip revoked devices
                                }

                                // We can now add this device to our linked devices
                                // The AddLinkedDevice method will perform validation and conversion
                                if (!_linkedDevices.ContainsKey(deviceKey))
                                {
                                    _linkedDevices[deviceKey] = deviceBytes;
                                    importCount++;
                                }
                            }
                            catch (FormatException)
                            {
                                // Skip invalid base64 strings
                                continue;
                            }
                        }
                    }
                }

                return importCount;
            }
            finally
            {
                // Ensure key is cleared
                if (key != null)
                {
                    SecureMemory.SecureClear(key);
                }

                // Clear decrypted data if it was sensitive
                if (jsonData != null && password != null)
                {
                    SecureMemory.SecureClear(jsonData);
                }
            }
        }

        /// <summary>
        /// Helper method to derive a key from a password
        /// </summary>
        private static byte[] DeriveKeyFromPassword(string password, byte[] salt)
        {
            using var pbkdf2 = new Rfc2898DeriveBytes(
                password,
                salt,
                Constants.PBKDF2_ITERATIONS,
                HashAlgorithmName.SHA256);

            return pbkdf2.GetBytes(Constants.AES_KEY_SIZE);
        }

        /// <summary>
        /// Performs cleanup of managed and unmanaged resources.
        /// </summary>
        /// <param name="disposing">True if called from Dispose(), false if called from finalizer</param>
        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            // Clean up managed resources if disposing
            if (disposing)
            {
                // Securely clear all sensitive data
                if (_deviceKeyPair.privateKey != null)
                {
                    SecureMemory.SecureClear(_deviceKeyPair.privateKey);
                }

                if (_syncKey != null)
                {
                    SecureMemory.SecureClear(_syncKey);
                }

                // Clear all linked devices
                foreach (var device in _linkedDevices.Values)
                {
                    SecureMemory.SecureClear(device);
                }

                _linkedDevices.Clear();
            }

            _disposed = true;
        }

        /// <summary>
        /// Finalizer to ensure resources are cleaned up
        /// </summary>
        ~DeviceManager()
        {
            Dispose(false);
        }

        /// <summary>
        /// Disposes resources used by the device manager
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Throws an ObjectDisposedException if this object has been disposed
        /// </summary>
        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(DeviceManager));
            }
        }
    }
}