using System.Collections.Concurrent;
using System.Security;
using System.Text;
using System.Security.Cryptography;
using Sodium;
using E2EELibrary.Core;
using E2EELibrary.Communication;
using E2EELibrary.Encryption;
using E2EELibrary.Models;
using E2EELibrary.KeyExchange;
using E2EELibrary.KeyManagement;
using System.Text.Json;

namespace E2EELibrary.MultiDevice
{
    /// <summary>
    /// Multi-device session manager for syncing session states
    /// </summary>
    public class DeviceManager
    {
        private readonly (byte[] publicKey, byte[] privateKey) _deviceKeyPair;

        // Changed from ConcurrentBag to ConcurrentDictionary to prevent duplicates
        private readonly ConcurrentDictionary<string, byte[]> _linkedDevices = new ConcurrentDictionary<string, byte[]>(StringComparer.Ordinal);

        private readonly byte[] _syncKey;
        private readonly object _syncLock = new object();

        /// <summary>
        /// Creates a new multi-device manager
        /// </summary>
        /// <param name="deviceKeyPair">This device's key pair</param>
        public DeviceManager((byte[] publicKey, byte[] privateKey) deviceKeyPair)
        {
            _deviceKeyPair = deviceKeyPair;

            // Generate a random sync key
            _syncKey = new byte[Constants.AES_KEY_SIZE];
            RandomNumberGenerator.Fill(_syncKey);
        }

        /// <summary>
        /// Adds a linked device
        /// </summary>
        /// <param name="devicePublicKey">Public key of the device to link</param>
        public void AddLinkedDevice(byte[] devicePublicKey)
        {
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

            // Validate X25519 public key if it's that length
            if (devicePublicKey.Length == Constants.X25519_KEY_SIZE &&
                !KeyValidation.ValidateX25519PublicKey(devicePublicKey))
            {
                throw new ArgumentException("Invalid X25519 public key", nameof(devicePublicKey));
            }

            // Convert key to X25519 if needed
            byte[] finalKey = devicePublicKey.Length == Constants.X25519_KEY_SIZE ?
                devicePublicKey :
                ScalarMult.Base(KeyConversion.DeriveX25519PublicKeyFromEd25519(devicePublicKey));

            // Create a deep copy of the key to prevent any external modification
            byte[] keyCopy = new byte[finalKey.Length];
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
            if (devicePublicKey == null)
                throw new ArgumentNullException(nameof(devicePublicKey));

            // Convert key to X25519 if needed
            byte[] finalKey = devicePublicKey.Length == Constants.X25519_KEY_SIZE ?
                devicePublicKey :
                ScalarMult.Base(KeyConversion.DeriveX25519PublicKeyFromEd25519(devicePublicKey));

            // Use Base64 representation as dictionary key
            string keyBase64 = Convert.ToBase64String(finalKey);

            // Try to remove and return result
            return _linkedDevices.TryRemove(keyBase64, out _);
        }

        /// <summary>
        /// Creates encrypted sync messages for other devices
        /// </summary>
        /// <param name="syncData">Data to sync</param>
        /// <returns>Dictionary of encrypted messages for each device</returns>
        public Dictionary<string, EncryptedMessage> CreateSyncMessages(byte[] syncData)
        {
            if (syncData == null)
                throw new ArgumentNullException(nameof(syncData));

            var result = new Dictionary<string, EncryptedMessage>();

            // Basic sanity check
            if (_linkedDevices.Count == 0)
                return result;

            // Make a secure copy of the sync data to avoid external modification during processing
            byte[] syncDataCopy = new byte[syncData.Length];
            syncData.AsSpan().CopyTo(syncDataCopy);

            // Prepare the sender's private key in X25519 format
            byte[] senderX25519Private = _deviceKeyPair.privateKey.Length != Constants.X25519_KEY_SIZE ?
                KeyConversion.DeriveX25519PrivateKeyFromEd25519(_deviceKeyPair.privateKey) :
                _deviceKeyPair.privateKey;

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
                            Console.WriteLine("Skipping invalid X25519 public key");
                            continue;
                        }
                        x25519PublicKey = deviceKey;
                    }
                    else if (deviceKey.Length == Constants.ED25519_PUBLIC_KEY_SIZE)
                    {
                        // Convert Ed25519 public key to X25519
                        x25519PublicKey = ScalarMult.Base(
                            KeyConversion.DeriveX25519PrivateKeyFromEd25519(deviceKey)
                        );
                    }
                    else
                    {
                        Console.WriteLine($"Skipping device key with invalid length: {deviceKey.Length}");
                        continue;
                    }

                    // Perform key exchange
                    byte[] sharedSecret = X3DHExchange.X3DHKeyExchange(x25519PublicKey, senderX25519Private);

                    // Sign the sync data
                    byte[] signature = MessageSigning.SignMessage(syncDataCopy, _deviceKeyPair.privateKey);

                    // Create sync message with timestamp for replay protection
                    var syncMessage = new DeviceSyncMessage
                    {
                        SenderPublicKey = _deviceKeyPair.publicKey,
                        Data = syncDataCopy,
                        Signature = signature,
                        Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                    };

                    // Serialize
                    string json = System.Text.Json.JsonSerializer.Serialize(new
                    {
                        senderPublicKey = Convert.ToBase64String(syncMessage.SenderPublicKey),
                        data = Convert.ToBase64String(syncMessage.Data),
                        signature = Convert.ToBase64String(syncMessage.Signature),
                        timestamp = syncMessage.Timestamp
                    });

                    // Encrypt
                    byte[] plaintext = Encoding.UTF8.GetBytes(json);
                    byte[] nonce = NonceGenerator.GenerateNonce();
                    byte[] ciphertext = AES.AESEncrypt(plaintext, sharedSecret, nonce);

                    // Add to result
                    string deviceKeyBase64 = deviceEntry.Key;
                    result[deviceKeyBase64] = new EncryptedMessage
                    {
                        Ciphertext = ciphertext,
                        Nonce = nonce
                    };
                }
                catch (Exception ex)
                {
                    // Log the error but continue processing other devices
                    Console.WriteLine($"Error creating sync message: {ex.Message}");
                }
            }

            // Securely clear the copy when done
            Array.Clear(syncDataCopy, 0, syncDataCopy.Length);
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
            if (encryptedMessage == null)
                throw new ArgumentNullException(nameof(encryptedMessage));

            // If we have a sender hint, try that device first
            if (senderHint != null)
            {
                // Convert the sender hint to base64 for the dictionary lookup
                string senderKeyBase64 = Convert.ToBase64String(senderHint);

                // Check if we have this sender in our linked devices
                if (_linkedDevices.TryGetValue(senderKeyBase64, out var _))
                {
                    byte[]? result = TryProcessSyncMessageFromDevice(encryptedMessage, senderHint);
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

                byte[]? result = TryProcessSyncMessageFromDevice(encryptedMessage, deviceKey);
                if (result != null)
                    return result;
            }

            // If we get here, we couldn't process the sync message with any device
            return null;
        }

        /// <summary>
        /// Attempts to process a sync message from a specific device
        /// </summary>
        /// <param name="encryptedMessage">Encrypted message</param>
        /// <param name="deviceKey">Device public key to try</param>
        /// <returns>Decrypted data if successful, null otherwise</returns>
        private byte[]? TryProcessSyncMessageFromDevice(EncryptedMessage encryptedMessage, byte[] deviceKey)
        {
            ArgumentNullException.ThrowIfNull(encryptedMessage.Ciphertext);
            ArgumentNullException.ThrowIfNull(encryptedMessage.Nonce);

            try
            {
                // Convert keys to X25519 format if needed
                byte[] x25519PrivateKey = _deviceKeyPair.privateKey.Length != Constants.X25519_KEY_SIZE ?
                    KeyConversion.DeriveX25519PrivateKeyFromEd25519(_deviceKeyPair.privateKey) : _deviceKeyPair.privateKey;

                byte[] x25519PublicKey = deviceKey.Length != Constants.X25519_KEY_SIZE ?
                    ScalarMult.Base(KeyConversion.DeriveX25519PrivateKeyFromEd25519(deviceKey)) : deviceKey;

                // For debugging purposes
                Console.WriteLine($"X25519 Private Key Length: {x25519PrivateKey.Length}");
                Console.WriteLine($"X25519 Public Key Length: {x25519PublicKey.Length}");

                // Additional validation
                if (!KeyValidation.ValidateX25519PublicKey(x25519PublicKey))
                {
                    Console.WriteLine("X25519 public key validation failed");
                    return null;
                }

                // Generate shared secret
                byte[] sharedSecret = X3DHExchange.X3DHKeyExchange(x25519PublicKey, x25519PrivateKey);

                Console.WriteLine($"Generated shared secret length: {sharedSecret.Length}");

                // Attempt to decrypt
                byte[] plaintext;
                try
                {
                    plaintext = AES.AESDecrypt(encryptedMessage.Ciphertext, sharedSecret, encryptedMessage.Nonce);
                    Console.WriteLine($"Successfully decrypted plaintext, length: {plaintext.Length}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Decryption failed: {ex.Message}");
                    return null;
                }

                string json = Encoding.UTF8.GetString(plaintext);
                Console.WriteLine($"Decrypted JSON: {json}");

                // Try to deserialize - this may fail if the decryption was incorrect
                Dictionary<string, object>? data;
                try
                {
                    data = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(json);
                    if (data == null)
                    {
                        Console.WriteLine("Deserialization returned null");
                        return null;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Deserialization failed: {ex.Message}");
                    return null;
                }

                // If we get here, deserialization succeeded
                if (!data.ContainsKey("senderPublicKey") || !data.ContainsKey("data") || !data.ContainsKey("signature"))
                {
                    Console.WriteLine("Required keys missing from deserialized data");
                    return null;
                }

                // Handle both JsonElement and string types when extracting values
                byte[] senderPubKey = Convert.FromBase64String(data["senderPublicKey"].ToString());
                byte[] syncData = Convert.FromBase64String(data["data"].ToString());
                byte[] signature = Convert.FromBase64String(data["signature"].ToString());

                // Get timestamp if present (for newer protocol versions)
                long timestamp = 0;
                if (data.ContainsKey("timestamp"))
                {
                    // Handle JsonElement type explicitly for timestamp 
                    if (data["timestamp"] is JsonElement jsonTimestamp)
                    {
                        timestamp = jsonTimestamp.ValueKind == JsonValueKind.Number
                            ? jsonTimestamp.GetInt64()
                            : long.Parse(jsonTimestamp.ToString());
                    }
                    else
                    {
                        timestamp = Convert.ToInt64(data["timestamp"].ToString());
                    }

                    // Verify timestamp to prevent replay attacks - reject messages older than 5 minutes
                    long currentTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                    if (timestamp > 0 && currentTime - timestamp > 5 * 60 * 1000)
                    {
                        Console.WriteLine("Message is too old, possible replay attack");
                        return null;
                    }
                }

                // Verify signature
                bool signatureValid = MessageSigning.VerifySignature(syncData, signature, senderPubKey);
                if (!signatureValid)
                {
                    Console.WriteLine("Signature verification failed");
                    return null;
                }

                Console.WriteLine("Signature verification succeeded");

                // Make a secure copy of the sync data to return
                byte[] result = new byte[syncData.Length];
                syncData.AsSpan().CopyTo(result.AsSpan());
                return result;
            }
            catch (Exception ex)
            {
                // Log the error for debugging
                Console.WriteLine($"Error in TryProcessSyncMessageFromDevice: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Gets the number of linked devices
        /// </summary>
        /// <returns>The number of unique linked devices</returns>
        public int GetLinkedDeviceCount()
        {
            return _linkedDevices.Count;
        }

        /// <summary>
        /// Checks if a device is already linked
        /// </summary>
        /// <param name="devicePublicKey">Public key of the device to check</param>
        /// <returns>True if the device is linked, false otherwise</returns>
        public bool IsDeviceLinked(byte[] devicePublicKey)
        {
            if (devicePublicKey == null)
                return false;

            // Convert key to X25519 format if needed
            byte[] finalKey = devicePublicKey.Length == Constants.X25519_KEY_SIZE ?
                devicePublicKey :
                ScalarMult.Base(KeyConversion.DeriveX25519PublicKeyFromEd25519(devicePublicKey));

            string keyBase64 = Convert.ToBase64String(finalKey);
            return _linkedDevices.ContainsKey(keyBase64);
        }

        /// <summary>
        /// Creates a revocation message for a device.
        /// </summary>
        /// <param name="deviceKeyToRevoke">The public key of the device to revoke</param>
        /// <returns>A signed revocation message</returns>
        public DeviceRevocationMessage CreateRevocationMessage(byte[] deviceKeyToRevoke)
        {
            if (deviceKeyToRevoke == null || deviceKeyToRevoke.Length == 0)
                throw new ArgumentException("Device key cannot be null or empty", nameof(deviceKeyToRevoke));

            long timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            // Combine device key and timestamp for signing
            byte[] timestampBytes = BitConverter.GetBytes(timestamp);
            byte[] dataToSign = new byte[deviceKeyToRevoke.Length + timestampBytes.Length];

            Buffer.BlockCopy(deviceKeyToRevoke, 0, dataToSign, 0, deviceKeyToRevoke.Length);
            Buffer.BlockCopy(timestampBytes, 0, dataToSign, deviceKeyToRevoke.Length, timestampBytes.Length);

            // Sign the combined data
            byte[] signature = MessageSigning.SignMessage(dataToSign, _deviceKeyPair.privateKey);

            // Create and return the revocation message
            return new DeviceRevocationMessage
            {
                RevokedDeviceKey = deviceKeyToRevoke,
                RevocationTimestamp = timestamp,
                Signature = signature
            };
        }

        /// <summary>
        /// Revokes a linked device and creates a revocation message.
        /// </summary>
        /// <param name="devicePublicKey">Public key of the device to revoke</param>
        /// <returns>A revocation message that should be distributed to other devices</returns>
        public DeviceRevocationMessage RevokeLinkedDevice(byte[] devicePublicKey)
        {
            if (devicePublicKey == null)
                throw new ArgumentNullException(nameof(devicePublicKey));

            // Convert key to X25519 format if needed
            byte[] finalKey = devicePublicKey.Length == Constants.X25519_KEY_SIZE ?
                devicePublicKey :
                KeyConversion.DeriveX25519PublicKeyFromEd25519(devicePublicKey);

            // Use Base64 representation as dictionary key
            string deviceId = Convert.ToBase64String(finalKey);

            // Try to remove from linked devices
            bool removed = _linkedDevices.TryRemove(deviceId, out var _);

            if (!removed)
            {
                throw new KeyNotFoundException("Device not found in linked devices");
            }

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
            if (revocationMessage == null)
                throw new ArgumentNullException(nameof(revocationMessage));

            if (trustedPublicKey == null)
                throw new ArgumentNullException(nameof(trustedPublicKey));

            // Validate the message
            if (!revocationMessage.Validate(trustedPublicKey))
                return false;

            // Get the device ID
            string deviceId = Convert.ToBase64String(revocationMessage.RevokedDeviceKey);

            // Remove the device if it exists
            return _linkedDevices.TryRemove(deviceId, out var _);
        }
    }
}