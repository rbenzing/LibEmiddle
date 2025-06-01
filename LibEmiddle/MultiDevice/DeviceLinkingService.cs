using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.Abstractions;
using System.Security.Cryptography;
using System.Text;

namespace LibEmiddle.MultiDevice
{
    /// <summary>
    /// Provides implementation for secure device linking, enabling multiple devices
    /// to establish trusted communication channels following the Signal Protocol specification.
    /// 
    /// <para>
    /// This service handles cryptographic operations related to linking new devices to an
    /// existing identity, including key exchange, signature verification, and deriving
    /// shared keys between devices.
    /// </para>
    /// </summary>
    public class DeviceLinkingService : IDeviceLinkingService, IDisposable
    {
        private readonly ICryptoProvider _cryptoProvider;
        private bool _disposed;

        // Maximum allowed difference (in milliseconds) between the message timestamp and the current time.
        private const long AllowedTimestampSkewMilliseconds = 300000; // 5 minutes

        /// <summary>
        /// Creates a new device linking service with the specified cryptographic provider.
        /// </summary>
        /// <param name="cryptoProvider">The cryptographic provider to use</param>
        public DeviceLinkingService(ICryptoProvider cryptoProvider)
        {
            _cryptoProvider = cryptoProvider ?? throw new ArgumentNullException(nameof(cryptoProvider));
        }

        /// <summary>
        /// Derives a shared key for a new device.
        /// Accepts X25519 public keys
        /// 
        /// <para>
        /// This method follows the Signal Protocol specification for deriving shared keys
        /// between devices. It supports X25519 key formats and includes
        /// information about the key format.
        /// </para>
        /// </summary>
        /// <param name="existingSharedKey">Existing device's shared key</param>
        /// <param name="newDevicePublicKey">New device's public key (X25519)</param>
        /// <returns>Shared key for the new device</returns>
        /// <exception cref="ArgumentNullException">Thrown if inputs are null</exception>
        /// <exception cref="ArgumentException">Thrown if key has invalid length</exception>
        /// <exception cref="CryptographicException">Thrown if key is invalid or conversion fails</exception>
        public byte[] DeriveSharedKeyForNewDevice(byte[] existingSharedKey, byte[] newDevicePublicKey)
        {
            ArgumentNullException.ThrowIfNull(existingSharedKey, nameof(existingSharedKey));
            ArgumentNullException.ThrowIfNull(newDevicePublicKey, nameof(newDevicePublicKey));

            if (newDevicePublicKey.Length != Constants.X25519_KEY_SIZE)
            {
                throw new ArgumentException($"Invalid public key length: {newDevicePublicKey.Length}. " +
                    $"Expected {Constants.X25519_KEY_SIZE} bytes.",
                    nameof(newDevicePublicKey));
            }

            // Use HKDF to derive the key
            return _cryptoProvider.DeriveKey(
                newDevicePublicKey,
                existingSharedKey,  // Use existing key as salt
                Encoding.Default.GetBytes($"DeviceLinkKeyDerivation-X25519")
            );   
        }

        /// <summary>
        /// Creates a device link message for establishing multi-device sync.
        /// 
        /// <para>
        /// Creates an encrypted message that can be sent to a new device to establish
        /// a secure communication channel. The message includes the main device's public key
        /// and a signature of the new device's public key, allowing the new device to verify
        /// the authenticity of the link.
        /// </para>
        /// </summary>
        /// <param name="mainDeviceKeyPair">The main device's identity key pair</param>
        /// <param name="newDevicePublicKey">The public key of the new device to link</param>
        /// <returns>An encrypted message containing linking information</returns>
        /// <exception cref="ArgumentNullException">Thrown if inputs are null</exception>
        /// <exception cref="ArgumentException">Thrown if keys are invalid</exception>
        public EncryptedMessage CreateDeviceLinkMessage(KeyPair mainDeviceKeyPair, byte[] newDevicePublicKey)
        {
            // Validate that the main device key pair is in Ed25519 format.
            ArgumentNullException.ThrowIfNull(mainDeviceKeyPair.PublicKey, nameof(mainDeviceKeyPair.PublicKey));
            ArgumentNullException.ThrowIfNull(mainDeviceKeyPair.PrivateKey, nameof(mainDeviceKeyPair.PrivateKey));

            if (mainDeviceKeyPair.PublicKey.Length != Constants.ED25519_PUBLIC_KEY_SIZE ||
                mainDeviceKeyPair.PrivateKey.Length != Constants.ED25519_PRIVATE_KEY_SIZE)
            {
                throw new ArgumentException("Main device key pair must be an Ed25519 key pair.", nameof(mainDeviceKeyPair));
            }

            ArgumentNullException.ThrowIfNull(newDevicePublicKey, nameof(newDevicePublicKey));

            byte[]? mainDeviceX25519Private = null;
            byte[]? newDeviceX25519Public = null;
            byte[]? sharedSecret = null;

            try
            {
                // Convert main device's Ed25519 private key to X25519
                mainDeviceX25519Private = _cryptoProvider.ConvertEd25519PrivateKeyToX25519(mainDeviceKeyPair.PrivateKey);

                // Convert new device's key to X25519 if necessary
                if (newDevicePublicKey.Length == Constants.ED25519_PUBLIC_KEY_SIZE)
                {
                    try
                    {
                        newDeviceX25519Public = _cryptoProvider.ConvertEd25519PublicKeyToX25519(newDevicePublicKey);
                    }
                    catch (Exception ex)
                    {
                        throw new ArgumentException("New device public key is not a valid Ed25519 public key.",
                            nameof(newDevicePublicKey), ex);
                    }
                }
                else if (newDevicePublicKey.Length == Constants.X25519_KEY_SIZE)
                {
                    // Validate X25519 key
                    if (!_cryptoProvider.ValidateX25519PublicKey(newDevicePublicKey))
                    {
                        throw new ArgumentException("Invalid X25519 public key.", nameof(newDevicePublicKey));
                    }
                    newDeviceX25519Public = (byte[])newDevicePublicKey.Clone();
                }
                else
                {
                    throw new ArgumentException($"Invalid public key length: {newDevicePublicKey.Length}. " +
                        $"Expected {Constants.ED25519_PUBLIC_KEY_SIZE} or {Constants.X25519_KEY_SIZE} bytes.",
                        nameof(newDevicePublicKey));
                }

                // Compute the shared secret using X3DH
                sharedSecret = _cryptoProvider.ScalarMult(mainDeviceX25519Private, newDeviceX25519Public);

                // Sign the new device's public key using the main device's Ed25519 private key
                byte[] signature = _cryptoProvider.Sign(newDevicePublicKey, mainDeviceKeyPair.PrivateKey);

                // Build the payload
                var payload = new
                {
                    mainDevicePublicKey = Convert.ToBase64String(mainDeviceKeyPair.PublicKey),
                    signature = Convert.ToBase64String(signature)
                };

                string json = System.Text.Json.JsonSerializer.Serialize(payload);
                byte[] plaintext = System.Text.Encoding.Default.GetBytes(json);
                byte[] nonce = Nonce.GenerateNonce();
                byte[] ciphertext = AES.AESEncrypt(plaintext, sharedSecret, nonce);

                // Use the main device's X25519 public key for SenderDHKey
                byte[] mainDeviceX25519Public = _cryptoProvider.ConvertEd25519PublicKeyToX25519(mainDeviceKeyPair.PublicKey);

                return new EncryptedMessage
                {
                    Ciphertext = ciphertext,
                    Nonce = nonce,
                    SenderDHKey = mainDeviceX25519Public, // Use X25519 public key from main device
                    Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    SenderMessageNumber = 0,
                    SessionId = Guid.NewGuid().ToString(),
                };
            }
            finally
            {
                // Securely clear sensitive materials
                if (mainDeviceX25519Private != null)
                    SecureMemory.SecureClear(mainDeviceX25519Private);
                if (newDeviceX25519Public != null)
                    SecureMemory.SecureClear(newDeviceX25519Public);
                if (sharedSecret != null)
                    SecureMemory.SecureClear(sharedSecret);
            }
        }

        /// <summary>
        /// Processes a device link message on the new device.
        /// 
        /// <para>
        /// Verifies and processes a device link message received from the main device.
        /// If the message is valid and properly signed, it extracts the main device's
        /// public key for establishing a trusted link.
        /// </para>
        /// </summary>
        /// <param name="encryptedMessage">The encrypted device link message</param>
        /// <param name="newDeviceKeyPair">The new device's identity key pair</param>
        /// <param name="expectedMainDevicePublicKey">The expected public key of the main device</param>
        /// <returns>The main device's public key if verification succeeds, null otherwise</returns>
        /// <exception cref="ArgumentNullException">Thrown if parameters are null</exception>
        public byte[]? ProcessDeviceLinkMessage(
            EncryptedMessage encryptedMessage,
            KeyPair newDeviceKeyPair,
            byte[] expectedMainDevicePublicKey)
        {
            ArgumentNullException.ThrowIfNull(encryptedMessage, nameof(encryptedMessage));

            // Instead of throwing for missing fields, treat them as invalid and return null.
            if (encryptedMessage.Ciphertext == null ||
                encryptedMessage.Nonce == null ||
                encryptedMessage.SenderDHKey == null)
            {
                LoggingManager.LogWarning(nameof(DeviceLinkingService),
                    "Device link message missing required fields (ciphertext, nonce, or SenderDHKey).");
                return null;
            }

            ArgumentNullException.ThrowIfNull(newDeviceKeyPair.PublicKey, nameof(newDeviceKeyPair.PublicKey));
            ArgumentNullException.ThrowIfNull(newDeviceKeyPair.PrivateKey, nameof(newDeviceKeyPair.PrivateKey));
            ArgumentNullException.ThrowIfNull(expectedMainDevicePublicKey, nameof(expectedMainDevicePublicKey));

            byte[]? newDeviceX25519Private = null;
            byte[]? sharedSecret = null;

            try
            {
                // Check replay protection using the timestamp.
                long currentTimestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                if (Math.Abs(currentTimestamp - encryptedMessage.Timestamp) > AllowedTimestampSkewMilliseconds)
                {
                    LoggingManager.LogWarning(nameof(DeviceLinkingService),
                        "Device link message rejected due to timestamp outside allowed window.");
                    return null;
                }

                // Convert the new device's Ed25519 private key to X25519.
                newDeviceX25519Private = _cryptoProvider.ConvertEd25519PrivateKeyToX25519(newDeviceKeyPair.PrivateKey);

                // Retrieve the main device's X25519 public key from SenderDHKey.
                byte[] mainDeviceX25519Public = encryptedMessage.SenderDHKey;
                if (mainDeviceX25519Public.Length != Constants.X25519_KEY_SIZE)
                {
                    LoggingManager.LogWarning(nameof(DeviceLinkingService),
                        $"Invalid main device X25519 public key length in SenderDHKey: {mainDeviceX25519Public.Length}, expected {Constants.X25519_KEY_SIZE}");
                    return null;
                }

                // Compute the shared secret.
                sharedSecret = _cryptoProvider.ScalarMult(newDeviceX25519Private, mainDeviceX25519Public);

                try
                {
                    // Decrypt the ciphertext.
                    byte[] plaintext = AES.AESDecrypt(
                        encryptedMessage.Ciphertext,
                        sharedSecret,
                        encryptedMessage.Nonce);

                    string json = System.Text.Encoding.UTF8.GetString(plaintext);

                    // Deserialize the payload.
                    var data = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(json);
                    if (data == null || !data.ContainsKey("mainDevicePublicKey") || !data.ContainsKey("signature"))
                    {
                        LoggingManager.LogWarning(nameof(DeviceLinkingService),
                            "Device link message payload missing required fields.");
                        return null;
                    }

                    byte[] mainDeviceEd25519Public = Convert.FromBase64String(data["mainDevicePublicKey"]);
                    byte[] signature = Convert.FromBase64String(data["signature"]);

                    // Ensure that the main device public key from the payload matches the expected one.
                    if (!SecureMemory.SecureCompare(mainDeviceEd25519Public, expectedMainDevicePublicKey))
                    {
                        LoggingManager.LogWarning(nameof(DeviceLinkingService),
                            "Device link message rejected due to mismatched main device public key.");
                        return null;
                    }

                    // Verify that the main device signed the new device's original Ed25519 public key.
                    if (_cryptoProvider.VerifySignature(newDeviceKeyPair.PublicKey, signature, mainDeviceEd25519Public))
                    {
                        return mainDeviceEd25519Public;
                    }
                    else
                    {
                        LoggingManager.LogWarning(nameof(DeviceLinkingService),
                            "Device link message signature verification failed.");
                        return null;
                    }
                }
                catch (Exception ex)
                {
                    LoggingManager.LogError(nameof(DeviceLinkingService),
                        $"Error decrypting or processing device link message: {ex.Message}");
                    return null;
                }
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(DeviceLinkingService),
                    $"Error processing device link message: {ex.Message}");
                return null;
            }
            finally
            {
                // Clear sensitive data
                if (newDeviceX25519Private != null)
                    SecureMemory.SecureClear(newDeviceX25519Private);
                if (sharedSecret != null)
                    SecureMemory.SecureClear(sharedSecret);
            }
        }

        /// <summary>
        /// Creates a device revocation message.
        /// </summary>
        /// <param name="userIdentityKeyPair">The user's identity key pair used to sign the revocation.</param>
        /// <param name="deviceToRevokePublicKey">The public key of the device to revoke.</param>
        /// <param name="reason">Optional reason for the revocation.</param>
        /// <returns>A signed device revocation message.</returns>
        /// <exception cref="ArgumentNullException">Thrown if user identity key pair is null or incomplete.</exception>
        /// <exception cref="ArgumentException">Thrown if device public key is invalid.</exception>
        public DeviceRevocationMessage CreateDeviceRevocationMessage(
            KeyPair userIdentityKeyPair,
            byte[] deviceToRevokePublicKey,
            string? reason = null)
        {
            ArgumentNullException.ThrowIfNull(userIdentityKeyPair, nameof(userIdentityKeyPair));
            ArgumentNullException.ThrowIfNull(userIdentityKeyPair.PublicKey, nameof(userIdentityKeyPair.PublicKey));
            ArgumentNullException.ThrowIfNull(userIdentityKeyPair.PrivateKey, nameof(userIdentityKeyPair.PrivateKey));
            ArgumentNullException.ThrowIfNull(deviceToRevokePublicKey, nameof(deviceToRevokePublicKey));

            // Normalize device key to X25519 format if needed
            byte[]? normalizedDeviceKey = null;
            try
            {
                // Validate and normalize the device key format
                if (deviceToRevokePublicKey.Length == Constants.ED25519_PUBLIC_KEY_SIZE)
                {
                    normalizedDeviceKey = _cryptoProvider.ConvertEd25519PublicKeyToX25519(deviceToRevokePublicKey);
                }
                else if (deviceToRevokePublicKey.Length == Constants.X25519_KEY_SIZE)
                {
                    if (!_cryptoProvider.ValidateX25519PublicKey(deviceToRevokePublicKey))
                    {
                        throw new ArgumentException("Invalid X25519 public key.", nameof(deviceToRevokePublicKey));
                    }
                    normalizedDeviceKey = deviceToRevokePublicKey.ToArray();
                }
                else
                {
                    throw new ArgumentException($"Invalid device public key length: {deviceToRevokePublicKey.Length}. " +
                        $"Expected {Constants.ED25519_PUBLIC_KEY_SIZE} or {Constants.X25519_KEY_SIZE} bytes.",
                        nameof(deviceToRevokePublicKey));
                }

                // Create the revocation message
                var revocationMessage = new DeviceRevocationMessage
                {
                    RevokedDevicePublicKey = normalizedDeviceKey,
                    UserIdentityPublicKey = userIdentityKeyPair.PublicKey,
                    Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    Reason = reason,
                    Version = ProtocolVersion.FULL_VERSION
                };

                // Create data to sign (revoked device key + user identity + timestamp)
                byte[] dataToSign = GetDataToSign(revocationMessage);

                // Sign with the user's identity private key
                revocationMessage.Signature = _cryptoProvider.Sign(dataToSign, userIdentityKeyPair.PrivateKey);

                return revocationMessage;
            }
            finally
            {
                // We don't need to clear normalizedDeviceKey here as it's stored in the returned object
            }
        }

        /// <summary>
        /// Verifies a device revocation message.
        /// </summary>
        /// <param name="revocationMessage">The revocation message to verify.</param>
        /// <param name="trustedUserIdentityKey">The trusted identity key of the user who owns the devices.</param>
        /// <returns>True if the revocation message is valid and properly signed.</returns>
        /// <exception cref="ArgumentNullException">Thrown if parameters are null.</exception>
        public bool VerifyDeviceRevocationMessage(
            DeviceRevocationMessage revocationMessage,
            byte[] trustedUserIdentityKey)
        {
            ArgumentNullException.ThrowIfNull(revocationMessage, nameof(revocationMessage));
            ArgumentNullException.ThrowIfNull(trustedUserIdentityKey, nameof(trustedUserIdentityKey));

            if (revocationMessage.Signature == null)
                throw new ArgumentNullException(nameof(revocationMessage.Signature));

            // Basic validation of the revocation message
            if (!revocationMessage.IsValid())
            {
                LoggingManager.LogWarning(nameof(DeviceLinkingService),
                    "Revocation message failed basic validation");
                return false;
            }

            // Verify that the message is from the expected user identity
            if (!SecureMemory.SecureCompare(revocationMessage.UserIdentityPublicKey, trustedUserIdentityKey))
            {
                LoggingManager.LogWarning(nameof(DeviceLinkingService),
                    "Revocation message has unexpected user identity key");
                return false;
            }

            // Check timestamp to prevent replay attacks
            long currentTimestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            long messageAge = currentTimestamp - revocationMessage.Timestamp;

            // Message too old or from the future (with some tolerance for clock skew)
            if (messageAge < -AllowedTimestampSkewMilliseconds || messageAge > Constants.MAX_REVOCATION_AGE_MS)
            {
                LoggingManager.LogWarning(nameof(DeviceLinkingService),
                    $"Revocation message has invalid timestamp. Age: {messageAge}ms");
                return false;
            }

            // Get the data that was signed
            byte[] dataToSign = GetDataToSign(revocationMessage);

            // Verify the signature
            return _cryptoProvider.VerifySignature(dataToSign, revocationMessage.Signature, trustedUserIdentityKey);
        }

        /// <summary>
        /// Constructs the data to be signed for a device revocation message.
        /// </summary>
        /// <param name="revocationMessage">The revocation message.</param>
        /// <returns>The byte array representing the data to sign.</returns>
        private byte[] GetDataToSign(DeviceRevocationMessage revocationMessage)
        {
            if (revocationMessage.RevokedDevicePublicKey == null)
                throw new ArgumentNullException(nameof(revocationMessage.RevokedDevicePublicKey));
            if (revocationMessage.UserIdentityPublicKey == null)
                throw new ArgumentNullException(nameof(revocationMessage.UserIdentityPublicKey));

            // Combine revoked device key + user identity + timestamp for signing
            using var ms = new MemoryStream();
            using var writer = new BinaryWriter(ms);

            writer.Write(revocationMessage.RevokedDevicePublicKey);
            writer.Write(revocationMessage.UserIdentityPublicKey);
            writer.Write(revocationMessage.Timestamp);
            writer.Write(Encoding.UTF8.GetBytes(revocationMessage.Id));

            if (!string.IsNullOrEmpty(revocationMessage.Reason))
            {
                writer.Write(Encoding.UTF8.GetBytes(revocationMessage.Reason));
            }

            return ms.ToArray();
        }

        /// <summary>
        /// Disposes of resources used by the DeviceLinkingService.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Disposes of resources used by the DeviceLinkingService.
        /// </summary>
        /// <param name="disposing">True if disposing, false if finalizing.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                // Dispose any managed resources if needed
                (_cryptoProvider as IDisposable)?.Dispose();
            }

            _disposed = true;
        }
    }
}