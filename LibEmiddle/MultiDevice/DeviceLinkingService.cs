using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.Abstractions;
using System.Security.Cryptography;

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
    public class DeviceLinkingService : IDeviceLinkingService
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
        /// Accepts either Ed25519 or X25519 public keys, performing conversion if needed.
        /// 
        /// <para>
        /// This method follows the Signal Protocol specification for deriving shared keys
        /// between devices. It supports both Ed25519 and X25519 key formats and includes
        /// information about the key format in the derivation info to ensure different results
        /// for different key types.
        /// </para>
        /// </summary>
        /// <param name="existingSharedKey">Existing device's shared key</param>
        /// <param name="newDevicePublicKey">New device's public key (Ed25519 or X25519)</param>
        /// <returns>Shared key for the new device</returns>
        /// <exception cref="ArgumentNullException">Thrown if inputs are null</exception>
        /// <exception cref="ArgumentException">Thrown if key has invalid length</exception>
        /// <exception cref="CryptographicException">Thrown if key is invalid</exception>
        public byte[] DeriveSharedKeyForNewDevice(byte[] existingSharedKey, byte[] newDevicePublicKey)
        {
            ArgumentNullException.ThrowIfNull(existingSharedKey, nameof(existingSharedKey));
            ArgumentNullException.ThrowIfNull(newDevicePublicKey, nameof(newDevicePublicKey));

            byte[]? normalizedPublicKey = null;
            string keyFormat;

            try
            {
                // Normalize the key to X25519 format, tracking the original format
                if (newDevicePublicKey.Length == Constants.ED25519_PUBLIC_KEY_SIZE)
                {
                    // Convert Ed25519 to X25519
                    normalizedPublicKey = _cryptoProvider.ConvertEd25519PublicKeyToX25519(newDevicePublicKey);
                    keyFormat = "Ed25519";
                }
                else if (newDevicePublicKey.Length == Constants.X25519_KEY_SIZE)
                {
                    // Validate the X25519 key
                    if (!_cryptoProvider.ValidateX25519PublicKey(newDevicePublicKey))
                    {
                        throw new CryptographicException("Public key is invalid.");
                    }
                    normalizedPublicKey = (byte[])newDevicePublicKey.Clone();
                    keyFormat = "X25519";
                }
                else
                {
                    throw new ArgumentException($"Invalid public key length: {newDevicePublicKey.Length}. " +
                        $"Expected {Constants.ED25519_PUBLIC_KEY_SIZE} or {Constants.X25519_KEY_SIZE} bytes.",
                        nameof(newDevicePublicKey));
                }

                // Include the original key format in the derivation info to ensure different results
                // for Ed25519 vs X25519 inputs
                byte[] keyDerivationInfo = System.Text.Encoding.Default.GetBytes($"DeviceLinkKeyDerivation-{keyFormat}");

                // Use HKDF to derive the key
                return _cryptoProvider.DeriveKey(
                    normalizedPublicKey,
                    existingSharedKey,  // Use existing key as salt
                    keyDerivationInfo
                );
            }
            finally
            {
                // Clear sensitive data
                if (normalizedPublicKey != null)
                {
                    SecureMemory.SecureClear(normalizedPublicKey);
                }
            }
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
        /// Throws if this object has been disposed.
        /// </summary>
        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(DeviceLinkingService));
            }
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