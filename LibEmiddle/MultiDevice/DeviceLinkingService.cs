using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.Abstractions;
using System.Security.Cryptography;
using System.Text;

namespace LibEmiddle.MultiDevice;

/// <summary>
/// Provides cryptographic operations for secure device linking, following the Signal Protocol 
/// specification for multi-device communication.
/// 
/// <para>
/// This service handles only the low-level cryptographic operations for device linking:
/// key exchange, signature creation/verification, and message encryption/decryption.
/// Higher-level device management is handled by <see cref="DeviceManager"/>.
/// </para>
/// </summary>
public sealed class DeviceLinkingService : IDeviceLinkingService, IDisposable
{
    private readonly ICryptoProvider _cryptoProvider;
    private bool _disposed;

    // Maximum allowed difference (in milliseconds) between the message timestamp and the current time.
    private const long AllowedTimestampSkewMilliseconds = 300000; // 5 minutes

    /// <summary>
    /// Creates a new device linking service with the specified cryptographic provider.
    /// </summary>
    /// <param name="cryptoProvider">The cryptographic provider to use for all cryptographic operations</param>
    /// <exception cref="ArgumentNullException">Thrown when cryptoProvider is null</exception>
    public DeviceLinkingService(ICryptoProvider cryptoProvider)
    {
        _cryptoProvider = cryptoProvider ?? throw new ArgumentNullException(nameof(cryptoProvider));
    }

    /// <summary>
    /// Derives a shared key for communication between two devices using X25519 key exchange.
    /// 
    /// <para>
    /// This method follows the Signal Protocol specification for deriving shared keys
    /// between devices using X25519 ECDH and HKDF key derivation.
    /// </para>
    /// </summary>
    /// <param name="existingSharedKey">Existing device's shared private key (X25519 format)</param>
    /// <param name="newDevicePublicKey">New device's public key (X25519 format)</param>
    /// <returns>Derived shared key for secure communication</returns>
    /// <exception cref="ArgumentNullException">Thrown if inputs are null</exception>
    /// <exception cref="ArgumentException">Thrown if key has invalid length</exception>
    /// <exception cref="CryptographicException">Thrown if key derivation fails</exception>
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

        if (!_cryptoProvider.ValidateX25519PublicKey(newDevicePublicKey))
        {
            throw new ArgumentException("Invalid X25519 public key", nameof(newDevicePublicKey));
        }

        try
        {
            // Use Signal-compliant HKDF (simplified from before)
            return Sodium.HkdfDerive(
                newDevicePublicKey,
                existingSharedKey,
                "LibEmiddle-DeviceLinking-v3"u8.ToArray(),
                32);
        }
        catch (Exception ex) when (ex is not ArgumentException)
        {
            throw new CryptographicException("Failed to derive shared key for new device", ex);
        }
    }

    /// <summary>
    /// Creates an encrypted device link message for establishing multi-device communication.
    /// 
    /// <para>
    /// Creates an encrypted message that can be sent to a new device to establish
    /// a secure communication channel. The message includes the main device's public key
    /// and a signature of the new device's public key for authenticity verification.
    /// </para>
    /// </summary>
    /// <param name="mainDeviceKeyPair">The main device's identity key pair (Ed25519)</param>
    /// <param name="newDevicePublicKey">The public key of the new device to link</param>
    /// <returns>An encrypted message containing linking information</returns>
    /// <exception cref="ArgumentNullException">Thrown if inputs are null</exception>
    /// <exception cref="ArgumentException">Thrown if keys are invalid or have wrong format</exception>
    /// <exception cref="CryptographicException">Thrown if encryption or signing fails</exception>
    public EncryptedMessage CreateDeviceLinkMessage(KeyPair mainDeviceKeyPair, byte[] newDevicePublicKey)
    {
        // Validate main device key pair (must be Ed25519)
        ArgumentNullException.ThrowIfNull(mainDeviceKeyPair.PublicKey, nameof(mainDeviceKeyPair.PublicKey));
        ArgumentNullException.ThrowIfNull(mainDeviceKeyPair.PrivateKey, nameof(mainDeviceKeyPair.PrivateKey));
        ArgumentNullException.ThrowIfNull(newDevicePublicKey, nameof(newDevicePublicKey));

        if (mainDeviceKeyPair.PublicKey.Length != Constants.ED25519_PUBLIC_KEY_SIZE ||
            mainDeviceKeyPair.PrivateKey.Length != Constants.ED25519_PRIVATE_KEY_SIZE)
        {
            throw new ArgumentException("Main device key pair must be an Ed25519 key pair", nameof(mainDeviceKeyPair));
        }

        if (!_cryptoProvider.ValidateEd25519PublicKey(mainDeviceKeyPair.PublicKey))
        {
            throw new ArgumentException("Invalid Ed25519 public key in main device key pair", nameof(mainDeviceKeyPair));
        }

        byte[]? mainDeviceX25519Private = null;
        byte[]? newDeviceX25519Public = null;
        byte[]? sharedSecret = null;

        try
        {
            // Convert main device's Ed25519 private key to X25519 for ECDH
            mainDeviceX25519Private = _cryptoProvider.ConvertEd25519PrivateKeyToX25519(mainDeviceKeyPair.PrivateKey);

            // Normalize and validate new device's public key
            newDeviceX25519Public = NormalizeToX25519PublicKey(newDevicePublicKey);

            // Perform X25519 ECDH to get shared secret
            sharedSecret = _cryptoProvider.ScalarMult(mainDeviceX25519Private, newDeviceX25519Public);

            // Sign the new device's public key using the main device's Ed25519 private key
            byte[] signature = _cryptoProvider.Sign(newDevicePublicKey, mainDeviceKeyPair.PrivateKey);

            // Create the payload containing main device's public key and signature
            var payload = new
            {
                mainDevicePublicKey = Convert.ToBase64String(mainDeviceKeyPair.PublicKey),
                signature = Convert.ToBase64String(signature),
                timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                protocolVersion = ProtocolVersion.FULL_VERSION
            };

            // Serialize and encrypt the payload
            string json = System.Text.Json.JsonSerializer.Serialize(payload);
            byte[] plaintext = Encoding.UTF8.GetBytes(json);
            byte[] nonce = Nonce.GenerateNonce();
            byte[] ciphertext = AES.AESEncrypt(plaintext, sharedSecret, nonce);

            // Convert main device's Ed25519 public key to X25519 for SenderDHKey
            byte[] mainDeviceX25519Public = _cryptoProvider.ConvertEd25519PublicKeyToX25519(mainDeviceKeyPair.PublicKey);

            return new EncryptedMessage
            {
                Ciphertext = ciphertext,
                Nonce = nonce,
                SenderDHKey = mainDeviceX25519Public,
                Timestamp = payload.timestamp,
                SenderMessageNumber = 0,
                SessionId = Guid.NewGuid().ToString(),
                MessageId = Guid.NewGuid().ToString()
            };
        }
        catch (Exception ex) when (ex is not ArgumentException and not ArgumentNullException)
        {
            throw new CryptographicException("Failed to create device link message", ex);
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
    /// Processes and verifies a device link message on the new device.
    /// 
    /// <para>
    /// Verifies and processes a device link message received from the main device.
    /// If the message is valid and properly signed, it extracts the main device's
    /// public key for establishing a trusted communication channel.
    /// </para>
    /// </summary>
    /// <param name="encryptedMessage">The encrypted device link message to process</param>
    /// <param name="newDeviceKeyPair">The new device's identity key pair (Ed25519)</param>
    /// <param name="expectedMainDevicePublicKey">The expected public key of the main device</param>
    /// <returns>The main device's public key if verification succeeds, null otherwise</returns>
    /// <exception cref="ArgumentNullException">Thrown if required parameters are null</exception>
    public byte[]? ProcessDeviceLinkMessage(
        EncryptedMessage encryptedMessage,
        KeyPair newDeviceKeyPair,
        byte[] expectedMainDevicePublicKey)
    {
        ArgumentNullException.ThrowIfNull(encryptedMessage, nameof(encryptedMessage));
        ArgumentNullException.ThrowIfNull(newDeviceKeyPair.PublicKey, nameof(newDeviceKeyPair.PublicKey));
        ArgumentNullException.ThrowIfNull(newDeviceKeyPair.PrivateKey, nameof(newDeviceKeyPair.PrivateKey));
        ArgumentNullException.ThrowIfNull(expectedMainDevicePublicKey, nameof(expectedMainDevicePublicKey));

        // Validate message has required fields
        if (encryptedMessage.Ciphertext == null ||
            encryptedMessage.Nonce == null ||
            encryptedMessage.SenderDHKey == null)
        {
            LoggingManager.LogWarning(nameof(DeviceLinkingService),
                "Device link message missing required fields");
            return null;
        }

        // Validate new device key pair format
        if (newDeviceKeyPair.PublicKey.Length != Constants.ED25519_PUBLIC_KEY_SIZE ||
            newDeviceKeyPair.PrivateKey.Length != Constants.ED25519_PRIVATE_KEY_SIZE)
        {
            LoggingManager.LogWarning(nameof(DeviceLinkingService),
                "New device key pair must be Ed25519 format");
            return null;
        }

        if (!_cryptoProvider.ValidateEd25519PublicKey(newDeviceKeyPair.PublicKey))
        {
            LoggingManager.LogWarning(nameof(DeviceLinkingService),
                "Invalid Ed25519 public key in new device key pair");
            return null;
        }

        byte[]? newDeviceX25519Private = null;
        byte[]? sharedSecret = null;

        try
        {
            // Check replay protection using timestamp
            long currentTimestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            if (Math.Abs(currentTimestamp - encryptedMessage.Timestamp) > AllowedTimestampSkewMilliseconds)
            {
                LoggingManager.LogWarning(nameof(DeviceLinkingService),
                    "Device link message rejected due to timestamp outside allowed window");
                return null;
            }

            // Convert new device's Ed25519 private key to X25519 for ECDH
            newDeviceX25519Private = _cryptoProvider.ConvertEd25519PrivateKeyToX25519(newDeviceKeyPair.PrivateKey);

            // Validate main device's X25519 public key from message
            byte[] mainDeviceX25519Public = encryptedMessage.SenderDHKey;
            if (mainDeviceX25519Public.Length != Constants.X25519_KEY_SIZE)
            {
                LoggingManager.LogWarning(nameof(DeviceLinkingService),
                    $"Invalid main device X25519 public key length: {mainDeviceX25519Public.Length}");
                return null;
            }

            if (!_cryptoProvider.ValidateX25519PublicKey(mainDeviceX25519Public))
            {
                LoggingManager.LogWarning(nameof(DeviceLinkingService),
                    "Invalid X25519 public key in SenderDHKey");
                return null;
            }

            // Perform ECDH to compute shared secret
            sharedSecret = _cryptoProvider.ScalarMult(newDeviceX25519Private, mainDeviceX25519Public);

            // Decrypt the message payload
            byte[] plaintext = AES.AESDecrypt(
                encryptedMessage.Ciphertext,
                sharedSecret,
                encryptedMessage.Nonce);

            string json = Encoding.UTF8.GetString(plaintext);

            // Parse the payload
            var data = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(json);
            if (data == null ||
                !data.TryGetValue("mainDevicePublicKey", out var mainKeyObj) ||
                !data.TryGetValue("signature", out var sigObj))
            {
                LoggingManager.LogWarning(nameof(DeviceLinkingService),
                    "Device link message payload missing required fields");
                return null;
            }

            string mainKeyBase64 = mainKeyObj.ToString() ?? throw new InvalidOperationException("Main device key is null");
            string signatureBase64 = sigObj.ToString() ?? throw new InvalidOperationException("Signature is null");

            byte[] mainDeviceEd25519Public = Convert.FromBase64String(mainKeyBase64);
            byte[] signature = Convert.FromBase64String(signatureBase64);

            // Verify the main device public key matches expected
            if (!SecureMemory.SecureCompare(mainDeviceEd25519Public, expectedMainDevicePublicKey))
            {
                LoggingManager.LogWarning(nameof(DeviceLinkingService),
                    "Device link message rejected: main device public key mismatch");
                return null;
            }

            // Verify the signature of the new device's public key
            if (!_cryptoProvider.VerifySignature(newDeviceKeyPair.PublicKey, signature, mainDeviceEd25519Public))
            {
                LoggingManager.LogWarning(nameof(DeviceLinkingService),
                    "Device link message signature verification failed");
                return null;
            }

            LoggingManager.LogInformation(nameof(DeviceLinkingService),
                "Device link message processed successfully");

            return mainDeviceEd25519Public;
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
    /// Creates a cryptographically signed device revocation message.
    /// 
    /// <para>
    /// Creates a tamper-proof revocation message that can be distributed to revoke
    /// a device's access. The message is signed with the user's identity key to
    /// ensure authenticity and prevent unauthorized revocations.
    /// </para>
    /// </summary>
    /// <param name="userIdentityKeyPair">The user's identity key pair for signing</param>
    /// <param name="deviceToRevokePublicKey">The public key of the device to revoke</param>
    /// <param name="reason">Optional reason for the revocation</param>
    /// <returns>A signed device revocation message</returns>
    /// <exception cref="ArgumentNullException">Thrown if required parameters are null</exception>
    /// <exception cref="ArgumentException">Thrown if keys are invalid</exception>
    /// <exception cref="CryptographicException">Thrown if signing fails</exception>
    /// <exception cref="InvalidOperationException">Thrown if trying to revoke own device</exception>
    public DeviceRevocationMessage CreateDeviceRevocationMessage(
        KeyPair userIdentityKeyPair,
        byte[] deviceToRevokePublicKey,
        string? reason = null)
    {
        ArgumentNullException.ThrowIfNull(userIdentityKeyPair, nameof(userIdentityKeyPair));
        ArgumentNullException.ThrowIfNull(userIdentityKeyPair.PublicKey, nameof(userIdentityKeyPair.PublicKey));
        ArgumentNullException.ThrowIfNull(userIdentityKeyPair.PrivateKey, nameof(userIdentityKeyPair.PrivateKey));
        ArgumentNullException.ThrowIfNull(deviceToRevokePublicKey, nameof(deviceToRevokePublicKey));

        // Validate user identity key pair
        if (userIdentityKeyPair.PublicKey.Length != Constants.ED25519_PUBLIC_KEY_SIZE ||
            userIdentityKeyPair.PrivateKey.Length != Constants.ED25519_PRIVATE_KEY_SIZE)
        {
            throw new ArgumentException("User identity key pair must be Ed25519 format", nameof(userIdentityKeyPair));
        }

        if (!_cryptoProvider.ValidateEd25519PublicKey(userIdentityKeyPair.PublicKey))
        {
            throw new ArgumentException("Invalid Ed25519 public key in user identity key pair", nameof(userIdentityKeyPair));
        }

        byte[]? normalizedDeviceKey = null;
        byte[]? normalizedUserKey = null;

        try
        {
            // Normalize device key to X25519 format for consistent comparison
            normalizedDeviceKey = NormalizeToX25519PublicKey(deviceToRevokePublicKey);
            normalizedUserKey = _cryptoProvider.ConvertEd25519PublicKeyToX25519(userIdentityKeyPair.PublicKey);

            // Prevent revoking own device by comparing normalized keys
            if (SecureMemory.SecureCompare(normalizedDeviceKey, normalizedUserKey))
            {
                throw new InvalidOperationException("Cannot revoke your own device");
            }

            // Create the revocation message
            var revocationMessage = new DeviceRevocationMessage
            {
                RevokedDevicePublicKey = normalizedDeviceKey.ToArray(), // Store in normalized X25519 format
                UserIdentityPublicKey = userIdentityKeyPair.PublicKey.ToArray(),
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                Reason = reason,
                Version = ProtocolVersion.FULL_VERSION
            };

            // Create data to sign
            byte[] dataToSign = GetRevocationDataToSign(revocationMessage);

            // Sign with the user's identity private key
            revocationMessage.Signature = _cryptoProvider.Sign(dataToSign, userIdentityKeyPair.PrivateKey);

            LoggingManager.LogInformation(nameof(DeviceLinkingService),
                $"Created device revocation message for device. Reason: {reason ?? "Not specified"}");

            return revocationMessage;
        }
        catch (Exception ex) when (ex is not ArgumentException and not ArgumentNullException and not InvalidOperationException)
        {
            LoggingManager.LogError(nameof(DeviceLinkingService), $"Error creating device revocation message: {ex.Message}");
            throw new CryptographicException("Failed to create device revocation message", ex);
        }
        finally
        {
            // Clear sensitive key material (but not the keys we return in the message)
            if (normalizedUserKey != null)
                SecureMemory.SecureClear(normalizedUserKey);
        }
    }

    /// <summary>
    /// Verifies the cryptographic authenticity of a device revocation message.
    /// 
    /// <para>
    /// Verifies that a revocation message is authentic, properly signed, and not
    /// subject to replay attacks. This ensures that only authorized parties can
    /// revoke devices and that revocation messages cannot be tampered with.
    /// </para>
    /// </summary>
    /// <param name="revocationMessage">The revocation message to verify</param>
    /// <param name="trustedUserIdentityKey">The trusted identity key of the user</param>
    /// <returns>True if the revocation message is valid and properly signed</returns>
    /// <exception cref="ArgumentNullException">Thrown if parameters are null</exception>
    public bool VerifyDeviceRevocationMessage(
        DeviceRevocationMessage revocationMessage,
        byte[] trustedUserIdentityKey)
    {
        ArgumentNullException.ThrowIfNull(revocationMessage, nameof(revocationMessage));
        ArgumentNullException.ThrowIfNull(trustedUserIdentityKey, nameof(trustedUserIdentityKey));

        // Basic validation
        if (!revocationMessage.IsValid())
        {
            LoggingManager.LogWarning(nameof(DeviceLinkingService),
                "Revocation message failed basic validation");
            return false;
        }

        if (revocationMessage.Signature == null || revocationMessage.UserIdentityPublicKey == null)
        {
            LoggingManager.LogWarning(nameof(DeviceLinkingService),
                "Revocation message missing signature or user identity key");
            return false;
        }

        // Validate trusted user identity key
        if (trustedUserIdentityKey.Length != Constants.ED25519_PUBLIC_KEY_SIZE ||
            !_cryptoProvider.ValidateEd25519PublicKey(trustedUserIdentityKey))
        {
            LoggingManager.LogWarning(nameof(DeviceLinkingService),
                "Invalid trusted user identity key");
            return false;
        }

        try
        {
            // Verify the message is from the expected user identity
            if (!SecureMemory.SecureCompare(revocationMessage.UserIdentityPublicKey, trustedUserIdentityKey))
            {
                LoggingManager.LogWarning(nameof(DeviceLinkingService),
                    "Revocation message has unexpected user identity key");
                return false;
            }

            // Check timestamp to prevent replay attacks
            long currentTimestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            long messageAge = currentTimestamp - revocationMessage.Timestamp;

            // Message too old or from the future (with tolerance for clock skew)
            if (messageAge < -AllowedTimestampSkewMilliseconds || messageAge > Constants.MAX_REVOCATION_AGE_MS)
            {
                LoggingManager.LogWarning(nameof(DeviceLinkingService),
                    $"Revocation message has invalid timestamp. Age: {messageAge}ms");
                return false;
            }

            // Get the data that was signed and verify signature
            byte[] dataToSign = GetRevocationDataToSign(revocationMessage);
            bool isValid = _cryptoProvider.VerifySignature(dataToSign, revocationMessage.Signature, trustedUserIdentityKey);

            if (isValid)
            {
                LoggingManager.LogInformation(nameof(DeviceLinkingService),
                    "Device revocation message verified successfully");
            }
            else
            {
                LoggingManager.LogWarning(nameof(DeviceLinkingService),
                    "Device revocation message signature verification failed");
            }

            return isValid;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(DeviceLinkingService),
                $"Error verifying device revocation message: {ex.Message}");
            return false;
        }
    }

    #region Private Helper Methods

    /// <summary>
    /// Normalizes a public key to X25519 format for consistent processing.
    /// </summary>
    /// <param name="publicKey">The public key to normalize (Ed25519 or X25519)</param>
    /// <returns>The key in X25519 format</returns>
    /// <exception cref="ArgumentException">Thrown if the key is invalid or has wrong length</exception>
    private byte[] NormalizeToX25519PublicKey(byte[] publicKey)
    {
        if (publicKey.Length == Constants.X25519_KEY_SIZE)
        {
            // Already X25519 format, validate and return copy
            if (!_cryptoProvider.ValidateX25519PublicKey(publicKey))
            {
                throw new ArgumentException("Invalid X25519 public key", nameof(publicKey));
            }
            return publicKey.ToArray();
        }
        else if (publicKey.Length == Constants.ED25519_PUBLIC_KEY_SIZE)
        {
            // Ed25519 format, validate and convert to X25519
            if (!_cryptoProvider.ValidateEd25519PublicKey(publicKey))
            {
                throw new ArgumentException("Invalid Ed25519 public key", nameof(publicKey));
            }
            return _cryptoProvider.ConvertEd25519PublicKeyToX25519(publicKey);
        }
        else
        {
            throw new ArgumentException(
                $"Invalid public key length: {publicKey.Length}. " +
                $"Expected {Constants.ED25519_PUBLIC_KEY_SIZE} or {Constants.X25519_KEY_SIZE} bytes",
                nameof(publicKey));
        }
    }

    /// <summary>
    /// Constructs the data to be signed for a device revocation message.
    /// </summary>
    /// <param name="revocationMessage">The revocation message</param>
    /// <returns>The byte array representing the data to sign</returns>
    /// <exception cref="ArgumentNullException">Thrown if required fields are null</exception>
    private static byte[] GetRevocationDataToSign(DeviceRevocationMessage revocationMessage)
    {
        if (revocationMessage.RevokedDevicePublicKey == null)
            throw new ArgumentNullException(nameof(revocationMessage.RevokedDevicePublicKey));
        if (revocationMessage.UserIdentityPublicKey == null)
            throw new ArgumentNullException(nameof(revocationMessage.UserIdentityPublicKey));

        // Combine fields in a deterministic order for signing
        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);

        // Core revocation data
        writer.Write(revocationMessage.RevokedDevicePublicKey);
        writer.Write(revocationMessage.UserIdentityPublicKey);
        writer.Write(revocationMessage.Timestamp);
        writer.Write(Encoding.UTF8.GetBytes(revocationMessage.Id));

        // Optional reason
        if (!string.IsNullOrEmpty(revocationMessage.Reason))
        {
            writer.Write(Encoding.UTF8.GetBytes(revocationMessage.Reason));
        }

        // Protocol version for future compatibility
        writer.Write(Encoding.UTF8.GetBytes(revocationMessage.Version));

        return ms.ToArray();
    }

    #endregion

    #region IDisposable Implementation

    /// <summary>
    /// Throws an ObjectDisposedException if this object has been disposed.
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
    /// <param name="disposing">True if disposing, false if finalizing</param>
    private void Dispose(bool disposing)
    {
        if (_disposed)
            return;

        if (disposing)
        {
            // Dispose managed resources if needed
            // Note: ICryptoProvider disposal is handled by the DI container
        }

        _disposed = true;
    }

    #endregion
}