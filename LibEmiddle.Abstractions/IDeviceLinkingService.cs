using LibEmiddle.Domain;

namespace LibEmiddle.Abstractions
{
    /// <summary>
    /// Defines the contract for a service that handles device linking and revocation
    /// between multiple devices belonging to the same user identity.
    /// </summary>
    public interface IDeviceLinkingService : IDisposable
    {
        /// <summary>
        /// Derives a shared key for a new device using X25519 key exchange.
        /// </summary>
        /// <param name="existingSharedKey">Existing device's X25519 private key (32 bytes).</param>
        /// <param name="newDevicePublicKey">New device's X25519 public key (32 bytes).</param>
        /// <returns>32-byte shared key for the new device.</returns>
        byte[] DeriveSharedKeyForNewDevice(byte[] existingSharedKey, byte[] newDevicePublicKey);

        /// <summary>
        /// Creates a device link message for establishing multi-device sync.
        /// </summary>
        /// <param name="mainDeviceKeyPair">The main device's Ed25519 identity key pair.</param>
        /// <param name="newDevicePublicKey">The Ed25519 or X25519 public key of the new device to link (32 bytes).</param>
        /// <returns>An encrypted message containing linking information.</returns>
        EncryptedMessage CreateDeviceLinkMessage(KeyPair mainDeviceKeyPair, byte[] newDevicePublicKey);

        /// <summary>
        /// Processes a device link message on the new device.
        /// </summary>
        /// <param name="encryptedMessage">The encrypted device link message.</param>
        /// <param name="newDeviceKeyPair">The new device's Ed25519 identity key pair.</param>
        /// <param name="expectedMainDevicePublicKey">The expected Ed25519 public key of the main device (32 bytes).</param>
        /// <returns>The main device's Ed25519 public key if verification succeeds, null otherwise.</returns>
        byte[]? ProcessDeviceLinkMessage(
            EncryptedMessage encryptedMessage,
            KeyPair newDeviceKeyPair,
            byte[] expectedMainDevicePublicKey);

        /// <summary>
        /// Creates a device revocation message.
        /// </summary>
        /// <param name="userIdentityKeyPair">The user's Ed25519 identity key pair used to sign the revocation.</param>
        /// <param name="deviceToRevokePublicKey">The Ed25519 or X25519 public key of the device to revoke (32 bytes).</param>
        /// <param name="reason">Optional reason for the revocation.</param>
        /// <returns>A signed device revocation message.</returns>
        DeviceRevocationMessage CreateDeviceRevocationMessage(
            KeyPair userIdentityKeyPair,
            byte[] deviceToRevokePublicKey,
            string? reason = null);

        /// <summary>
        /// Verifies a device revocation message.
        /// </summary>
        /// <param name="revocationMessage">The revocation message to verify.</param>
        /// <param name="trustedUserIdentityKey">The trusted Ed25519 identity key of the user who owns the devices (32 bytes).</param>
        /// <returns>True if the revocation message is valid and properly signed.</returns>
        bool VerifyDeviceRevocationMessage(
            DeviceRevocationMessage revocationMessage,
            byte[] trustedUserIdentityKey);
    }
}