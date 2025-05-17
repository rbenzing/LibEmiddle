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
        /// Derives a shared key for a new device.
        /// </summary>
        /// <param name="existingSharedKey">Existing device's shared key.</param>
        /// <param name="newDevicePublicKey">New device's public key (Ed25519 or X25519).</param>
        /// <returns>Shared key for the new device.</returns>
        byte[] DeriveSharedKeyForNewDevice(byte[] existingSharedKey, byte[] newDevicePublicKey);

        /// <summary>
        /// Creates a device link message for establishing multi-device sync.
        /// </summary>
        /// <param name="mainDeviceKeyPair">The main device's identity key pair.</param>
        /// <param name="newDevicePublicKey">The public key of the new device to link.</param>
        /// <returns>An encrypted message containing linking information.</returns>
        EncryptedMessage CreateDeviceLinkMessage(KeyPair mainDeviceKeyPair, byte[] newDevicePublicKey);

        /// <summary>
        /// Processes a device link message on the new device.
        /// </summary>
        /// <param name="encryptedMessage">The encrypted device link message.</param>
        /// <param name="newDeviceKeyPair">The new device's identity key pair.</param>
        /// <param name="expectedMainDevicePublicKey">The expected public key of the main device.</param>
        /// <returns>The main device's public key if verification succeeds, null otherwise.</returns>
        byte[]? ProcessDeviceLinkMessage(
            EncryptedMessage encryptedMessage,
            KeyPair newDeviceKeyPair,
            byte[] expectedMainDevicePublicKey);

        /// <summary>
        /// Creates a device revocation message.
        /// </summary>
        /// <param name="userIdentityKeyPair">The user's identity key pair used to sign the revocation.</param>
        /// <param name="deviceToRevokePublicKey">The public key of the device to revoke.</param>
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
        /// <param name="trustedUserIdentityKey">The trusted identity key of the user who owns the devices.</param>
        /// <returns>True if the revocation message is valid and properly signed.</returns>
        bool VerifyDeviceRevocationMessage(
            DeviceRevocationMessage revocationMessage,
            byte[] trustedUserIdentityKey);
    }
}