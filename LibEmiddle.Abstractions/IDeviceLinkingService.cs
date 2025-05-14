using LibEmiddle.Domain;

namespace LibEmiddle.MultiDevice
{
    /// <summary>
    /// Defines the interface for device linking services that handle secure initialization
    /// of connections between multiple devices belonging to the same user identity.
    /// </summary>
    public interface IDeviceLinkingService : IDisposable
    {
        /// <summary>
        /// Creates a device link message for establishing multi-device sync.
        /// </summary>
        /// <param name="mainDeviceKeyPair">The main device's identity key pair</param>
        /// <param name="newDevicePublicKey">The public key of the new device to link</param>
        /// <returns>An encrypted message containing linking information</returns>
        EncryptedMessage CreateDeviceLinkMessage(KeyPair mainDeviceKeyPair, byte[] newDevicePublicKey);

        /// <summary>
        /// Processes a device link message on the new device.
        /// </summary>
        /// <param name="encryptedMessage">The encrypted device link message</param>
        /// <param name="newDeviceKeyPair">The new device's identity key pair</param>
        /// <param name="expectedMainDevicePublicKey">The expected public key of the main device</param>
        /// <returns>The main device's public key if verification succeeds, null otherwise</returns>
        byte[]? ProcessDeviceLinkMessage(EncryptedMessage encryptedMessage, KeyPair newDeviceKeyPair, byte[] expectedMainDevicePublicKey);

        /// <summary>
        /// Derives a shared key for a new device.
        /// </summary>
        /// <param name="existingSharedKey">Existing device's shared key</param>
        /// <param name="newDevicePublicKey">New device's public key</param>
        /// <returns>Shared key for the new device</returns>
        byte[] DeriveSharedKeyForNewDevice(byte[] existingSharedKey, byte[] newDevicePublicKey);
    }
}