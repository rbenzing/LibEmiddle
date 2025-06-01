using LibEmiddle.Domain;
using System.Security;

namespace LibEmiddle.Abstractions
{
    /// <summary>
    /// Interface for managing multiple devices in an end-to-end encrypted system.
    /// Allows for adding, removing, and syncing data between devices using the Signal Protocol.
    /// </summary>
    public interface IDeviceManager : IDisposable
    {
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
        void AddLinkedDevice(byte[] devicePublicKey);

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
        bool RemoveLinkedDevice(byte[] devicePublicKey);

        /// <summary>
        /// Creates encrypted sync messages for other devices.
        /// </summary>
        /// <param name="syncData">Data to sync to other devices.</param>
        /// <returns>Dictionary mapping device identifiers to encrypted messages.</returns>
        /// <exception cref="ArgumentNullException">Thrown when syncData is null.</exception>
        /// <exception cref="ObjectDisposedException">Thrown if the manager has been disposed.</exception>
        Dictionary<string, EncryptedMessage> CreateSyncMessages(byte[] syncData);

        /// <summary>
        /// Processes a received sync message from another device.
        /// </summary>
        /// <param name="encryptedMessage">The encrypted message to process.</param>
        /// <param name="senderHint">Optional sender device key hint.</param>
        /// <returns>The decrypted sync data if successful, null otherwise.</returns>
        /// <exception cref="ArgumentNullException">Thrown when encryptedMessage is null.</exception>
        /// <exception cref="ObjectDisposedException">Thrown if the manager has been disposed.</exception>
        Task<byte[]?> ProcessSyncMessageAsync(EncryptedMessage encryptedMessage, byte[]? senderHint = null);

        /// <summary>
        /// Gets the number of linked devices.
        /// </summary>
        /// <returns>The number of unique linked devices.</returns>
        /// <exception cref="ObjectDisposedException">Thrown if the manager has been disposed.</exception>
        int GetLinkedDeviceCount();

        /// <summary>
        /// Checks if a device is already linked.
        /// </summary>
        /// <param name="devicePublicKey">Public key of the device to check.</param>
        /// <returns>True if the device is linked, false otherwise.</returns>
        /// <exception cref="ObjectDisposedException">Thrown if the manager has been disposed.</exception>
        bool IsDeviceLinked(ReadOnlySpan<byte> devicePublicKey);

        /// <summary>
        /// Checks if a device has been revoked.
        /// </summary>
        /// <param name="devicePublicKey">Public key of the device to check.</param>
        /// <returns>True if the device was revoked, false otherwise.</returns>
        bool IsDeviceRevoked(byte[] devicePublicKey);

        /// <summary>
        /// Creates a revocation message for a device.
        /// </summary>
        /// <param name="devicePublicKey">The public key of the device to revoke.</param>
        /// <param name="reason">Optional reason for the revocation.</param>
        /// <returns>A signed revocation message that can be distributed to other devices.</returns>
        /// <exception cref="ArgumentException">Thrown when deviceKeyToRevoke is null or empty.</exception>
        /// <exception cref="ObjectDisposedException">Thrown if the manager has been disposed.</exception>
        DeviceRevocationMessage CreateDeviceRevocationMessage(byte[] devicePublicKey, string? reason = null);

        /// <summary>
        /// Processes a revocation message received from another device.
        /// </summary>
        /// <param name="revocationMessage">The received revocation message.</param>
        /// <returns>True if the message was valid and the device was removed.</returns>
        /// <exception cref="ArgumentNullException">Thrown when revocationMessage or trustedPublicKey is null.</exception>
        /// <exception cref="ObjectDisposedException">Thrown if the manager has been disposed.</exception>
        bool ProcessDeviceRevocationMessage(DeviceRevocationMessage revocationMessage);

        /// <summary>
        /// Imports device revocations from a serialized representation.
        /// </summary>
        /// <param name="serializedRevocations">The serialized revocations</param>
        /// <returns>The number of imported revocations</returns>
        int ImportRevocations(string serializedRevocations);

        /// <summary>
        /// Exports the device revocations for persistence.
        /// </summary>
        /// <returns>Serialized representation of all processed revocations</returns>
        string ExportRevocations();

        /// <summary>
        /// Gets a list of all revoked device public keys.
        /// </summary>
        /// <returns>A list of revoked device public keys (in normalized X25519 format)</returns>
        public List<byte[]> GetRevokedDeviceKeys();

        /// <summary>
        /// Exports linked devices to a serialized representation for persistence.
        /// </summary>
        /// <returns>A JSON serialized representation of linked devices.</returns>
        string ExportLinkedDevices();

        /// <summary>
        /// Imports linked devices from a serialized representation.
        /// </summary>
        /// <param name="serializedDevices">The serialized devices data.</param>
        /// <returns>The number of imported devices.</returns>
        int ImportLinkedDevices(string serializedDevices);

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
        byte[]? ProcessSyncMessage(EncryptedMessage encryptedMessage, byte[]? senderHint = null);

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
        bool ProcessDeviceLinkMessage(EncryptedMessage encryptedMessage, byte[] expectedMainDevicePublicKey);

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
        EncryptedMessage CreateDeviceLinkMessage(byte[] newDevicePublicKey);
    }
}