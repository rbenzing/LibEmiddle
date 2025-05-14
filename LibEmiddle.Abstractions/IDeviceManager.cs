using LibEmiddle.Domain;
using System.Security;

namespace LibEmiddle.MultiDevice
{
    /// <summary>
    /// Interface for managing multiple devices in an end-to-end encrypted system.
    /// Allows for adding, removing, and syncing data between devices using the Signal Protocol.
    /// </summary>
    public interface IDeviceManager : IDisposable
    {
        /// <summary>
        /// Adds a linked device using its public key.
        /// </summary>
        /// <param name="devicePublicKey">Public key of the device to link.</param>
        /// <exception cref="ArgumentNullException">Thrown when devicePublicKey is null.</exception>
        /// <exception cref="SecurityException">Thrown when trying to add a previously revoked device.</exception>
        void AddLinkedDevice(byte[] devicePublicKey);

        /// <summary>
        /// Removes a linked device.
        /// </summary>
        /// <param name="devicePublicKey">Public key of the device to remove.</param>
        /// <returns>True if the device was found and removed, false otherwise.</returns>
        /// <exception cref="ArgumentNullException">Thrown when devicePublicKey is null.</exception>
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
        /// <param name="deviceKeyToRevoke">The public key of the device to revoke.</param>
        /// <returns>A signed revocation message that can be distributed to other devices.</returns>
        /// <exception cref="ArgumentException">Thrown when deviceKeyToRevoke is null or empty.</exception>
        /// <exception cref="ObjectDisposedException">Thrown if the manager has been disposed.</exception>
        DeviceRevocationMessage CreateRevocationMessage(byte[] deviceKeyToRevoke);

        /// <summary>
        /// Revokes a linked device and creates a revocation message.
        /// </summary>
        /// <param name="devicePublicKey">Public key of the device to revoke.</param>
        /// <returns>A revocation message that should be distributed to other devices.</returns>
        /// <exception cref="ArgumentNullException">Thrown when devicePublicKey is null.</exception>
        /// <exception cref="KeyNotFoundException">Thrown when the device is not found in linked devices.</exception>
        /// <exception cref="ObjectDisposedException">Thrown if the manager has been disposed.</exception>
        DeviceRevocationMessage RevokeLinkedDevice(byte[] devicePublicKey);

        /// <summary>
        /// Processes a revocation message received from another device.
        /// </summary>
        /// <param name="revocationMessage">The received revocation message.</param>
        /// <param name="trustedPublicKey">The trusted public key for verification.</param>
        /// <returns>True if the message was valid and the device was removed.</returns>
        /// <exception cref="ArgumentNullException">Thrown when revocationMessage or trustedPublicKey is null.</exception>
        /// <exception cref="ObjectDisposedException">Thrown if the manager has been disposed.</exception>
        bool ProcessRevocationMessage(DeviceRevocationMessage revocationMessage, byte[] trustedPublicKey);

        /// <summary>
        /// Exports all linked devices to a serialized format for backup.
        /// </summary>
        /// <param name="password">Optional password to encrypt the export.</param>
        /// <returns>Serialized linked devices data.</returns>
        /// <exception cref="ObjectDisposedException">Thrown if the manager has been disposed.</exception>
        byte[] ExportLinkedDevices(string? password = null);

        /// <summary>
        /// Imports linked devices from a serialized format.
        /// </summary>
        /// <param name="data">Serialized linked devices data.</param>
        /// <param name="password">Optional password if the data is encrypted.</param>
        /// <returns>Number of devices imported.</returns>
        /// <exception cref="ArgumentException">Thrown when data is null or empty.</exception>
        /// <exception cref="ObjectDisposedException">Thrown if the manager has been disposed.</exception>
        int ImportLinkedDevices(byte[] data, string? password = null);
    }
}