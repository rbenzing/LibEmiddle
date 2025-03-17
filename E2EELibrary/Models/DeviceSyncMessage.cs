
namespace E2EELibrary.Models
{
    /// <summary>
    /// Updates the DeviceSyncMessage class to include timestamp for replay protection
    /// </summary>
    public class DeviceSyncMessage
    {
        /// <summary>
        /// Sender device's public key
        /// </summary>
        public byte[]? SenderPublicKey { get; set; }

        /// <summary>
        /// Data to sync
        /// </summary>
        public byte[]? Data { get; set; }

        /// <summary>
        /// Signature of the data
        /// </summary>
        public byte[]? Signature { get; set; }

        /// <summary>
        /// Timestamp to prevent replay attacks (milliseconds since Unix epoch)
        /// </summary>
        public long Timestamp { get; set; }
    }
}
