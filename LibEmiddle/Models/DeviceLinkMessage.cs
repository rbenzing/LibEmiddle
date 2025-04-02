
namespace E2EELibrary.Models
{
    /// <summary>
    /// Device link message for multi-device setups
    /// </summary>
    public class DeviceLinkMessage
    {
        /// <summary>
        /// Main device's public key
        /// </summary>
        public byte[]? MainDevicePublicKey { get; set; }

        /// <summary>
        /// Signature of the new device's public key
        /// </summary>
        public byte[]? Signature { get; set; }
    }
}
