namespace LibEmiddle.Domain
{
    /// <summary>
    /// Stores information about a linked device.
    /// </summary>
    public class DeviceInfo
    {
        /// <summary>
        /// The device's public key (X25519 format).
        /// </summary>
        public byte[] PublicKey { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// When the device was linked (milliseconds since epoch).
        /// </summary>
        public long LinkedAt { get; set; }
    }
}
