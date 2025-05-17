namespace LibEmiddle.Domain
{
    /// <summary>
    /// Serialization-friendly representation of linked device information.
    /// </summary>
    public class LinkedDeviceInfo
    {
        /// <summary>
        /// Gets or sets the device identifier.
        /// </summary>
        public string Id { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the Base64-encoded device public key.
        /// </summary>
        public string PublicKey { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets when the device was linked (milliseconds since epoch).
        /// </summary>
        public long LinkedAt { get; set; }
    }
}