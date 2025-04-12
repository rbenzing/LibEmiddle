namespace LibEmiddle.Models
{
    /// <summary>
    /// Metadata class for key files to support salt rotation
    /// </summary>
    public class KeyFileMetadata
    {
        /// <summary>
        /// File format version
        /// </summary>
        public int Version { get; set; } = 1;

        /// <summary>
        /// Timestamp when the key file was created
        /// </summary>
        public long CreatedAt { get; set; }

        /// <summary>
        /// Number of days before the salt should be rotated
        /// </summary>
        public int RotationPeriodDays { get; set; } = 30;

        /// <summary>
        /// Timestamp when the salt was last rotated
        /// </summary>
        public long LastRotated { get; set; }
    }
}
