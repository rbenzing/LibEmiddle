namespace LibEmiddle.Domain
{
    /// <summary>
    /// Metadata class for key files to support salt rotation
    /// </summary>
    public class KeyFileMetadata
    {

        /// <summary>
        /// Gets or sets the key identifier.
        /// </summary>
        public string KeyId { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the type of key.
        /// </summary>
        public string KeyType { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets when the key was created.
        /// </summary>
        public DateTime CreatedAt { get; set; }

        /// <summary>
        /// Gets or sets when the key was last updated.
        /// </summary>
        public DateTime UpdatedAt { get; set; }

        /// <summary>
        /// Gets or sets the version of the library that created this key.
        /// </summary>
        public string Version { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the nonce used for encryption (if applicable).
        /// </summary>
        public byte[]? Nonce { get; set; }

        /// <summary>
        /// Number of days before the salt should be rotated
        /// </summary>
        public int RotationPeriodDays { get; set; } = 30;

        /// <summary>
        /// Timestamp when the salt was last rotated
        /// </summary>
        public long RotationTimestamp { get; set; }
    }
}
