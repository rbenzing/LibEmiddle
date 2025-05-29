#pragma warning disable IDE0130 // Namespace does not match folder structure
namespace LibEmiddle.Domain
#pragma warning restore IDE0130 // Namespace does not match folder structure
{
    /// <summary>
    /// DTO for serializing and deserializing group session state.
    /// </summary>
    public class GroupSessionDto
    {
        /// <summary>
        /// Gets or sets the unique identifier for the group.
        /// </summary>
        public string GroupId { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the Base64-encoded current chain key.
        /// </summary>
        public string ChainKeyBase64 { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the current chain key iteration.
        /// </summary>
        public uint Iteration { get; set; }

        /// <summary>
        /// Gets or sets the Base64-encoded creator identity public key.
        /// </summary>
        public string CreatorIdentityKeyBase64 { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the timestamp of group session creation.
        /// </summary>
        public DateTime CreationTimestamp { get; set; }

        /// <summary>
        /// Gets or sets the timestamp when the session keys were established.
        /// </summary>
        public DateTime KeyEstablishmentTimestamp { get; set; }

        /// <summary>
        /// Gets or sets serialized metadata as JSON (nullable).
        /// </summary>
        public string? MetadataJson { get; set; }
    }
}
