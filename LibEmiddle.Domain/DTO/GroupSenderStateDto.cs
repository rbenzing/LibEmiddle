#pragma warning disable IDE0130 // Namespace does not match folder structurenamespace LibEmiddle.Domain
namespace LibEmiddle.Domain
#pragma warning restore IDE0130 // Namespace does not match folder structurenamespace LibEmiddle.Domain
{
    /// <summary>
    /// DTO for serializing and deserializing group sender state.
    /// </summary>
    public class GroupSenderStateDto
    {
        /// <summary>
        /// Gets or sets the Base64-encoded chain key.
        /// </summary>
        public string ChainKey { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the current iteration (message number).
        /// </summary>
        public uint Iteration { get; set; }

        /// <summary>
        /// Gets or sets the creation timestamp (milliseconds since Unix epoch).
        /// </summary>
        public long CreationTimestamp { get; set; }
    }
}
