namespace LibEmiddle.Domain
{
    /// <summary>
    /// Represents the sender state for a group.
    /// </summary>
    public class GroupSenderState
    {
        /// <summary>
        /// Gets or sets the current chain key.
        /// </summary>
        public byte[] ChainKey { get; set; } = Array.Empty<byte>();

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
