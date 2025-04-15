namespace LibEmiddle.Domain
{
    /// <summary>
    /// Sender key distribution message for group messaging
    /// </summary>
    public class SenderKeyDistributionMessage
    {
        /// <summary>
        /// Group identifier
        /// </summary>
        public string? GroupId { get; set; }

        /// <summary>
        /// Current chain key for the group
        /// </summary>
        public byte[]? ChainKey { get; set; }

        /// <summary>
        /// Current iteration number of the chain key
        /// This allows recipients to initialize their sender state correctly
        /// </summary>
        public uint Iteration { get; set; }

        /// <summary>
        /// Sender's identity key
        /// </summary>
        public byte[]? SenderIdentityKey { get; set; }

        /// <summary>
        /// Signature of the distribution message data
        /// </summary>
        public byte[]? Signature { get; set; }

        /// <summary>
        /// Message identifier
        /// </summary>
        public string? MessageId { get; set; }

        /// <summary>
        /// Timestamp for this distribution (milliseconds since Unix epoch)
        /// Used to implement backward secrecy - new members can only decrypt
        /// messages sent after they received the key
        /// </summary>
        public long Timestamp { get; set; } = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
    }
}