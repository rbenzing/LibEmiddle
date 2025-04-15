namespace LibEmiddle.Domain
{
    /// <summary>
    /// Encrypted group message
    /// </summary>
    public class EncryptedGroupMessage
    {
        /// <summary>
        /// Group identifier
        /// </summary>
        public string? GroupId { get; set; }

        /// <summary>
        /// Sender's identity key
        /// </summary>
        public byte[]? SenderIdentityKey { get; set; }

        /// <summary>
        /// Encrypted message
        /// </summary>
        public byte[]? Ciphertext { get; set; }

        /// <summary>
        /// Nonce used for encryption
        /// </summary>
        public byte[]? Nonce { get; set; }

        /// <summary>
        /// Timestamp to prevent replay attacks and ensure backward secrecy
        /// (milliseconds since Unix epoch)
        /// </summary>
        public long Timestamp { get; set; }

        /// <summary>
        /// Message identifier for access control and replay protection
        /// </summary>
        public string? MessageId { get; set; }

        /// <summary>
        /// Chain key iteration number for ratchet protocol
        /// </summary>
        public uint Iteration { get; set; }
    }
}