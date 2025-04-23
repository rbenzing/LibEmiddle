namespace LibEmiddle.Domain
{
    /// <summary>
    /// Encrypted group message
    /// </summary>
    public class EncryptedGroupMessage
    {
        /// <summary>
        /// Unique message identifier
        /// </summary>
        public string? MessageId { get; set; }

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
        /// Timestamp of the last key rotation (helps enforce forward secrecy)
        /// </summary>
        public long KeyRotationTimestamp { get; set; }

        /// <summary>
        /// Chain key iteration number for ratchet protocol
        /// </summary>
        public uint Iteration { get; set; }

        /// <summary>
        /// Validates that all required fields are present
        /// </summary>
        /// <returns>True if the message is valid</returns>
        public bool IsValid()
        {
            return !string.IsNullOrEmpty(GroupId) &&
                   !string.IsNullOrEmpty(MessageId) &&
                   SenderIdentityKey != null &&
                   Ciphertext != null &&
                   Nonce != null &&
                   Timestamp > 0;
        }
    }
}