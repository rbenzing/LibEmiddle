namespace LibEmiddle.Domain.DTO
{
    /// <summary>
    /// DTO for serializing and deserializing Double Ratchet session state.
    /// </summary>
    public class DoubleRatchetSessionDto
    {
        /// <summary>
        /// Gets or sets the unique identifier for this session.
        /// </summary>
        public string SessionId { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the Base64-encoded root key of the Double Ratchet protocol.
        /// </summary>
        public string RootKey { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the Base64-encoded sender chain key.
        /// </summary>
        public string? SenderChainKey { get; set; }

        /// <summary>
        /// Gets or sets the Base64-encoded receiver chain key.
        /// </summary>
        public string? ReceiverChainKey { get; set; }

        /// <summary>
        /// Gets or sets the sender ratchet key pair.
        /// </summary>
        public KeyPairDto SenderRatchetKeyPair { get; set; } = new KeyPairDto();

        /// <summary>
        /// Gets or sets the Base64-encoded receiver ratchet public key.
        /// </summary>
        public string? ReceiverRatchetPublicKey { get; set; }

        /// <summary>
        /// Gets or sets the Base64-encoded previous receiver ratchet public key.
        /// </summary>
        public string? PreviousReceiverRatchetPublicKey { get; set; }

        /// <summary>
        /// Gets or sets the sender message number.
        /// </summary>
        public uint SendMessageNumber { get; set; }

        /// <summary>
        /// Gets or sets the receiver message number.
        /// </summary>
        public uint ReceiveMessageNumber { get; set; }

        /// <summary>
        /// Gets or sets the dictionary of sent message keys.
        /// Key is message number, value is Base64-encoded key.
        /// </summary>
        public Dictionary<uint, string> SentMessages { get; set; } = new Dictionary<uint, string>();

        /// <summary>
        /// Gets or sets the dictionary of skipped message keys.
        /// Key is a SkippedMessageKeyDto, value is Base64-encoded key.
        /// </summary>
        public Dictionary<SkippedMessageKeyDto, string> SkippedMessageKeys { get; set; } =
            new Dictionary<SkippedMessageKeyDto, string>();

        /// <summary>
        /// Gets or sets whether the session is initialized.
        /// </summary>
        public bool IsInitialized { get; set; }

        /// <summary>
        /// Gets or sets the creation timestamp (milliseconds since Unix epoch).
        /// </summary>
        public long CreationTimestamp { get; set; }
    }
}
