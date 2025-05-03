using System.Text.Json.Serialization;

namespace LibEmiddle.Domain
{
    /// <summary>
    /// Represents an encrypted message for individual communication, containing
    /// all necessary metadata for routing, decryption, and verification.
    /// </summary>
    public class EncryptedMessage
    {
        /// <summary>
        /// Gets or sets a unique identifier for this message.
        /// </summary>
        public string? MessageId { get; set; }

        /// <summary>
        /// Gets or sets the session identifier this message belongs to.
        /// </summary>
        public string SessionId { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the sender's DH ratchet public key.
        /// Used for the Double Ratchet protocol.
        /// </summary>
        public byte[]? SenderDHKey { get; set; }

        /// <summary>
        /// Gets or sets the sender's message number.
        /// Used for ordering messages and skipped message handling.
        /// </summary>
        public uint SenderMessageNumber { get; set; }

        /// <summary>
        /// Gets or sets the encrypted message content.
        /// </summary>
        public byte[]? Ciphertext { get; set; }

        /// <summary>
        /// Gets or sets the nonce used for encryption.
        /// </summary>
        public byte[]? Nonce { get; set; }

        /// <summary>
        /// Gets or sets the timestamp when the message was created
        /// (milliseconds since Unix epoch).
        /// </summary>
        public long Timestamp { get; set; }

        /// <summary>
        /// Gets or sets additional headers for the message.
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public Dictionary<string, string>? Headers { get; set; }

        /// <summary>
        /// Creates a deep clone of this encrypted message.
        /// </summary>
        /// <returns>A cloned copy of this encrypted message.</returns>
        public EncryptedMessage Clone()
        {
            return new EncryptedMessage
            {
                MessageId = MessageId,
                SessionId = SessionId,
                SenderDHKey = SenderDHKey?.ToArray(),
                SenderMessageNumber = SenderMessageNumber,
                Ciphertext = Ciphertext?.ToArray(),
                Nonce = Nonce?.ToArray(),
                Timestamp = Timestamp,
                Headers = Headers != null ? new Dictionary<string, string>(Headers) : null
            };
        }

        /// <summary>
        /// Validates that all required fields are present and properly formatted.
        /// </summary>
        /// <returns>True if the encrypted message is valid, false otherwise.</returns>
        public bool IsValid()
        {
            if (string.IsNullOrEmpty(SessionId))
                return false;

            if (SenderDHKey == null || SenderDHKey.Length == 0)
                return false;

            if (Ciphertext == null || Ciphertext.Length == 0)
                return false;

            if (Nonce == null || Nonce.Length == 0)
                return false;

            return true;
        }

        /// <summary>
        /// Gets the estimated size of this message in bytes.
        /// </summary>
        /// <returns>The estimated size in bytes.</returns>
        public int GetEstimatedSize()
        {
            int size = 0;

            // String sizes (assume UTF-8 encoding)
            size += (MessageId?.Length ?? 0) * sizeof(char);
            size += SessionId.Length * sizeof(char);

            // Byte arrays
            size += SenderDHKey?.Length ?? 0;
            size += Ciphertext?.Length ?? 0;
            size += Nonce?.Length ?? 0;

            // Other fields
            size += sizeof(uint); // SenderMessageNumber
            size += sizeof(long); // Timestamp

            // Headers
            if (Headers != null)
            {
                foreach (var kvp in Headers)
                {
                    size += kvp.Key.Length * sizeof(char);
                    size += kvp.Value.Length * sizeof(char);
                }
            }

            return size;
        }
    }
}