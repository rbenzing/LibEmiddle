using System.Text.Json.Serialization;

namespace LibEmiddle.Domain
{
    /// <summary>
    /// Represents an encrypted message for group communication, containing
    /// all necessary metadata for routing, decryption, and verification.
    /// </summary>
    public class EncryptedGroupMessage
    {
        /// <summary>
        /// Gets or sets a unique identifier for this message.
        /// </summary>
        public string? MessageId { get; set; }

        /// <summary>
        /// Gets or sets the group identifier this message belongs to.
        /// </summary>
        public string GroupId { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the sender's identity public key.
        /// </summary>
        public byte[] SenderIdentityKey { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Gets or sets the encrypted message content.
        /// </summary>
        public byte[] Ciphertext { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Gets or sets the nonce used for encryption.
        /// </summary>
        public byte[] Nonce { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Gets or sets the timestamp when the message was created
        /// (milliseconds since Unix epoch).
        /// </summary>
        public long Timestamp { get; set; }

        /// <summary>
        /// Gets or sets the timestamp of the key rotation epoch that was used
        /// to encrypt this message (milliseconds since Unix epoch).
        /// </summary>
        public long RotationEpoch { get; set; }

        /// <summary>
        /// Gets or sets the signature of the message for authenticity verification.
        /// </summary>
        public byte[]? Signature { get; set; }

        /// <summary>
        /// Gets or sets additional headers for the message.
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public Dictionary<string, string>? Headers { get; set; }

        /// <summary>
        /// Creates a deep clone of this encrypted group message.
        /// </summary>
        /// <returns>A cloned copy of this encrypted group message.</returns>
        public EncryptedGroupMessage Clone()
        {
            return new EncryptedGroupMessage
            {
                MessageId = MessageId,
                GroupId = GroupId,
                SenderIdentityKey = SenderIdentityKey.ToArray(),
                Ciphertext = Ciphertext.ToArray(),
                Nonce = Nonce.ToArray(),
                Timestamp = Timestamp,
                RotationEpoch = RotationEpoch,
                Signature = Signature?.ToArray(),
                Headers = Headers != null ? new Dictionary<string, string>(Headers) : null
            };
        }

        /// <summary>
        /// Validates that all required fields are present and properly formatted.
        /// </summary>
        /// <returns>True if the encrypted message is valid, false otherwise.</returns>
        public bool IsValid()
        {
            if (string.IsNullOrEmpty(GroupId))
                return false;

            if (SenderIdentityKey == null || SenderIdentityKey.Length == 0)
                return false;

            if (Ciphertext == null || Ciphertext.Length == 0)
                return false;

            if (Nonce == null || Nonce.Length == 0)
                return false;

            if (Timestamp <= 0)
                return false;

            // Signature is optional in some contexts

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
            size += GroupId.Length * sizeof(char);

            // Byte arrays
            size += SenderIdentityKey.Length;
            size += Ciphertext.Length;
            size += Nonce.Length;
            size += Signature?.Length ?? 0;

            // Other fields
            size += sizeof(long) * 2; // Timestamp and RotationEpoch

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