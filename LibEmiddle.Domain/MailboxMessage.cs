using System.ComponentModel.DataAnnotations;
using LibEmiddle.Domain.Enums;

namespace LibEmiddle.Domain
{
    /// <summary>
    /// Represents a message in the mailbox system.
    /// </summary>
    public class MailboxMessage
    {
        /// <summary>
        /// Creates a new mailbox message with specific recipient and sender keys and payload.
        /// </summary>
        /// <param name="recipientKey">The recipient's public key</param>
        /// <param name="senderKey">The sender's public key</param>
        /// <param name="payload">The encrypted payload</param>
        /// <exception cref="ArgumentNullException">Thrown when any required parameter is null</exception>
        public MailboxMessage(byte[] recipientKey, byte[] senderKey, EncryptedMessage payload)
        {
            RecipientKey = recipientKey ?? throw new ArgumentNullException(nameof(recipientKey));
            SenderKey = senderKey ?? throw new ArgumentNullException(nameof(senderKey));
            EncryptedPayload = payload ?? throw new ArgumentNullException(nameof(payload));
        }

        /// <summary>
        /// Unique message identifier
        /// </summary>
        [Required]
        public string Id { get; set; } = Guid.NewGuid().ToString();

        /// <summary>
        /// Recipient's public key
        /// </summary>
        [Required]
        public byte[] RecipientKey { get; set; }

        /// <summary>
        /// Sender's public key
        /// </summary>
        [Required]
        public byte[] SenderKey { get; set; }

        /// <summary>
        /// The encrypted message payload
        /// </summary>
        [Required]
        public EncryptedMessage EncryptedPayload { get; set; }

        /// <summary>
        /// Message type for routing
        /// </summary>
        public MessageType Type { get; set; } = MessageType.Chat;

        /// <summary>
        /// When the message was created
        /// </summary>
        public long Timestamp { get; set; } = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        /// <summary>
        /// Optional message expiration time in milliseconds since Unix epoch
        /// </summary>
        public long? ExpiresAt { get; set; }

        /// <summary>
        /// Whether the message has been delivered to the recipient
        /// </summary>
        public bool IsDelivered { get; set; } = false;

        /// <summary>
        /// Whether the message has been read by the recipient
        /// </summary>
        public bool IsRead { get; set; } = false;

        /// <summary>
        /// Time when the message was delivered (milliseconds)
        /// </summary>
        public long? DeliveredAt { get; set; }

        /// <summary>
        /// Time when the message was read (milliseconds)
        /// </summary>
        public long? ReadAt { get; set; }

        /// <summary>
        /// Optional metadata for the message.
        /// </summary>
        public Dictionary<string, string>? Metadata { get; set; }

        /// <summary>
        /// Checks if the message has expired.
        /// </summary>
        /// <returns>True if the message has expired, false otherwise</returns>
        public bool IsExpired()
        {
            if (!ExpiresAt.HasValue || ExpiresAt.Value <= 0)
                return false; // No expiration time set

            long currentTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            return currentTime > ExpiresAt.Value;
        }

        /// <summary>
        /// Serializes the message to a byte array for transport.
        /// </summary>
        /// <returns>A byte array representation of the essential message fields.</returns>
        public byte[] ToByteArray()
        {
            // Implementation would use consistent binary serialization
            using var memoryStream = new System.IO.MemoryStream();
            using var writer = new System.IO.BinaryWriter(memoryStream);

            writer.Write(Id);

            writer.Write(SenderKey.Length);
            writer.Write(SenderKey);

            writer.Write(RecipientKey.Length);
            writer.Write(RecipientKey);

            if (EncryptedPayload == null)
                throw new ArgumentNullException(nameof(EncryptedPayload));

            // Write the encrypted payload's essential fields
            writer.Write(EncryptedPayload.SessionId ?? string.Empty);

            var hasSenderDHKey = EncryptedPayload.SenderDHKey != null;
            writer.Write(hasSenderDHKey);
            if (hasSenderDHKey)
            {
                writer.Write(EncryptedPayload.SenderDHKey!.Length);
                writer.Write(EncryptedPayload.SenderDHKey);
            }

            writer.Write(EncryptedPayload.SenderMessageNumber);

            var hasCiphertext = EncryptedPayload.Ciphertext != null;
            writer.Write(hasCiphertext);
            if (hasCiphertext)
            {
                writer.Write(EncryptedPayload.Ciphertext!.Length);
                writer.Write(EncryptedPayload.Ciphertext);
            }

            var hasNonce = EncryptedPayload.Nonce != null;
            writer.Write(hasNonce);
            if (hasNonce)
            {
                writer.Write(EncryptedPayload.Nonce!.Length);
                writer.Write(EncryptedPayload.Nonce);
            }

            writer.Write((int)Type);
            writer.Write(Timestamp);

            return memoryStream.ToArray();
        }
    }
}