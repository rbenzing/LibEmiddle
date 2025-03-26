using System;

namespace E2EELibrary.Models
{
    /// <summary>
    /// Represents a message in the mailbox system.
    /// </summary>
    public class MailboxMessage
    {
        /// <summary>
        /// Unique message identifier
        /// </summary>
        public string MessageId { get; set; } = Guid.NewGuid().ToString();

        /// <summary>
        /// Recipient's public key
        /// </summary>
        public byte[] RecipientKey { get; set; }

        /// <summary>
        /// Sender's public key
        /// </summary>
        public byte[] SenderKey { get; set; }

        /// <summary>
        /// The encrypted message payload
        /// </summary>
        public EncryptedMessage EncryptedPayload { get; set; }

        /// <summary>
        /// Message type for routing
        /// </summary>
        public MessageType Type { get; set; }

        /// <summary>
        /// When the message was created
        /// </summary>
        public long Timestamp { get; set; }

        /// <summary>
        /// Optional message expiration time in milliseconds since Unix epoch
        /// </summary>
        public long ExpiresAt { get; set; }

        /// <summary>
        /// Whether the message has been delivered to the recipient
        /// </summary>
        public bool IsDelivered { get; set; }

        /// <summary>
        /// Whether the message has been read by the recipient
        /// </summary>
        public bool IsRead { get; set; }

        /// <summary>
        /// Time when the message was delivered
        /// </summary>
        public long? DeliveredAt { get; set; }

        /// <summary>
        /// Time when the message was read
        /// </summary>
        public long? ReadAt { get; set; }

        /// <summary>
        /// Creates a new mailbox message.
        /// </summary>
        public MailboxMessage()
        {
            Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        }

        /// <summary>
        /// Checks if the message has expired.
        /// </summary>
        /// <returns>True if the message has expired, false otherwise</returns>
        public bool IsExpired()
        {
            if (ExpiresAt <= 0)
                return false; // No expiration time set

            long currentTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            return currentTime > ExpiresAt;
        }
    }

    /// <summary>
    /// Type of mailbox message
    /// </summary>
    public enum MessageType
    {
        /// <summary>
        /// A regular chat message
        /// </summary>
        Chat = 0,

        /// <summary>
        /// A device sync message
        /// </summary>
        DeviceSync = 1,

        /// <summary>
        /// A key exchange or key update message
        /// </summary>
        KeyExchange = 2,

        /// <summary>
        /// A group chat message
        /// </summary>
        GroupChat = 3,

        /// <summary>
        /// A device revocation message
        /// </summary>
        DeviceRevocation = 4,

        /// <summary>
        /// A file transfer message
        /// </summary>
        FileTransfer = 5,

        /// <summary>
        /// A delivery receipt
        /// </summary>
        DeliveryReceipt = 7,

        /// <summary>
        /// A read receipt
        /// </summary>
        ReadReceipt = 8
    }
}