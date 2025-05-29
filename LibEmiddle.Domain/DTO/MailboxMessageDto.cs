using LibEmiddle.Domain.Enums;

#pragma warning disable IDE0130 // Namespace does not match folder structure
namespace LibEmiddle.Domain
#pragma warning restore IDE0130 // Namespace does not match folder structure
{
    /// <summary>
    /// DTO for serializing and deserializing mailbox messages for transport.
    /// </summary>
    public class MailboxMessageDto
    {
        /// <summary>
        /// Gets or sets the unique message identifier.
        /// </summary>
        public string MessageId { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the sender's identifier.
        /// </summary>
        public string SenderId { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the sender's device identifier.
        /// </summary>
        public string SenderDeviceId { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the recipient's identifier.
        /// </summary>
        public string RecipientId { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the recipient's device identifier.
        /// </summary>
        public string? RecipientDeviceId { get; set; }

        /// <summary>
        /// Gets or sets the session identifier.
        /// </summary>
        public string SessionId { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the message type.
        /// </summary>
        public MessageType Type { get; set; }

        /// <summary>
        /// Gets or sets the message content.
        /// </summary>
        public string Content { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the message timestamp (milliseconds since Unix epoch).
        /// </summary>
        public long Timestamp { get; set; }

        /// <summary>
        /// Gets or sets additional message headers.
        /// </summary>
        public Dictionary<string, string> Headers { get; set; } = new Dictionary<string, string>();
    }
}