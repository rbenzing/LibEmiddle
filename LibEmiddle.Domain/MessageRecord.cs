namespace LibEmiddle.Domain
{
    /// <summary>
    /// Represents a single message entry stored locally in the chat history.
    /// Contains both plaintext content (for display) and metadata about the message,
    /// such as direction and timestamp. Optionally includes the encrypted form.
    /// </summary>
    public class MessageRecord
    {
        /// <summary>
        /// Indicates whether this message was sent by the local user (true)
        /// or received from the remote party (false). Used for UI display.
        /// </summary>
        public bool IsOutgoing { get; set; }

        /// <summary>
        /// The timestamp when the message was sent or received locally (UTC).
        /// Used for sorting and display.
        /// </summary>
        public DateTime Timestamp { get; set; }

        /// <summary>
        /// The plaintext content of the message (UTF-8 string).
        /// This is stored *after* successful decryption for received messages,
        /// or *before* encryption for outgoing messages, allowing the local user
        /// to view the conversation history. Can be null if content isn't stored
        /// or if there was an error during processing.
        /// </summary>
        public string? Content { get; set; }

        /// <summary>
        /// Optional: A reference to the EncryptedMessage object that was actually
        /// sent or received over the network. This contains the ciphertext, nonce,
        /// sender's DH key for that message, message number, etc.
        /// Storing this might be useful for debugging, resending logic (use with caution),
        /// or displaying more detailed message status, but is not strictly required
        /// just to display the plaintext history.
        /// </summary>
        public EncryptedMessage? EncryptedMessage { get; set; }

        /// <summary>
        /// Default constructor. Initializes the timestamp to the current UTC time.
        /// </summary>
        public MessageRecord()
        {
            // Default timestamp to the moment the record is created
            Timestamp = DateTime.UtcNow;
        }

        /// <summary>
        /// Constructor for easily creating a populated message record.
        /// </summary>
        public MessageRecord(bool isOutgoing, string? content, EncryptedMessage? encryptedDetails = null)
        {
            IsOutgoing = isOutgoing;
            Timestamp = DateTime.UtcNow; // Or use timestamp from EncryptedMessage if available/preferred
            Content = content;
            EncryptedMessage = encryptedDetails;
        }
    }
}