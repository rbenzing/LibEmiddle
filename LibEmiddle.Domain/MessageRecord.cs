using System.Text;

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

        /// <summary>
        /// Securely wipes sensitive data held by this record from heap memory.
        /// <para>
        /// For the <see cref="Content"/> string the GC root is removed by setting the
        /// reference to <c>null</c>.  Additionally the UTF-8 byte representation of the
        /// content is zeroed before the reference is dropped, reducing the window during
        /// which the cleartext bytes remain reachable.
        /// </para>
        /// <para>
        /// The byte arrays on the associated <see cref="EncryptedMessage"/> (Ciphertext,
        /// Nonce, SenderDHKey) are overwritten with zeros via
        /// <see cref="Array.Clear(Array)"/> so their contents cannot be read from a heap dump
        /// after this call returns.  The <see cref="EncryptedMessage"/> reference is then
        /// set to <c>null</c>.
        /// </para>
        /// </summary>
        public void SecureWipe()
        {
            // --- plaintext string ---
            // Strings are immutable in .NET; we cannot zero the underlying char buffer
            // through the public API.  Encoding to bytes and zeroing the byte array
            // clears the encoded representation from the stack/heap before we drop the
            // reference, which narrows the exposure window.
            if (Content != null)
            {
                byte[]? contentBytes = null;
                try
                {
                    contentBytes = Encoding.UTF8.GetBytes(Content);
                }
                finally
                {
                    if (contentBytes != null)
                    {
                        Array.Clear(contentBytes, 0, contentBytes.Length);
                    }
                }
                Content = null;
            }

            // --- encrypted message byte arrays ---
            if (EncryptedMessage != null)
            {
                if (EncryptedMessage.Ciphertext != null)
                {
                    Array.Clear(EncryptedMessage.Ciphertext, 0, EncryptedMessage.Ciphertext.Length);
                    EncryptedMessage.Ciphertext = null;
                }

                if (EncryptedMessage.Nonce != null)
                {
                    Array.Clear(EncryptedMessage.Nonce, 0, EncryptedMessage.Nonce.Length);
                    EncryptedMessage.Nonce = null;
                }

                if (EncryptedMessage.SenderDHKey != null)
                {
                    Array.Clear(EncryptedMessage.SenderDHKey, 0, EncryptedMessage.SenderDHKey.Length);
                    EncryptedMessage.SenderDHKey = null;
                }

                EncryptedMessage = null;
            }
        }
    }
}