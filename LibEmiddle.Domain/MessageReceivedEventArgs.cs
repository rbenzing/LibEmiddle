namespace LibEmiddle.Domain
{
    /// <summary>
    /// Event arguments for the MessageReceived event.
    /// </summary>
    /// <remarks>
    /// Initializes a new instance of the MessageReceivedEventArgs class.
    /// </remarks>
    /// <param name="senderKey">The sender's public key.</param>
    /// <param name="message">The message content.</param>
    /// <param name="timestamp">The timestamp of the message.</param>
    public class MessageReceivedEventArgs(byte[] senderKey, string message, long timestamp) : EventArgs
    {
        /// <summary>
        /// The sender's public key.
        /// </summary>
        public byte[] SenderKey { get; } = senderKey ?? throw new ArgumentNullException(nameof(senderKey));

        /// <summary>
        /// The message content.
        /// </summary>
        public string Message { get; } = message ?? throw new ArgumentNullException(nameof(message));

        /// <summary>
        /// The timestamp of the message.
        /// </summary>
        public long Timestamp { get; } = timestamp;
    }
}
