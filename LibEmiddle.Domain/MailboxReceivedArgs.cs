namespace LibEmiddle.Domain
{
    /// <summary>
    /// Event arguments for the MessageReceived event.
    /// </summary>
    /// <remarks>
    /// Initializes a new instance of the MailboxMessageReceivedEventArgs class.
    /// </remarks>
    /// <param name="message">The received message.</param>
    public class MailboxMessageReceivedEventArgs(MailboxMessage message) : EventArgs
    {
        /// <summary>
        /// The received mailbox message.
        /// </summary>
        public MailboxMessage Message { get; } = message ?? throw new ArgumentNullException(nameof(message));
    }
}
