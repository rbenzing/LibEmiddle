using LibEmiddle.Domain.Enums;

namespace LibEmiddle.Messaging.Chat
{
    /// <summary>
    /// Configuration options for a chat session.
    /// </summary>
    public class ChatSessionOptions
    {
        /// <summary>
        /// Gets or sets the remote user's identifier.
        /// </summary>
        public string RemoteUserId { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the key rotation strategy to use for this session.
        /// </summary>
        public KeyRotationStrategy RotationStrategy { get; set; } = KeyRotationStrategy.Standard;

        /// <summary>
        /// Gets or sets whether to track message history within the session.
        /// </summary>
        public bool TrackMessageHistory { get; set; } = true;

        /// <summary>
        /// Gets or sets the maximum number of messages to track in history.
        /// </summary>
        public int MaxTrackedMessages { get; set; } = 100;

        /// <summary>
        /// Gets or sets whether to auto-activate the session on first message.
        /// </summary>
        public bool AutoActivate { get; set; } = true;

        /// <summary>
        /// Gets or sets metadata to associate with the session.
        /// </summary>
        public Dictionary<string, string> Metadata { get; set; } = new Dictionary<string, string>();
    }
}
