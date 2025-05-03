using LibEmiddle.Domain.Enums;

namespace LibEmiddle.Domain.DTO
{
    /// <summary>
    /// DTO for serializing and deserializing session state for persistence.
    /// </summary>
    public class SerializedSessionData
    {
        /// <summary>
        /// Gets or sets the unique identifier for this session.
        /// </summary>
        public string SessionId { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the type of session.
        /// </summary>
        public SessionType SessionType { get; set; }

        /// <summary>
        /// Gets or sets the current state of the session.
        /// </summary>
        public SessionState State { get; set; }

        /// <summary>
        /// Gets or sets when the session was created.
        /// </summary>
        public DateTime CreatedAt { get; set; }

        /// <summary>
        /// Gets or sets when the session was last modified.
        /// </summary>
        public DateTime LastModifiedAt { get; set; }

        /// <summary>
        /// Gets or sets session metadata.
        /// </summary>
        public Dictionary<string, string> Metadata { get; set; } = new Dictionary<string, string>();

        /// <summary>
        /// Gets or sets session properties.
        /// </summary>
        public Dictionary<string, string> Properties { get; set; } = new Dictionary<string, string>();

        /// <summary>
        /// Gets or sets the serialized Double Ratchet crypto state.
        /// </summary>
        public string CryptoState { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the serialized group state for group sessions.
        /// </summary>
        public string? GroupState { get; set; }
    }
}