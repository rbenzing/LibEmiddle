namespace LibEmiddle.Domain
{
    /// <summary>
    /// Represents the serializable state of group keys for persistence.
    /// </summary>
    public class GroupKeyState
    {
        /// <summary>
        /// Gets or sets the group identifier.
        /// </summary>
        public string GroupId { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the sender state.
        /// </summary>
        public GroupSenderStateDto? SenderState { get; set; }

        /// <summary>
        /// Gets or sets the receiver states.
        /// Key is the Base64-encoded sender identity key, value is the Base64-encoded sender key.
        /// </summary>
        public Dictionary<string, string> ReceiverStates { get; set; } = new Dictionary<string, string>();

        /// <summary>
        /// Gets or sets the timestamp of the last key rotation.
        /// </summary>
        public long LastRotationTimestamp { get; set; }
    }
}
