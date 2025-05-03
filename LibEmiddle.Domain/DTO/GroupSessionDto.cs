using LibEmiddle.Domain.Enums;

namespace LibEmiddle.Domain.DTO
{
    /// <summary>
    /// DTO for serializing and deserializing group session state.
    /// </summary>
    public class GroupSessionDto
    {
        /// <summary>
        /// Gets or sets the unique identifier for this group session.
        /// </summary>
        public string SessionId { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the group identifier.
        /// </summary>
        public string GroupId { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the Base64-encoded creator public key.
        /// </summary>
        public string CreatorPublicKey { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the rotation strategy.
        /// </summary>
        public KeyRotationStrategy RotationStrategy { get; set; }

        /// <summary>
        /// Gets or sets the group name.
        /// </summary>
        public string GroupName { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets when the group was created.
        /// </summary>
        public DateTime CreatedAt { get; set; }

        /// <summary>
        /// Gets or sets when the group was last modified.
        /// </summary>
        public DateTime LastModifiedAt { get; set; }

        /// <summary>
        /// Gets or sets when the group key was last rotated.
        /// </summary>
        public DateTime LastKeyRotation { get; set; }

        /// <summary>
        /// Gets or sets the list of members' public keys (Base64-encoded).
        /// </summary>
        public List<string> MemberPublicKeys { get; set; } = new List<string>();

        /// <summary>
        /// Gets or sets the list of admin members' public keys (Base64-encoded).
        /// </summary>
        public List<string> AdminPublicKeys { get; set; } = new List<string>();

        /// <summary>
        /// Gets or sets the dictionary of member join timestamps.
        /// Key is Base64-encoded public key, value is join timestamp.
        /// </summary>
        public Dictionary<string, long> MemberJoinTimestamps { get; set; } = new Dictionary<string, long>();

        /// <summary>
        /// Gets or sets the dictionary of removed members.
        /// Key is Base64-encoded public key, value is removal timestamp.
        /// </summary>
        public Dictionary<string, long> RemovedMembers { get; set; } = new Dictionary<string, long>();

        /// <summary>
        /// Gets or sets the current chain key (Base64-encoded).
        /// </summary>
        public string? CurrentChainKey { get; set; }

        /// <summary>
        /// Gets or sets the current chain key iteration.
        /// </summary>
        public uint CurrentIteration { get; set; }

        /// <summary>
        /// Gets or sets session metadata.
        /// </summary>
        public Dictionary<string, string> Metadata { get; set; } = new Dictionary<string, string>();
    }
}