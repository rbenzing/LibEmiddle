namespace LibEmiddle.Domain
{
    /// <summary>
    /// Represents a member of a group.
    /// </summary>
    public class GroupMember
    {
        /// <summary>
        /// Gets or sets the member's public key.
        /// </summary>
        public byte[] PublicKey { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Gets or sets when the member joined the group (milliseconds since Unix epoch).
        /// </summary>
        public long JoinedAt { get; set; }

        /// <summary>
        /// Gets or sets whether the member is an admin.
        /// </summary>
        public bool IsAdmin { get; set; }

        /// <summary>
        /// Gets or sets whether the member is the owner (creator).
        /// </summary>
        public bool IsOwner { get; set; }

        /// <summary>
        /// Creates a deep clone of this group member.
        /// </summary>
        /// <returns>A cloned copy of this group member.</returns>
        public GroupMember Clone()
        {
            return new GroupMember
            {
                PublicKey = PublicKey.ToArray(),
                JoinedAt = JoinedAt,
                IsAdmin = IsAdmin,
                IsOwner = IsOwner
            };
        }
    }
}
