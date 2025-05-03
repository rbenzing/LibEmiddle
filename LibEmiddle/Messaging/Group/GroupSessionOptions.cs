using LibEmiddle.Domain.Enums;

namespace LibEmiddle.Messaging.Group
{
    /// <summary>
    /// Configuration options for a group session.
    /// </summary>
    public class GroupSessionOptions
    {
        /// <summary>
        /// Gets or sets the group identifier.
        /// </summary>
        public string GroupId { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the key rotation strategy to use for this group.
        /// </summary>
        public KeyRotationStrategy RotationStrategy { get; set; } = KeyRotationStrategy.Standard;

        /// <summary>
        /// Gets or sets the group name.
        /// </summary>
        public string GroupName { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets whether the creator is automatically an admin.
        /// </summary>
        public bool CreatorIsAdmin { get; set; } = true;

        /// <summary>
        /// Gets or sets whether admins can add new members.
        /// </summary>
        public bool AdminsCanAddMembers { get; set; } = true;

        /// <summary>
        /// Gets or sets whether members can add new members.
        /// </summary>
        public bool MembersCanAddMembers { get; set; } = false;

        /// <summary>
        /// Gets or sets whether admins can remove members.
        /// </summary>
        public bool AdminsCanRemoveMembers { get; set; } = true;

        /// <summary>
        /// Gets or sets whether members can rotate group keys.
        /// </summary>
        public bool MembersCanRotateKeys { get; set; } = false;

        /// <summary>
        /// Gets or sets maximum group size.
        /// </summary>
        public int MaxGroupSize { get; set; } = 100;

        /// <summary>
        /// Gets or sets metadata to associate with the group.
        /// </summary>
        public Dictionary<string, string> Metadata { get; set; } = new Dictionary<string, string>();
    }
}
