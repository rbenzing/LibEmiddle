using System.Collections.Concurrent;

namespace LibEmiddle.Domain
{
    /// <summary>
    /// Represents information about a group.
    /// </summary>
    public class GroupInfo
    {
        /// <summary>
        /// Gets or sets the group identifier.
        /// </summary>
        public string GroupId { get; set; } = new Guid().ToString();

        /// <summary>
        /// Gets or sets the group name.
        /// </summary>
        public string GroupName { get; set; } = "Untitled";

        /// <summary>
        /// Gets or sets when the group was created (milliseconds since Unix epoch).
        /// </summary>
        public long CreatedAt { get; set; }

        /// <summary>
        /// Gets or sets the creator's public key.
        /// </summary>
        public byte[]? CreatorPublicKey { get; set; }

        /// <summary>
        /// Gets or sets the dictionary of current members.
        /// Key is the member ID, value is the member information.
        /// </summary>
        public ConcurrentDictionary<string, GroupMember> Members { get; set; } = new ConcurrentDictionary<string, GroupMember>();

        /// <summary>
        /// Gets or sets the dictionary of removed members.
        /// Key is the member ID, value is the removal timestamp.
        /// </summary>
        public ConcurrentDictionary<string, long> RemovedMembers { get; set; } = new ConcurrentDictionary<string, long>();

        /// <summary>
        /// Creates a deep clone of this group info.
        /// </summary>
        /// <returns>A cloned copy of this group info.</returns>
        public GroupInfo Clone()
        {
            var clone = new GroupInfo
            {
                GroupId = GroupId,
                GroupName = GroupName,
                CreatedAt = CreatedAt,
                CreatorPublicKey = CreatorPublicKey?.ToArray()
            };

            // Clone members
            foreach (var kvp in Members)
            {
                clone.Members[kvp.Key] = kvp.Value.Clone();
            }

            // Clone removed members
            foreach (var kvp in RemovedMembers)
            {
                clone.RemovedMembers[kvp.Key] = kvp.Value;
            }

            return clone;
        }
    }
}
