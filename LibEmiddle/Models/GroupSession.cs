using E2EELibrary.Core;

namespace E2EELibrary.Models
{
    /// <summary>
    /// Represents the state of a group messaging session
    /// </summary>
    public class GroupSession
    {
        /// <summary>
        /// Group identifier
        /// </summary>
        public string GroupId { get; set; } = string.Empty;

        /// <summary>
        /// Sender key for this group
        /// </summary>
        public byte[] SenderKey { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Identity key of the group creator
        /// </summary>
        public byte[] CreatorIdentityKey { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// When the group was created (milliseconds since Unix epoch)
        /// </summary>
        public long CreationTimestamp { get; set; }

        /// <summary>
        /// When the key was last rotated (milliseconds since Unix epoch)
        /// </summary>
        public long LastKeyRotation { get; set; }

        /// <summary>
        /// Custom metadata for the group
        /// </summary>
        public Dictionary<string, string>? Metadata { get; set; }

        /// <summary>
        /// Creates a deep copy of this session
        /// </summary>
        /// <returns>New independent copy of the session</returns>
        public GroupSession Clone()
        {
            var clone = new GroupSession
            {
                GroupId = this.GroupId,
                CreationTimestamp = this.CreationTimestamp,
                LastKeyRotation = this.LastKeyRotation
            };

            // Deep copy of SenderKey
            if (this.SenderKey != null)
            {
                clone.SenderKey = Sodium.GenerateRandomBytes(this.SenderKey.Length);
                this.SenderKey.AsSpan().CopyTo(clone.SenderKey.AsSpan());
            }

            // Deep copy of CreatorIdentityKey
            if (this.CreatorIdentityKey != null)
            {
                clone.CreatorIdentityKey = Sodium.GenerateRandomBytes(this.CreatorIdentityKey.Length);
                this.CreatorIdentityKey.AsSpan().CopyTo(clone.CreatorIdentityKey.AsSpan());
            }

            // Deep copy of Metadata
            if (this.Metadata != null)
            {
                clone.Metadata = new Dictionary<string, string>(this.Metadata);
            }

            return clone;
        }
    }
}