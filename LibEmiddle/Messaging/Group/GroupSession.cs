using LibEmiddle.Core;

namespace LibEmiddle.Messaging.Group
{
    /// <summary>
    /// Represents the state of a group messaging session
    /// </summary>
    public class GroupSession : IDisposable
    {
        /// <summary>
        /// Group identifier
        /// </summary>
        public string GroupId { get; set; } = string.Empty;

        /// <summary>
        /// Sender key as Base64
        /// </summary>
        public string SenderKeyBase64 { get; set; } = string.Empty;

        /// <summary>
        /// Creator's identity key as Base64
        /// </summary>
        public string CreatorIdentityKeyBase64 { get; set; } = string.Empty;

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
                GroupId = GroupId,
                CreationTimestamp = CreationTimestamp,
                LastKeyRotation = LastKeyRotation
            };

            // Deep copy of SenderKey
            if (SenderKey != null)
            {
                clone.SenderKey = Sodium.GenerateRandomBytes(SenderKey.Length);
                SenderKey.AsSpan().CopyTo(clone.SenderKey.AsSpan());
            }

            // Deep copy of CreatorIdentityKey
            if (CreatorIdentityKey != null)
            {
                clone.CreatorIdentityKey = Sodium.GenerateRandomBytes(CreatorIdentityKey.Length);
                CreatorIdentityKey.AsSpan().CopyTo(clone.CreatorIdentityKey.AsSpan());
            }

            // Deep copy of Metadata
            if (Metadata != null)
            {
                clone.Metadata = new Dictionary<string, string>(Metadata);
            }

            return clone;
        }

        /// <summary>
        /// Cleanup secret keys
        /// </summary>
        public void Dispose()
        {
            SecureMemory.SecureClear(SenderKey);
            SecureMemory.SecureClear(CreatorIdentityKey);
        }
    }
}