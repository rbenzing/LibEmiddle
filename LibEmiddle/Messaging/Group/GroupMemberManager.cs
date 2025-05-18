using System.Collections.Concurrent;
using LibEmiddle.Core;
using LibEmiddle.Abstractions;
using LibEmiddle.Domain;

namespace LibEmiddle.Messaging.Group
{
    /// <summary>
    /// Manages group membership, including members, admins, roles,
    /// and permissions within group chat contexts.
    /// </summary>
    /// <remarks>
    /// Initializes a new instance of the GroupMemberManager class.
    /// </remarks>
    /// <param name="cryptoProvider">The cryptographic provider implementation.</param>
    public class GroupMemberManager(ICryptoProvider cryptoProvider)
    {
        private readonly ICryptoProvider _cryptoProvider = cryptoProvider ?? throw new ArgumentNullException(nameof(cryptoProvider));

        // Group information
        private readonly ConcurrentDictionary<string, GroupInfo> _groups = new();

        /// <summary>
        /// Creates a new group with the specified creator.
        /// </summary>
        /// <param name="groupId">The identifier of the group.</param>
        /// <param name="groupName">The name of the group.</param>
        /// <param name="creatorPublicKey">The creator's public key.</param>
        /// <param name="creatorIsAdmin">Whether the creator is an admin.</param>
        /// <returns>True if the group was created successfully.</returns>
        public bool CreateGroup(string groupId, string groupName, byte[] creatorPublicKey, bool creatorIsAdmin = true)
        {
            if (string.IsNullOrEmpty(groupId))
                throw new ArgumentException("Group ID cannot be null or empty.", nameof(groupId));

            if (string.IsNullOrEmpty(groupName))
                throw new ArgumentException("Group name cannot be null or empty.", nameof(groupName));

            if (creatorPublicKey == null || creatorPublicKey.Length == 0)
                throw new ArgumentException("Creator public key cannot be null or empty.", nameof(creatorPublicKey));

            // Check if group already exists
            if (_groups.ContainsKey(groupId))
                return false;

            var groupInfo = new GroupInfo
            {
                GroupId = groupId,
                GroupName = groupName,
                CreatedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                CreatorPublicKey = creatorPublicKey.ToArray() // Create a copy
            };

            // Add creator as a member and possibly admin
            string creatorId = GetMemberId(creatorPublicKey);
            groupInfo.Members[creatorId] = new GroupMember
            {
                PublicKey = creatorPublicKey.ToArray(),
                JoinedAt = groupInfo.CreatedAt,
                IsAdmin = creatorIsAdmin,
                IsOwner = true
            };

            // Store the group
            return _groups.TryAdd(groupId, groupInfo);
        }

        /// <summary>
        /// Deletes a group.
        /// </summary>
        /// <param name="groupId">The identifier of the group.</param>
        /// <returns>True if the group was deleted successfully.</returns>
        public bool DeleteGroup(string groupId)
        {
            if (string.IsNullOrEmpty(groupId))
                throw new ArgumentException("Group ID cannot be null or empty.", nameof(groupId));

            return _groups.TryRemove(groupId, out _);
        }

        /// <summary>
        /// Adds a member to a group.
        /// </summary>
        /// <param name="groupId">The identifier of the group.</param>
        /// <param name="memberPublicKey">The member's public key.</param>
        /// <param name="isAdmin">Whether the member is an admin.</param>
        /// <returns>True if the member was added successfully.</returns>
        public bool AddMember(string groupId, byte[] memberPublicKey, bool isAdmin = false)
        {
            if (string.IsNullOrEmpty(groupId))
                throw new ArgumentException("Group ID cannot be null or empty.", nameof(groupId));

            if (memberPublicKey == null || memberPublicKey.Length == 0)
                throw new ArgumentException("Member public key cannot be null or empty.", nameof(memberPublicKey));

            if (!_groups.TryGetValue(groupId, out var groupInfo))
                return false;

            // Get member ID
            string memberId = GetMemberId(memberPublicKey);

            // Check if already a member
            if (groupInfo.Members.ContainsKey(memberId))
                return false;

            // Add the member
            var member = new GroupMember
            {
                PublicKey = memberPublicKey.ToArray(),
                JoinedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                IsAdmin = isAdmin,
                IsOwner = false
            };

            groupInfo.Members[memberId] = member;

            // Check if previously removed
            groupInfo.RemovedMembers.TryRemove(memberId, out _);

            return true;
        }

        /// <summary>
        /// Removes a member from a group.
        /// </summary>
        /// <param name="groupId">The identifier of the group.</param>
        /// <param name="memberPublicKey">The member's public key.</param>
        /// <returns>True if the member was removed successfully.</returns>
        public bool RemoveMember(string groupId, byte[] memberPublicKey)
        {
            if (string.IsNullOrEmpty(groupId))
                throw new ArgumentException("Group ID cannot be null or empty.", nameof(groupId));

            if (memberPublicKey == null || memberPublicKey.Length == 0)
                throw new ArgumentException("Member public key cannot be null or empty.", nameof(memberPublicKey));

            if (!_groups.TryGetValue(groupId, out var groupInfo))
                return false;

            // Get member ID
            string memberId = GetMemberId(memberPublicKey);

            // Check if actually a member
            if (!groupInfo.Members.TryGetValue(memberId, out var member))
                return false;

            // Can't remove the owner
            if (member.IsOwner)
                return false;

            // Remove the member
            if (groupInfo.Members.TryRemove(memberId, out _))
            {
                // Record removal timestamp
                long removalTimestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                groupInfo.RemovedMembers[memberId] = removalTimestamp;
                return true;
            }

            return false;
        }

        /// <summary>
        /// Records that the user has joined a group.
        /// </summary>
        /// <param name="groupId">The identifier of the group.</param>
        /// <param name="userPublicKey">The user's public key.</param>
        /// <returns>True if the join was recorded successfully.</returns>
        public bool JoinGroup(string groupId, byte[] userPublicKey)
        {
            if (string.IsNullOrEmpty(groupId))
                throw new ArgumentException("Group ID cannot be null or empty.", nameof(groupId));

            if (userPublicKey == null || userPublicKey.Length == 0)
                throw new ArgumentException("User public key cannot be null or empty.", nameof(userPublicKey));

            // If the group doesn't exist, create it
            var groupInfo = _groups.GetOrAdd(groupId, new GroupInfo
            {
                GroupId = groupId,
                GroupName = "Unknown Group", // Default name
                CreatedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
            });

            // Get user ID
            string userId = GetMemberId(userPublicKey);

            // Add as member if not already
            if (!groupInfo.Members.ContainsKey(userId))
            {
                var member = new GroupMember
                {
                    PublicKey = userPublicKey.ToArray(),
                    JoinedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    IsAdmin = false,
                    IsOwner = false
                };

                groupInfo.Members[userId] = member;

                // Check if previously removed
                groupInfo.RemovedMembers.TryRemove(userId, out _);
            }

            return true;
        }

        /// <summary>
        /// Records that the user has left a group.
        /// </summary>
        /// <param name="groupId">The identifier of the group.</param>
        /// <param name="userPublicKey">The user's public key.</param>
        /// <returns>True if the leave was recorded successfully.</returns>
        public bool LeaveGroup(string groupId, byte[] userPublicKey)
        {
            if (string.IsNullOrEmpty(groupId))
                throw new ArgumentException("Group ID cannot be null or empty.", nameof(groupId));

            if (userPublicKey == null || userPublicKey.Length == 0)
                throw new ArgumentException("User public key cannot be null or empty.", nameof(userPublicKey));

            if (!_groups.TryGetValue(groupId, out var groupInfo))
                return false;

            // Get user ID
            string userId = GetMemberId(userPublicKey);

            // Remove from members
            if (groupInfo.Members.TryRemove(userId, out _))
            {
                // Record removal timestamp
                long removalTimestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                groupInfo.RemovedMembers[userId] = removalTimestamp;
                return true;
            }

            return false;
        }

        /// <summary>
        /// Checks if a user is a member of a group.
        /// </summary>
        /// <param name="groupId">The identifier of the group.</param>
        /// <param name="memberPublicKey">The member's public key.</param>
        /// <returns>True if the user is a member.</returns>
        public bool IsMember(string groupId, byte[] memberPublicKey)
        {
            if (string.IsNullOrEmpty(groupId))
                throw new ArgumentException("Group ID cannot be null or empty.", nameof(groupId));

            if (memberPublicKey == null || memberPublicKey.Length == 0)
                throw new ArgumentException("Member public key cannot be null or empty.", nameof(memberPublicKey));

            if (!_groups.TryGetValue(groupId, out var groupInfo))
                return false;

            // Get member ID
            string memberId = GetMemberId(memberPublicKey);

            return groupInfo.Members.ContainsKey(memberId);
        }

        /// <summary>
        /// Checks if a user is an admin of a group.
        /// </summary>
        /// <param name="groupId">The identifier of the group.</param>
        /// <param name="memberPublicKey">The member's public key.</param>
        /// <returns>True if the user is an admin.</returns>
        public bool IsGroupAdmin(string groupId, byte[] memberPublicKey)
        {
            if (string.IsNullOrEmpty(groupId))
                throw new ArgumentException("Group ID cannot be null or empty.", nameof(groupId));

            if (memberPublicKey == null || memberPublicKey.Length == 0)
                throw new ArgumentException("Member public key cannot be null or empty.", nameof(memberPublicKey));

            if (!_groups.TryGetValue(groupId, out var groupInfo))
                return false;

            // Get member ID
            string memberId = GetMemberId(memberPublicKey);

            if (groupInfo.Members.TryGetValue(memberId, out var member))
            {
                return member.IsAdmin || member.IsOwner;
            }

            return false;
        }

        /// <summary>
        /// Checks if a user was previously an admin of a group.
        /// </summary>
        /// <param name="groupId">The identifier of the group.</param>
        /// <param name="memberPublicKey">The member's public key.</param>
        /// <returns>True if the user was previously an admin.</returns>
        public bool WasAdmin(string groupId, byte[] memberPublicKey)
        {
            if (string.IsNullOrEmpty(groupId))
                throw new ArgumentException("Group ID cannot be null or empty.", nameof(groupId));

            if (memberPublicKey == null || memberPublicKey.Length == 0)
                throw new ArgumentException("Member public key cannot be null or empty.", nameof(memberPublicKey));

            if (!_groups.TryGetValue(groupId, out var groupInfo))
                return false;

            // Get member ID
            string memberId = GetMemberId(memberPublicKey);

            // First check if currently a member
            if (IsGroupAdmin(groupId, memberPublicKey))
                return true;

            // Check removed members history
            // For now we assume that removed members were not admins
            // A more comprehensive implementation would store admin status in removal records
            return false;
        }

        /// <summary>
        /// Checks if a user has permission to rotate the group key.
        /// </summary>
        /// <param name="groupId">The identifier of the group.</param>
        /// <param name="memberPublicKey">The member's public key.</param>
        /// <returns>True if the user has key rotation permission.</returns>
        public bool HasKeyRotationPermission(string groupId, byte[] memberPublicKey)
        {
            // By default, only admins and owners can rotate keys
            return IsGroupAdmin(groupId, memberPublicKey);
        }

        /// <summary>
        /// Checks if a user was removed from a group before a specific timestamp.
        /// </summary>
        /// <param name="groupId">The identifier of the group.</param>
        /// <param name="memberPublicKey">The member's public key.</param>
        /// <param name="timestamp">The timestamp to check against.</param>
        /// <returns>True if the user was removed before the timestamp.</returns>
        public bool WasRemovedBeforeTimestamp(string groupId, byte[] memberPublicKey, long timestamp)
        {
            if (string.IsNullOrEmpty(groupId))
                throw new ArgumentException("Group ID cannot be null or empty.", nameof(groupId));

            if (memberPublicKey == null || memberPublicKey.Length == 0)
                throw new ArgumentException("Member public key cannot be null or empty.", nameof(memberPublicKey));

            if (!_groups.TryGetValue(groupId, out var groupInfo))
                return false;

            // Get member ID
            string memberId = GetMemberId(memberPublicKey);

            // Check if the member is in the removed members list
            if (groupInfo.RemovedMembers.TryGetValue(memberId, out var removalTimestamp))
            {
                // Check if the removal happened before the given timestamp
                return removalTimestamp < timestamp;
            }

            return false;
        }

        /// <summary>
        /// Gets the list of members in a group.
        /// </summary>
        /// <param name="groupId">The identifier of the group.</param>
        /// <returns>A list of member public keys.</returns>
        public List<byte[]> GetMembers(string groupId)
        {
            if (string.IsNullOrEmpty(groupId))
                throw new ArgumentException("Group ID cannot be null or empty.", nameof(groupId));

            if (!_groups.TryGetValue(groupId, out var groupInfo))
                return new List<byte[]>();

            return groupInfo.Members.Values.Select(m => m.PublicKey.ToArray()).ToList();
        }

        /// <summary>
        /// Gets the list of admin members in a group.
        /// </summary>
        /// <param name="groupId">The identifier of the group.</param>
        /// <returns>A list of admin member public keys.</returns>
        public List<byte[]> GetAdmins(string groupId)
        {
            if (string.IsNullOrEmpty(groupId))
                throw new ArgumentException("Group ID cannot be null or empty.", nameof(groupId));

            if (!_groups.TryGetValue(groupId, out var groupInfo))
                return new List<byte[]>();

            return groupInfo.Members.Values
                .Where(m => m.IsAdmin || m.IsOwner)
                .Select(m => m.PublicKey.ToArray())
                .ToList();
        }

        /// <summary>
        /// Promotes a member to admin status.
        /// </summary>
        /// <param name="groupId">The identifier of the group.</param>
        /// <param name="memberPublicKey">The member's public key.</param>
        /// <returns>True if the member was promoted successfully.</returns>
        public bool PromoteToAdmin(string groupId, byte[] memberPublicKey)
        {
            if (string.IsNullOrEmpty(groupId))
                throw new ArgumentException("Group ID cannot be null or empty.", nameof(groupId));

            if (memberPublicKey == null || memberPublicKey.Length == 0)
                throw new ArgumentException("Member public key cannot be null or empty.", nameof(memberPublicKey));

            if (!_groups.TryGetValue(groupId, out var groupInfo))
                return false;

            // Get member ID
            string memberId = GetMemberId(memberPublicKey);

            // Check if actually a member
            if (!groupInfo.Members.TryGetValue(memberId, out var member))
                return false;

            // Already an admin or owner
            if (member.IsAdmin || member.IsOwner)
                return false;

            // Promote to admin
            member.IsAdmin = true;
            return true;
        }

        /// <summary>
        /// Demotes an admin to regular member status.
        /// </summary>
        /// <param name="groupId">The identifier of the group.</param>
        /// <param name="memberPublicKey">The member's public key.</param>
        /// <returns>True if the member was demoted successfully.</returns>
        public bool DemoteFromAdmin(string groupId, byte[] memberPublicKey)
        {
            if (string.IsNullOrEmpty(groupId))
                throw new ArgumentException("Group ID cannot be null or empty.", nameof(groupId));

            if (memberPublicKey == null || memberPublicKey.Length == 0)
                throw new ArgumentException("Member public key cannot be null or empty.", nameof(memberPublicKey));

            if (!_groups.TryGetValue(groupId, out var groupInfo))
                return false;

            // Get member ID
            string memberId = GetMemberId(memberPublicKey);

            // Check if actually a member
            if (!groupInfo.Members.TryGetValue(memberId, out var member))
                return false;

            // Can't demote the owner
            if (member.IsOwner)
                return false;

            // Not an admin
            if (!member.IsAdmin)
                return false;

            // Demote from admin
            member.IsAdmin = false;
            return true;
        }

        /// <summary>
        /// Gets the group information.
        /// </summary>
        /// <param name="groupId">The identifier of the group.</param>
        /// <returns>The group information.</returns>
        public GroupInfo? GetGroupInfo(string groupId)
        {
            if (string.IsNullOrEmpty(groupId))
                throw new ArgumentException("Group ID cannot be null or empty.", nameof(groupId));

            if (_groups.TryGetValue(groupId, out var groupInfo))
            {
                // Create a deep copy to prevent modification
                return groupInfo.Clone();
            }

            return null;
        }

        /// <summary>
        /// Exports the state of all groups for persistence.
        /// </summary>
        /// <returns>A dictionary mapping group IDs to serialized group states.</returns>
        public Dictionary<string, string> ExportState()
        {
            var result = new Dictionary<string, string>();

            foreach (var kvp in _groups)
            {
                string groupId = kvp.Key;
                GroupInfo groupInfo = kvp.Value;

                // Serialize the group info
                string serialized = SerializeGroupInfo(groupInfo);
                result[groupId] = serialized;
            }

            return result;
        }

        /// <summary>
        /// Imports group states from persistence.
        /// </summary>
        /// <param name="state">A dictionary mapping group IDs to serialized group states.</param>
        /// <returns>The number of groups imported.</returns>
        public int ImportState(Dictionary<string, string> state)
        {
            if (state == null)
                throw new ArgumentNullException(nameof(state));

            int importedCount = 0;

            foreach (var kvp in state)
            {
                string groupId = kvp.Key;
                string serialized = kvp.Value;

                try
                {
                    // Deserialize the group info
                    GroupInfo? groupInfo = DeserializeGroupInfo(serialized);
                    if (groupInfo != null)
                    {
                        _groups[groupId] = groupInfo;
                        importedCount++;
                    }
                }
                catch (Exception ex)
                {
                    LoggingManager.LogError(nameof(GroupMemberManager), $"Failed to import state for group {groupId}: {ex.Message}");
                }
            }

            return importedCount;
        }

        /// <summary>
        /// Gets a unique identifier for a member based on their public key.
        /// </summary>
        /// <param name="publicKey">The member's public key.</param>
        /// <returns>A unique identifier string.</returns>
        private string GetMemberId(byte[] publicKey)
        {
            // Use Base64 representation of the public key as the ID
            return Convert.ToBase64String(publicKey);
        }

        /// <summary>
        /// Serializes a GroupInfo object to a string.
        /// </summary>
        /// <param name="groupInfo">The group information to serialize.</param>
        /// <returns>The serialized string.</returns>
        private string SerializeGroupInfo(GroupInfo groupInfo)
        {
            // In a real implementation, this would use a proper serialization format
            // such as JSON or Protocol Buffers
            return JsonSerialization.Serialize(groupInfo);
        }

        /// <summary>
        /// Deserializes a string to a GroupInfo object.
        /// </summary>
        /// <param name="serialized">The serialized string.</param>
        /// <returns>The deserialized GroupInfo object.</returns>
        private GroupInfo? DeserializeGroupInfo(string serialized)
        {
            // In a real implementation, this would use a proper deserialization format
            // such as JSON or Protocol Buffers
            return JsonSerialization.Deserialize<GroupInfo>(serialized);
        }
    }

    /// <summary>
    /// Represents information about a group.
    /// </summary>
    public class GroupInfo
    {
        /// <summary>
        /// Gets or sets the group identifier.
        /// </summary>
        public string GroupId { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the group name.
        /// </summary>
        public string GroupName { get; set; } = string.Empty;

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