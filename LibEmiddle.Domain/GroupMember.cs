using LibEmiddle.Domain.Enums;

namespace LibEmiddle.Domain
{
    /// <summary>
    /// Represents a member of a group.
    /// Enhanced in v2.5 with granular permissions and metadata support.
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
        /// Note: When advanced group management is enabled, use Role and CustomPermissions instead.
        /// </summary>
        public bool IsAdmin { get; set; }

        /// <summary>
        /// Gets or sets whether the member is the owner (creator).
        /// Note: When advanced group management is enabled, use Role instead.
        /// </summary>
        public bool IsOwner { get; set; }

        // --- v2.5 Enhanced Features (Additive) ---

        /// <summary>
        /// Gets or sets the member's role in the group (v2.5).
        /// Provides more granular role management than the simple IsAdmin/IsOwner flags.
        /// Defaults to Member for backward compatibility.
        /// </summary>
        public MemberRole Role { get; set; } = MemberRole.Member;

        /// <summary>
        /// Gets or sets custom permissions for this member (v2.5).
        /// Allows fine-grained control over what actions a member can perform.
        /// Only effective when advanced group management is enabled.
        /// </summary>
        public HashSet<GroupPermission> CustomPermissions { get; set; } = new();

        /// <summary>
        /// Gets or sets when the member is muted until (v2.5).
        /// Null means the member is not muted.
        /// </summary>
        public DateTime? MutedUntil { get; set; } = null;

        /// <summary>
        /// Gets or sets additional metadata for this member (v2.5).
        /// Can store custom properties like display name, avatar URL, etc.
        /// </summary>
        public Dictionary<string, string> Metadata { get; set; } = new();

        /// <summary>
        /// Gets or sets when the member was last active (v2.5).
        /// Updated when the member sends messages or performs actions.
        /// </summary>
        public DateTime? LastActivity { get; set; } = null;

        /// <summary>
        /// Gets or sets the member's invitation code if they were invited (v2.5).
        /// Used for tracking invitation chains and managing member onboarding.
        /// </summary>
        public string? InvitationCode { get; set; } = null;

        // --- Computed Properties ---

        /// <summary>
        /// Gets whether the member is currently muted.
        /// </summary>
        public bool IsMuted => MutedUntil.HasValue && MutedUntil.Value > DateTime.UtcNow;

        /// <summary>
        /// Gets whether the member has a specific permission.
        /// Considers both role-based and custom permissions.
        /// </summary>
        /// <param name="permission">The permission to check.</param>
        /// <returns>True if the member has the permission.</returns>
        public bool HasPermission(GroupPermission permission)
        {
            // Check custom permissions first
            if (CustomPermissions.Contains(permission))
                return true;

            // Check role-based permissions for backward compatibility
            return Role switch
            {
                MemberRole.Owner => true, // Owner has all permissions
                MemberRole.Admin => permission != GroupPermission.ManageAdmins, // Admin has most permissions except managing other admins
                MemberRole.Moderator => permission == GroupPermission.SendMessage || 
                                       permission == GroupPermission.ModerateMembers,
                MemberRole.Member => permission == GroupPermission.SendMessage,
                _ => false
            };
        }

        /// <summary>
        /// Gets the effective permissions for this member.
        /// Combines role-based and custom permissions.
        /// </summary>
        /// <returns>Set of all permissions the member has.</returns>
        public HashSet<GroupPermission> GetEffectivePermissions()
        {
            var permissions = new HashSet<GroupPermission>(CustomPermissions);

            // Add role-based permissions
            switch (Role)
            {
                case MemberRole.Owner:
                    permissions.Add(GroupPermission.All);
                    break;
                case MemberRole.Admin:
                    permissions.Add(GroupPermission.SendMessage);
                    permissions.Add(GroupPermission.AddMember);
                    permissions.Add(GroupPermission.RemoveMember);
                    permissions.Add(GroupPermission.ChangeSettings);
                    permissions.Add(GroupPermission.RotateKeys);
                    permissions.Add(GroupPermission.ModerateMembers);
                    break;
                case MemberRole.Moderator:
                    permissions.Add(GroupPermission.SendMessage);
                    permissions.Add(GroupPermission.ModerateMembers);
                    break;
                case MemberRole.Member:
                    permissions.Add(GroupPermission.SendMessage);
                    break;
            }

            return permissions;
        }

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
                IsOwner = IsOwner,
                // v2.5 properties
                Role = Role,
                CustomPermissions = new HashSet<GroupPermission>(CustomPermissions),
                MutedUntil = MutedUntil,
                Metadata = new Dictionary<string, string>(Metadata),
                LastActivity = LastActivity,
                InvitationCode = InvitationCode
            };
        }

        /// <summary>
        /// Migrates legacy admin/owner flags to the new role system.
        /// Called automatically when advanced group management is enabled.
        /// </summary>
        public void MigrateToRoleSystem()
        {
            if (IsOwner)
                Role = MemberRole.Owner;
            else if (IsAdmin)
                Role = MemberRole.Admin;
            else
                Role = MemberRole.Member;
        }
    }
}
