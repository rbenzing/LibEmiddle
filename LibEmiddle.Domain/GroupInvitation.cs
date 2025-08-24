using LibEmiddle.Domain.Enums;

namespace LibEmiddle.Domain
{
    /// <summary>
    /// Represents an invitation to join a group (v2.5).
    /// Provides secure, time-limited, and usage-controlled group access.
    /// </summary>
    public class GroupInvitation
    {
        /// <summary>
        /// Unique invitation code.
        /// </summary>
        public string InvitationCode { get; set; } = string.Empty;

        /// <summary>
        /// The group this invitation is for.
        /// </summary>
        public string GroupId { get; set; } = string.Empty;

        /// <summary>
        /// Public key of the member who created this invitation.
        /// </summary>
        public byte[] CreatedBy { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// When this invitation was created.
        /// </summary>
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// When this invitation expires.
        /// </summary>
        public DateTime ExpiresAt { get; set; }

        /// <summary>
        /// Maximum number of times this invitation can be used (null for unlimited).
        /// </summary>
        public int? MaxUses { get; set; }

        /// <summary>
        /// Number of times this invitation has been used.
        /// </summary>
        public int UsedCount { get; set; } = 0;

        /// <summary>
        /// Default role for members who join with this invitation.
        /// </summary>
        public MemberRole DefaultRole { get; set; } = MemberRole.Member;

        /// <summary>
        /// Whether this invitation has been revoked.
        /// </summary>
        public bool IsRevoked { get; set; } = false;

        /// <summary>
        /// When this invitation was revoked.
        /// </summary>
        public DateTime? RevokedAt { get; set; }

        /// <summary>
        /// Public key of the member who revoked this invitation.
        /// </summary>
        public byte[]? RevokedBy { get; set; }

        /// <summary>
        /// Optional reason for revocation.
        /// </summary>
        public string? RevocationReason { get; set; }

        /// <summary>
        /// Custom permissions granted to members who join with this invitation.
        /// </summary>
        public HashSet<GroupPermission> CustomPermissions { get; set; } = new();

        /// <summary>
        /// Additional metadata for this invitation.
        /// </summary>
        public Dictionary<string, string> Metadata { get; set; } = new();

        /// <summary>
        /// List of members who used this invitation.
        /// </summary>
        public List<InvitationUsage> UsageHistory { get; set; } = new();

        /// <summary>
        /// Gets whether this invitation is currently valid and can be used.
        /// </summary>
        public bool IsValid
        {
            get
            {
                if (IsRevoked) return false;
                if (DateTime.UtcNow > ExpiresAt) return false;
                if (MaxUses.HasValue && UsedCount >= MaxUses.Value) return false;
                return true;
            }
        }

        /// <summary>
        /// Gets the remaining uses for this invitation.
        /// </summary>
        public int? RemainingUses => MaxUses.HasValue ? Math.Max(0, MaxUses.Value - UsedCount) : null;

        /// <summary>
        /// Records usage of this invitation.
        /// </summary>
        /// <param name="memberPublicKey">The public key of the member who used the invitation.</param>
        /// <param name="joinedAt">When the member joined.</param>
        public void RecordUsage(byte[] memberPublicKey, DateTime? joinedAt = null)
        {
            UsedCount++;
            UsageHistory.Add(new InvitationUsage
            {
                MemberPublicKey = memberPublicKey,
                UsedAt = joinedAt ?? DateTime.UtcNow
            });
        }

        /// <summary>
        /// Revokes this invitation.
        /// </summary>
        /// <param name="revokedBy">The public key of the member revoking the invitation.</param>
        /// <param name="reason">Optional reason for revocation.</param>
        public void Revoke(byte[] revokedBy, string? reason = null)
        {
            IsRevoked = true;
            RevokedAt = DateTime.UtcNow;
            RevokedBy = revokedBy;
            RevocationReason = reason;
        }

        /// <summary>
        /// Creates a deep clone of this invitation.
        /// </summary>
        public GroupInvitation Clone()
        {
            return new GroupInvitation
            {
                InvitationCode = InvitationCode,
                GroupId = GroupId,
                CreatedBy = CreatedBy.ToArray(),
                CreatedAt = CreatedAt,
                ExpiresAt = ExpiresAt,
                MaxUses = MaxUses,
                UsedCount = UsedCount,
                DefaultRole = DefaultRole,
                IsRevoked = IsRevoked,
                RevokedAt = RevokedAt,
                RevokedBy = RevokedBy?.ToArray(),
                RevocationReason = RevocationReason,
                CustomPermissions = new HashSet<GroupPermission>(CustomPermissions),
                Metadata = new Dictionary<string, string>(Metadata),
                UsageHistory = UsageHistory.Select(u => u.Clone()).ToList()
            };
        }
    }

    /// <summary>
    /// Records when and by whom an invitation was used (v2.5).
    /// </summary>
    public class InvitationUsage
    {
        /// <summary>
        /// Public key of the member who used the invitation.
        /// </summary>
        public byte[] MemberPublicKey { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// When the invitation was used.
        /// </summary>
        public DateTime UsedAt { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Additional metadata about the usage.
        /// </summary>
        public Dictionary<string, string> Metadata { get; set; } = new();

        /// <summary>
        /// Creates a deep clone of this usage record.
        /// </summary>
        public InvitationUsage Clone()
        {
            return new InvitationUsage
            {
                MemberPublicKey = MemberPublicKey.ToArray(),
                UsedAt = UsedAt,
                Metadata = new Dictionary<string, string>(Metadata)
            };
        }
    }
}