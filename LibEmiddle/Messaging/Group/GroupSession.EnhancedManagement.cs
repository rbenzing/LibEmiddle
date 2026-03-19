using System.Collections.Concurrent;
using System.Text;
using LibEmiddle.Abstractions;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;

namespace LibEmiddle.Messaging.Group;

public sealed partial class GroupSession
{
    #region Enhanced Group Management

    /// <summary>
    /// Gets all members of the group with their roles and permissions.
    /// </summary>
    /// <returns>Collection of group members with enhanced information.</returns>
    public async Task<IReadOnlyCollection<GroupMember>> GetMembersAsync()
    {
        ThrowIfDisposed();

        await _sessionLock.WaitAsync();
        try
        {
            return _members.Values.Select(m => m.Clone()).ToList().AsReadOnly();
        }
        finally
        {
            _sessionLock.Release();
        }
    }

    /// <summary>
    /// Gets a specific member by their public key.
    /// </summary>
    /// <param name="memberPublicKey">The public key of the member to find.</param>
    /// <returns>The group member, or null if not found.</returns>
    public async Task<GroupMember?> GetMemberAsync(byte[] memberPublicKey)
    {
        ThrowIfDisposed();

        ArgumentNullException.ThrowIfNull(memberPublicKey);

        await _sessionLock.WaitAsync();
        try
        {
            string memberId = GetMemberId(memberPublicKey);
            return _members.TryGetValue(memberId, out var member) ? member.Clone() : null;
        }
        finally
        {
            _sessionLock.Release();
        }
    }

    /// <summary>
    /// Changes a member's role in the group.
    /// </summary>
    /// <param name="memberPublicKey">The public key of the member.</param>
    /// <param name="newRole">The new role to assign.</param>
    /// <returns>True if the role was changed successfully.</returns>
    /// <exception cref="UnauthorizedAccessException">Thrown when the current user lacks permission.</exception>
    public async Task<bool> ChangeMemberRoleAsync(byte[] memberPublicKey, MemberRole newRole)
    {
        ThrowIfDisposed();

        ArgumentNullException.ThrowIfNull(memberPublicKey);

        await _sessionLock.WaitAsync();
        try
        {
            if (State == SessionState.Terminated)
                throw new InvalidOperationException("Cannot change member role: Session is terminated.");

            // Check permissions - only owners and admins can change roles
            if (!HasAdvancedPermission(GroupPermission.ManageAdmins))
                throw new UnauthorizedAccessException("You don't have permission to change member roles.");

            string memberId = GetMemberId(memberPublicKey);
            if (!_members.TryGetValue(memberId, out var member))
                return false;

            // Cannot change owner role or demote the only owner
            if (member.Role == MemberRole.Owner)
                throw new InvalidOperationException("Cannot change the role of the group owner.");

            // Cannot promote to owner
            if (newRole == MemberRole.Owner)
                throw new InvalidOperationException("Cannot promote member to owner. Transfer ownership separately.");

            member.Role = newRole;
            member.LastActivity = DateTime.UtcNow;

            LoggingManager.LogInformation(nameof(GroupSession),
                $"Changed member role to {newRole} in group {GroupId}");

            return true;
        }
        finally
        {
            _sessionLock.Release();
        }
    }

    /// <summary>
    /// Grants specific permissions to a member.
    /// </summary>
    /// <param name="memberPublicKey">The public key of the member.</param>
    /// <param name="permissions">The permissions to grant.</param>
    /// <returns>True if the permissions were granted successfully.</returns>
    /// <exception cref="UnauthorizedAccessException">Thrown when the current user lacks permission.</exception>
    public async Task<bool> GrantPermissionsAsync(byte[] memberPublicKey, IEnumerable<GroupPermission> permissions)
    {
        ThrowIfDisposed();

        ArgumentNullException.ThrowIfNull(memberPublicKey);
        ArgumentNullException.ThrowIfNull(permissions);

        await _sessionLock.WaitAsync();
        try
        {
            if (State == SessionState.Terminated)
                throw new InvalidOperationException("Cannot grant permissions: Session is terminated.");

            // Check permissions
            if (!HasAdvancedPermission(GroupPermission.ManageAdmins))
                throw new UnauthorizedAccessException("You don't have permission to grant permissions.");

            string memberId = GetMemberId(memberPublicKey);
            if (!_members.TryGetValue(memberId, out var member))
                return false;

            foreach (var permission in permissions)
            {
                member.CustomPermissions.Add(permission);
            }

            member.LastActivity = DateTime.UtcNow;

            LoggingManager.LogInformation(nameof(GroupSession),
                $"Granted permissions to member in group {GroupId}");

            return true;
        }
        finally
        {
            _sessionLock.Release();
        }
    }

    /// <summary>
    /// Revokes specific permissions from a member.
    /// </summary>
    /// <param name="memberPublicKey">The public key of the member.</param>
    /// <param name="permissions">The permissions to revoke.</param>
    /// <returns>True if the permissions were revoked successfully.</returns>
    /// <exception cref="UnauthorizedAccessException">Thrown when the current user lacks permission.</exception>
    public async Task<bool> RevokePermissionsAsync(byte[] memberPublicKey, IEnumerable<GroupPermission> permissions)
    {
        ThrowIfDisposed();

        ArgumentNullException.ThrowIfNull(memberPublicKey);
        ArgumentNullException.ThrowIfNull(permissions);

        await _sessionLock.WaitAsync();
        try
        {
            if (State == SessionState.Terminated)
                throw new InvalidOperationException("Cannot revoke permissions: Session is terminated.");

            // Check permissions
            if (!HasAdvancedPermission(GroupPermission.ManageAdmins))
                throw new UnauthorizedAccessException("You don't have permission to revoke permissions.");

            string memberId = GetMemberId(memberPublicKey);
            if (!_members.TryGetValue(memberId, out var member))
                return false;

            foreach (var permission in permissions)
            {
                member.CustomPermissions.Remove(permission);
            }

            member.LastActivity = DateTime.UtcNow;

            LoggingManager.LogInformation(nameof(GroupSession),
                $"Revoked permissions from member in group {GroupId}");

            return true;
        }
        finally
        {
            _sessionLock.Release();
        }
    }

    /// <summary>
    /// Mutes a member for a specified duration.
    /// </summary>
    /// <param name="memberPublicKey">The public key of the member to mute.</param>
    /// <param name="duration">How long to mute the member for.</param>
    /// <param name="reason">Optional reason for the mute.</param>
    /// <returns>True if the member was muted successfully.</returns>
    /// <exception cref="UnauthorizedAccessException">Thrown when the current user lacks permission.</exception>
    public async Task<bool> MuteMemberAsync(byte[] memberPublicKey, TimeSpan duration, string? reason = null)
    {
        ThrowIfDisposed();

        ArgumentNullException.ThrowIfNull(memberPublicKey);

        await _sessionLock.WaitAsync();
        try
        {
            if (State == SessionState.Terminated)
                throw new InvalidOperationException("Cannot mute member: Session is terminated.");

            // Check permissions
            if (!HasAdvancedPermission(GroupPermission.ModerateMembers))
                throw new UnauthorizedAccessException("You don't have permission to mute members.");

            string memberId = GetMemberId(memberPublicKey);
            if (!_members.TryGetValue(memberId, out var member))
                return false;

            // Cannot mute owners or admins
            if (member.Role == MemberRole.Owner || member.Role == MemberRole.Admin)
                throw new InvalidOperationException("Cannot mute group owners or administrators.");

            member.MutedUntil = DateTime.UtcNow.Add(duration);
            member.LastActivity = DateTime.UtcNow;

            if (!string.IsNullOrEmpty(reason))
            {
                member.Metadata["MuteReason"] = reason;
            }

            LoggingManager.LogInformation(nameof(GroupSession),
                $"Muted member for {duration} in group {GroupId}. Reason: {reason ?? "None"}");

            return true;
        }
        finally
        {
            _sessionLock.Release();
        }
    }

    /// <summary>
    /// Unmutes a member.
    /// </summary>
    /// <param name="memberPublicKey">The public key of the member to unmute.</param>
    /// <returns>True if the member was unmuted successfully.</returns>
    /// <exception cref="UnauthorizedAccessException">Thrown when the current user lacks permission.</exception>
    public async Task<bool> UnmuteMemberAsync(byte[] memberPublicKey)
    {
        ThrowIfDisposed();

        ArgumentNullException.ThrowIfNull(memberPublicKey);

        await _sessionLock.WaitAsync();
        try
        {
            if (State == SessionState.Terminated)
                throw new InvalidOperationException("Cannot unmute member: Session is terminated.");

            // Check permissions
            if (!HasAdvancedPermission(GroupPermission.ModerateMembers))
                throw new UnauthorizedAccessException("You don't have permission to unmute members.");

            string memberId = GetMemberId(memberPublicKey);
            if (!_members.TryGetValue(memberId, out var member))
                return false;

            member.MutedUntil = null;
            member.LastActivity = DateTime.UtcNow;
            member.Metadata.Remove("MuteReason");

            LoggingManager.LogInformation(nameof(GroupSession),
                $"Unmuted member in group {GroupId}");

            return true;
        }
        finally
        {
            _sessionLock.Release();
        }
    }

    /// <summary>
    /// Sets metadata for a group member.
    /// </summary>
    /// <param name="memberPublicKey">The public key of the member.</param>
    /// <param name="key">The metadata key.</param>
    /// <param name="value">The metadata value.</param>
    /// <returns>True if the metadata was set successfully.</returns>
    /// <exception cref="UnauthorizedAccessException">Thrown when the current user lacks permission.</exception>
    public async Task<bool> SetMemberMetadataAsync(byte[] memberPublicKey, string key, string value)
    {
        ThrowIfDisposed();

        ArgumentNullException.ThrowIfNull(memberPublicKey);
        ArgumentException.ThrowIfNullOrEmpty(key);
        ArgumentNullException.ThrowIfNull(value);

        await _sessionLock.WaitAsync();
        try
        {
            if (State == SessionState.Terminated)
                throw new InvalidOperationException("Cannot set member metadata: Session is terminated.");

            // Check if it's their own metadata or if they have admin permissions
            string currentUserId = GetMemberId(_identityKeyPair.PublicKey);
            string targetMemberId = GetMemberId(memberPublicKey);

            if (currentUserId != targetMemberId && !HasAdvancedPermission(GroupPermission.ManageAdmins))
                throw new UnauthorizedAccessException("You don't have permission to set metadata for other members.");

            if (!_members.TryGetValue(targetMemberId, out var member))
                return false;

            member.Metadata[key] = value;
            member.LastActivity = DateTime.UtcNow;

            return true;
        }
        finally
        {
            _sessionLock.Release();
        }
    }

    /// <summary>
    /// Creates an invitation code for the group.
    /// </summary>
    /// <param name="expiresIn">How long the invitation should be valid for.</param>
    /// <param name="maxUses">Maximum number of times the invitation can be used (null for unlimited).</param>
    /// <param name="defaultRole">The role new members will have when joining with this invitation.</param>
    /// <returns>The invitation code.</returns>
    /// <exception cref="UnauthorizedAccessException">Thrown when the current user lacks permission.</exception>
    public async Task<string> CreateInvitationAsync(TimeSpan expiresIn, int? maxUses = null, MemberRole defaultRole = MemberRole.Member)
    {
        ThrowIfDisposed();

        await _sessionLock.WaitAsync();
        try
        {
            if (State == SessionState.Terminated)
                throw new InvalidOperationException("Cannot create invitation: Session is terminated.");

            // Check permissions
            if (!HasAdvancedPermission(GroupPermission.AddMember))
                throw new UnauthorizedAccessException("You don't have permission to create invitations.");

            var invitation = new GroupInvitation
            {
                InvitationCode = Guid.NewGuid().ToString("N"),
                GroupId = GroupId,
                CreatedBy = _identityKeyPair.PublicKey,
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.Add(expiresIn),
                MaxUses = maxUses,
                DefaultRole = defaultRole
            };

            _activeInvitations.TryAdd(invitation.InvitationCode, invitation);

            LoggingManager.LogInformation(nameof(GroupSession),
                $"Created invitation {invitation.InvitationCode} for group {GroupId}");

            return invitation.InvitationCode;
        }
        finally
        {
            _sessionLock.Release();
        }
    }

    /// <summary>
    /// Revokes an invitation code.
    /// </summary>
    /// <param name="invitationCode">The invitation code to revoke.</param>
    /// <returns>True if the invitation was revoked successfully.</returns>
    /// <exception cref="UnauthorizedAccessException">Thrown when the current user lacks permission.</exception>
    public async Task<bool> RevokeInvitationAsync(string invitationCode)
    {
        ThrowIfDisposed();

        ArgumentException.ThrowIfNullOrEmpty(invitationCode);

        await _sessionLock.WaitAsync();
        try
        {
            if (State == SessionState.Terminated)
                throw new InvalidOperationException("Cannot revoke invitation: Session is terminated.");

            // Check permissions
            if (!HasAdvancedPermission(GroupPermission.AddMember))
                throw new UnauthorizedAccessException("You don't have permission to revoke invitations.");

            if (!_activeInvitations.TryGetValue(invitationCode, out var invitation))
                return false;

            invitation.Revoke(_identityKeyPair.PublicKey, "Manually revoked");

            LoggingManager.LogInformation(nameof(GroupSession),
                $"Revoked invitation {invitationCode} for group {GroupId}");

            return true;
        }
        finally
        {
            _sessionLock.Release();
        }
    }

    /// <summary>
    /// Joins the group using an invitation code.
    /// </summary>
    /// <param name="invitationCode">The invitation code to use.</param>
    /// <param name="memberPublicKey">The public key of the new member.</param>
    /// <returns>True if the member joined successfully.</returns>
    public async Task<bool> JoinWithInvitationAsync(string invitationCode, byte[] memberPublicKey)
    {
        ThrowIfDisposed();

        ArgumentException.ThrowIfNullOrEmpty(invitationCode);
        ArgumentNullException.ThrowIfNull(memberPublicKey);

        await _sessionLock.WaitAsync();
        try
        {
            if (State == SessionState.Terminated)
                throw new InvalidOperationException("Cannot join group: Session is terminated.");

            if (!_activeInvitations.TryGetValue(invitationCode, out var invitation))
                return false;

            if (!invitation.IsValid)
                return false;

            // Add the member
            string memberId = GetMemberId(memberPublicKey);
            if (_members.ContainsKey(memberId))
                return false; // Already a member

            var newMember = new GroupMember
            {
                PublicKey = memberPublicKey,
                JoinedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                Role = invitation.DefaultRole,
                CustomPermissions = new HashSet<GroupPermission>(invitation.CustomPermissions),
                LastActivity = DateTime.UtcNow,
                InvitationCode = invitationCode
            };

            // Set legacy flags for backward compatibility
            if (invitation.DefaultRole == MemberRole.Admin)
                newMember.IsAdmin = true;
            else if (invitation.DefaultRole == MemberRole.Owner)
                newMember.IsOwner = true;

            _members.TryAdd(memberId, newMember);
            invitation.RecordUsage(memberPublicKey);

            LoggingManager.LogInformation(nameof(GroupSession),
                $"Member joined group {GroupId} using invitation {invitationCode}");

            return true;
        }
        finally
        {
            _sessionLock.Release();
        }
    }

    /// <summary>
    /// Gets group statistics and insights.
    /// </summary>
    /// <returns>Group statistics including member activity, message counts, etc.</returns>
    public async Task<GroupStatistics> GetGroupStatisticsAsync()
    {
        ThrowIfDisposed();

        await _sessionLock.WaitAsync();
        try
        {
            var statistics = new GroupStatistics
            {
                TotalMembers = _members.Count,
                GroupCreatedAt = CreatedAt,
                GeneratedAt = DateTime.UtcNow
            };

            // Calculate member statistics
            var activeThreshold = DateTime.UtcNow.AddDays(-7);
            statistics.ActiveMembers = _members.Values.Count(m => m.LastActivity >= activeThreshold);
            statistics.MutedMembers = _members.Values.Count(m => m.IsMuted);

            // Role breakdown
            statistics.MembersByRole = _members.Values
                .GroupBy(m => m.Role)
                .ToDictionary(g => g.Key, g => g.Count());

            // Find most active member
            var mostActiveKvp = _members.Values
                .Where(m => m.LastActivity.HasValue)
                .OrderByDescending(m => m.LastActivity)
                .FirstOrDefault();

            if (mostActiveKvp != null)
            {
                statistics.MostActiveMember = mostActiveKvp.PublicKey;
                statistics.LastMessageAt = mostActiveKvp.LastActivity;
            }

            // Invitation statistics
            statistics.ActiveInvitations = _activeInvitations.Values.Count(i => i.IsValid);
            statistics.MembersJoinedViaInvitation = _members.Values.Count(m => !string.IsNullOrEmpty(m.InvitationCode));

            // Find last member joined
            var lastJoined = _members.Values
                .OrderByDescending(m => m.JoinedAt)
                .FirstOrDefault();

            if (lastJoined != null)
            {
                statistics.LastMemberJoinedAt = DateTimeOffset.FromUnixTimeMilliseconds(lastJoined.JoinedAt).UtcDateTime;
            }

            // Calculate health score
            statistics.HealthScore = CalculateGroupHealthScore(statistics);

            return statistics;
        }
        finally
        {
            _sessionLock.Release();
        }
    }

    #endregion
}
