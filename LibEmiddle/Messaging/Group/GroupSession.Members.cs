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
    #region Group Member Management

    public async Task<bool> AddMemberAsync(byte[] memberPublicKey)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(memberPublicKey);

        await _sessionLock.WaitAsync();
        try
        {
            if (State == SessionState.Terminated)
                throw new InvalidOperationException("Cannot add member: Session is terminated.");

            // Check permissions
            if (!HasPermission(GroupOperation.AddMember))
                throw new UnauthorizedAccessException("You don't have permission to add members to this group.");

            string memberId = GetMemberId(memberPublicKey);

            // Check if already a member
            if (_members.ContainsKey(memberId))
                return false;

            var member = new GroupMember
            {
                PublicKey = memberPublicKey.ToArray(),
                JoinedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                IsAdmin = false,
                IsOwner = false
            };

            bool added = _members.TryAdd(memberId, member);
            if (added)
            {
                _removedMembers.TryRemove(memberId, out _);
                RecordJoinTime(memberPublicKey);
            }

            return added;
        }
        finally
        {
            _sessionLock.Release();
        }
    }

    public async Task<bool> RemoveMemberAsync(byte[] memberPublicKey)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(memberPublicKey);

        await _sessionLock.WaitAsync();
        try
        {
            if (State == SessionState.Terminated)
                throw new InvalidOperationException("Cannot remove member: Session is terminated.");

            if (!HasPermission(GroupOperation.RemoveMember))
                throw new UnauthorizedAccessException("You don't have permission to remove members from this group.");

            string memberId = GetMemberId(memberPublicKey);

            if (_members.TryGetValue(memberId, out var member))
            {
                // Can't remove the owner
                if (member.IsOwner)
                    return false;

                if (_members.TryRemove(memberId, out _))
                {
                    _removedMembers[memberId] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

                    // Rotate key after removing member for forward secrecy
                    await RotateKeyInternalAsync();
                    return true;
                }
            }

            return false;
        }
        finally
        {
            _sessionLock.Release();
        }
    }

    #endregion
}
