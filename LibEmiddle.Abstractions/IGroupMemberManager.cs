using LibEmiddle.Domain;

namespace LibEmiddle.Abstractions
{
    /// <summary>
    /// Interface for managing group membership, roles, and permissions.
    /// </summary>
    public interface IGroupMemberManager
    {
        bool CreateGroup(string groupId, string groupName, byte[] creatorPublicKey, bool creatorIsAdmin = true);
        bool DeleteGroup(string groupId);
        bool AddMember(string groupId, byte[] memberPublicKey, bool isAdmin = false);
        bool RemoveMember(string groupId, byte[] memberPublicKey);
        bool JoinGroup(string groupId, byte[] userPublicKey);
        bool LeaveGroup(string groupId, byte[] userPublicKey);
        bool IsMember(string groupId, byte[] memberPublicKey);
        bool IsGroupAdmin(string groupId, byte[] memberPublicKey);
        bool WasAdmin(string groupId, byte[] memberPublicKey);
        bool HasKeyRotationPermission(string groupId, byte[] memberPublicKey);
        bool WasRemovedBeforeTimestamp(string groupId, byte[] memberPublicKey, long timestamp);
        List<byte[]> GetMembers(string groupId);
        List<byte[]> GetAdmins(string groupId);
        bool PromoteToAdmin(string groupId, byte[] memberPublicKey);
        bool DemoteFromAdmin(string groupId, byte[] memberPublicKey);
        GroupInfo? GetGroupInfo(string groupId);
        Dictionary<string, string> ExportState();
        int ImportState(Dictionary<string, string> state);
    }
}
