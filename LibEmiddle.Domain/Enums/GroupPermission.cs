namespace LibEmiddle.Domain.Enums
{
    /// <summary>
    /// Defines granular permissions for group members.
    /// Can be combined using bitwise operations for flexible role management.
    /// </summary>
    [Flags]
    public enum GroupPermission
    {
        /// <summary>
        /// No permissions (read-only member).
        /// </summary>
        None = 0,

        /// <summary>
        /// Permission to send messages to the group.
        /// </summary>
        SendMessage = 1,

        /// <summary>
        /// Permission to add new members to the group.
        /// </summary>
        AddMember = 2,

        /// <summary>
        /// Permission to remove members from the group.
        /// </summary>
        RemoveMember = 4,

        /// <summary>
        /// Permission to change group settings and metadata.
        /// </summary>
        ChangeSettings = 8,

        /// <summary>
        /// Permission to manage admin roles and delegate permissions.
        /// </summary>
        ManageAdmins = 16,

        /// <summary>
        /// Permission to rotate group encryption keys.
        /// </summary>
        RotateKeys = 32,

        /// <summary>
        /// Permission to mute or unmute other members.
        /// </summary>
        ModerateMembers = 64,

        /// <summary>
        /// All permissions combined (super admin).
        /// </summary>
        All = SendMessage | AddMember | RemoveMember | ChangeSettings | ManageAdmins | RotateKeys | ModerateMembers
    }
}