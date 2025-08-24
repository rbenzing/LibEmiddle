namespace LibEmiddle.Domain.Enums
{
    /// <summary>
    /// Represents a member's role in a group (v2.5 enhanced)
    /// </summary>
    public enum MemberRole
    {
        /// <summary>
        /// Regular group member with basic permissions
        /// </summary>
        Member = 0,

        /// <summary>
        /// Group moderator with message moderation capabilities
        /// </summary>
        Moderator = 1,

        /// <summary>
        /// Group admin with member management capabilities
        /// </summary>
        Admin = 2,

        /// <summary>
        /// Group owner with full control
        /// </summary>
        Owner = 3
    }
}
