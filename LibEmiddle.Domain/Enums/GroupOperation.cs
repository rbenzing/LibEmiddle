namespace LibEmiddle.Domain.Enums
{
    /// <summary>
    /// Represents the types of operations that can be performed on a group.
    /// </summary>
    public enum GroupOperation
    {
        Send,
        AddMember,
        RemoveMember,
        PromoteAdmin,
        DemoteAdmin,
        RotateKey,
        DeleteGroup
    }
}
