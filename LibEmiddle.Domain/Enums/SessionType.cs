namespace LibEmiddle.Domain.Enums
{
    /// <summary>
    /// Defines types of cryptographic sessions.
    /// </summary>
    public enum SessionType
    {
        /// <summary>
        /// Individual 1:1 chat session.
        /// </summary>
        Individual = 0,

        /// <summary>
        /// Group chat session.
        /// </summary>
        Group = 1
    }
}
