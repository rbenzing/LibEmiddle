namespace LibEmiddle.Domain.Enums
{
    /// <summary>
    /// Defines possible states of a session.
    /// </summary>
    public enum SessionState
    {
        /// <summary>
        /// Session has been created but not activated.
        /// </summary>
        Initialized = 0,

        /// <summary>
        /// Session is active and can send/receive messages.
        /// </summary>
        Active = 1,

        /// <summary>
        /// Session is temporarily suspended.
        /// </summary>
        Suspended = 2,

        /// <summary>
        /// Session is permanently terminated.
        /// </summary>
        Terminated = 3
    }
}
