namespace LibEmiddle.Domain.Enums
{
    /// <summary>
    /// Defines message priority levels for batching and transmission.
    /// </summary>
    public enum MessagePriority
    {
        /// <summary>
        /// Lowest priority - can be delayed significantly.
        /// </summary>
        Low = 0,

        /// <summary>
        /// Normal priority - default level for most messages.
        /// </summary>
        Normal = 1,

        /// <summary>
        /// High priority - should be sent with minimal delay.
        /// </summary>
        High = 2,

        /// <summary>
        /// Highest priority - bypasses batching and sends immediately.
        /// </summary>
        Critical = 3
    }
}