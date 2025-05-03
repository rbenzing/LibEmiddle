namespace LibEmiddle.Domain.Enums
{
    /// <summary>
    /// Defines strategies for key rotation in encryption sessions.
    /// </summary>
    public enum KeyRotationStrategy
    {
        /// <summary>
        /// Standard rotation according to protocol defaults 
        /// (every 20 messages).
        /// </summary>
        Standard = 0,
        
        /// <summary>
        /// More frequent key rotation after every message,
        /// providing maximum forward secrecy at the cost of performance.
        /// </summary>
        AfterEveryMessage = 1,
        
        /// <summary>
        /// Hourly rotation regardless of message count.
        /// </summary>
        Hourly = 2,
        
        /// <summary>
        /// Daily rotation regardless of message count.
        /// </summary>
        Daily = 3,
        
        /// <summary>
        /// Weekly rotation regardless of message count.
        /// </summary>
        Weekly = 4
    }
}
