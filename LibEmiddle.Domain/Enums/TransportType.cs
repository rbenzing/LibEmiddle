namespace LibEmiddle.Domain.Enums
{
    /// <summary>
    /// Represents transport types for the LibEmiddle client.
    /// </summary>
    public enum TransportType
    {
        /// <summary>
        /// In-memory transport for testing and local development.
        /// </summary>
        InMemory,
        
        /// <summary>
        /// HTTP transport for remote communications.
        /// </summary>
        Http,
        
        /// <summary>
        /// WebSocket transport for real-time communications.
        /// </summary>
        WebSocket,
        
        /// <summary>
        /// WebRTC transport for peer-to-peer communications (v2.5).
        /// Enables direct encrypted communication between clients.
        /// </summary>
        WebRTC
    }
}
