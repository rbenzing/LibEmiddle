namespace LibEmiddle.Domain.Enums
{
    /// <summary>
    /// Types of operations for resilience pattern application (v2.5).
    /// Different operation types may have different resilience policies.
    /// </summary>
    public enum ResilienceOperationType
    {
        /// <summary>
        /// Message sending operations (individual messages).
        /// </summary>
        MessageSend = 1,

        /// <summary>
        /// Message receiving operations.
        /// </summary>
        MessageReceive = 2,

        /// <summary>
        /// Key exchange operations.
        /// </summary>
        KeyExchange = 3,

        /// <summary>
        /// Session establishment operations.
        /// </summary>
        SessionEstablishment = 4,

        /// <summary>
        /// Group operations (create, join, leave).
        /// </summary>
        GroupOperations = 5,

        /// <summary>
        /// Connection establishment to remote endpoints.
        /// </summary>
        ConnectionEstablishment = 6,

        /// <summary>
        /// Health check operations.
        /// </summary>
        HealthCheck = 7,

        /// <summary>
        /// Batch message sending operations.
        /// </summary>
        BatchMessageSend = 8,

        /// <summary>
        /// Storage operations (session persistence, key storage).
        /// </summary>
        StorageOperations = 9,

        /// <summary>
        /// Device linking and synchronization operations.
        /// </summary>
        DeviceOperations = 10,

        /// <summary>
        /// Generic network operations not covered by other types.
        /// </summary>
        GenericNetwork = 100
    }

    /// <summary>
    /// Circuit breaker states for resilience management (v2.5).
    /// </summary>
    public enum CircuitBreakerState
    {
        /// <summary>
        /// Circuit is closed - operations flow normally.
        /// </summary>
        Closed = 0,

        /// <summary>
        /// Circuit is open - operations are blocked to allow recovery.
        /// </summary>
        Open = 1,

        /// <summary>
        /// Circuit is half-open - testing if service has recovered.
        /// </summary>
        HalfOpen = 2
    }

    /// <summary>
    /// Health status for components and connections (v2.5).
    /// </summary>
    public enum HealthStatus
    {
        /// <summary>
        /// Component is healthy and functioning normally.
        /// </summary>
        Healthy = 0,

        /// <summary>
        /// Component has minor issues but is still functional.
        /// </summary>
        Degraded = 1,

        /// <summary>
        /// Component is unhealthy and may not function properly.
        /// </summary>
        Unhealthy = 2,

        /// <summary>
        /// Health status is unknown or cannot be determined.
        /// </summary>
        Unknown = 3
    }
}