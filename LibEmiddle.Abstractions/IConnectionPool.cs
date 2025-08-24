using LibEmiddle.Domain;

namespace LibEmiddle.Abstractions
{
    /// <summary>
    /// Interface for managing a pool of network connections (v2.5).
    /// Provides efficient connection reuse, health monitoring, and automatic recovery.
    /// </summary>
    public interface IConnectionPool : IDisposable
    {
        /// <summary>
        /// Gets the name/identifier of this connection pool.
        /// </summary>
        string PoolName { get; }

        /// <summary>
        /// Gets the current pool statistics.
        /// </summary>
        ConnectionPoolStatistics Statistics { get; }

        /// <summary>
        /// Gets whether the pool is healthy and operational.
        /// </summary>
        bool IsHealthy { get; }

        /// <summary>
        /// Acquires a connection from the pool.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token for the operation.</param>
        /// <returns>A pooled connection or null if none available.</returns>
        Task<IPooledConnection?> AcquireConnectionAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Returns a connection to the pool.
        /// </summary>
        /// <param name="connection">The connection to return.</param>
        /// <param name="isHealthy">Whether the connection is still healthy.</param>
        Task ReturnConnectionAsync(IPooledConnection connection, bool isHealthy = true);

        /// <summary>
        /// Validates the health of all connections in the pool.
        /// </summary>
        /// <returns>Number of unhealthy connections removed.</returns>
        Task<int> ValidateConnectionsAsync();

        /// <summary>
        /// Clears all connections from the pool.
        /// </summary>
        Task ClearPoolAsync();

        /// <summary>
        /// Event fired when pool health changes.
        /// </summary>
        event EventHandler<PoolHealthChangedEventArgs>? HealthChanged;

        /// <summary>
        /// Event fired when connection statistics change significantly.
        /// </summary>
        event EventHandler<ConnectionPoolStatistics>? StatisticsChanged;
    }

    /// <summary>
    /// Interface for a pooled network connection (v2.5).
    /// </summary>
    public interface IPooledConnection : IDisposable
    {
        /// <summary>
        /// Unique identifier for this connection.
        /// </summary>
        string ConnectionId { get; }

        /// <summary>
        /// When this connection was created.
        /// </summary>
        DateTime CreatedAt { get; }

        /// <summary>
        /// When this connection was last used.
        /// </summary>
        DateTime LastUsedAt { get; }

        /// <summary>
        /// Number of times this connection has been used.
        /// </summary>
        int UseCount { get; }

        /// <summary>
        /// Whether this connection is currently healthy.
        /// </summary>
        bool IsHealthy { get; }

        /// <summary>
        /// Whether this connection is currently in use.
        /// </summary>
        bool IsInUse { get; set; }

        /// <summary>
        /// The underlying transport connection.
        /// </summary>
        object UnderlyingConnection { get; }

        /// <summary>
        /// Additional metadata for this connection.
        /// </summary>
        Dictionary<string, object> Metadata { get; }

        /// <summary>
        /// Tests the health of this connection.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token for the operation.</param>
        /// <returns>True if the connection is healthy.</returns>
        Task<bool> TestHealthAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Sends data through this connection.
        /// </summary>
        /// <param name="data">Data to send.</param>
        /// <param name="cancellationToken">Cancellation token for the operation.</param>
        /// <returns>True if data was sent successfully.</returns>
        Task<bool> SendAsync(byte[] data, CancellationToken cancellationToken = default);

        /// <summary>
        /// Receives data from this connection.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token for the operation.</param>
        /// <returns>Received data or null if none available.</returns>
        Task<byte[]?> ReceiveAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Marks this connection as used.
        /// </summary>
        void MarkUsed();

        /// <summary>
        /// Event fired when connection health changes.
        /// </summary>
        event EventHandler<bool>? HealthChanged;
    }

    /// <summary>
    /// Factory interface for creating connection pools (v2.5).
    /// </summary>
    public interface IConnectionPoolFactory
    {
        /// <summary>
        /// Creates a connection pool for the specified endpoint.
        /// </summary>
        /// <param name="endpoint">The endpoint to connect to.</param>
        /// <param name="options">Pool configuration options.</param>
        /// <returns>A configured connection pool.</returns>
        Task<IConnectionPool> CreatePoolAsync(string endpoint, ConnectionPoolOptions options);

        /// <summary>
        /// Gets the default pool options for a transport type.
        /// </summary>
        /// <param name="transportType">The transport type.</param>
        /// <returns>Default pool options.</returns>
        ConnectionPoolOptions GetDefaultOptions(string transportType);

        /// <summary>
        /// Gets all active pools managed by this factory.
        /// </summary>
        /// <returns>Collection of active pools.</returns>
        IEnumerable<IConnectionPool> GetActivePools();

        /// <summary>
        /// Closes and disposes all pools.
        /// </summary>
        Task DisposeAllPoolsAsync();
    }

    /// <summary>
    /// Event arguments for pool health changes (v2.5).
    /// </summary>
    public class PoolHealthChangedEventArgs : EventArgs
    {
        /// <summary>
        /// The pool that changed health status.
        /// </summary>
        public IConnectionPool Pool { get; set; } = null!;

        /// <summary>
        /// Whether the pool is now healthy.
        /// </summary>
        public bool IsHealthy { get; set; }

        /// <summary>
        /// Previous health status.
        /// </summary>
        public bool PreviousHealthy { get; set; }

        /// <summary>
        /// Reason for the health change.
        /// </summary>
        public string Reason { get; set; } = string.Empty;

        /// <summary>
        /// When the health change occurred.
        /// </summary>
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    }
}