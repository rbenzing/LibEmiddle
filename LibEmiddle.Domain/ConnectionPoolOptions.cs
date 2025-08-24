namespace LibEmiddle.Domain
{
    /// <summary>
    /// Configuration options for connection pooling and management.
    /// Enables efficient reuse of transport connections and improved performance.
    /// </summary>
    public class ConnectionPoolOptions
    {
        /// <summary>
        /// Maximum number of connections to maintain in the pool per endpoint.
        /// </summary>
        public int MaxConnections { get; set; } = 10;

        /// <summary>
        /// Minimum number of connections to keep alive in the pool.
        /// </summary>
        public int MinConnections { get; set; } = 1;

        /// <summary>
        /// Maximum time to wait for a connection from the pool.
        /// </summary>
        public TimeSpan ConnectionTimeout { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>
        /// Maximum time a connection can remain idle before being closed.
        /// </summary>
        public TimeSpan IdleTimeout { get; set; } = TimeSpan.FromMinutes(5);

        /// <summary>
        /// Maximum lifetime of a connection before it's forcibly closed and recreated.
        /// Helps prevent issues with long-lived connections.
        /// </summary>
        public TimeSpan MaxConnectionLifetime { get; set; } = TimeSpan.FromHours(1);

        /// <summary>
        /// Whether to enable connection reuse across multiple operations.
        /// </summary>
        public bool EnableConnectionReuse { get; set; } = true;

        /// <summary>
        /// Whether to validate connections before returning them from the pool.
        /// </summary>
        public bool ValidateOnReturn { get; set; } = true;

        /// <summary>
        /// Interval for background cleanup of expired connections.
        /// </summary>
        public TimeSpan CleanupInterval { get; set; } = TimeSpan.FromMinutes(1);

        /// <summary>
        /// Whether to enable connection health monitoring.
        /// </summary>
        public bool EnableHealthMonitoring { get; set; } = true;

        /// <summary>
        /// Validates the connection pool configuration.
        /// </summary>
        /// <returns>True if the configuration is valid.</returns>
        public bool IsValid()
        {
            return MaxConnections > 0 &&
                   MinConnections >= 0 &&
                   MinConnections <= MaxConnections &&
                   ConnectionTimeout > TimeSpan.Zero &&
                   IdleTimeout > TimeSpan.Zero &&
                   MaxConnectionLifetime > TimeSpan.Zero &&
                   CleanupInterval > TimeSpan.Zero;
        }

        /// <summary>
        /// Returns a configuration optimized for high-performance scenarios.
        /// </summary>
        public static ConnectionPoolOptions HighPerformance => new()
        {
            MaxConnections = 20,
            MinConnections = 5,
            ConnectionTimeout = TimeSpan.FromSeconds(10),
            IdleTimeout = TimeSpan.FromMinutes(2),
            MaxConnectionLifetime = TimeSpan.FromMinutes(30),
            EnableConnectionReuse = true,
            ValidateOnReturn = true,
            EnableHealthMonitoring = true
        };

        /// <summary>
        /// Returns a configuration optimized for resource-constrained environments.
        /// </summary>
        public static ConnectionPoolOptions ResourceConstrained => new()
        {
            MaxConnections = 3,
            MinConnections = 1,
            ConnectionTimeout = TimeSpan.FromSeconds(60),
            IdleTimeout = TimeSpan.FromMinutes(10),
            MaxConnectionLifetime = TimeSpan.FromHours(2),
            EnableConnectionReuse = true,
            ValidateOnReturn = false,
            EnableHealthMonitoring = false
        };
    }

    /// <summary>
    /// Statistics and metrics for a connection pool (v2.5).
    /// </summary>
    public class ConnectionPoolStatistics
    {
        /// <summary>
        /// Total number of connections in the pool.
        /// </summary>
        public int TotalConnections { get; set; }

        /// <summary>
        /// Number of connections currently in use.
        /// </summary>
        public int ActiveConnections { get; set; }

        /// <summary>
        /// Number of idle connections available for use.
        /// </summary>
        public int IdleConnections { get; set; }

        /// <summary>
        /// Number of failed connection attempts.
        /// </summary>
        public int FailedConnections { get; set; }

        /// <summary>
        /// Average time to acquire a connection from the pool.
        /// </summary>
        public TimeSpan AverageAcquisitionTime { get; set; }

        /// <summary>
        /// Pool utilization percentage (0.0 to 1.0).
        /// </summary>
        public double PoolUtilization { get; set; }

        /// <summary>
        /// Total number of connections created since pool startup.
        /// </summary>
        public long TotalConnectionsCreated { get; set; }

        /// <summary>
        /// Total number of connections disposed since pool startup.
        /// </summary>
        public long TotalConnectionsDisposed { get; set; }

        /// <summary>
        /// Number of connection validation failures.
        /// </summary>
        public int ValidationFailures { get; set; }

        /// <summary>
        /// When these statistics were last updated.
        /// </summary>
        public DateTime LastUpdated { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Calculates the pool efficiency ratio.
        /// </summary>
        public double EfficiencyRatio => 
            TotalConnectionsCreated > 0 ? 
                (double)(TotalConnectionsCreated - FailedConnections) / TotalConnectionsCreated : 
                1.0;
    }
}