namespace LibEmiddle.Domain.Diagnostics
{
    /// <summary>
    /// Health metrics for LibEmiddle operations (v2.5).
    /// Provides real-time information about client performance and status.
    /// </summary>
    public class LibEmiddleHealthMetrics
    {
        /// <summary>
        /// Average time taken for encryption operations in milliseconds.
        /// </summary>
        public double AverageEncryptionTimeMs { get; set; }

        /// <summary>
        /// Average time taken for decryption operations in milliseconds.
        /// </summary>
        public double AverageDecryptionTimeMs { get; set; }

        /// <summary>
        /// Number of currently active sessions.
        /// </summary>
        public int ActiveSessions { get; set; }

        /// <summary>
        /// Number of messages pending delivery.
        /// </summary>
        public int PendingMessages { get; set; }

        /// <summary>
        /// When the last key rotation occurred.
        /// </summary>
        public DateTime LastKeyRotation { get; set; }

        /// <summary>
        /// List of recent error messages (last 10).
        /// </summary>
        public List<string> RecentErrors { get; set; } = new();

        /// <summary>
        /// Total number of messages sent since client initialization.
        /// </summary>
        public long TotalMessagesSent { get; set; }

        /// <summary>
        /// Total number of messages received since client initialization.
        /// </summary>
        public long TotalMessagesReceived { get; set; }

        /// <summary>
        /// Number of failed message delivery attempts.
        /// </summary>
        public int FailedDeliveries { get; set; }

        /// <summary>
        /// Number of linked devices.
        /// </summary>
        public int LinkedDevicesCount { get; set; }

        /// <summary>
        /// Memory usage of the client in bytes.
        /// </summary>
        public long MemoryUsageBytes { get; set; }

        /// <summary>
        /// Uptime of the client since initialization.
        /// </summary>
        public TimeSpan Uptime { get; set; }

        /// <summary>
        /// Network latency to the primary endpoint in milliseconds.
        /// </summary>
        public double NetworkLatencyMs { get; set; }

        /// <summary>
        /// Transport connection status.
        /// </summary>
        public ConnectionStatus TransportStatus { get; set; }

        /// <summary>
        /// Last time metrics were updated.
        /// </summary>
        public DateTime LastUpdated { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Gets the overall health status based on the metrics.
        /// </summary>
        public HealthStatus OverallStatus
        {
            get
            {
                if (RecentErrors.Count > 5)
                    return HealthStatus.Critical;

                if (FailedDeliveries > 10 || NetworkLatencyMs > 5000)
                    return HealthStatus.Warning;

                if (TransportStatus != ConnectionStatus.Connected)
                    return HealthStatus.Warning;

                return HealthStatus.Healthy;
            }
        }
    }

    /// <summary>
    /// Connection status enumeration.
    /// </summary>
    public enum ConnectionStatus
    {
        Disconnected,
        Connecting,
        Connected,
        Reconnecting,
        Failed
    }

    /// <summary>
    /// Health status enumeration.
    /// </summary>
    public enum HealthStatus
    {
        Healthy,
        Warning,
        Critical,
        Unknown
    }
}