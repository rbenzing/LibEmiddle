using LibEmiddle.Domain.Enums;

namespace LibEmiddle.Domain.Diagnostics
{
    /// <summary>
    /// Comprehensive diagnostic report for LibEmiddle client (v2.5).
    /// Contains detailed information about client state, performance, and configuration.
    /// </summary>
    public class DiagnosticReport
    {
        /// <summary>
        /// When this report was generated.
        /// </summary>
        public DateTime GeneratedAt { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Unique identifier for this report.
        /// </summary>
        public string ReportId { get; set; } = Guid.NewGuid().ToString();

        /// <summary>
        /// LibEmiddle client version.
        /// </summary>
        public string ClientVersion { get; set; } = "2.5.0";

        /// <summary>
        /// Current health metrics.
        /// </summary>
        public LibEmiddleHealthMetrics HealthMetrics { get; set; } = new();

        /// <summary>
        /// Client configuration summary.
        /// </summary>
        public ConfigurationSummary Configuration { get; set; } = new();

        /// <summary>
        /// Session information.
        /// </summary>
        public SessionSummary Sessions { get; set; } = new();

        /// <summary>
        /// Transport information.
        /// </summary>
        public TransportSummary Transport { get; set; } = new();

        /// <summary>
        /// Cryptographic information.
        /// </summary>
        public CryptographicSummary Cryptography { get; set; } = new();

        /// <summary>
        /// Recent events (last 50).
        /// </summary>
        public List<DiagnosticEvent> RecentEvents { get; set; } = new();

        /// <summary>
        /// Performance statistics.
        /// </summary>
        public PerformanceStatistics Performance { get; set; } = new();

        /// <summary>
        /// Feature flags status.
        /// </summary>
        public FeatureFlagsStatus Features { get; set; } = new();

        /// <summary>
        /// Security audit information.
        /// </summary>
        public SecurityAudit Security { get; set; } = new();
    }

    /// <summary>
    /// Configuration summary for diagnostic report.
    /// </summary>
    public class ConfigurationSummary
    {
        public TransportType TransportType { get; set; }
        public KeyExchangeMode KeyExchangeMode { get; set; }
        public bool MultiDeviceEnabled { get; set; }
        public bool MessageHistoryEnabled { get; set; }
        public bool SecureMemoryEnabled { get; set; }
        public int MaxLinkedDevices { get; set; }
        public int MaxMessageHistoryPerSession { get; set; }
        public string? ServerEndpoint { get; set; }
    }

    /// <summary>
    /// Session summary for diagnostic report.
    /// </summary>
    public class SessionSummary
    {
        public int TotalSessions { get; set; }
        public int ActiveSessions { get; set; }
        public int ChatSessions { get; set; }
        public int GroupSessions { get; set; }
        public DateTime? OldestSessionCreated { get; set; }
        public DateTime? NewestSessionCreated { get; set; }
    }

    /// <summary>
    /// Transport summary for diagnostic report.
    /// </summary>
    public class TransportSummary
    {
        public ConnectionStatus Status { get; set; }
        public string? Endpoint { get; set; }
        public DateTime? LastConnected { get; set; }
        public int ConnectionAttempts { get; set; }
        public int SuccessfulConnections { get; set; }
        public double AverageLatencyMs { get; set; }
        public long BytesSent { get; set; }
        public long BytesReceived { get; set; }
    }

    /// <summary>
    /// Cryptographic summary for diagnostic report.
    /// </summary>
    public class CryptographicSummary
    {
        public DateTime? LastKeyRotation { get; set; }
        public int TotalKeyRotations { get; set; }
        public int OneTimePreKeysAvailable { get; set; }
        public bool PostQuantumEnabled { get; set; }
        public DateTime? IdentityKeyCreated { get; set; }
        public int ActiveSignedPreKeys { get; set; }
    }

    /// <summary>
    /// Performance statistics for diagnostic report.
    /// </summary>
    public class PerformanceStatistics
    {
        public double AverageEncryptionTimeMs { get; set; }
        public double AverageDecryptionTimeMs { get; set; }
        public double AverageKeyGenerationTimeMs { get; set; }
        public long TotalOperations { get; set; }
        public long FailedOperations { get; set; }
        public double SuccessRate => TotalOperations > 0 ? ((double)(TotalOperations - FailedOperations) / TotalOperations) * 100 : 0;
        public long MemoryUsageBytes { get; set; }
        public TimeSpan Uptime { get; set; }
    }

    /// <summary>
    /// Feature flags status for diagnostic report.
    /// </summary>
    public class FeatureFlagsStatus
    {
        public bool AsyncMessageStreams { get; set; }
        public bool MessageBatching { get; set; }
        public bool AdvancedGroupManagement { get; set; }
        public bool HealthMonitoring { get; set; }
        public bool FluentBuilder { get; set; }
        public bool PluggableStorage { get; set; }
        public bool PostQuantumPreparation { get; set; }
        public bool WebRTCTransport { get; set; }
        public bool ConnectionPooling { get; set; }
        public bool SessionBackup { get; set; }
    }

    /// <summary>
    /// Security audit information for diagnostic report.
    /// </summary>
    public class SecurityAudit
    {
        public int SecurityEventsLast24Hours { get; set; }
        public DateTime? LastSecurityEvent { get; set; }
        public bool AllSessionsSecure { get; set; }
        public bool CertificateValidationEnabled { get; set; }
        public int FailedAuthenticationAttempts { get; set; }
        public int SuspiciousActivities { get; set; }
        public List<string> SecurityWarnings { get; set; } = new();
    }
}