using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;

namespace LibEmiddle.Abstractions
{
    /// <summary>
    /// Interface for advanced key rotation management (v2.5).
    /// Provides sophisticated key rotation policies and monitoring capabilities.
    /// </summary>
    public interface IAdvancedKeyRotationManager : IDisposable
    {
        /// <summary>
        /// Sets the key rotation policy for a specific session.
        /// </summary>
        /// <param name="sessionId">ID of the session.</param>
        /// <param name="policy">Key rotation policy to apply.</param>
        Task SetRotationPolicyAsync(string sessionId, KeyRotationPolicy policy);

        /// <summary>
        /// Gets the current key rotation policy for a session.
        /// </summary>
        /// <param name="sessionId">ID of the session.</param>
        /// <returns>Current rotation policy or null if not set.</returns>
        Task<KeyRotationPolicy?> GetRotationPolicyAsync(string sessionId);

        /// <summary>
        /// Manually triggers a key rotation for a specific session.
        /// </summary>
        /// <param name="sessionId">ID of the session.</param>
        /// <param name="rotationType">Type of keys to rotate.</param>
        /// <param name="reason">Reason for the rotation.</param>
        /// <param name="priority">Priority level for the rotation.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Rotation operation result.</returns>
        Task<KeyRotationResult> TriggerRotationAsync(
            string sessionId,
            KeyRotationType rotationType,
            KeyRotationReason reason,
            KeyRotationPriority priority = KeyRotationPriority.Normal,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Schedules a key rotation for a specific time.
        /// </summary>
        /// <param name="sessionId">ID of the session.</param>
        /// <param name="scheduledTime">When to perform the rotation.</param>
        /// <param name="rotationType">Type of keys to rotate.</param>
        /// <param name="reason">Reason for the rotation.</param>
        /// <returns>Scheduled rotation ID.</returns>
        Task<string> ScheduleRotationAsync(
            string sessionId,
            DateTime scheduledTime,
            KeyRotationType rotationType,
            KeyRotationReason reason);

        /// <summary>
        /// Cancels a scheduled key rotation.
        /// </summary>
        /// <param name="rotationId">ID of the scheduled rotation.</param>
        /// <param name="reason">Reason for cancellation.</param>
        Task CancelScheduledRotationAsync(string rotationId, string? reason = null);

        /// <summary>
        /// Gets the status of a key rotation operation.
        /// </summary>
        /// <param name="rotationId">ID of the rotation operation.</param>
        /// <returns>Current status of the rotation.</returns>
        Task<KeyRotationOperationStatus> GetRotationStatusAsync(string rotationId);

        /// <summary>
        /// Gets the rotation history for a session.
        /// </summary>
        /// <param name="sessionId">ID of the session.</param>
        /// <param name="limit">Maximum number of history entries to return.</param>
        /// <returns>List of rotation history entries.</returns>
        Task<IReadOnlyList<KeyRotationHistoryEntry>> GetRotationHistoryAsync(string sessionId, int limit = 100);

        /// <summary>
        /// Gets key rotation statistics for monitoring.
        /// </summary>
        /// <param name="sessionId">ID of the session, or null for global statistics.</param>
        /// <param name="timeRange">Time range for statistics calculation.</param>
        /// <returns>Rotation statistics.</returns>
        Task<KeyRotationStatistics> GetRotationStatisticsAsync(string? sessionId = null, TimeSpan? timeRange = null);

        /// <summary>
        /// Validates whether a key rotation can be performed.
        /// </summary>
        /// <param name="sessionId">ID of the session.</param>
        /// <param name="rotationType">Type of keys to rotate.</param>
        /// <returns>Validation result with any issues found.</returns>
        Task<KeyRotationValidationResult> ValidateRotationAsync(string sessionId, KeyRotationType rotationType);

        /// <summary>
        /// Updates the risk assessment for adaptive rotation policies.
        /// </summary>
        /// <param name="sessionId">ID of the session.</param>
        /// <param name="riskLevel">Current risk level (0.0 to 1.0).</param>
        /// <param name="riskFactors">Specific risk factors detected.</param>
        Task UpdateRiskAssessmentAsync(string sessionId, double riskLevel, Dictionary<string, object> riskFactors);

        /// <summary>
        /// Gets the next scheduled rotation time for a session.
        /// </summary>
        /// <param name="sessionId">ID of the session.</param>
        /// <returns>Next rotation time or null if no rotation scheduled.</returns>
        Task<DateTime?> GetNextRotationTimeAsync(string sessionId);

        /// <summary>
        /// Enables or disables automatic rotation for a session.
        /// </summary>
        /// <param name="sessionId">ID of the session.</param>
        /// <param name="enabled">Whether to enable automatic rotation.</param>
        Task SetAutomaticRotationAsync(string sessionId, bool enabled);

        /// <summary>
        /// Exports key rotation audit logs for compliance.
        /// </summary>
        /// <param name="sessionId">ID of the session, or null for all sessions.</param>
        /// <param name="startTime">Start time for the audit period.</param>
        /// <param name="endTime">End time for the audit period.</param>
        /// <param name="format">Export format (e.g., "json", "xml", "csv").</param>
        /// <returns>Exported audit data.</returns>
        Task<byte[]> ExportAuditLogsAsync(
            string? sessionId,
            DateTime startTime,
            DateTime endTime,
            string format = "json");

        /// <summary>
        /// Event fired when a key rotation is completed.
        /// </summary>
        event EventHandler<KeyRotationCompletedEventArgs>? RotationCompleted;

        /// <summary>
        /// Event fired when a key rotation fails.
        /// </summary>
        event EventHandler<KeyRotationFailedEventArgs>? RotationFailed;

        /// <summary>
        /// Event fired when a rotation is scheduled.
        /// </summary>
        event EventHandler<KeyRotationScheduledEventArgs>? RotationScheduled;

        /// <summary>
        /// Event fired when risk level changes significantly.
        /// </summary>
        event EventHandler<RiskLevelChangedEventArgs>? RiskLevelChanged;
    }

    /// <summary>
    /// Result of a key rotation operation.
    /// </summary>
    public class KeyRotationResult
    {
        /// <summary>
        /// Unique identifier for this rotation operation.
        /// </summary>
        public string RotationId { get; set; } = string.Empty;

        /// <summary>
        /// Whether the rotation was successful.
        /// </summary>
        public bool Success { get; set; }

        /// <summary>
        /// Current status of the rotation.
        /// </summary>
        public KeyRotationStatus Status { get; set; }

        /// <summary>
        /// Error message if the rotation failed.
        /// </summary>
        public string? ErrorMessage { get; set; }

        /// <summary>
        /// Time when the rotation started.
        /// </summary>
        public DateTime StartTime { get; set; }

        /// <summary>
        /// Time when the rotation completed (if applicable).
        /// </summary>
        public DateTime? EndTime { get; set; }

        /// <summary>
        /// Type of keys that were rotated.
        /// </summary>
        public KeyRotationType RotationType { get; set; }

        /// <summary>
        /// Reason for the rotation.
        /// </summary>
        public KeyRotationReason Reason { get; set; }

        /// <summary>
        /// Additional metadata about the rotation.
        /// </summary>
        public Dictionary<string, object> Metadata { get; set; } = new();

        /// <summary>
        /// Duration of the rotation operation.
        /// </summary>
        public TimeSpan Duration => EndTime?.Subtract(StartTime) ?? TimeSpan.Zero;
    }

    /// <summary>
    /// Status information for a key rotation operation.
    /// </summary>
    public class KeyRotationOperationStatus
    {
        /// <summary>
        /// Rotation operation ID.
        /// </summary>
        public string RotationId { get; set; } = string.Empty;

        /// <summary>
        /// Current status.
        /// </summary>
        public KeyRotationStatus Status { get; set; }

        /// <summary>
        /// Progress percentage (0-100).
        /// </summary>
        public int ProgressPercentage { get; set; }

        /// <summary>
        /// Current operation being performed.
        /// </summary>
        public string CurrentOperation { get; set; } = string.Empty;

        /// <summary>
        /// Estimated time remaining.
        /// </summary>
        public TimeSpan? EstimatedTimeRemaining { get; set; }

        /// <summary>
        /// Any error that occurred.
        /// </summary>
        public string? ErrorMessage { get; set; }

        /// <summary>
        /// When the status was last updated.
        /// </summary>
        public DateTime LastUpdated { get; set; } = DateTime.UtcNow;
    }

    /// <summary>
    /// Historical record of a key rotation.
    /// </summary>
    public class KeyRotationHistoryEntry
    {
        /// <summary>
        /// Rotation operation ID.
        /// </summary>
        public string RotationId { get; set; } = string.Empty;

        /// <summary>
        /// Session ID where rotation occurred.
        /// </summary>
        public string SessionId { get; set; } = string.Empty;

        /// <summary>
        /// Type of keys rotated.
        /// </summary>
        public KeyRotationType RotationType { get; set; }

        /// <summary>
        /// Reason for rotation.
        /// </summary>
        public KeyRotationReason Reason { get; set; }

        /// <summary>
        /// When the rotation started.
        /// </summary>
        public DateTime StartTime { get; set; }

        /// <summary>
        /// When the rotation completed.
        /// </summary>
        public DateTime? EndTime { get; set; }

        /// <summary>
        /// Final status of the rotation.
        /// </summary>
        public KeyRotationStatus Status { get; set; }

        /// <summary>
        /// Duration of the rotation.
        /// </summary>
        public TimeSpan Duration { get; set; }

        /// <summary>
        /// Error message if rotation failed.
        /// </summary>
        public string? ErrorMessage { get; set; }

        /// <summary>
        /// User or system that triggered the rotation.
        /// </summary>
        public string TriggeredBy { get; set; } = string.Empty;

        /// <summary>
        /// Additional metadata.
        /// </summary>
        public Dictionary<string, object> Metadata { get; set; } = new();
    }

    /// <summary>
    /// Statistics about key rotation operations.
    /// </summary>
    public class KeyRotationStatistics
    {
        /// <summary>
        /// Total number of rotations performed.
        /// </summary>
        public long TotalRotations { get; set; }

        /// <summary>
        /// Number of successful rotations.
        /// </summary>
        public long SuccessfulRotations { get; set; }

        /// <summary>
        /// Number of failed rotations.
        /// </summary>
        public long FailedRotations { get; set; }

        /// <summary>
        /// Average rotation duration.
        /// </summary>
        public TimeSpan AverageRotationDuration { get; set; }

        /// <summary>
        /// Median rotation duration.
        /// </summary>
        public TimeSpan MedianRotationDuration { get; set; }

        /// <summary>
        /// Maximum rotation duration observed.
        /// </summary>
        public TimeSpan MaxRotationDuration { get; set; }

        /// <summary>
        /// Minimum rotation duration observed.
        /// </summary>
        public TimeSpan MinRotationDuration { get; set; }

        /// <summary>
        /// Current rotation frequency (rotations per hour).
        /// </summary>
        public double RotationFrequency { get; set; }

        /// <summary>
        /// Success rate percentage (0-100).
        /// </summary>
        public double SuccessRate => TotalRotations > 0 ? (double)SuccessfulRotations / TotalRotations * 100 : 0;

        /// <summary>
        /// Breakdown by rotation reason.
        /// </summary>
        public Dictionary<KeyRotationReason, long> RotationsByReason { get; set; } = new();

        /// <summary>
        /// Breakdown by rotation type.
        /// </summary>
        public Dictionary<KeyRotationType, long> RotationsByType { get; set; } = new();

        /// <summary>
        /// Time period these statistics cover.
        /// </summary>
        public TimeSpan TimePeriod { get; set; }

        /// <summary>
        /// When these statistics were generated.
        /// </summary>
        public DateTime GeneratedAt { get; set; } = DateTime.UtcNow;
    }

    /// <summary>
    /// Result of key rotation validation.
    /// </summary>
    public class KeyRotationValidationResult
    {
        /// <summary>
        /// Whether the rotation can proceed.
        /// </summary>
        public bool CanRotate { get; set; }

        /// <summary>
        /// List of validation warnings.
        /// </summary>
        public List<string> Warnings { get; set; } = new();

        /// <summary>
        /// List of validation errors that prevent rotation.
        /// </summary>
        public List<string> Errors { get; set; } = new();

        /// <summary>
        /// Estimated time for the rotation to complete.
        /// </summary>
        public TimeSpan EstimatedDuration { get; set; }

        /// <summary>
        /// Risk level of performing the rotation (0.0 to 1.0).
        /// </summary>
        public double RiskLevel { get; set; }

        /// <summary>
        /// Recommended time to perform the rotation.
        /// </summary>
        public DateTime? RecommendedTime { get; set; }
    }

    /// <summary>
    /// Event arguments for rotation completion events.
    /// </summary>
    public class KeyRotationCompletedEventArgs : EventArgs
    {
        /// <summary>
        /// Result of the completed rotation.
        /// </summary>
        public KeyRotationResult Result { get; set; } = new();

        /// <summary>
        /// Session ID where rotation occurred.
        /// </summary>
        public string SessionId { get; set; } = string.Empty;
    }

    /// <summary>
    /// Event arguments for rotation failure events.
    /// </summary>
    public class KeyRotationFailedEventArgs : EventArgs
    {
        /// <summary>
        /// Result of the failed rotation.
        /// </summary>
        public KeyRotationResult Result { get; set; } = new();

        /// <summary>
        /// Session ID where rotation failed.
        /// </summary>
        public string SessionId { get; set; } = string.Empty;

        /// <summary>
        /// Exception that caused the failure.
        /// </summary>
        public Exception? Exception { get; set; }
    }

    /// <summary>
    /// Event arguments for rotation scheduling events.
    /// </summary>
    public class KeyRotationScheduledEventArgs : EventArgs
    {
        /// <summary>
        /// ID of the scheduled rotation.
        /// </summary>
        public string RotationId { get; set; } = string.Empty;

        /// <summary>
        /// Session ID for the scheduled rotation.
        /// </summary>
        public string SessionId { get; set; } = string.Empty;

        /// <summary>
        /// When the rotation is scheduled to occur.
        /// </summary>
        public DateTime ScheduledTime { get; set; }

        /// <summary>
        /// Type of rotation scheduled.
        /// </summary>
        public KeyRotationType RotationType { get; set; }

        /// <summary>
        /// Reason for the scheduled rotation.
        /// </summary>
        public KeyRotationReason Reason { get; set; }
    }

    /// <summary>
    /// Event arguments for risk level change events.
    /// </summary>
    public class RiskLevelChangedEventArgs : EventArgs
    {
        /// <summary>
        /// Session ID where risk level changed.
        /// </summary>
        public string SessionId { get; set; } = string.Empty;

        /// <summary>
        /// Previous risk level.
        /// </summary>
        public double PreviousRiskLevel { get; set; }

        /// <summary>
        /// New risk level.
        /// </summary>
        public double NewRiskLevel { get; set; }

        /// <summary>
        /// Risk factors that contributed to the change.
        /// </summary>
        public Dictionary<string, object> RiskFactors { get; set; } = new();

        /// <summary>
        /// Whether the change triggered an automatic rotation.
        /// </summary>
        public bool TriggeredRotation { get; set; }
    }
}