using LibEmiddle.Domain.Diagnostics;

namespace LibEmiddle.Abstractions
{
    /// <summary>
    /// Interface for LibEmiddle diagnostic and health monitoring capabilities (v2.5).
    /// Provides real-time insights into client performance, health, and operational status.
    /// </summary>
    public interface ILibEmiddleDiagnostics
    {
        /// <summary>
        /// Gets the current health metrics for the client.
        /// </summary>
        /// <returns>Current health metrics snapshot.</returns>
        LibEmiddleHealthMetrics GetHealthMetrics();

        /// <summary>
        /// Generates a comprehensive diagnostic report.
        /// </summary>
        /// <returns>Detailed diagnostic report containing all system information.</returns>
        Task<DiagnosticReport> GenerateDiagnosticReportAsync();

        /// <summary>
        /// Gets real-time diagnostic events as they occur.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token to stop the stream.</param>
        /// <returns>Async enumerable of diagnostic events.</returns>
        IAsyncEnumerable<DiagnosticEvent> GetRealTimeDiagnosticsAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Records a custom diagnostic event.
        /// </summary>
        /// <param name="diagnosticEvent">The event to record.</param>
        void RecordEvent(DiagnosticEvent diagnosticEvent);

        /// <summary>
        /// Enables or disables diagnostic collection.
        /// </summary>
        /// <param name="enabled">Whether to enable diagnostic collection.</param>
        void SetDiagnosticsEnabled(bool enabled);

        /// <summary>
        /// Gets whether diagnostics are currently enabled.
        /// </summary>
        bool IsEnabled { get; }

        /// <summary>
        /// Event raised when a critical diagnostic condition is detected.
        /// </summary>
        event EventHandler<DiagnosticEvent>? CriticalEventDetected;

        /// <summary>
        /// Clears diagnostic history and resets metrics.
        /// </summary>
        void Reset();

        /// <summary>
        /// Exports diagnostic data to a specified format.
        /// </summary>
        /// <param name="format">Export format (json, csv, xml).</param>
        /// <param name="filePath">File path to export to.</param>
        /// <returns>True if export was successful.</returns>
        Task<bool> ExportDiagnosticsAsync(string format, string filePath);
    }

    /// <summary>
    /// Interface for health checking LibEmiddle components.
    /// </summary>
    public interface ILibEmiddleHealthCheck
    {
        /// <summary>
        /// Performs a health check on the component.
        /// </summary>
        /// <param name="context">Health check context.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Health check result.</returns>
        Task<HealthCheckResult> CheckAsync(HealthCheckContext context, CancellationToken cancellationToken = default);

        /// <summary>
        /// The name of this health check.
        /// </summary>
        string Name { get; }

        /// <summary>
        /// Tags associated with this health check.
        /// </summary>
        IEnumerable<string> Tags { get; }
    }

    /// <summary>
    /// Context for health checks.
    /// </summary>
    public class HealthCheckContext
    {
        /// <summary>
        /// Registration information for the health check.
        /// </summary>
        public HealthCheckRegistration Registration { get; set; } = new();

        /// <summary>
        /// Cancellation token for the health check operation.
        /// </summary>
        public CancellationToken CancellationToken { get; set; }
    }

    /// <summary>
    /// Registration information for a health check.
    /// </summary>
    public class HealthCheckRegistration
    {
        /// <summary>
        /// The name of the health check.
        /// </summary>
        public string Name { get; set; } = string.Empty;

        /// <summary>
        /// The timeout for the health check.
        /// </summary>
        public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>
        /// Tags associated with the health check.
        /// </summary>
        public HashSet<string> Tags { get; set; } = new();
    }

    /// <summary>
    /// Result of a health check operation.
    /// </summary>
    public class HealthCheckResult
    {
        /// <summary>
        /// The health status.
        /// </summary>
        public HealthStatus Status { get; set; }

        /// <summary>
        /// Description of the health check result.
        /// </summary>
        public string Description { get; set; } = string.Empty;

        /// <summary>
        /// Exception that occurred during the health check, if any.
        /// </summary>
        public Exception? Exception { get; set; }

        /// <summary>
        /// Additional data associated with the health check.
        /// </summary>
        public Dictionary<string, object> Data { get; set; } = new();

        /// <summary>
        /// Duration of the health check.
        /// </summary>
        public TimeSpan Duration { get; set; }

        /// <summary>
        /// Creates a healthy result.
        /// </summary>
        /// <param name="description">Optional description.</param>
        /// <param name="data">Optional additional data.</param>
        /// <returns>Healthy health check result.</returns>
        public static HealthCheckResult Healthy(string? description = null, Dictionary<string, object>? data = null)
        {
            return new HealthCheckResult
            {
                Status = HealthStatus.Healthy,
                Description = description ?? "Healthy",
                Data = data ?? new Dictionary<string, object>()
            };
        }

        /// <summary>
        /// Creates an unhealthy result.
        /// </summary>
        /// <param name="description">Description of the problem.</param>
        /// <param name="exception">Exception that caused the unhealthy state.</param>
        /// <param name="data">Optional additional data.</param>
        /// <returns>Unhealthy health check result.</returns>
        public static HealthCheckResult Unhealthy(string description, Exception? exception = null, Dictionary<string, object>? data = null)
        {
            return new HealthCheckResult
            {
                Status = HealthStatus.Critical,
                Description = description,
                Exception = exception,
                Data = data ?? new Dictionary<string, object>()
            };
        }

        /// <summary>
        /// Creates a degraded result.
        /// </summary>
        /// <param name="description">Description of the degraded state.</param>
        /// <param name="exception">Optional exception information.</param>
        /// <param name="data">Optional additional data.</param>
        /// <returns>Degraded health check result.</returns>
        public static HealthCheckResult Degraded(string description, Exception? exception = null, Dictionary<string, object>? data = null)
        {
            return new HealthCheckResult
            {
                Status = HealthStatus.Warning,
                Description = description,
                Exception = exception,
                Data = data ?? new Dictionary<string, object>()
            };
        }
    }
}