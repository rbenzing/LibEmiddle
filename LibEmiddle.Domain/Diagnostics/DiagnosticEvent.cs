namespace LibEmiddle.Domain.Diagnostics
{
    /// <summary>
    /// Represents a diagnostic event in the LibEmiddle system (v2.5).
    /// Used for real-time monitoring and debugging.
    /// </summary>
    public class DiagnosticEvent
    {
        /// <summary>
        /// Unique identifier for this event.
        /// </summary>
        public string Id { get; set; } = Guid.NewGuid().ToString();

        /// <summary>
        /// When the event occurred.
        /// </summary>
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// The type of diagnostic event.
        /// </summary>
        public DiagnosticEventType EventType { get; set; }

        /// <summary>
        /// The component that generated this event.
        /// </summary>
        public string Component { get; set; } = string.Empty;

        /// <summary>
        /// The severity level of this event.
        /// </summary>
        public DiagnosticSeverity Severity { get; set; }

        /// <summary>
        /// A human-readable message describing the event.
        /// </summary>
        public string Message { get; set; } = string.Empty;

        /// <summary>
        /// Additional data associated with the event.
        /// </summary>
        public Dictionary<string, object> Data { get; set; } = new();

        /// <summary>
        /// The session ID associated with this event, if applicable.
        /// </summary>
        public string? SessionId { get; set; }

        /// <summary>
        /// The operation that was being performed when this event occurred.
        /// </summary>
        public string? Operation { get; set; }

        /// <summary>
        /// Duration of the operation in milliseconds, if applicable.
        /// </summary>
        public double? DurationMs { get; set; }

        /// <summary>
        /// Exception information if this event represents an error.
        /// </summary>
        public ExceptionInfo? Exception { get; set; }

        /// <summary>
        /// Creates a diagnostic event for an operation start.
        /// </summary>
        public static DiagnosticEvent OperationStarted(string component, string operation, string? sessionId = null)
        {
            return new DiagnosticEvent
            {
                EventType = DiagnosticEventType.OperationStarted,
                Component = component,
                Operation = operation,
                SessionId = sessionId,
                Severity = DiagnosticSeverity.Information,
                Message = $"Operation {operation} started in {component}"
            };
        }

        /// <summary>
        /// Creates a diagnostic event for an operation completion.
        /// </summary>
        public static DiagnosticEvent OperationCompleted(string component, string operation, double durationMs, string? sessionId = null)
        {
            return new DiagnosticEvent
            {
                EventType = DiagnosticEventType.OperationCompleted,
                Component = component,
                Operation = operation,
                SessionId = sessionId,
                DurationMs = durationMs,
                Severity = DiagnosticSeverity.Information,
                Message = $"Operation {operation} completed in {component} after {durationMs:F2}ms"
            };
        }

        /// <summary>
        /// Creates a diagnostic event for an error.
        /// </summary>
        public static DiagnosticEvent Error(string component, string message, Exception? exception = null, string? sessionId = null)
        {
            return new DiagnosticEvent
            {
                EventType = DiagnosticEventType.Error,
                Component = component,
                SessionId = sessionId,
                Severity = DiagnosticSeverity.Error,
                Message = message,
                Exception = exception != null ? new ExceptionInfo(exception) : null
            };
        }

        /// <summary>
        /// Creates a diagnostic event for a performance metric.
        /// </summary>
        public static DiagnosticEvent PerformanceMetric(string component, string metricName, object value, string? sessionId = null)
        {
            return new DiagnosticEvent
            {
                EventType = DiagnosticEventType.PerformanceMetric,
                Component = component,
                SessionId = sessionId,
                Severity = DiagnosticSeverity.Information,
                Message = $"Performance metric {metricName}: {value}",
                Data = { [metricName] = value }
            };
        }
    }

    /// <summary>
    /// Types of diagnostic events.
    /// </summary>
    public enum DiagnosticEventType
    {
        OperationStarted,
        OperationCompleted,
        Error,
        Warning,
        PerformanceMetric,
        SecurityEvent,
        NetworkEvent,
        SessionEvent,
        KeyRotation,
        DeviceSync
    }

    /// <summary>
    /// Severity levels for diagnostic events.
    /// </summary>
    public enum DiagnosticSeverity
    {
        Trace,
        Debug,
        Information,
        Warning,
        Error,
        Critical
    }

    /// <summary>
    /// Exception information for diagnostic events.
    /// </summary>
    public class ExceptionInfo
    {
        /// <summary>
        /// The exception type name.
        /// </summary>
        public string TypeName { get; set; }

        /// <summary>
        /// The exception message.
        /// </summary>
        public string Message { get; set; }

        /// <summary>
        /// The stack trace.
        /// </summary>
        public string? StackTrace { get; set; }

        /// <summary>
        /// Inner exception information.
        /// </summary>
        public ExceptionInfo? InnerException { get; set; }

        public ExceptionInfo(Exception exception)
        {
            TypeName = exception.GetType().Name;
            Message = exception.Message;
            StackTrace = exception.StackTrace;
            
            if (exception.InnerException != null)
                InnerException = new ExceptionInfo(exception.InnerException);
        }
    }
}