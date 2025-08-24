using LibEmiddle.Domain.Enums;

namespace LibEmiddle.Domain
{
    /// <summary>
    /// Statistics for resilience operations monitoring and diagnostics (v2.5).
    /// Provides insight into the performance and reliability of operations.
    /// </summary>
    public class ResilienceStats
    {
        /// <summary>
        /// Type of operation these statistics represent.
        /// </summary>
        public ResilienceOperationType OperationType { get; set; }

        /// <summary>
        /// Total number of operation executions.
        /// </summary>
        public long TotalExecutions { get; set; }

        /// <summary>
        /// Number of successful executions.
        /// </summary>
        public long SuccessfulExecutions { get; set; }

        /// <summary>
        /// Number of failed executions.
        /// </summary>
        public long FailedExecutions { get; set; }

        /// <summary>
        /// Current circuit breaker state for this operation type.
        /// </summary>
        public CircuitBreakerState CircuitBreakerState { get; set; }

        /// <summary>
        /// Average execution time for operations of this type.
        /// </summary>
        public TimeSpan AverageExecutionTime { get; set; }

        /// <summary>
        /// When the last execution occurred.
        /// </summary>
        public DateTime? LastExecutionTime { get; set; }

        /// <summary>
        /// The last exception that occurred (if any).
        /// </summary>
        public Exception? LastException { get; set; }

        /// <summary>
        /// Success rate as a percentage (0.0 to 1.0).
        /// </summary>
        public double SuccessRate => TotalExecutions > 0 ? (double)SuccessfulExecutions / TotalExecutions : 0.0;

        /// <summary>
        /// Failure rate as a percentage (0.0 to 1.0).
        /// </summary>
        public double FailureRate => TotalExecutions > 0 ? (double)FailedExecutions / TotalExecutions : 0.0;

        /// <summary>
        /// Whether the operation type is considered healthy based on recent statistics.
        /// </summary>
        public bool IsHealthy => SuccessRate >= 0.95 && CircuitBreakerState == CircuitBreakerState.Closed;

        /// <summary>
        /// Creates a copy of these resilience statistics.
        /// </summary>
        /// <returns>A new ResilienceStats instance with copied values.</returns>
        public ResilienceStats Clone()
        {
            return new ResilienceStats
            {
                OperationType = OperationType,
                TotalExecutions = TotalExecutions,
                SuccessfulExecutions = SuccessfulExecutions,
                FailedExecutions = FailedExecutions,
                CircuitBreakerState = CircuitBreakerState,
                AverageExecutionTime = AverageExecutionTime,
                LastExecutionTime = LastExecutionTime,
                LastException = LastException
            };
        }

        /// <summary>
        /// Resets all statistics to their initial state.
        /// </summary>
        public void Reset()
        {
            TotalExecutions = 0;
            SuccessfulExecutions = 0;
            FailedExecutions = 0;
            CircuitBreakerState = CircuitBreakerState.Closed;
            AverageExecutionTime = TimeSpan.Zero;
            LastExecutionTime = null;
            LastException = null;
        }
    }
}