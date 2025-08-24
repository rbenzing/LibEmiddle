using LibEmiddle.Abstractions;
using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;

namespace LibEmiddle.Infrastructure
{
    /// <summary>
    /// Stub implementation of resilience management for API development and testing.
    /// This implementation provides the interface contract but doesn't perform actual resilience patterns.
    /// </summary>
    /// <remarks>
    /// WARNING: This is a stub implementation for v2.5 API development.
    /// In a production environment, this should be replaced with a real implementation
    /// that provides actual circuit breakers, retry policies, timeouts, and other resilience patterns.
    /// </remarks>
    internal class ResilienceManagerStub : IResilienceManager
    {
        private readonly ResilienceOptions _options;
        private readonly Dictionary<ResilienceOperationType, ResilienceStats> _stats;

        public ResilienceManagerStub(ResilienceOptions options)
        {
            _options = options ?? throw new ArgumentNullException(nameof(options));
            _stats = new Dictionary<ResilienceOperationType, ResilienceStats>();
        }

        public async Task<T> ExecuteAsync<T>(
            Func<CancellationToken, Task<T>> operation,
            ResilienceOperationType operationType,
            CancellationToken cancellationToken = default)
        {
            // Stub implementation: just execute the operation directly
            // In a real implementation, this would apply retry, circuit breaker, and timeout policies
            try
            {
                return await operation(cancellationToken);
            }
            catch (Exception ex)
            {
                // Log the failure for statistics
                RecordFailure(operationType, ex);
                throw;
            }
        }

        public async Task ExecuteAsync(
            Func<CancellationToken, Task> operation,
            ResilienceOperationType operationType,
            CancellationToken cancellationToken = default)
        {
            // Stub implementation: just execute the operation directly
            try
            {
                await operation(cancellationToken);
            }
            catch (Exception ex)
            {
                // Log the failure for statistics
                RecordFailure(operationType, ex);
                throw;
            }
        }

        public Task<ResilienceStats> GetStatisticsAsync(ResilienceOperationType operationType)
        {
            _stats.TryGetValue(operationType, out var stats);
            return Task.FromResult(stats ?? new ResilienceStats
            {
                OperationType = operationType,
                TotalExecutions = 0,
                SuccessfulExecutions = 0,
                FailedExecutions = 0,
                CircuitBreakerState = CircuitBreakerState.Closed,
                AverageExecutionTime = TimeSpan.Zero,
                LastExecutionTime = null
            });
        }

        public Task<Dictionary<ResilienceOperationType, ResilienceStats>> GetAllStatisticsAsync()
        {
            var allStats = new Dictionary<ResilienceOperationType, ResilienceStats>();
            
            foreach (var operationType in Enum.GetValues<ResilienceOperationType>())
            {
                _stats.TryGetValue(operationType, out var stats);
                allStats[operationType] = stats ?? new ResilienceStats
                {
                    OperationType = operationType,
                    TotalExecutions = 0,
                    SuccessfulExecutions = 0,
                    FailedExecutions = 0,
                    CircuitBreakerState = CircuitBreakerState.Closed,
                    AverageExecutionTime = TimeSpan.Zero,
                    LastExecutionTime = null
                };
            }

            return Task.FromResult(allStats);
        }

        public Task ResetStatisticsAsync(ResilienceOperationType? operationType = null)
        {
            if (operationType.HasValue)
            {
                _stats.Remove(operationType.Value);
            }
            else
            {
                _stats.Clear();
            }

            return Task.CompletedTask;
        }

        private void RecordFailure(ResilienceOperationType operationType, Exception exception)
        {
            if (!_stats.TryGetValue(operationType, out var stats))
            {
                stats = new ResilienceStats
                {
                    OperationType = operationType,
                    TotalExecutions = 0,
                    SuccessfulExecutions = 0,
                    FailedExecutions = 0,
                    CircuitBreakerState = CircuitBreakerState.Closed,
                    AverageExecutionTime = TimeSpan.Zero,
                    LastExecutionTime = DateTime.UtcNow
                };
                _stats[operationType] = stats;
            }

            stats.TotalExecutions++;
            stats.FailedExecutions++;
            stats.LastExecutionTime = DateTime.UtcNow;
            stats.LastException = exception;
        }

        public void Dispose()
        {
            // Nothing to dispose in stub implementation
        }
    }

}