using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;

namespace LibEmiddle.Abstractions
{
    /// <summary>
    /// Interface for managing resilience patterns like circuit breakers, retries, and timeouts (v2.5).
    /// Provides robust error handling and automatic recovery for network operations.
    /// </summary>
    public interface IResilienceManager : IDisposable
    {
        /// <summary>
        /// Executes an operation with resilience patterns applied.
        /// </summary>
        /// <typeparam name="T">Return type of the operation.</typeparam>
        /// <param name="operation">The operation to execute.</param>
        /// <param name="operationType">Type of operation for policy selection.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Result of the operation or throws if all retries failed.</returns>
        Task<T> ExecuteAsync<T>(
            Func<CancellationToken, Task<T>> operation,
            ResilienceOperationType operationType,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Executes an operation without return value with resilience patterns applied.
        /// </summary>
        /// <param name="operation">The operation to execute.</param>
        /// <param name="operationType">Type of operation for policy selection.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        Task ExecuteAsync(
            Func<CancellationToken, Task> operation,
            ResilienceOperationType operationType,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets resilience statistics for a specific operation type.
        /// </summary>
        /// <param name="operationType">Type of operation to get statistics for.</param>
        /// <returns>Current resilience statistics for the operation type.</returns>
        Task<ResilienceStats> GetStatisticsAsync(ResilienceOperationType operationType);

        /// <summary>
        /// Gets resilience statistics for all operation types.
        /// </summary>
        /// <returns>Dictionary of resilience statistics by operation type.</returns>
        Task<Dictionary<ResilienceOperationType, ResilienceStats>> GetAllStatisticsAsync();

        /// <summary>
        /// Resets resilience statistics for a specific operation type or all types.
        /// </summary>
        /// <param name="operationType">Operation type to reset, or null to reset all.</param>
        Task ResetStatisticsAsync(ResilienceOperationType? operationType = null);
    }
}