using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using LibEmiddle.Abstractions;
using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;

namespace LibEmiddle.Infrastructure
{
    /// <summary>
    /// Real implementation of <see cref="IResilienceManager"/> providing retry with
    /// exponential backoff, circuit breaker (Closed/HalfOpen/Open), and per-call timeout.
    /// </summary>
    internal sealed class ResilienceManager : IResilienceManager
    {
        private readonly ResilienceOptions _options;
        private readonly ConcurrentDictionary<ResilienceOperationType, OperationState> _state = new();

        /// <summary>
        /// Initialises a new <see cref="ResilienceManager"/> with the supplied options.
        /// </summary>
        /// <param name="options">Resilience configuration; must not be <see langword="null"/>.</param>
        public ResilienceManager(ResilienceOptions options)
        {
            _options = options ?? throw new ArgumentNullException(nameof(options));
        }

        /// <inheritdoc/>
        public async Task<T> ExecuteAsync<T>(
            Func<CancellationToken, Task<T>> operation,
            ResilienceOperationType operationType,
            CancellationToken cancellationToken = default)
        {
            var state = _state.GetOrAdd(operationType, _ => new OperationState());
            ThrowIfOpen(state, operationType);

            int attempt = 0;
            Exception? lastException = null;

            while (attempt <= _options.RetryPolicy.MaxRetries)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var sw = Stopwatch.StartNew();
                try
                {
                    T result = await ExecuteWithTimeoutAsync(operation, cancellationToken).ConfigureAwait(false);
                    sw.Stop();
                    RecordSuccess(state, sw.Elapsed);
                    return result;
                }
                catch (OperationCanceledException)
                {
                    throw; // never retry cancellation
                }
                catch (Exception ex)
                {
                    sw.Stop();
                    lastException = ex;
                    RecordFailure(state, ex, sw.Elapsed);
                    attempt++;
                    if (attempt <= _options.RetryPolicy.MaxRetries)
                        await DelayAsync(attempt, cancellationToken).ConfigureAwait(false);
                }
            }

            throw lastException!;
        }

        /// <inheritdoc/>
        public async Task ExecuteAsync(
            Func<CancellationToken, Task> operation,
            ResilienceOperationType operationType,
            CancellationToken cancellationToken = default)
        {
            await ExecuteAsync<bool>(async ct =>
            {
                await operation(ct).ConfigureAwait(false);
                return true;
            }, operationType, cancellationToken).ConfigureAwait(false);
        }

        /// <inheritdoc/>
        public Task<ResilienceStats> GetStatisticsAsync(ResilienceOperationType operationType)
        {
            var state = _state.GetOrAdd(operationType, _ => new OperationState());
            return Task.FromResult(state.ToStats(operationType));
        }

        /// <inheritdoc/>
        public Task<Dictionary<ResilienceOperationType, ResilienceStats>> GetAllStatisticsAsync()
        {
            var result = new Dictionary<ResilienceOperationType, ResilienceStats>();
            foreach (var kvp in _state)
                result[kvp.Key] = kvp.Value.ToStats(kvp.Key);
            return Task.FromResult(result);
        }

        /// <inheritdoc/>
        public Task ResetStatisticsAsync(ResilienceOperationType? operationType = null)
        {
            if (operationType.HasValue)
            {
                if (_state.TryGetValue(operationType.Value, out var s)) s.Reset();
            }
            else
            {
                foreach (var s in _state.Values) s.Reset();
            }
            return Task.CompletedTask;
        }

        /// <inheritdoc/>
        public void Dispose() { /* no unmanaged resources */ }

        // ------------------------------------------------------------------
        // Private helpers
        // ------------------------------------------------------------------

        private async Task<T> ExecuteWithTimeoutAsync<T>(
            Func<CancellationToken, Task<T>> operation,
            CancellationToken cancellationToken)
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(_options.TimeoutPolicy.DefaultTimeout);
            return await operation(timeoutCts.Token).ConfigureAwait(false);
        }

        private void ThrowIfOpen(OperationState state, ResilienceOperationType operationType)
        {
            if (state.CircuitState != CircuitBreakerState.Open) return;

            if (DateTime.UtcNow - state.CircuitOpenedAt >= _options.CircuitBreakerPolicy.RecoveryTimeout)
            {
                state.CircuitState = CircuitBreakerState.HalfOpen;
                return;
            }

            throw new InvalidOperationException(
                $"Circuit breaker is Open for {operationType}. Retry after recovery timeout.");
        }

        private static void RecordSuccess(OperationState state, TimeSpan elapsed)
        {
            Interlocked.Increment(ref state.TotalExecutions);
            Interlocked.Increment(ref state.SuccessfulExecutions);
            state.UpdateAverageTime(elapsed);
            state.LastExecutionTime = DateTime.UtcNow;
            state.CircuitState = CircuitBreakerState.Closed;
            Interlocked.Exchange(ref state.ConsecutiveFailures, 0);
        }

        private void RecordFailure(OperationState state, Exception ex, TimeSpan elapsed)
        {
            Interlocked.Increment(ref state.TotalExecutions);
            Interlocked.Increment(ref state.FailedExecutions);
            state.UpdateAverageTime(elapsed);
            state.LastExecutionTime = DateTime.UtcNow;
            state.LastException = ex;

            long failures = Interlocked.Increment(ref state.ConsecutiveFailures);
            if (Interlocked.Read(ref state.TotalExecutions) >= _options.CircuitBreakerPolicy.MinimumThroughput
                && failures >= _options.CircuitBreakerPolicy.FailureThreshold
                && state.CircuitState != CircuitBreakerState.Open)
            {
                state.CircuitState = CircuitBreakerState.Open;
                state.CircuitOpenedAt = DateTime.UtcNow;
            }
        }

        private async Task DelayAsync(int attempt, CancellationToken ct)
        {
            TimeSpan delay = _options.RetryPolicy.UseExponentialBackoff
                ? TimeSpan.FromMilliseconds(Math.Min(
                    _options.RetryPolicy.BaseDelay.TotalMilliseconds
                        * Math.Pow(_options.RetryPolicy.BackoffMultiplier, attempt - 1),
                    _options.RetryPolicy.MaxDelay.TotalMilliseconds))
                : _options.RetryPolicy.BaseDelay;

            if (_options.EnableJitter)
            {
#pragma warning disable SCS0005 // jitter is non-secret; cryptographic randomness is not required here
                double jitter = Random.Shared.NextDouble() * delay.TotalMilliseconds * 0.2;
#pragma warning restore SCS0005
                delay = TimeSpan.FromMilliseconds(delay.TotalMilliseconds + jitter);
            }

            await Task.Delay(delay, ct).ConfigureAwait(false);
        }

        // ------------------------------------------------------------------
        // Per-operation mutable state (lock-free via Interlocked)
        // ------------------------------------------------------------------

        private sealed class OperationState
        {
            public long TotalExecutions;
            public long SuccessfulExecutions;
            public long FailedExecutions;
            public long ConsecutiveFailures;
            public volatile CircuitBreakerState CircuitState = CircuitBreakerState.Closed;
            public DateTime CircuitOpenedAt;
            public DateTime? LastExecutionTime;
            public Exception? LastException;
            private long _totalElapsedMs;

            public void UpdateAverageTime(TimeSpan elapsed) =>
                Interlocked.Add(ref _totalElapsedMs, (long)elapsed.TotalMilliseconds);

            public void Reset()
            {
                Interlocked.Exchange(ref TotalExecutions, 0);
                Interlocked.Exchange(ref SuccessfulExecutions, 0);
                Interlocked.Exchange(ref FailedExecutions, 0);
                Interlocked.Exchange(ref ConsecutiveFailures, 0);
                Interlocked.Exchange(ref _totalElapsedMs, 0);
                CircuitState = CircuitBreakerState.Closed;
                LastExecutionTime = null;
                LastException = null;
            }

            public ResilienceStats ToStats(ResilienceOperationType operationType)
            {
                long total = Interlocked.Read(ref TotalExecutions);
                return new ResilienceStats
                {
                    OperationType = operationType,
                    TotalExecutions = total,
                    SuccessfulExecutions = Interlocked.Read(ref SuccessfulExecutions),
                    FailedExecutions = Interlocked.Read(ref FailedExecutions),
                    CircuitBreakerState = CircuitState,
                    AverageExecutionTime = total > 0
                        ? TimeSpan.FromMilliseconds(Interlocked.Read(ref _totalElapsedMs) / (double)total)
                        : TimeSpan.Zero,
                    LastExecutionTime = LastExecutionTime,
                    LastException = LastException
                };
            }
        }
    }
}
