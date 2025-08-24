namespace LibEmiddle.Domain
{
    /// <summary>
    /// Configuration options for resilience patterns including retry, circuit breaker, and timeout policies.
    /// Enhances reliability in unreliable network conditions.
    /// </summary>
    public class ResilienceOptions
    {
        /// <summary>
        /// Retry policy configuration.
        /// </summary>
        public RetryPolicy RetryPolicy { get; set; } = new();

        /// <summary>
        /// Circuit breaker policy configuration.
        /// </summary>
        public CircuitBreakerPolicy CircuitBreakerPolicy { get; set; } = new();

        /// <summary>
        /// Timeout policy configuration.
        /// </summary>
        public TimeoutPolicy TimeoutPolicy { get; set; } = new();

        /// <summary>
        /// Whether to enable automatic failover to backup endpoints.
        /// </summary>
        public bool EnableFailover { get; set; } = false;

        /// <summary>
        /// List of fallback endpoints to use when primary endpoint fails.
        /// Only used when EnableFailover is true.
        /// </summary>
        public string[] FallbackEndpoints { get; set; } = Array.Empty<string>();

        /// <summary>
        /// Whether to enable jitter in retry delays to prevent thundering herd.
        /// </summary>
        public bool EnableJitter { get; set; } = true;

        /// <summary>
        /// Validates the resilience configuration.
        /// </summary>
        /// <returns>True if the configuration is valid.</returns>
        public bool IsValid()
        {
            return RetryPolicy.IsValid() &&
                   CircuitBreakerPolicy.IsValid() &&
                   TimeoutPolicy.IsValid() &&
                   (!EnableFailover || FallbackEndpoints.Length > 0);
        }
    }

    /// <summary>
    /// Configuration for retry behavior.
    /// </summary>
    public class RetryPolicy
    {
        /// <summary>
        /// Maximum number of retry attempts.
        /// </summary>
        public int MaxRetries { get; set; } = 3;

        /// <summary>
        /// Base delay between retry attempts.
        /// </summary>
        public TimeSpan BaseDelay { get; set; } = TimeSpan.FromMilliseconds(1000);

        /// <summary>
        /// Maximum delay between retry attempts.
        /// </summary>
        public TimeSpan MaxDelay { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>
        /// Multiplier for exponential backoff.
        /// </summary>
        public double BackoffMultiplier { get; set; } = 2.0;

        /// <summary>
        /// Whether to use exponential backoff.
        /// </summary>
        public bool UseExponentialBackoff { get; set; } = true;

        /// <summary>
        /// Validates the retry policy configuration.
        /// </summary>
        /// <returns>True if the configuration is valid.</returns>
        public bool IsValid()
        {
            return MaxRetries >= 0 &&
                   BaseDelay > TimeSpan.Zero &&
                   MaxDelay >= BaseDelay &&
                   BackoffMultiplier > 1.0;
        }
    }

    /// <summary>
    /// Configuration for circuit breaker behavior.
    /// </summary>
    public class CircuitBreakerPolicy
    {
        /// <summary>
        /// Number of consecutive failures before opening the circuit.
        /// </summary>
        public int FailureThreshold { get; set; } = 5;

        /// <summary>
        /// Time to wait before attempting to close the circuit.
        /// </summary>
        public TimeSpan RecoveryTimeout { get; set; } = TimeSpan.FromMinutes(1);

        /// <summary>
        /// Minimum number of requests in the sampling period.
        /// </summary>
        public int MinimumThroughput { get; set; } = 10;

        /// <summary>
        /// Sampling period for calculating failure rate.
        /// </summary>
        public TimeSpan SamplingPeriod { get; set; } = TimeSpan.FromMinutes(1);

        /// <summary>
        /// Validates the circuit breaker policy configuration.
        /// </summary>
        /// <returns>True if the configuration is valid.</returns>
        public bool IsValid()
        {
            return FailureThreshold > 0 &&
                   RecoveryTimeout > TimeSpan.Zero &&
                   MinimumThroughput > 0 &&
                   SamplingPeriod > TimeSpan.Zero;
        }
    }

    /// <summary>
    /// Configuration for timeout behavior.
    /// </summary>
    public class TimeoutPolicy
    {
        /// <summary>
        /// Default timeout for operations.
        /// </summary>
        public TimeSpan DefaultTimeout { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>
        /// Timeout for connection establishment.
        /// </summary>
        public TimeSpan ConnectionTimeout { get; set; } = TimeSpan.FromSeconds(10);

        /// <summary>
        /// Timeout for sending data.
        /// </summary>
        public TimeSpan SendTimeout { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>
        /// Timeout for receiving data.
        /// </summary>
        public TimeSpan ReceiveTimeout { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>
        /// Validates the timeout policy configuration.
        /// </summary>
        /// <returns>True if the configuration is valid.</returns>
        public bool IsValid()
        {
            return DefaultTimeout > TimeSpan.Zero &&
                   ConnectionTimeout > TimeSpan.Zero &&
                   SendTimeout > TimeSpan.Zero &&
                   ReceiveTimeout > TimeSpan.Zero;
        }
    }
}