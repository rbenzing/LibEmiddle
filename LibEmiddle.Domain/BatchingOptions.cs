using LibEmiddle.Domain.Enums;

namespace LibEmiddle.Domain
{
    /// <summary>
    /// Configuration options for message batching and compression.
    /// Allows optimizing throughput and bandwidth usage for high-volume messaging scenarios.
    /// </summary>
    public class BatchingOptions
    {
        /// <summary>
        /// Maximum number of messages to include in a single batch.
        /// Default is 1 (no batching) for backward compatibility.
        /// Set to higher values to enable batching.
        /// </summary>
        public int MaxBatchSize { get; set; } = 1;

        /// <summary>
        /// Maximum time to wait for additional messages before sending a partial batch.
        /// Default is zero (no delay) for backward compatibility.
        /// Set to small values (e.g., 50-100ms) to enable temporal batching.
        /// </summary>
        public TimeSpan MaxBatchDelay { get; set; } = TimeSpan.Zero;

        /// <summary>
        /// Maximum age of a batch before it's automatically sent.
        /// This is the same concept as MaxBatchDelay but with a different name for compatibility.
        /// </summary>
        public TimeSpan MaxBatchAge { get; set; } = TimeSpan.FromMilliseconds(100);

        /// <summary>
        /// Whether to enable automatic flushing of batches based on time intervals.
        /// When enabled, batches will be automatically sent based on MaxBatchAge timing.
        /// </summary>
        public bool EnableAutoFlush { get; set; } = true;

        /// <summary>
        /// Whether to apply compression to batched messages.
        /// Only effective when MaxBatchSize > 1.
        /// </summary>
        public bool EnableCompression { get; set; } = false;

        /// <summary>
        /// Compression level to use when EnableCompression is true.
        /// </summary>
        public CompressionLevel CompressionLevel { get; set; } = CompressionLevel.None;

        /// <summary>
        /// Minimum batch size required before compression is applied.
        /// Prevents overhead of compressing very small batches.
        /// </summary>
        public int MinimumCompressionSize { get; set; } = 1024; // 1KB

        /// <summary>
        /// Whether to preserve message ordering within batches.
        /// When true, messages are processed in the order they were batched.
        /// </summary>
        public bool PreserveOrdering { get; set; } = true;

        /// <summary>
        /// Maximum total size of a batch in bytes before forcing transmission.
        /// Prevents memory issues with very large batches.
        /// </summary>
        public int MaxBatchSizeBytes { get; set; } = 1024 * 1024; // 1MB

        /// <summary>
        /// Validates the batching configuration.
        /// </summary>
        /// <returns>True if the configuration is valid.</returns>
        public bool IsValid()
        {
            return MaxBatchSize > 0 &&
                   MaxBatchDelay >= TimeSpan.Zero &&
                   MaxBatchAge >= TimeSpan.Zero &&
                   MinimumCompressionSize > 0 &&
                   MaxBatchSizeBytes > 0;
        }

        /// <summary>
        /// Returns the default batching configuration.
        /// Provides balanced settings suitable for most scenarios.
        /// </summary>
        public static BatchingOptions Default => new()
        {
            MaxBatchSize = 10,
            MaxBatchDelay = TimeSpan.FromMilliseconds(50),
            MaxBatchAge = TimeSpan.FromMilliseconds(50),
            EnableAutoFlush = true,
            EnableCompression = false,
            PreserveOrdering = true,
            MaxBatchSizeBytes = 1024 * 1024, // 1MB
            MinimumCompressionSize = 1024 // 1KB
        };

        /// <summary>
        /// Returns a configuration optimized for real-time messaging.
        /// Minimal batching with focus on low latency.
        /// </summary>
        public static BatchingOptions RealTime => new()
        {
            MaxBatchSize = 3,
            MaxBatchDelay = TimeSpan.FromMilliseconds(10),
            MaxBatchAge = TimeSpan.FromMilliseconds(10),
            EnableAutoFlush = true,
            EnableCompression = false,
            PreserveOrdering = true
        };

        /// <summary>
        /// Returns a configuration optimized for high throughput.
        /// Larger batches with compression for maximum efficiency.
        /// </summary>
        public static BatchingOptions HighThroughput => new()
        {
            MaxBatchSize = 50,
            MaxBatchDelay = TimeSpan.FromMilliseconds(100),
            MaxBatchAge = TimeSpan.FromMilliseconds(100),
            EnableAutoFlush = true,
            EnableCompression = true,
            CompressionLevel = CompressionLevel.Optimal,
            PreserveOrdering = true
        };

        /// <summary>
        /// Returns a configuration optimized for bandwidth-constrained environments.
        /// Maximum compression with larger batches to minimize overhead.
        /// </summary>
        public static BatchingOptions BandwidthOptimized => new()
        {
            MaxBatchSize = 100,
            MaxBatchDelay = TimeSpan.FromMilliseconds(250),
            MaxBatchAge = TimeSpan.FromMilliseconds(250),
            EnableAutoFlush = true,
            EnableCompression = true,
            CompressionLevel = CompressionLevel.SmallestSize,
            MinimumCompressionSize = 512,
            PreserveOrdering = true
        };
    }
}