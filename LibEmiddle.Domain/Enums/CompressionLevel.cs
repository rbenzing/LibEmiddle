namespace LibEmiddle.Domain.Enums
{
    /// <summary>
    /// Defines compression levels for message batching and transport optimization.
    /// </summary>
    public enum CompressionLevel
    {
        /// <summary>
        /// No compression applied (default for backward compatibility).
        /// </summary>
        None = 0,

        /// <summary>
        /// Fastest compression with minimal CPU usage.
        /// Suitable for real-time messaging scenarios.
        /// </summary>
        Fastest = 1,

        /// <summary>
        /// Balanced compression optimizing for both speed and size.
        /// Recommended for most use cases.
        /// </summary>
        Optimal = 2,

        /// <summary>
        /// Maximum compression prioritizing smallest possible size.
        /// Best for bandwidth-constrained environments.
        /// </summary>
        SmallestSize = 3
    }
}