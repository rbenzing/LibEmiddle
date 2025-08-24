using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;

namespace LibEmiddle.Abstractions
{
    /// <summary>
    /// Factory interface for creating post-quantum cryptographic implementations (v2.5 preparation).
    /// Provides methods to discover, configure, and create post-quantum crypto instances.
    /// </summary>
    public interface IPostQuantumCryptoFactory
    {
        /// <summary>
        /// Gets all available post-quantum algorithms in this implementation.
        /// </summary>
        /// <returns>Collection of supported algorithms.</returns>
        IEnumerable<PostQuantumAlgorithm> GetAvailableAlgorithms();

        /// <summary>
        /// Creates a post-quantum cryptographic implementation for the specified algorithm.
        /// </summary>
        /// <param name="algorithm">The post-quantum algorithm to use.</param>
        /// <param name="options">Configuration options for the algorithm.</param>
        /// <returns>A configured post-quantum crypto implementation.</returns>
        Task<IPostQuantumCrypto> CreateAsync(PostQuantumAlgorithm algorithm, PostQuantumOptions? options = null);

        /// <summary>
        /// Gets the recommended algorithm for the specified security level and performance profile.
        /// </summary>
        /// <param name="securityLevel">Required security level in bits (e.g., 128, 192, 256).</param>
        /// <param name="performanceProfile">Preferred performance characteristics.</param>
        /// <returns>The recommended algorithm.</returns>
        PostQuantumAlgorithm GetRecommendedAlgorithm(int securityLevel = 128, PostQuantumPerformance performanceProfile = PostQuantumPerformance.Balanced);

        /// <summary>
        /// Checks if a specific post-quantum algorithm is available in this implementation.
        /// </summary>
        /// <param name="algorithm">The algorithm to check.</param>
        /// <returns>True if the algorithm is supported.</returns>
        bool IsAlgorithmAvailable(PostQuantumAlgorithm algorithm);

        /// <summary>
        /// Gets detailed information about a specific algorithm.
        /// </summary>
        /// <param name="algorithm">The algorithm to get information about.</param>
        /// <returns>Algorithm information including key sizes, security level, and capabilities.</returns>
        PostQuantumAlgorithmInfo GetAlgorithmInfo(PostQuantumAlgorithm algorithm);

        /// <summary>
        /// Compares performance of multiple algorithms across different operations.
        /// </summary>
        /// <param name="algorithms">Algorithms to benchmark.</param>
        /// <param name="operations">Operations to measure.</param>
        /// <returns>Performance comparison results.</returns>
        Task<Dictionary<PostQuantumAlgorithm, Dictionary<PostQuantumOperation, OperationMetrics>>> GetPerformanceComparisonAsync(
            IEnumerable<PostQuantumAlgorithm> algorithms,
            IEnumerable<PostQuantumOperation> operations);

        /// <summary>
        /// Suggests the best algorithm for specific constraints and requirements.
        /// </summary>
        /// <param name="constraints">Performance and security constraints.</param>
        /// <returns>Algorithm suggestion with reasoning.</returns>
        AlgorithmSuggestion SuggestAlgorithm(PostQuantumConstraints constraints);
    }
}