using LibEmiddle.Domain.Enums;

namespace LibEmiddle.Domain
{
    /// <summary>
    /// Constraints for post-quantum algorithm selection (v2.5).
    /// Used to specify requirements when selecting the optimal algorithm.
    /// </summary>
    public class PostQuantumConstraints
    {
        /// <summary>
        /// Minimum security level required in bits.
        /// </summary>
        public int MinimumSecurityLevel { get; set; } = 128;

        /// <summary>
        /// Maximum acceptable key size in bytes.
        /// </summary>
        public int MaxKeySize { get; set; } = 32768;

        /// <summary>
        /// Maximum acceptable signature size in bytes.
        /// </summary>
        public int MaxSignatureSize { get; set; } = 16384;

        /// <summary>
        /// Preferred performance profile.
        /// </summary>
        public PostQuantumPerformance PreferredPerformance { get; set; } = PostQuantumPerformance.Balanced;

        /// <summary>
        /// Whether to require NIST-approved algorithms only.
        /// </summary>
        public bool RequireNistApproved { get; set; } = true;
    }

    /// <summary>
    /// Result of post-quantum algorithm suggestion (v2.5).
    /// Contains the recommended algorithm along with reasoning and alternatives.
    /// </summary>
    public class AlgorithmSuggestion
    {
        /// <summary>
        /// The recommended algorithm.
        /// </summary>
        public PostQuantumAlgorithm Algorithm { get; set; }

        /// <summary>
        /// Human-readable reasoning for the recommendation.
        /// </summary>
        public string Reasoning { get; set; } = string.Empty;

        /// <summary>
        /// Confidence score for this recommendation (0.0 to 1.0).
        /// </summary>
        public double Confidence { get; set; }

        /// <summary>
        /// Alternative algorithms that also meet the constraints.
        /// </summary>
        public List<PostQuantumAlgorithm> Alternatives { get; set; } = new();
    }
}