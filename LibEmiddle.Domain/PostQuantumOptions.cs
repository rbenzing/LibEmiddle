using LibEmiddle.Domain.Enums;

namespace LibEmiddle.Domain
{
    /// <summary>
    /// Configuration options for post-quantum cryptography (v2.5 preparation).
    /// </summary>
    public class PostQuantumOptions
    {
        /// <summary>
        /// The preferred post-quantum algorithm.
        /// </summary>
        public PostQuantumAlgorithm PreferredAlgorithm { get; set; } = PostQuantumAlgorithm.Kyber768;

        /// <summary>
        /// Fallback algorithms if the preferred one is not available.
        /// </summary>
        public List<PostQuantumAlgorithm> FallbackAlgorithms { get; set; } = new()
        {
            PostQuantumAlgorithm.Kyber512,
            PostQuantumAlgorithm.Kyber1024
        };

        /// <summary>
        /// Performance profile preference.
        /// </summary>
        public PostQuantumPerformance PerformanceProfile { get; set; } = PostQuantumPerformance.Balanced;

        /// <summary>
        /// Minimum security level required (in bits).
        /// </summary>
        public PostQuantumSecurityLevel MinimumSecurityLevel { get; set; } = PostQuantumSecurityLevel.Level1;

        /// <summary>
        /// Whether to require NIST-approved algorithms only.
        /// </summary>
        public bool RequireNistApproved { get; set; } = true;

        /// <summary>
        /// Whether to enable hybrid mode (classical + post-quantum).
        /// </summary>
        public bool EnableHybridMode { get; set; } = true;

        /// <summary>
        /// Implementation variant preference.
        /// </summary>
        public PostQuantumVariant PreferredVariant { get; set; } = PostQuantumVariant.Optimized;

        /// <summary>
        /// Key expiration time for generated keys.
        /// </summary>
        public TimeSpan? KeyExpiration { get; set; } = TimeSpan.FromDays(365);

        /// <summary>
        /// Whether to enable side-channel protection.
        /// </summary>
        public bool EnableSideChannelProtection { get; set; } = false;

        /// <summary>
        /// Maximum acceptable key size in bytes.
        /// </summary>
        public int MaxKeySize { get; set; } = 32768; // 32KB

        /// <summary>
        /// Maximum acceptable signature size in bytes.
        /// </summary>
        public int MaxSignatureSize { get; set; } = 16384; // 16KB

        /// <summary>
        /// Performance timeout for cryptographic operations.
        /// </summary>
        public TimeSpan OperationTimeout { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>
        /// Whether to cache generated key pairs.
        /// </summary>
        public bool EnableKeyCaching { get; set; } = false;

        /// <summary>
        /// Maximum number of cached key pairs.
        /// </summary>
        public int MaxCachedKeys { get; set; } = 10;

        /// <summary>
        /// Custom algorithm parameters.
        /// </summary>
        public Dictionary<PostQuantumAlgorithm, Dictionary<string, object>> AlgorithmParameters { get; set; } = new();

        /// <summary>
        /// Whether to enable performance monitoring.
        /// </summary>
        public bool EnablePerformanceMonitoring { get; set; } = false;

        /// <summary>
        /// Whether to run self-tests on initialization.
        /// </summary>
        public bool RunSelfTests { get; set; } = true;

        /// <summary>
        /// Additional configuration metadata.
        /// </summary>
        public Dictionary<string, object> Metadata { get; set; } = new();

        /// <summary>
        /// Creates a copy of these options with default values.
        /// </summary>
        public static PostQuantumOptions Default() => new();

        /// <summary>
        /// Creates options optimized for speed.
        /// </summary>
        public static PostQuantumOptions ForSpeed() => new()
        {
            PreferredAlgorithm = PostQuantumAlgorithm.Kyber512,
            PerformanceProfile = PostQuantumPerformance.Speed,
            MinimumSecurityLevel = PostQuantumSecurityLevel.Level1,
            FallbackAlgorithms = new() { PostQuantumAlgorithm.Falcon512 }
        };

        /// <summary>
        /// Creates options optimized for security.
        /// </summary>
        public static PostQuantumOptions ForSecurity() => new()
        {
            PreferredAlgorithm = PostQuantumAlgorithm.Kyber1024,
            PerformanceProfile = PostQuantumPerformance.Conservative,
            MinimumSecurityLevel = PostQuantumSecurityLevel.Level3,
            EnableSideChannelProtection = true,
            RequireNistApproved = true,
            FallbackAlgorithms = new() { PostQuantumAlgorithm.Dilithium5, PostQuantumAlgorithm.SPHINCS_SHA256_256f }
        };

        /// <summary>
        /// Creates options optimized for size (smaller keys/signatures).
        /// </summary>
        public static PostQuantumOptions ForSize() => new()
        {
            PreferredAlgorithm = PostQuantumAlgorithm.Falcon512,
            PerformanceProfile = PostQuantumPerformance.Size,
            MaxKeySize = 4096, // 4KB
            MaxSignatureSize = 2048, // 2KB
            FallbackAlgorithms = new() { PostQuantumAlgorithm.Kyber512 }
        };

        /// <summary>
        /// Creates options for hybrid classical + post-quantum mode.
        /// </summary>
        public static PostQuantumOptions ForHybrid() => new()
        {
            PreferredAlgorithm = PostQuantumAlgorithm.Kyber768,
            EnableHybridMode = true,
            MinimumSecurityLevel = PostQuantumSecurityLevel.Level2,
            FallbackAlgorithms = new() { PostQuantumAlgorithm.Kyber512, PostQuantumAlgorithm.Kyber1024 }
        };

        /// <summary>
        /// Creates a deep clone of these options.
        /// </summary>
        public PostQuantumOptions Clone()
        {
            var clone = new PostQuantumOptions
            {
                PreferredAlgorithm = PreferredAlgorithm,
                FallbackAlgorithms = new List<PostQuantumAlgorithm>(FallbackAlgorithms),
                PerformanceProfile = PerformanceProfile,
                MinimumSecurityLevel = MinimumSecurityLevel,
                RequireNistApproved = RequireNistApproved,
                EnableHybridMode = EnableHybridMode,
                PreferredVariant = PreferredVariant,
                KeyExpiration = KeyExpiration,
                EnableSideChannelProtection = EnableSideChannelProtection,
                MaxKeySize = MaxKeySize,
                MaxSignatureSize = MaxSignatureSize,
                OperationTimeout = OperationTimeout,
                EnableKeyCaching = EnableKeyCaching,
                MaxCachedKeys = MaxCachedKeys,
                EnablePerformanceMonitoring = EnablePerformanceMonitoring,
                RunSelfTests = RunSelfTests,
                Metadata = new Dictionary<string, object>(Metadata)
            };

            // Deep clone algorithm parameters
            foreach (var kvp in AlgorithmParameters)
            {
                clone.AlgorithmParameters[kvp.Key] = new Dictionary<string, object>(kvp.Value);
            }

            return clone;
        }

        /// <summary>
        /// Validates that the current configuration is valid and supported.
        /// </summary>
        /// <returns>List of validation errors (empty if valid).</returns>
        public List<string> Validate()
        {
            var errors = new List<string>();

            // Check algorithm compatibility
            if (RequireNistApproved && !IsNistApproved(PreferredAlgorithm))
            {
                errors.Add($"Preferred algorithm {PreferredAlgorithm} is not NIST-approved but RequireNistApproved is true");
            }

            // Check fallback algorithms
            if (RequireNistApproved)
            {
                var nonNistFallbacks = FallbackAlgorithms.Where(a => !IsNistApproved(a)).ToList();
                if (nonNistFallbacks.Any())
                {
                    errors.Add($"Fallback algorithms contain non-NIST-approved algorithms: {string.Join(", ", nonNistFallbacks)}");
                }
            }

            // Check size limits
            if (MaxKeySize < 1024)
            {
                errors.Add("MaxKeySize is too small (minimum 1024 bytes)");
            }

            if (MaxSignatureSize < 512)
            {
                errors.Add("MaxSignatureSize is too small (minimum 512 bytes)");
            }

            // Check timeout
            if (OperationTimeout < TimeSpan.FromSeconds(1))
            {
                errors.Add("OperationTimeout is too short (minimum 1 second)");
            }

            return errors;
        }

        /// <summary>
        /// Checks if an algorithm is NIST-approved.
        /// </summary>
        private static bool IsNistApproved(PostQuantumAlgorithm algorithm)
        {
            return algorithm switch
            {
                PostQuantumAlgorithm.Kyber512 or
                PostQuantumAlgorithm.Kyber768 or
                PostQuantumAlgorithm.Kyber1024 or
                PostQuantumAlgorithm.Dilithium2 or
                PostQuantumAlgorithm.Dilithium3 or
                PostQuantumAlgorithm.Dilithium5 or
                PostQuantumAlgorithm.Falcon512 or
                PostQuantumAlgorithm.Falcon1024 or
                PostQuantumAlgorithm.SPHINCS_SHA256_128f or
                PostQuantumAlgorithm.SPHINCS_SHA256_192f or
                PostQuantumAlgorithm.SPHINCS_SHA256_256f => true,
                _ => false
            };
        }

        /// <summary>
        /// Gets recommended options for a specific use case.
        /// </summary>
        public static PostQuantumOptions ForUseCase(string useCase)
        {
            return useCase.ToLowerInvariant() switch
            {
                "messaging" or "chat" => ForSpeed(),
                "document" or "file" => ForSecurity(),
                "mobile" or "iot" => ForSize(),
                "enterprise" or "corporate" => ForHybrid(),
                _ => Default()
            };
        }
    }
}