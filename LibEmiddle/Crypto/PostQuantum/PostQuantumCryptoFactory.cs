using LibEmiddle.Abstractions;
using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;
using LibEmiddle.Core;

namespace LibEmiddle.Crypto.PostQuantum
{
    /// <summary>
    /// Factory for creating post-quantum cryptography implementations (v2.5 preparation).
    /// 
    /// This factory provides stub implementations for testing and API development.
    /// Real post-quantum implementations will be added in future versions.
    /// </summary>
    public class PostQuantumCryptoFactory : IPostQuantumCryptoFactory
    {
        private static readonly Dictionary<PostQuantumAlgorithm, PostQuantumAlgorithmInfo> _algorithmRegistry = 
            new Dictionary<PostQuantumAlgorithm, PostQuantumAlgorithmInfo>();

        static PostQuantumCryptoFactory()
        {
            // Initialize the algorithm registry with supported algorithms
            RegisterAlgorithms();
        }

        public IEnumerable<PostQuantumAlgorithm> GetAvailableAlgorithms()
        {
            // Return all NIST-approved algorithms that we have stubs for
            return new[]
            {
                PostQuantumAlgorithm.Kyber512,
                PostQuantumAlgorithm.Kyber768,
                PostQuantumAlgorithm.Kyber1024,
                PostQuantumAlgorithm.Dilithium2,
                PostQuantumAlgorithm.Dilithium3,
                PostQuantumAlgorithm.Dilithium5,
                PostQuantumAlgorithm.Falcon512,
                PostQuantumAlgorithm.Falcon1024,
                PostQuantumAlgorithm.SPHINCS_SHA256_128f,
                PostQuantumAlgorithm.SPHINCS_SHA256_192f,
                PostQuantumAlgorithm.SPHINCS_SHA256_256f
            };
        }

        public async Task<IPostQuantumCrypto> CreateAsync(PostQuantumAlgorithm algorithm, PostQuantumOptions? options = null)
        {
            await Task.Delay(1); // Minimal async delay
            
            if (algorithm == PostQuantumAlgorithm.None)
            {
                throw new ArgumentException("Cannot create post-quantum crypto for algorithm 'None'");
            }

            if (!IsAlgorithmAvailable(algorithm))
            {
                throw new NotSupportedException($"Post-quantum algorithm {algorithm} is not available in this implementation");
            }

            options ??= PostQuantumOptions.Default();
            
            // Validate options
            var validationErrors = options.Validate();
            if (validationErrors.Any())
            {
                throw new ArgumentException($"Invalid options: {string.Join(", ", validationErrors)}");
            }

            LoggingManager.LogInformation(nameof(PostQuantumCryptoFactory), 
                $"Creating stub post-quantum crypto implementation for algorithm {algorithm}");
            
            // Return stub implementation
            var implementation = new PostQuantumCryptoStub(algorithm, options);
            
            // Run self-tests if requested
            if (options.RunSelfTests)
            {
                var testResults = await implementation.RunSelfTestAsync();
                if (!testResults.Success)
                {
                    throw new InvalidOperationException($"Self-tests failed for algorithm {algorithm}");
                }
            }
            
            return implementation;
        }

        public PostQuantumAlgorithm GetRecommendedAlgorithm(int securityLevel = 128, PostQuantumPerformance performanceProfile = PostQuantumPerformance.Balanced)
        {
            // Choose algorithm based on security level and performance profile
            return (securityLevel, performanceProfile) switch
            {
                // 128-bit security
                (128, PostQuantumPerformance.Speed) => PostQuantumAlgorithm.Kyber512,
                (128, PostQuantumPerformance.Size) => PostQuantumAlgorithm.Falcon512,
                (128, PostQuantumPerformance.Balanced) => PostQuantumAlgorithm.Kyber512,
                (128, PostQuantumPerformance.Conservative) => PostQuantumAlgorithm.Dilithium2,
                
                // 192-bit security
                (192, PostQuantumPerformance.Speed) => PostQuantumAlgorithm.Kyber768,
                (192, PostQuantumPerformance.Size) => PostQuantumAlgorithm.Kyber768,
                (192, PostQuantumPerformance.Balanced) => PostQuantumAlgorithm.Kyber768,
                (192, PostQuantumPerformance.Conservative) => PostQuantumAlgorithm.Dilithium3,
                
                // 256-bit security
                (256, PostQuantumPerformance.Speed) => PostQuantumAlgorithm.Kyber1024,
                (256, PostQuantumPerformance.Size) => PostQuantumAlgorithm.Falcon1024,
                (256, PostQuantumPerformance.Balanced) => PostQuantumAlgorithm.Kyber1024,
                (256, PostQuantumPerformance.Conservative) => PostQuantumAlgorithm.Dilithium5,
                
                // Higher security levels
                (>= 384, _) => PostQuantumAlgorithm.Dilithium5,
                
                // Default fallback
                _ => PostQuantumAlgorithm.Kyber768
            };
        }

        public bool IsAlgorithmAvailable(PostQuantumAlgorithm algorithm)
        {
            // For stub implementation, we support all NIST-approved algorithms
            var availableAlgorithms = GetAvailableAlgorithms();
            return availableAlgorithms.Contains(algorithm);
        }

        public PostQuantumAlgorithmInfo GetAlgorithmInfo(PostQuantumAlgorithm algorithm)
        {
            if (_algorithmRegistry.TryGetValue(algorithm, out var info))
            {
                return info;
            }
            
            throw new ArgumentException($"Unknown post-quantum algorithm: {algorithm}");
        }

        /// <summary>
        /// Creates a factory with custom algorithm support (for testing or custom implementations).
        /// </summary>
        /// <param name="customAlgorithms">Custom algorithm implementations to register.</param>
        /// <returns>Factory with custom algorithm support.</returns>
        public static PostQuantumCryptoFactory CreateWithCustomAlgorithms(
            Dictionary<PostQuantumAlgorithm, Func<PostQuantumOptions?, Task<IPostQuantumCrypto>>> customAlgorithms)
        {
            var factory = new PostQuantumCryptoFactory();
            
            // This would be used to register custom implementations in a real scenario
            LoggingManager.LogInformation(nameof(PostQuantumCryptoFactory), 
                $"Created factory with {customAlgorithms.Count} custom algorithm implementations");
            
            return factory;
        }

        /// <summary>
        /// Gets performance comparison between algorithms for a specific use case.
        /// </summary>
        /// <param name="algorithms">Algorithms to compare.</param>
        /// <param name="operations">Operations to benchmark.</param>
        /// <returns>Performance comparison results.</returns>
        public async Task<Dictionary<PostQuantumAlgorithm, Dictionary<PostQuantumOperation, OperationMetrics>>> 
            GetPerformanceComparisonAsync(
                IEnumerable<PostQuantumAlgorithm> algorithms, 
                IEnumerable<PostQuantumOperation> operations)
        {
            var results = new Dictionary<PostQuantumAlgorithm, Dictionary<PostQuantumOperation, OperationMetrics>>();
            
            foreach (var algorithm in algorithms)
            {
                if (!IsAlgorithmAvailable(algorithm)) continue;
                
                var crypto = await CreateAsync(algorithm);
                var algorithmResults = new Dictionary<PostQuantumOperation, OperationMetrics>();
                
                foreach (var operation in operations)
                {
                    var metrics = await crypto.EstimatePerformanceAsync(operation);
                    algorithmResults[operation] = metrics;
                }
                
                results[algorithm] = algorithmResults;
            }
            
            return results;
        }

        /// <summary>
        /// Suggests the best algorithm for specific constraints.
        /// </summary>
        /// <param name="constraints">Performance and security constraints.</param>
        /// <returns>Suggested algorithm and reasoning.</returns>
        public AlgorithmSuggestion SuggestAlgorithm(PostQuantumConstraints constraints)
        {
            var candidates = GetAvailableAlgorithms()
                .Where(alg => {
                    var info = GetAlgorithmInfo(alg);
                    return info.SecurityLevel >= constraints.MinimumSecurityLevel &&
                           info.KeySizes.PublicKeyBytes <= constraints.MaxKeySize &&
                           info.KeySizes.SignatureBytes <= constraints.MaxSignatureSize &&
                           (!constraints.RequireNistApproved || info.IsNistApproved);
                })
                .ToList();
            
            if (!candidates.Any())
            {
                return new AlgorithmSuggestion
                {
                    Algorithm = PostQuantumAlgorithm.None,
                    Reasoning = "No algorithms meet the specified constraints",
                    Confidence = 0.0
                };
            }
            
            // Score algorithms based on constraints
            var scored = candidates.Select(alg => {
                var info = GetAlgorithmInfo(alg);
                var score = CalculateAlgorithmScore(alg, info, constraints);
                return new { Algorithm = alg, Info = info, Score = score };
            }).OrderByDescending(x => x.Score).ToList();
            
            var best = scored.First();
            
            return new AlgorithmSuggestion
            {
                Algorithm = best.Algorithm,
                Reasoning = GenerateRecommendationReasoning(best.Algorithm, best.Info, constraints),
                Confidence = best.Score,
                Alternatives = scored.Skip(1).Take(2).Select(x => x.Algorithm).ToList()
            };
        }

        private static void RegisterAlgorithms()
        {
            // Register all supported algorithms with their metadata
            var algorithms = new[]
            {
                CreateAlgorithmInfo(PostQuantumAlgorithm.Kyber512, "Kyber-512", "NIST-approved lattice-based KEM", true, 128, PostQuantumPerformance.Speed, 800, 1632, 768, 32, 0),
                CreateAlgorithmInfo(PostQuantumAlgorithm.Kyber768, "Kyber-768", "NIST-approved lattice-based KEM", true, 192, PostQuantumPerformance.Balanced, 1184, 2400, 1088, 32, 0),
                CreateAlgorithmInfo(PostQuantumAlgorithm.Kyber1024, "Kyber-1024", "NIST-approved lattice-based KEM", true, 256, PostQuantumPerformance.Conservative, 1568, 3168, 1568, 32, 0),
                CreateAlgorithmInfo(PostQuantumAlgorithm.Dilithium2, "Dilithium2", "NIST-approved lattice-based signature", true, 128, PostQuantumPerformance.Speed, 1312, 2528, 0, 0, 2420),
                CreateAlgorithmInfo(PostQuantumAlgorithm.Dilithium3, "Dilithium3", "NIST-approved lattice-based signature", true, 192, PostQuantumPerformance.Balanced, 1952, 4000, 0, 0, 3293),
                CreateAlgorithmInfo(PostQuantumAlgorithm.Dilithium5, "Dilithium5", "NIST-approved lattice-based signature", true, 256, PostQuantumPerformance.Conservative, 2592, 4864, 0, 0, 4595),
                CreateAlgorithmInfo(PostQuantumAlgorithm.Falcon512, "FALCON-512", "NIST-approved lattice-based signature", true, 128, PostQuantumPerformance.Size, 897, 1281, 0, 0, 690),
                CreateAlgorithmInfo(PostQuantumAlgorithm.Falcon1024, "FALCON-1024", "NIST-approved lattice-based signature", true, 256, PostQuantumPerformance.Size, 1793, 2305, 0, 0, 1330),
                CreateAlgorithmInfo(PostQuantumAlgorithm.SPHINCS_SHA256_128f, "SPHINCS+-SHA256-128f", "NIST-approved hash-based signature", true, 128, PostQuantumPerformance.Conservative, 32, 64, 0, 0, 16976),
                CreateAlgorithmInfo(PostQuantumAlgorithm.SPHINCS_SHA256_192f, "SPHINCS+-SHA256-192f", "NIST-approved hash-based signature", true, 192, PostQuantumPerformance.Conservative, 48, 96, 0, 0, 35664),
                CreateAlgorithmInfo(PostQuantumAlgorithm.SPHINCS_SHA256_256f, "SPHINCS+-SHA256-256f", "NIST-approved hash-based signature", true, 256, PostQuantumPerformance.Conservative, 64, 128, 0, 0, 49856)
            };
            
            foreach (var algorithm in algorithms)
            {
                _algorithmRegistry[algorithm.Algorithm] = algorithm;
            }
        }

        private static PostQuantumAlgorithmInfo CreateAlgorithmInfo(
            PostQuantumAlgorithm algorithm, string name, string description, bool isNist, int securityLevel,
            PostQuantumPerformance performance, int pubKeyBytes, int privKeyBytes, int ciphertextBytes, 
            int sharedSecretBytes, int sigBytes)
        {
            return new PostQuantumAlgorithmInfo
            {
                Algorithm = algorithm,
                Name = name,
                Description = description,
                IsNistApproved = isNist,
                SecurityLevel = securityLevel,
                PerformanceProfile = performance,
                KeySizes = new PostQuantumKeySizes
                {
                    PublicKeyBytes = pubKeyBytes,
                    PrivateKeyBytes = privKeyBytes,
                    CiphertextBytes = ciphertextBytes,
                    SharedSecretBytes = sharedSecretBytes,
                    SignatureBytes = sigBytes
                },
                SupportedOperations = GetSupportedOperations(algorithm)
            };
        }

        private static HashSet<PostQuantumOperation> GetSupportedOperations(PostQuantumAlgorithm algorithm)
        {
            return algorithm switch
            {
                PostQuantumAlgorithm.Kyber512 or PostQuantumAlgorithm.Kyber768 or PostQuantumAlgorithm.Kyber1024 =>
                    new HashSet<PostQuantumOperation> { PostQuantumOperation.KeyGeneration, PostQuantumOperation.Encapsulation, PostQuantumOperation.Decapsulation, PostQuantumOperation.HybridKeyAgreement },
                
                PostQuantumAlgorithm.Dilithium2 or PostQuantumAlgorithm.Dilithium3 or PostQuantumAlgorithm.Dilithium5 or
                PostQuantumAlgorithm.Falcon512 or PostQuantumAlgorithm.Falcon1024 or
                PostQuantumAlgorithm.SPHINCS_SHA256_128f or PostQuantumAlgorithm.SPHINCS_SHA256_192f or PostQuantumAlgorithm.SPHINCS_SHA256_256f =>
                    new HashSet<PostQuantumOperation> { PostQuantumOperation.KeyGeneration, PostQuantumOperation.Sign, PostQuantumOperation.Verify },
                
                _ => new HashSet<PostQuantumOperation>()
            };
        }

        private double CalculateAlgorithmScore(PostQuantumAlgorithm algorithm, PostQuantumAlgorithmInfo info, PostQuantumConstraints constraints)
        {
            double score = 1.0;
            
            // Prefer NIST-approved algorithms
            if (info.IsNistApproved) score += 0.3;
            
            // Prefer matching performance profile
            if (info.PerformanceProfile == constraints.PreferredPerformance) score += 0.2;
            
            // Penalize oversized keys/signatures
            if (info.KeySizes.PublicKeyBytes > constraints.MaxKeySize * 0.8) score -= 0.1;
            if (info.KeySizes.SignatureBytes > constraints.MaxSignatureSize * 0.8) score -= 0.1;
            
            // Prefer higher security (but not excessively so)
            var securityBonus = Math.Min(0.2, (info.SecurityLevel - constraints.MinimumSecurityLevel) / 128.0 * 0.1);
            score += securityBonus;
            
            return Math.Max(0.0, Math.Min(1.0, score));
        }

        private string GenerateRecommendationReasoning(PostQuantumAlgorithm algorithm, PostQuantumAlgorithmInfo info, PostQuantumConstraints constraints)
        {
            var reasons = new List<string>();
            
            if (info.IsNistApproved)
                reasons.Add("NIST-approved");
            
            if (info.SecurityLevel >= constraints.MinimumSecurityLevel)
                reasons.Add($"meets {constraints.MinimumSecurityLevel}-bit security requirement");
            
            if (info.PerformanceProfile == constraints.PreferredPerformance)
                reasons.Add($"matches {constraints.PreferredPerformance} performance profile");
            
            if (info.KeySizes.PublicKeyBytes <= constraints.MaxKeySize)
                reasons.Add("acceptable key size");
            
            return $"Recommended {algorithm}: {string.Join(", ", reasons)}";
        }
    }

}