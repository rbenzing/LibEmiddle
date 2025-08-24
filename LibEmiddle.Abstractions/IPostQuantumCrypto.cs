using LibEmiddle.Domain.Enums;
using LibEmiddle.Domain;

namespace LibEmiddle.Abstractions
{
    /// <summary>
    /// Interface for post-quantum cryptographic operations (v2.5 preparation).
    /// This interface defines the contract for quantum-resistant cryptographic algorithms
    /// that will be integrated into LibEmiddle's encryption pipeline.
    /// 
    /// Note: This is a preparation interface for future post-quantum support.
    /// Implementations are not yet available and will be added in future versions.
    /// </summary>
    public interface IPostQuantumCrypto
    {
        /// <summary>
        /// Gets the post-quantum algorithm being used.
        /// </summary>
        PostQuantumAlgorithm Algorithm { get; }

        /// <summary>
        /// Gets whether this implementation is NIST-approved.
        /// </summary>
        bool IsNistApproved { get; }

        /// <summary>
        /// Gets the security level (in bits) provided by this algorithm.
        /// </summary>
        int SecurityLevel { get; }

        /// <summary>
        /// Gets performance characteristics of this algorithm.
        /// </summary>
        PostQuantumPerformance PerformanceProfile { get; }

        /// <summary>
        /// Generates a new post-quantum key pair.
        /// </summary>
        /// <returns>A key pair suitable for post-quantum operations.</returns>
        Task<PostQuantumKeyPair> GenerateKeyPairAsync();

        /// <summary>
        /// Performs key encapsulation (KEM) using the recipient's public key.
        /// Returns both the encapsulated key and the shared secret.
        /// </summary>
        /// <param name="publicKey">The recipient's public key.</param>
        /// <returns>Encapsulation result containing ciphertext and shared secret.</returns>
        Task<KemResult> EncapsulateAsync(PostQuantumPublicKey publicKey);

        /// <summary>
        /// Performs key decapsulation using the private key and ciphertext.
        /// Recovers the shared secret from the encapsulated key.
        /// </summary>
        /// <param name="privateKey">The private key for decapsulation.</param>
        /// <param name="ciphertext">The encapsulated key ciphertext.</param>
        /// <returns>The shared secret, or null if decapsulation failed.</returns>
        Task<byte[]?> DecapsulateAsync(PostQuantumPrivateKey privateKey, byte[] ciphertext);

        /// <summary>
        /// Creates a digital signature using post-quantum algorithms.
        /// </summary>
        /// <param name="privateKey">The private key for signing.</param>
        /// <param name="message">The message to sign.</param>
        /// <returns>The digital signature.</returns>
        Task<byte[]> SignAsync(PostQuantumPrivateKey privateKey, byte[] message);

        /// <summary>
        /// Verifies a digital signature using post-quantum algorithms.
        /// </summary>
        /// <param name="publicKey">The public key for verification.</param>
        /// <param name="message">The original message.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <returns>True if the signature is valid.</returns>
        Task<bool> VerifyAsync(PostQuantumPublicKey publicKey, byte[] message, byte[] signature);

        /// <summary>
        /// Performs hybrid key agreement combining classical and post-quantum methods.
        /// This provides protection against both classical and quantum attacks.
        /// </summary>
        /// <param name="classicalPrivateKey">Classical private key (X25519).</param>
        /// <param name="postQuantumPrivateKey">Post-quantum private key.</param>
        /// <param name="classicalPublicKey">Peer's classical public key.</param>
        /// <param name="postQuantumPublicKey">Peer's post-quantum public key.</param>
        /// <returns>Hybrid shared secret.</returns>
        Task<byte[]> HybridKeyAgreementAsync(
            byte[] classicalPrivateKey,
            PostQuantumPrivateKey postQuantumPrivateKey,
            byte[] classicalPublicKey,
            PostQuantumPublicKey postQuantumPublicKey);

        /// <summary>
        /// Estimates the computational cost of operations for performance planning.
        /// </summary>
        /// <param name="operation">The operation to estimate.</param>
        /// <returns>Performance metrics for the operation.</returns>
        Task<OperationMetrics> EstimatePerformanceAsync(PostQuantumOperation operation);

        /// <summary>
        /// Tests the implementation for correctness and performance.
        /// </summary>
        /// <returns>Test results including performance benchmarks.</returns>
        Task<PostQuantumTestResults> RunSelfTestAsync();
    }


    /// <summary>
    /// Results from key encapsulation mechanism (KEM) operations (v2.5).
    /// </summary>
    public class KemResult
    {
        /// <summary>
        /// The encapsulated key ciphertext.
        /// </summary>
        public byte[] Ciphertext { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// The shared secret derived from the key encapsulation.
        /// </summary>
        public byte[] SharedSecret { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Additional metadata about the encapsulation.
        /// </summary>
        public Dictionary<string, object> Metadata { get; set; } = new();
    }

    /// <summary>
    /// Metrics for post-quantum cryptographic operations (v2.5).
    /// </summary>
    public class OperationMetrics
    {
        /// <summary>
        /// Estimated time to complete the operation.
        /// </summary>
        public TimeSpan EstimatedDuration { get; set; }

        /// <summary>
        /// Estimated memory usage for the operation.
        /// </summary>
        public long EstimatedMemoryBytes { get; set; }

        /// <summary>
        /// Estimated CPU cycles required.
        /// </summary>
        public long EstimatedCpuCycles { get; set; }

        /// <summary>
        /// Size of the resulting data (keys, signatures, etc.).
        /// </summary>
        public int ResultSizeBytes { get; set; }

        /// <summary>
        /// Additional performance metrics.
        /// </summary>
        public Dictionary<string, object> AdditionalMetrics { get; set; } = new();
    }

    /// <summary>
    /// Results from post-quantum implementation self-tests (v2.5).
    /// </summary>
    public class PostQuantumTestResults
    {
        /// <summary>
        /// Whether all tests passed successfully.
        /// </summary>
        public bool Success { get; set; }

        /// <summary>
        /// Test results for each operation type.
        /// </summary>
        public Dictionary<PostQuantumOperation, OperationMetrics> PerformanceResults { get; set; } = new();

        /// <summary>
        /// Any errors or warnings from the tests.
        /// </summary>
        public List<string> Messages { get; set; } = new();

        /// <summary>
        /// When the tests were run.
        /// </summary>
        public DateTime TestTime { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Additional test metadata.
        /// </summary>
        public Dictionary<string, object> Metadata { get; set; } = new();
    }

    /// <summary>
    /// Information about a post-quantum algorithm (v2.5).
    /// </summary>
    public class PostQuantumAlgorithmInfo
    {
        /// <summary>
        /// The algorithm identifier.
        /// </summary>
        public PostQuantumAlgorithm Algorithm { get; set; }

        /// <summary>
        /// Human-readable name of the algorithm.
        /// </summary>
        public string Name { get; set; } = string.Empty;

        /// <summary>
        /// Brief description of the algorithm.
        /// </summary>
        public string Description { get; set; } = string.Empty;

        /// <summary>
        /// Whether this algorithm is NIST-approved.
        /// </summary>
        public bool IsNistApproved { get; set; }

        /// <summary>
        /// Security level in bits.
        /// </summary>
        public int SecurityLevel { get; set; }

        /// <summary>
        /// Performance characteristics.
        /// </summary>
        public PostQuantumPerformance PerformanceProfile { get; set; }

        /// <summary>
        /// Supported operations.
        /// </summary>
        public HashSet<PostQuantumOperation> SupportedOperations { get; set; } = new();

        /// <summary>
        /// Key size information.
        /// </summary>
        public PostQuantumKeySizes KeySizes { get; set; } = new();

        /// <summary>
        /// Additional algorithm metadata.
        /// </summary>
        public Dictionary<string, object> Metadata { get; set; } = new();
    }

    /// <summary>
    /// Key size information for post-quantum algorithms (v2.5).
    /// </summary>
    public class PostQuantumKeySizes
    {
        /// <summary>
        /// Public key size in bytes.
        /// </summary>
        public int PublicKeyBytes { get; set; }

        /// <summary>
        /// Private key size in bytes.
        /// </summary>
        public int PrivateKeyBytes { get; set; }

        /// <summary>
        /// Signature size in bytes (for signature algorithms).
        /// </summary>
        public int SignatureBytes { get; set; }

        /// <summary>
        /// Ciphertext size in bytes (for KEM algorithms).
        /// </summary>
        public int CiphertextBytes { get; set; }

        /// <summary>
        /// Shared secret size in bytes.
        /// </summary>
        public int SharedSecretBytes { get; set; }
    }
}