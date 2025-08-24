namespace LibEmiddle.Domain.Enums
{
    /// <summary>
    /// Post-quantum cryptographic algorithms supported by LibEmiddle (v2.5 preparation).
    /// These algorithms are designed to be resistant to attacks by quantum computers.
    /// </summary>
    public enum PostQuantumAlgorithm
    {
        /// <summary>
        /// No post-quantum algorithm (classical cryptography only).
        /// </summary>
        None = 0,

        // --- NIST-Approved Key Encapsulation Mechanisms (KEMs) ---

        /// <summary>
        /// Kyber-512 - NIST-approved lattice-based KEM (128-bit security).
        /// Fast performance, moderate key sizes.
        /// </summary>
        Kyber512 = 1,

        /// <summary>
        /// Kyber-768 - NIST-approved lattice-based KEM (192-bit security).
        /// Balanced performance and security.
        /// </summary>
        Kyber768 = 2,

        /// <summary>
        /// Kyber-1024 - NIST-approved lattice-based KEM (256-bit security).
        /// Higher security, larger key sizes.
        /// </summary>
        Kyber1024 = 3,

        // --- NIST-Approved Digital Signature Algorithms ---

        /// <summary>
        /// Dilithium2 - NIST-approved lattice-based signature (128-bit security).
        /// Fast verification, moderate signature sizes.
        /// </summary>
        Dilithium2 = 10,

        /// <summary>
        /// Dilithium3 - NIST-approved lattice-based signature (192-bit security).
        /// Balanced performance and security.
        /// </summary>
        Dilithium3 = 11,

        /// <summary>
        /// Dilithium5 - NIST-approved lattice-based signature (256-bit security).
        /// Highest security level.
        /// </summary>
        Dilithium5 = 12,

        /// <summary>
        /// FALCON-512 - NIST-approved lattice-based signature (128-bit security).
        /// Compact signatures, faster than Dilithium.
        /// </summary>
        Falcon512 = 20,

        /// <summary>
        /// FALCON-1024 - NIST-approved lattice-based signature (256-bit security).
        /// Compact signatures with high security.
        /// </summary>
        Falcon1024 = 21,

        /// <summary>
        /// SPHINCS+-SHA256-128f - NIST-approved hash-based signature (128-bit security).
        /// Stateless, conservative security assumptions.
        /// </summary>
        SPHINCS_SHA256_128f = 30,

        /// <summary>
        /// SPHINCS+-SHA256-192f - NIST-approved hash-based signature (192-bit security).
        /// Stateless, conservative security assumptions.
        /// </summary>
        SPHINCS_SHA256_192f = 31,

        /// <summary>
        /// SPHINCS+-SHA256-256f - NIST-approved hash-based signature (256-bit security).
        /// Stateless, conservative security assumptions.
        /// </summary>
        SPHINCS_SHA256_256f = 32,

        // --- Experimental/Research Algorithms (Not NIST-approved yet) ---

        /// <summary>
        /// SIKE/SIDH - Isogeny-based KEM (experimental, potentially vulnerable).
        /// Note: This algorithm has known vulnerabilities and should not be used.
        /// </summary>
        [Obsolete("SIKE/SIDH has known vulnerabilities and should not be used.")]
        SIKE = 100,

        /// <summary>
        /// Classic McEliece - Code-based KEM (conservative, large keys).
        /// Very conservative security assumptions but impractical key sizes.
        /// </summary>
        ClassicMcEliece = 101,

        /// <summary>
        /// HQC - Code-based KEM (experimental).
        /// Research algorithm, not yet standardized.
        /// </summary>
        HQC = 102,

        /// <summary>
        /// Rainbow - Multivariate signature (experimental, potentially vulnerable).
        /// Note: Rainbow has been broken and should not be used.
        /// </summary>
        [Obsolete("Rainbow has been cryptographically broken and should not be used.")]
        Rainbow = 103
    }

    /// <summary>
    /// Performance profiles for post-quantum algorithms (v2.5).
    /// </summary>
    public enum PostQuantumPerformance
    {
        /// <summary>
        /// Balanced performance and security (default).
        /// </summary>
        Balanced = 0,

        /// <summary>
        /// Optimized for speed (faster operations, may have larger keys/signatures).
        /// </summary>
        Speed = 1,

        /// <summary>
        /// Optimized for size (smaller keys/signatures, may be slower).
        /// </summary>
        Size = 2,

        /// <summary>
        /// Conservative approach (highest security, potentially slower).
        /// </summary>
        Conservative = 3
    }

    /// <summary>
    /// Types of post-quantum cryptographic operations (v2.5).
    /// </summary>
    public enum PostQuantumOperation
    {
        /// <summary>
        /// Key pair generation.
        /// </summary>
        KeyGeneration = 0,

        /// <summary>
        /// Key encapsulation (KEM encrypt).
        /// </summary>
        Encapsulation = 1,

        /// <summary>
        /// Key decapsulation (KEM decrypt).
        /// </summary>
        Decapsulation = 2,

        /// <summary>
        /// Digital signature generation.
        /// </summary>
        Sign = 3,

        /// <summary>
        /// Digital signature verification.
        /// </summary>
        Verify = 4,

        /// <summary>
        /// Hybrid key agreement (classical + post-quantum).
        /// </summary>
        HybridKeyAgreement = 5
    }

    /// <summary>
    /// Types of post-quantum keys (v2.5).
    /// </summary>
    public enum PostQuantumKeyType
    {
        /// <summary>
        /// Public key.
        /// </summary>
        Public = 0,

        /// <summary>
        /// Private key.
        /// </summary>
        Private = 1,

        /// <summary>
        /// Key pair (both public and private).
        /// </summary>
        Pair = 2
    }

    /// <summary>
    /// Security levels for post-quantum cryptography (v2.5).
    /// Based on NIST security categories.
    /// </summary>
    public enum PostQuantumSecurityLevel
    {
        /// <summary>
        /// Category 1: Security equivalent to AES-128 (128-bit security).
        /// </summary>
        Level1 = 128,

        /// <summary>
        /// Category 2: Security equivalent to SHA-256 collision resistance (192-bit security).
        /// </summary>
        Level2 = 192,

        /// <summary>
        /// Category 3: Security equivalent to AES-256 (256-bit security).
        /// </summary>
        Level3 = 256,

        /// <summary>
        /// Category 4: Security higher than AES-256.
        /// </summary>
        Level4 = 384,

        /// <summary>
        /// Category 5: Security much higher than AES-256.
        /// </summary>
        Level5 = 512
    }

    /// <summary>
    /// Post-quantum cryptographic primitives (v2.5).
    /// </summary>
    public enum PostQuantumPrimitive
    {
        /// <summary>
        /// Key Encapsulation Mechanism (KEM).
        /// </summary>
        KEM = 0,

        /// <summary>
        /// Digital signature scheme.
        /// </summary>
        Signature = 1,

        /// <summary>
        /// Hybrid scheme combining classical and post-quantum.
        /// </summary>
        Hybrid = 2
    }

    /// <summary>
    /// Mathematical foundations of post-quantum algorithms (v2.5).
    /// </summary>
    public enum PostQuantumMathematicalBasis
    {
        /// <summary>
        /// Lattice-based cryptography (e.g., Kyber, Dilithium, FALCON).
        /// </summary>
        Lattice = 0,

        /// <summary>
        /// Hash-based cryptography (e.g., SPHINCS+).
        /// </summary>
        Hash = 1,

        /// <summary>
        /// Code-based cryptography (e.g., Classic McEliece, HQC).
        /// </summary>
        Code = 2,

        /// <summary>
        /// Multivariate cryptography (e.g., Rainbow - deprecated).
        /// </summary>
        Multivariate = 3,

        /// <summary>
        /// Isogeny-based cryptography (e.g., SIKE - broken).
        /// </summary>
        [Obsolete("Isogeny-based cryptography has known vulnerabilities.")]
        Isogeny = 4,

        /// <summary>
        /// Symmetric-key based (e.g., for hybrid constructions).
        /// </summary>
        Symmetric = 5
    }

    /// <summary>
    /// Implementation variants for post-quantum algorithms (v2.5).
    /// </summary>
    public enum PostQuantumVariant
    {
        /// <summary>
        /// Reference implementation (standard security).
        /// </summary>
        Reference = 0,

        /// <summary>
        /// Optimized implementation (better performance).
        /// </summary>
        Optimized = 1,

        /// <summary>
        /// Side-channel resistant implementation.
        /// </summary>
        SideChannelResistant = 2,

        /// <summary>
        /// Compact implementation (smaller code/memory footprint).
        /// </summary>
        Compact = 3,

        /// <summary>
        /// Hardware-accelerated implementation.
        /// </summary>
        Hardware = 4
    }
}