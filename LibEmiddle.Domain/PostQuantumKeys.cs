using LibEmiddle.Domain.Enums;

namespace LibEmiddle.Domain
{
    /// <summary>
    /// Represents a post-quantum cryptographic key pair (v2.5 preparation).
    /// </summary>
    public class PostQuantumKeyPair
    {
        /// <summary>
        /// The post-quantum algorithm used for this key pair.
        /// </summary>
        public PostQuantumAlgorithm Algorithm { get; set; }

        /// <summary>
        /// The public key component.
        /// </summary>
        public PostQuantumPublicKey PublicKey { get; set; } = new();

        /// <summary>
        /// The private key component.
        /// </summary>
        public PostQuantumPrivateKey PrivateKey { get; set; } = new();

        /// <summary>
        /// When this key pair was generated.
        /// </summary>
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// When this key pair expires (optional).
        /// </summary>
        public DateTime? ExpiresAt { get; set; }

        /// <summary>
        /// Additional metadata for this key pair.
        /// </summary>
        public Dictionary<string, string> Metadata { get; set; } = new();

        /// <summary>
        /// Gets whether this key pair has expired.
        /// </summary>
        public bool IsExpired => ExpiresAt.HasValue && ExpiresAt.Value <= DateTime.UtcNow;

        /// <summary>
        /// Gets the security level of this key pair in bits.
        /// </summary>
        public int SecurityLevel => Algorithm switch
        {
            PostQuantumAlgorithm.Kyber512 => 128,
            PostQuantumAlgorithm.Kyber768 => 192,
            PostQuantumAlgorithm.Kyber1024 => 256,
            PostQuantumAlgorithm.Dilithium2 => 128,
            PostQuantumAlgorithm.Dilithium3 => 192,
            PostQuantumAlgorithm.Dilithium5 => 256,
            PostQuantumAlgorithm.Falcon512 => 128,
            PostQuantumAlgorithm.Falcon1024 => 256,
            PostQuantumAlgorithm.SPHINCS_SHA256_128f => 128,
            PostQuantumAlgorithm.SPHINCS_SHA256_192f => 192,
            PostQuantumAlgorithm.SPHINCS_SHA256_256f => 256,
            _ => 128
        };

        /// <summary>
        /// Creates a deep clone of this key pair.
        /// </summary>
        public PostQuantumKeyPair Clone()
        {
            return new PostQuantumKeyPair
            {
                Algorithm = Algorithm,
                PublicKey = PublicKey.Clone(),
                PrivateKey = PrivateKey.Clone(),
                CreatedAt = CreatedAt,
                ExpiresAt = ExpiresAt,
                Metadata = new Dictionary<string, string>(Metadata)
            };
        }
    }

    /// <summary>
    /// Represents a post-quantum public key (v2.5 preparation).
    /// </summary>
    public class PostQuantumPublicKey
    {
        /// <summary>
        /// The post-quantum algorithm for this key.
        /// </summary>
        public PostQuantumAlgorithm Algorithm { get; set; }

        /// <summary>
        /// The raw key material.
        /// </summary>
        public byte[] KeyData { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Key identifier for efficient lookup.
        /// </summary>
        public string KeyId { get; set; } = string.Empty;

        /// <summary>
        /// When this key was created.
        /// </summary>
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Additional parameters specific to the algorithm.
        /// </summary>
        public Dictionary<string, object> Parameters { get; set; } = new();

        /// <summary>
        /// Gets the size of this public key in bytes.
        /// </summary>
        public int SizeBytes => KeyData.Length;

        /// <summary>
        /// Gets the fingerprint (hash) of this public key for identification.
        /// </summary>
        public string Fingerprint
        {
            get
            {
                if (KeyData.Length == 0) return string.Empty;
                
                using var sha256 = System.Security.Cryptography.SHA256.Create();
                var hash = sha256.ComputeHash(KeyData);
                return Convert.ToHexString(hash)[..16]; // First 16 characters
            }
        }

        /// <summary>
        /// Validates that this public key is well-formed.
        /// </summary>
        /// <returns>True if the key is valid.</returns>
        public bool IsValid()
        {
            if (KeyData.Length == 0) return false;
            if (string.IsNullOrEmpty(KeyId)) return false;
            
            // Algorithm-specific validation would go here
            // For now, just check basic structure
            return true;
        }

        /// <summary>
        /// Creates a deep clone of this public key.
        /// </summary>
        public PostQuantumPublicKey Clone()
        {
            return new PostQuantumPublicKey
            {
                Algorithm = Algorithm,
                KeyData = KeyData.ToArray(),
                KeyId = KeyId,
                CreatedAt = CreatedAt,
                Parameters = new Dictionary<string, object>(Parameters)
            };
        }

        /// <summary>
        /// Exports this public key to a portable format.
        /// </summary>
        public PostQuantumKeyExport Export()
        {
            return new PostQuantumKeyExport
            {
                Algorithm = Algorithm,
                KeyType = PostQuantumKeyType.Public,
                KeyData = KeyData,
                KeyId = KeyId,
                CreatedAt = CreatedAt,
                Parameters = Parameters,
                Metadata = new Dictionary<string, object>
                {
                    ["Fingerprint"] = Fingerprint,
                    ["SizeBytes"] = SizeBytes
                }
            };
        }
    }

    /// <summary>
    /// Represents a post-quantum private key (v2.5 preparation).
    /// </summary>
    public class PostQuantumPrivateKey : IDisposable
    {
        /// <summary>
        /// The post-quantum algorithm for this key.
        /// </summary>
        public PostQuantumAlgorithm Algorithm { get; set; }

        /// <summary>
        /// The raw private key material (sensitive).
        /// </summary>
        public byte[] KeyData { get; private set; } = Array.Empty<byte>();

        /// <summary>
        /// Key identifier for efficient lookup.
        /// </summary>
        public string KeyId { get; set; } = string.Empty;

        /// <summary>
        /// When this key was created.
        /// </summary>
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Additional parameters specific to the algorithm.
        /// </summary>
        public Dictionary<string, object> Parameters { get; set; } = new();

        /// <summary>
        /// Whether this private key has been disposed.
        /// </summary>
        public bool IsDisposed { get; private set; }

        /// <summary>
        /// Gets the size of this private key in bytes.
        /// </summary>
        public int SizeBytes => KeyData.Length;

        /// <summary>
        /// Sets the key data (should only be called during key generation).
        /// </summary>
        /// <param name="keyData">The private key material.</param>
        public void SetKeyData(byte[] keyData)
        {
            if (IsDisposed)
                throw new ObjectDisposedException(nameof(PostQuantumPrivateKey));
            
            // Clear existing key data
            if (KeyData.Length > 0)
            {
                Array.Clear(KeyData, 0, KeyData.Length);
            }
            
            KeyData = keyData.ToArray();
        }

        /// <summary>
        /// Gets a copy of the key data (use with caution).
        /// </summary>
        /// <returns>Copy of the private key material.</returns>
        public byte[] GetKeyDataCopy()
        {
            if (IsDisposed)
                throw new ObjectDisposedException(nameof(PostQuantumPrivateKey));
            
            return KeyData.ToArray();
        }

        /// <summary>
        /// Validates that this private key is well-formed.
        /// </summary>
        /// <returns>True if the key is valid.</returns>
        public bool IsValid()
        {
            if (IsDisposed) return false;
            if (KeyData.Length == 0) return false;
            if (string.IsNullOrEmpty(KeyId)) return false;
            
            // Algorithm-specific validation would go here
            return true;
        }

        /// <summary>
        /// Creates a deep clone of this private key.
        /// </summary>
        public PostQuantumPrivateKey Clone()
        {
            if (IsDisposed)
                throw new ObjectDisposedException(nameof(PostQuantumPrivateKey));
            
            var clone = new PostQuantumPrivateKey
            {
                Algorithm = Algorithm,
                KeyId = KeyId,
                CreatedAt = CreatedAt,
                Parameters = new Dictionary<string, object>(Parameters)
            };
            
            clone.SetKeyData(KeyData);
            return clone;
        }

        /// <summary>
        /// Exports this private key to a portable format (use with extreme caution).
        /// </summary>
        /// <param name="includePrivateKey">Whether to include the private key material.</param>
        public PostQuantumKeyExport Export(bool includePrivateKey = false)
        {
            if (IsDisposed)
                throw new ObjectDisposedException(nameof(PostQuantumPrivateKey));
            
            return new PostQuantumKeyExport
            {
                Algorithm = Algorithm,
                KeyType = PostQuantumKeyType.Private,
                KeyData = includePrivateKey ? KeyData.ToArray() : Array.Empty<byte>(),
                KeyId = KeyId,
                CreatedAt = CreatedAt,
                Parameters = Parameters,
                Metadata = new Dictionary<string, object>
                {
                    ["SizeBytes"] = SizeBytes,
                    ["HasPrivateKey"] = includePrivateKey
                }
            };
        }

        /// <summary>
        /// Securely disposes of this private key.
        /// </summary>
        public void Dispose()
        {
            if (!IsDisposed)
            {
                // Securely clear the key material
                if (KeyData.Length > 0)
                {
                    Array.Clear(KeyData, 0, KeyData.Length);
                }
                
                KeyData = Array.Empty<byte>();
                Parameters.Clear();
                IsDisposed = true;
            }
        }
    }

    /// <summary>
    /// Exportable representation of a post-quantum key (v2.5 preparation).
    /// </summary>
    public class PostQuantumKeyExport
    {
        /// <summary>
        /// The post-quantum algorithm.
        /// </summary>
        public PostQuantumAlgorithm Algorithm { get; set; }

        /// <summary>
        /// The type of key (public or private).
        /// </summary>
        public PostQuantumKeyType KeyType { get; set; }

        /// <summary>
        /// The key material.
        /// </summary>
        public byte[] KeyData { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Key identifier.
        /// </summary>
        public string KeyId { get; set; } = string.Empty;

        /// <summary>
        /// When this key was created.
        /// </summary>
        public DateTime CreatedAt { get; set; }

        /// <summary>
        /// Algorithm-specific parameters.
        /// </summary>
        public Dictionary<string, object> Parameters { get; set; } = new();

        /// <summary>
        /// Additional metadata.
        /// </summary>
        public Dictionary<string, object> Metadata { get; set; } = new();

        /// <summary>
        /// Export format version for compatibility.
        /// </summary>
        public int FormatVersion { get; set; } = 1;

        /// <summary>
        /// Converts this export back to a typed key.
        /// </summary>
        public object ToTypedKey()
        {
            return KeyType switch
            {
                PostQuantumKeyType.Public => new PostQuantumPublicKey
                {
                    Algorithm = Algorithm,
                    KeyData = KeyData.ToArray(),
                    KeyId = KeyId,
                    CreatedAt = CreatedAt,
                    Parameters = Parameters
                },
                PostQuantumKeyType.Private => CreatePrivateKey(),
                _ => throw new ArgumentException($"Unknown key type: {KeyType}")
            };
        }

        private PostQuantumPrivateKey CreatePrivateKey()
        {
            var privateKey = new PostQuantumPrivateKey
            {
                Algorithm = Algorithm,
                KeyId = KeyId,
                CreatedAt = CreatedAt,
                Parameters = Parameters
            };
            
            if (KeyData.Length > 0)
            {
                privateKey.SetKeyData(KeyData);
            }
            
            return privateKey;
        }
    }
}