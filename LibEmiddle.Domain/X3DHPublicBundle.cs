namespace LibEmiddle.Domain
{
    /// <summary>
    /// Public portion of X3DH key bundle, containing only public keys.
    /// This class follows the Signal Protocol specification for X3DH key bundles.
    /// </summary>
    public class X3DHPublicBundle
    {
        /// <summary>
        /// Long-term identity public key (Ed25519 format)
        /// </summary>
        public byte[]? IdentityKey { get; set; }

        /// <summary>
        /// Signed pre-key (X25519 format)
        /// </summary>
        public byte[]? SignedPreKey { get; set; }

        /// <summary>
        /// Signature of signed pre-key (created with identity key)
        /// </summary>
        public byte[]? SignedPreKeySignature { get; set; }

        /// <summary>
        /// List of one-time pre-keys (X25519 format)
        /// </summary>
        public List<byte[]>? OneTimePreKeys { get; set; }

        /// <summary>
        /// Unique identifier for the signed pre-key
        /// </summary>
        public uint SignedPreKeyId { get; set; }

        /// <summary>
        /// List of unique identifiers for one-time pre-keys, matching the index in OneTimePreKeys
        /// </summary>
        public List<uint>? OneTimePreKeyIds { get; set; }

        /// <summary>
        /// Protocol version for compatibility checks
        /// </summary>
        public string? ProtocolVersion { get; set; }

        /// <summary>
        /// Timestamp when this bundle was created (milliseconds since Unix epoch)
        /// </summary>
        public long CreationTimestamp { get; set; }

        /// <summary>
        /// Creates a new empty X3DHPublicBundle
        /// </summary>
        public X3DHPublicBundle()
        {
            OneTimePreKeys = new List<byte[]>();
            OneTimePreKeyIds = new List<uint>();
        }
    }
}