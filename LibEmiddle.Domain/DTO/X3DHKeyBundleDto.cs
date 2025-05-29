#pragma warning disable IDE0130 // Namespace does not match folder structure
namespace LibEmiddle.Domain
#pragma warning restore IDE0130 // Namespace does not match folder structure
{
    /// <summary>
    /// DTO for serializing and deserializing X3DH key bundles for transport.
    /// </summary>
    public class X3DHKeyBundleDto
    {
        /// <summary>
        /// Gets or sets the Base64-encoded identity key (Ed25519 public key).
        /// </summary>
        public string IdentityKey { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the Base64-encoded signed pre-key (X25519 public key).
        /// </summary>
        public string SignedPreKey { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the signed pre-key ID.
        /// </summary>
        public uint SignedPreKeyId { get; set; }

        /// <summary>
        /// Gets or sets the Base64-encoded signature of the signed pre-key.
        /// </summary>
        public string SignedPreKeySignature { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the list of Base64-encoded one-time pre-keys (X25519 public keys).
        /// </summary>
        public List<string> OneTimePreKeys { get; set; } = new List<string>();

        /// <summary>
        /// Gets or sets the list of one-time pre-key IDs.
        /// </summary>
        public List<uint> OneTimePreKeyIds { get; set; } = new List<uint>();

        /// <summary>
        /// Gets or sets the protocol version.
        /// </summary>
        public string ProtocolVersion { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the creation timestamp (milliseconds since Unix epoch).
        /// </summary>
        public long CreationTimestamp { get; set; }
    }
}