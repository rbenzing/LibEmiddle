namespace LibEmiddle.Domain
{
    /// <summary>
    /// Represents the public components of an X3DH key bundle that can be safely shared
    /// with other parties for establishing secure sessions using the Signal protocol.
    /// </summary>
    public class X3DHPublicBundle
    {
        /// <summary>
        /// Gets or sets the Ed25519 identity public key.
        /// </summary>
        /// <remarks>
        /// This is a required field per the Signal X3DH specification.
        /// The identity key is the long-term public key that identifies a user.
        /// </remarks>
        public byte[] IdentityKey { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Gets or sets the X25519 signed pre-key.
        /// </summary>
        /// <remarks>
        /// This is a required field per the Signal X3DH specification.
        /// The signed pre-key is a medium-term key that is signed with the identity key.
        /// </remarks>
        public byte[] SignedPreKey { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Gets or sets the signed pre-key's unique identifier.
        /// </summary>
        /// <remarks>
        /// This is a required field per the Signal X3DH specification.
        /// The ID must be greater than 0 to be valid.
        /// </remarks>
        public uint SignedPreKeyId { get; set; }

        /// <summary>
        /// Gets or sets the signature of the signed pre-key, created using the identity key.
        /// </summary>
        /// <remarks>
        /// This is a required field per the Signal X3DH specification.
        /// The signature proves that the signed pre-key belongs to the identity key owner.
        /// </remarks>
        public byte[] SignedPreKeySignature { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Gets or sets the list of one-time pre-keys (X25519 public keys).
        /// </summary>
        /// <remarks>
        /// These are optional per the Signal X3DH specification, but recommended.
        /// One-time pre-keys provide better forward secrecy when used.
        /// </remarks>
        public List<byte[]> OneTimePreKeys { get; set; } = new List<byte[]>();

        /// <summary>
        /// Gets or sets the list of one-time pre-key identifiers.
        /// </summary>
        /// <remarks>
        /// Each one-time pre-key must have a corresponding ID.
        /// The IDs must be greater than 0 to be valid.
        /// </remarks>
        public List<uint> OneTimePreKeyIds { get; set; } = new List<uint>();

        /// <summary>
        /// Gets or sets the protocol version string.
        /// </summary>
        public string ProtocolVersion { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the creation timestamp (milliseconds since Unix epoch).
        /// </summary>
        public long CreationTimestamp { get; set; }

        /// <summary>
        /// Creates a new instance of the X3DHPublicBundle class.
        /// </summary>
        public X3DHPublicBundle()
        {
        }

        /// <summary>
        /// Creates a new instance of the X3DHPublicBundle class with the specified values.
        /// </summary>
        /// <param name="identityKey">The Ed25519 identity public key.</param>
        /// <param name="signedPreKey">The X25519 signed pre-key.</param>
        /// <param name="signedPreKeyId">The signed pre-key's unique identifier.</param>
        /// <param name="signedPreKeySignature">The signature of the signed pre-key.</param>
        /// <exception cref="ArgumentNullException">Thrown when any required parameter is null.</exception>
        /// <exception cref="ArgumentException">Thrown when signedPreKeyId is 0.</exception>
        public X3DHPublicBundle(
            byte[] identityKey,
            byte[] signedPreKey,
            uint signedPreKeyId,
            byte[] signedPreKeySignature)
        {
            ArgumentNullException.ThrowIfNull(identityKey, nameof(identityKey));
            ArgumentNullException.ThrowIfNull(signedPreKey, nameof(signedPreKey));
            ArgumentNullException.ThrowIfNull(signedPreKeySignature, nameof(signedPreKeySignature));

            if (signedPreKeyId == 0)
                throw new ArgumentException("Signed pre-key ID cannot be 0.", nameof(signedPreKeyId));

            IdentityKey = identityKey.ToArray();
            SignedPreKey = signedPreKey.ToArray();
            SignedPreKeyId = signedPreKeyId;
            SignedPreKeySignature = signedPreKeySignature.ToArray();
            CreationTimestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        }

        /// <summary>
        /// Adds a one-time pre-key to the bundle.
        /// </summary>
        /// <param name="keyId">The one-time pre-key's unique identifier.</param>
        /// <param name="publicKey">The X25519 one-time pre-key public key.</param>
        /// <exception cref="ArgumentNullException">Thrown when publicKey is null.</exception>
        /// <exception cref="ArgumentException">Thrown when keyId is 0 or already exists.</exception>
        public void AddOneTimePreKey(uint keyId, byte[] publicKey)
        {
            ArgumentNullException.ThrowIfNull(publicKey, nameof(publicKey));

            if (keyId == 0)
                throw new ArgumentException("One-time pre-key ID cannot be 0.", nameof(keyId));

            if (OneTimePreKeyIds.Contains(keyId))
                throw new ArgumentException($"One-time pre-key ID {keyId} already exists in this bundle.", nameof(keyId));

            OneTimePreKeyIds.Add(keyId);
            OneTimePreKeys.Add(publicKey.ToArray());
        }

        /// <summary>
        /// Validates that all required fields of the bundle are present and properly formatted
        /// according to the Signal X3DH specification.
        /// </summary>
        /// <returns>True if the bundle is valid, false otherwise.</returns>
        public bool Validate()
        {
            // Check required public components
            if (IdentityKey == null || IdentityKey.Length != Constants.ED25519_PUBLIC_KEY_SIZE)
                return false;

            if (SignedPreKey == null || SignedPreKey.Length != Constants.X25519_KEY_SIZE)
                return false;

            if (SignedPreKeyId == 0) // Must be greater than 0
                return false;

            if (SignedPreKeySignature == null || SignedPreKeySignature.Length != 64) // Ed25519 signature is 64 bytes
                return false;

            // Validate one-time pre-keys if present
            if (OneTimePreKeys.Count > 0)
            {
                if (OneTimePreKeys.Count != OneTimePreKeyIds.Count)
                    return false;

                for (int i = 0; i < OneTimePreKeys.Count; i++)
                {
                    uint keyId = OneTimePreKeyIds[i];
                    byte[]? key = OneTimePreKeys[i];

                    if (key == null || key.Length != Constants.X25519_KEY_SIZE || keyId == 0)
                        return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Clones this bundle to create a new instance with the same values.
        /// </summary>
        /// <returns>A new X3DHPublicBundle with the same values as this one.</returns>
        public X3DHPublicBundle Clone()
        {
            var clone = new X3DHPublicBundle
            {
                IdentityKey = IdentityKey?.ToArray() ?? Array.Empty<byte>(),
                SignedPreKey = SignedPreKey?.ToArray() ?? Array.Empty<byte>(),
                SignedPreKeyId = SignedPreKeyId,
                SignedPreKeySignature = SignedPreKeySignature?.ToArray() ?? Array.Empty<byte>(),
                OneTimePreKeys = OneTimePreKeys.Select(k => k?.ToArray() ?? Array.Empty<byte>()).ToList(),
                OneTimePreKeyIds = OneTimePreKeyIds.ToList(),
                ProtocolVersion = ProtocolVersion,
                CreationTimestamp = CreationTimestamp
            };

            return clone;
        }
    }
}