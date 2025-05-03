namespace LibEmiddle.Domain
{
    /// <summary>
    /// Represents a complete X3DH key bundle containing both public and private components
    /// for establishing secure sessions between parties using the Signal protocol.
    /// </summary>
    public class X3DHKeyBundle
    {
        // Public components - These are shared with other parties

        /// <summary>
        /// Gets or sets the Ed25519 identity public key.
        /// </summary>
        public byte[]? IdentityKey { get; set; }

        /// <summary>
        /// Gets or sets the X25519 signed pre-key.
        /// </summary>
        public byte[]? SignedPreKey { get; set; }

        /// <summary>
        /// Gets or sets the signed pre-key's unique identifier.
        /// </summary>
        public uint SignedPreKeyId { get; set; }

        /// <summary>
        /// Gets or sets the signature of the signed pre-key, created using the identity key.
        /// </summary>
        public byte[]? SignedPreKeySignature { get; set; }

        /// <summary>
        /// Gets or sets the list of one-time pre-keys (X25519 public keys).
        /// </summary>
        public List<byte[]> OneTimePreKeys { get; set; } = new List<byte[]>();

        /// <summary>
        /// Gets or sets the list of one-time pre-key identifiers.
        /// </summary>
        public List<uint> OneTimePreKeyIds { get; set; } = new List<uint>();

        /// <summary>
        /// Gets or sets the protocol version string.
        /// </summary>
        public string ProtocolVersion { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the creation timestamp (milliseconds since Unix epoch).
        /// </summary>
        public long CreationTimestamp { get; set; }

        // Private components - These are never shared
        private byte[]? _identityKeyPrivate;
        private byte[]? _signedPreKeyPrivate;
        private readonly Dictionary<uint, byte[]> _oneTimePreKeysPrivate = new Dictionary<uint, byte[]>();

        /// <summary>
        /// Sets the private portion of the identity key.
        /// </summary>
        /// <param name="privateKey">The Ed25519 identity private key.</param>
        public void SetIdentityKeyPrivate(byte[] privateKey)
        {
            if (privateKey == null)
                throw new ArgumentNullException(nameof(privateKey));

            if (privateKey.Length != Constants.ED25519_PRIVATE_KEY_SIZE)
                throw new ArgumentException($"Invalid identity key size. Expected {Constants.ED25519_PRIVATE_KEY_SIZE} bytes.");

            _identityKeyPrivate = privateKey.ToArray(); // Create a copy for security
        }

        /// <summary>
        /// Gets the private portion of the identity key.
        /// </summary>
        /// <returns>The Ed25519 identity private key.</returns>
        public byte[]? GetIdentityKeyPrivate()
        {
            return _identityKeyPrivate?.ToArray(); // Return a copy for security
        }

        /// <summary>
        /// Sets the private portion of the signed pre-key.
        /// </summary>
        /// <param name="privateKey">The X25519 signed pre-key private key.</param>
        public void SetSignedPreKeyPrivate(byte[] privateKey)
        {
            if (privateKey == null)
                throw new ArgumentNullException(nameof(privateKey));

            if (privateKey.Length != Constants.X25519_KEY_SIZE)
                throw new ArgumentException($"Invalid signed pre-key size. Expected {Constants.X25519_KEY_SIZE} bytes.");

            _signedPreKeyPrivate = privateKey.ToArray(); // Create a copy for security
        }

        /// <summary>
        /// Gets the private portion of the signed pre-key.
        /// </summary>
        /// <returns>The X25519 signed pre-key private key.</returns>
        public byte[]? GetSignedPreKeyPrivate()
        {
            return _signedPreKeyPrivate?.ToArray(); // Return a copy for security
        }

        /// <summary>
        /// Sets the private portion of a one-time pre-key.
        /// </summary>
        /// <param name="keyId">The ID of the one-time pre-key.</param>
        /// <param name="privateKey">The X25519 one-time pre-key private key.</param>
        public void SetOneTimePreKeyPrivate(uint keyId, byte[] privateKey)
        {
            if (privateKey == null)
                throw new ArgumentNullException(nameof(privateKey));

            if (privateKey.Length != Constants.X25519_KEY_SIZE)
                throw new ArgumentException($"Invalid one-time pre-key size. Expected {Constants.X25519_KEY_SIZE} bytes.");

            if (!OneTimePreKeyIds.Contains(keyId))
                throw new ArgumentException($"One-time pre-key ID {keyId} not found in this bundle.");

            _oneTimePreKeysPrivate[keyId] = privateKey.ToArray(); // Create a copy for security
        }

        /// <summary>
        /// Gets the private portion of a one-time pre-key.
        /// </summary>
        /// <param name="keyId">The ID of the one-time pre-key.</param>
        /// <returns>The X25519 one-time pre-key private key.</returns>
        public byte[]? GetOneTimePreKeyPrivate(uint keyId)
        {
            if (_oneTimePreKeysPrivate.TryGetValue(keyId, out var privateKey))
                return privateKey.ToArray(); // Return a copy for security

            return null;
        }

        /// <summary>
        /// Creates a public-only version of this bundle that can be safely shared.
        /// </summary>
        /// <returns>An X3DHPublicBundle containing only the public components.</returns>
        public X3DHPublicBundle ToPublicBundle()
        {
            return new X3DHPublicBundle
            {
                IdentityKey = IdentityKey?.ToArray(),
                SignedPreKey = SignedPreKey?.ToArray(),
                SignedPreKeyId = SignedPreKeyId,
                SignedPreKeySignature = SignedPreKeySignature?.ToArray(),
                OneTimePreKeys = OneTimePreKeys.Select(k => k.ToArray()).ToList(),
                OneTimePreKeyIds = OneTimePreKeyIds.ToList(),
                ProtocolVersion = ProtocolVersion,
                CreationTimestamp = CreationTimestamp
            };
        }

        /// <summary>
        /// Validates that all required fields of the bundle are present and properly formatted.
        /// </summary>
        /// <returns>True if the bundle is valid, false otherwise.</returns>
        public bool Validate()
        {
            bool identityKeysValid = IdentityKey != null &&
                                    IdentityKey.Length == Constants.ED25519_PUBLIC_KEY_SIZE &&
                                    _identityKeyPrivate != null &&
                                    _identityKeyPrivate.Length == Constants.ED25519_PRIVATE_KEY_SIZE;

            bool signedPreKeysValid = SignedPreKey != null &&
                                     SignedPreKey.Length == Constants.X25519_KEY_SIZE &&
                                     SignedPreKeyId > 0 &&
                                     SignedPreKeySignature != null &&
                                     SignedPreKeySignature.Length == Constants.ED25519_PRIVATE_KEY_SIZE &&
                                     _signedPreKeyPrivate != null &&
                                     _signedPreKeyPrivate.Length == Constants.X25519_KEY_SIZE;

            if (!identityKeysValid || !signedPreKeysValid)
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

                    if (key == null ||
                        key.Length != Constants.X25519_KEY_SIZE ||
                        keyId == 0 ||
                        !_oneTimePreKeysPrivate.ContainsKey(keyId) ||
                        _oneTimePreKeysPrivate[keyId].Length != Constants.X25519_KEY_SIZE)
                    {
                        return false;
                    }
                }
            }

            return true;
        }

        /// <summary>
        /// Securely clears all private key material from memory.
        /// </summary>
        public void ClearPrivateKeys()
        {
            if (_identityKeyPrivate != null)
            {
                _identityKeyPrivate = null;
            }

            if (_signedPreKeyPrivate != null)
            {
                _signedPreKeyPrivate = null;
            }

            _oneTimePreKeysPrivate.Clear();
        }

        /// <summary>
        /// Clean up resources on finalization.
        /// </summary>
        ~X3DHKeyBundle()
        {
            ClearPrivateKeys();
        }
    }
}