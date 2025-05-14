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

        // Private components - These are never shared
        private byte[]? _identityKeyPrivate;
        private byte[]? _signedPreKeyPrivate;
        private readonly Dictionary<uint, byte[]> _oneTimePreKeysPrivate = new Dictionary<uint, byte[]>();

        /// <summary>
        /// Sets the private portion of the identity key.
        /// </summary>
        /// <param name="privateKey">The Ed25519 identity private key.</param>
        /// <exception cref="ArgumentNullException">Thrown when privateKey is null.</exception>
        /// <exception cref="ArgumentException">Thrown when privateKey is not the correct size.</exception>
        public void SetIdentityKeyPrivate(byte[] privateKey)
        {
            ArgumentNullException.ThrowIfNull(privateKey, nameof(privateKey));

            if (privateKey.Length != Constants.ED25519_PRIVATE_KEY_SIZE)
                throw new ArgumentException($"Invalid identity key size. Expected {Constants.ED25519_PRIVATE_KEY_SIZE} bytes.", nameof(privateKey));

            _identityKeyPrivate = privateKey.ToArray(); // Create a copy for security
        }

        /// <summary>
        /// Gets the private portion of the identity key.
        /// </summary>
        /// <returns>The Ed25519 identity private key, or null if not set.</returns>
        public byte[]? GetIdentityKeyPrivate()
        {
            return _identityKeyPrivate?.ToArray(); // Return a copy for security
        }

        /// <summary>
        /// Sets the private portion of the signed pre-key.
        /// </summary>
        /// <param name="privateKey">The X25519 signed pre-key private key.</param>
        /// <exception cref="ArgumentNullException">Thrown when privateKey is null.</exception>
        /// <exception cref="ArgumentException">Thrown when privateKey is not the correct size.</exception>
        public void SetSignedPreKeyPrivate(byte[] privateKey)
        {
            ArgumentNullException.ThrowIfNull(privateKey, nameof(privateKey));

            if (privateKey.Length != Constants.X25519_KEY_SIZE)
                throw new ArgumentException($"Invalid signed pre-key size. Expected {Constants.X25519_KEY_SIZE} bytes.", nameof(privateKey));

            _signedPreKeyPrivate = privateKey.ToArray(); // Create a copy for security
        }

        /// <summary>
        /// Gets the private portion of the signed pre-key.
        /// </summary>
        /// <returns>The X25519 signed pre-key private key, or null if not set.</returns>
        public byte[]? GetSignedPreKeyPrivate()
        {
            return _signedPreKeyPrivate?.ToArray(); // Return a copy for security
        }

        /// <summary>
        /// Sets the private portion of a one-time pre-key.
        /// </summary>
        /// <param name="keyId">The ID of the one-time pre-key.</param>
        /// <param name="privateKey">The X25519 one-time pre-key private key.</param>
        /// <exception cref="ArgumentNullException">Thrown when privateKey is null.</exception>
        /// <exception cref="ArgumentException">Thrown when privateKey is not the correct size or keyId is not found.</exception>
        public void SetOneTimePreKeyPrivate(uint keyId, byte[] privateKey)
        {
            ArgumentNullException.ThrowIfNull(privateKey, nameof(privateKey));

            if (privateKey.Length != Constants.X25519_KEY_SIZE)
                throw new ArgumentException($"Invalid one-time pre-key size. Expected {Constants.X25519_KEY_SIZE} bytes.", nameof(privateKey));

            if (keyId == 0)
                throw new ArgumentException("One-time pre-key ID cannot be 0.", nameof(keyId));

            if (!OneTimePreKeyIds.Contains(keyId))
                throw new ArgumentException($"One-time pre-key ID {keyId} not found in this bundle.", nameof(keyId));

            _oneTimePreKeysPrivate[keyId] = privateKey.ToArray(); // Create a copy for security
        }

        /// <summary>
        /// Gets the private portion of a one-time pre-key.
        /// </summary>
        /// <param name="keyId">The ID of the one-time pre-key.</param>
        /// <returns>The X25519 one-time pre-key private key, or null if not found.</returns>
        public byte[]? GetOneTimePreKeyPrivate(uint keyId)
        {
            if (keyId == 0)
                return null;

            if (_oneTimePreKeysPrivate.TryGetValue(keyId, out var privateKey))
                return privateKey.ToArray(); // Return a copy for security

            return null;
        }

        /// <summary>
        /// Creates a public-only version of this bundle that can be safely shared.
        /// </summary>
        /// <returns>An X3DHPublicBundle containing only the public components.</returns>
        /// <exception cref="InvalidOperationException">Thrown if the bundle is not valid.</exception>
        public X3DHPublicBundle ToPublicBundle()
        {
            if (!Validate())
                throw new InvalidOperationException("Cannot create public bundle: bundle is not valid.");

            return new X3DHPublicBundle
            {
                IdentityKey = IdentityKey.ToArray(),
                SignedPreKey = SignedPreKey.ToArray(),
                SignedPreKeyId = SignedPreKeyId,
                SignedPreKeySignature = SignedPreKeySignature.ToArray(),
                OneTimePreKeys = OneTimePreKeys.Select(k => k.ToArray()).ToList(),
                OneTimePreKeyIds = OneTimePreKeyIds.ToList(),
                ProtocolVersion = ProtocolVersion,
                CreationTimestamp = CreationTimestamp
            };
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

            // Check required private components
            if (_identityKeyPrivate == null || _identityKeyPrivate.Length != Constants.ED25519_PRIVATE_KEY_SIZE)
                return false;

            if (_signedPreKeyPrivate == null || _signedPreKeyPrivate.Length != Constants.X25519_KEY_SIZE)
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

                    // Private keys might not be present for all one-time prekeys (e.g., when receiving a bundle)
                    if (_oneTimePreKeysPrivate.TryGetValue(keyId, out var privateKey))
                    {
                        if (privateKey.Length != Constants.X25519_KEY_SIZE)
                            return false;
                    }
                }
            }

            return true;
        }

        /// <summary>
        /// Validates that just the required public fields of the bundle are present and properly formatted.
        /// This is useful when validating a received bundle where private keys are not available.
        /// </summary>
        /// <returns>True if the public components are valid, false otherwise.</returns>
        public bool ValidatePublicComponents()
        {
            // Check required public components
            if (IdentityKey == null || IdentityKey.Length != Constants.ED25519_PUBLIC_KEY_SIZE)
                return false;

            if (SignedPreKey == null || SignedPreKey.Length != Constants.X25519_KEY_SIZE)
                return false;

            if (SignedPreKeyId == 0) // Must be greater than 0
                return false;

            if (SignedPreKeySignature == null || SignedPreKeySignature.Length != Constants.ED25519_PRIVATE_KEY_SIZE)
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
        /// Securely clears all private key material from memory.
        /// </summary>
        public void ClearPrivateKeys()
        {
            if (_identityKeyPrivate != null)
            {
                // Zero out all bytes in the array for security
                Array.Clear(_identityKeyPrivate, 0, _identityKeyPrivate.Length);
                _identityKeyPrivate = null;
            }

            if (_signedPreKeyPrivate != null)
            {
                // Zero out all bytes in the array for security
                Array.Clear(_signedPreKeyPrivate, 0, _signedPreKeyPrivate.Length);
                _signedPreKeyPrivate = null;
            }

            foreach (var key in _oneTimePreKeysPrivate.Values)
            {
                // Zero out all bytes in the array for security
                Array.Clear(key, 0, key.Length);
            }
            _oneTimePreKeysPrivate.Clear();
        }

        /// <summary>
        /// Finalizer to ensure private keys are cleared from memory.
        /// </summary>
        ~X3DHKeyBundle()
        {
            ClearPrivateKeys();
        }
    }
}