using E2EELibrary.Core;

namespace E2EELibrary.Models
{
    /// <summary>
    /// X3DH key bundle for initial key exchange, following the Signal Protocol specification.
    /// Contains public and private cryptographic keys for secure key exchange.
    /// </summary>
    public class X3DHKeyBundle
    {
        /// <summary>
        /// Long-term identity key (Ed25519 format)
        /// </summary>
        public byte[]? IdentityKey { get; set; }

        /// <summary>
        /// The signed prekey (X25519 format)
        /// </summary>
        public byte[]? SignedPreKey { get; set; }

        /// <summary>
        /// The signed prekey signature (created with identity key)
        /// </summary>
        public byte[]? SignedPreKeySignature { get; set; }

        /// <summary>
        /// List of one-time prekeys (X25519 format)
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

        // Private fields for sensitive key material
        private byte[]? _identityKeyPrivate;
        private byte[]? _signedPreKeyPrivate;

        /// <summary>
        /// Creates a new empty X3DHKeyBundle
        /// </summary>
        public X3DHKeyBundle()
        {
            OneTimePreKeys = new List<byte[]>();
            OneTimePreKeyIds = new List<uint>();
            CreationTimestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        }

        /// <summary>
        /// Gets the private identity key
        /// </summary>
        /// <returns>The private identity key (caller must not modify)</returns>
        public byte[]? GetIdentityKeyPrivate()
        {
            // Return a secure copy to prevent modification of the original
            if (_identityKeyPrivate == null) return null;
            byte[] copy = Sodium.GenerateRandomBytes(_identityKeyPrivate.Length);
            _identityKeyPrivate.AsSpan().CopyTo(copy.AsSpan());
            return copy;
        }

        /// <summary>
        /// Sets the private identity key
        /// </summary>
        /// <param name="value">The private key to store</param>
        public void SetIdentityKeyPrivate(byte[]? value)
        {
            if (_identityKeyPrivate != null)
            {
                SecureMemory.SecureClear(_identityKeyPrivate);
            }

            if (value == null)
            {
                _identityKeyPrivate = null;
                return;
            }

            _identityKeyPrivate = Sodium.GenerateRandomBytes(value.Length);
            value.AsSpan().CopyTo(_identityKeyPrivate.AsSpan());
        }

        /// <summary>
        /// Gets the signed private prekey
        /// </summary>
        /// <returns>The signed private prekey (caller must not modify)</returns>
        public byte[]? GetSignedPreKeyPrivate()
        {
            if (_signedPreKeyPrivate == null) return null;
            byte[] copy = Sodium.GenerateRandomBytes(_signedPreKeyPrivate.Length);
            _signedPreKeyPrivate.AsSpan().CopyTo(copy.AsSpan());
            return copy;
        }

        /// <summary>
        /// Sets the signed private prekey
        /// </summary>
        /// <param name="value">The signed private prekey to store</param>
        public void SetSignedPreKeyPrivate(byte[]? value)
        {
            if (_signedPreKeyPrivate != null)
            {
                SecureMemory.SecureClear(_signedPreKeyPrivate);
            }

            if (value == null)
            {
                _signedPreKeyPrivate = null;
                return;
            }

            _signedPreKeyPrivate = Sodium.GenerateRandomBytes(value.Length);
            value.AsSpan().CopyTo(_signedPreKeyPrivate.AsSpan());
        }

        /// <summary>
        /// Securely clears all private key material from memory when no longer needed.
        /// This should be called as soon as the key bundle is no longer required
        /// to minimize the time sensitive data remains in memory.
        /// </summary>
        public void ClearPrivateKeys()
        {
            if (_identityKeyPrivate != null)
            {
                SecureMemory.SecureClear(_identityKeyPrivate);
                _identityKeyPrivate = null;
            }

            if (_signedPreKeyPrivate != null)
            {
                SecureMemory.SecureClear(_signedPreKeyPrivate);
                _signedPreKeyPrivate = null;
            }
        }

        /// <summary>
        /// Creates a public bundle from this key bundle (containing only public keys)
        /// </summary>
        /// <returns>A public bundle suitable for sharing</returns>
        public X3DHPublicBundle ToPublicBundle()
        {
            return new X3DHPublicBundle
            {
                IdentityKey = this.IdentityKey,
                SignedPreKey = this.SignedPreKey,
                SignedPreKeySignature = this.SignedPreKeySignature,
                OneTimePreKeys = this.OneTimePreKeys,
                SignedPreKeyId = this.SignedPreKeyId,
                OneTimePreKeyIds = this.OneTimePreKeyIds,
                ProtocolVersion = this.ProtocolVersion,
                CreationTimestamp = this.CreationTimestamp
            };
        }

        /// <summary>
        /// Removes a specific one-time pre-key by ID
        /// </summary>
        /// <param name="preKeyId">ID of the pre-key to remove</param>
        /// <returns>True if the pre-key was found and removed</returns>
        public bool RemoveOneTimePreKey(uint preKeyId)
        {
            if (OneTimePreKeyIds == null || OneTimePreKeys == null)
                return false;

            int index = OneTimePreKeyIds.IndexOf(preKeyId);
            if (index != -1 && index < OneTimePreKeys.Count)
            {
                OneTimePreKeys.RemoveAt(index);
                OneTimePreKeyIds.RemoveAt(index);
                return true;
            }

            return false;
        }
    }
}