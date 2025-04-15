using LibEmiddle.Core;

namespace LibEmiddle.Models
{
    /// <summary>
    /// X3DH key bundle for initial key exchange, following the Signal Protocol specification.
    /// Contains public and private cryptographic keys for secure key exchange.
    /// </summary>
    public class X3DHKeyBundle
    {
        /// <summary>
        /// Public long-term identity key (32 byte Ed25519).
        /// Used by others to verify the Signed PreKey signature.
        /// </summary>
        public byte[]? IdentityKey { get; set; }

        /// <summary>
        /// Public signed prekey (32 byte X25519).
        /// Used for an initial Diffie-Hellman calculation. Rotated periodically.
        /// </summary>
        public byte[]? SignedPreKey { get; set; }

        /// <summary>
        /// Signature of the SignedPreKey public key using the IdentityKey private key (64 byte Ed25519).
        /// </summary>
        public byte[]? SignedPreKeySignature { get; set; }

        /// <summary>
        /// List of public one-time prekeys (32 byte X25519).
        /// Consumed during key agreement to provide forward secrecy.
        /// </summary>
        public List<byte[]>? OneTimePreKeys { get; set; }

        /// <summary>
        /// Unique identifier for the Signed PreKey (non-zero).
        /// </summary>
        public uint SignedPreKeyId { get; set; }

        /// <summary>
        /// List of unique identifiers for one-time pre-keys (non-zero),
        /// matching the index/order in OneTimePreKeys.
        /// </summary>
        public List<uint>? OneTimePreKeyIds { get; set; }

        /// <summary>
        /// Protocol version for compatibility checks (optional).
        /// </summary>
        public string? ProtocolVersion { get; set; }

        /// <summary>
        /// Timestamp when this bundle was created (milliseconds since Unix epoch).
        /// Useful for key rotation policies.
        /// </summary>
        public long CreationTimestamp { get; set; }

        // Private fields for sensitive key material
        private byte[]? _identityKeyPrivate;
        private byte[]? _signedPreKeyPrivate;
        // Store private OPKs mapped by their public ID for easy lookup
        private Dictionary<uint, byte[]>? _oneTimePreKeysPrivate;

        private bool _disposed = false; // To detect redundant calls to Dispose

        /// <summary>
        /// Creates a new empty X3DHKeyBundle.
        /// </summary>
        public X3DHKeyBundle()
        {
            OneTimePreKeys = new List<byte[]>();
            OneTimePreKeyIds = new List<uint>();
            _oneTimePreKeysPrivate = new Dictionary<uint, byte[]>(); // Initialize the dictionary
            CreationTimestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        }

        /// <summary>
        /// Gets a copy of the private identity key. Caller MUST securely clear the copy when done.
        /// </summary>
        /// <returns>A copy of the private identity key, or null if not set.</returns>
        /// <exception cref="ObjectDisposedException">Thrown if the bundle has been disposed.</exception>
        public byte[] GetIdentityKeyPrivate()
        {
            if (_disposed) throw new ObjectDisposedException(nameof(X3DHKeyBundle));

            ArgumentNullException.ThrowIfNull(_identityKeyPrivate);

            // Return a copy to prevent modification of the internal key
            return [.. _identityKeyPrivate];
        }

        /// <summary>
        /// Sets the private identity key, securely storing a copy.
        /// Clears any previously stored key.
        /// </summary>
        /// <param name="value">The private key bytes to store.</param>
        /// <exception cref="ObjectDisposedException">Thrown if the bundle has been disposed.</exception>
        public void SetIdentityKeyPrivate(byte[]? value)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(X3DHKeyBundle));
            // Clear existing key securely before replacing
            if (_identityKeyPrivate != null)
            {
                SecureMemory.SecureClear(_identityKeyPrivate);
            }

            if (value == null)
            {
                _identityKeyPrivate = null;
            }
            else
            {
                // Store a copy
                _identityKeyPrivate = new byte[value.Length];
                value.AsSpan().CopyTo(_identityKeyPrivate.AsSpan());
            }
        }

        /// <summary>
        /// Gets a copy of the private signed prekey. Caller MUST securely clear the copy when done.
        /// </summary>
        /// <returns>A copy of the private signed prekey, or null if not set.</returns>
        /// <exception cref="ObjectDisposedException">Thrown if the bundle has been disposed.</exception>
        public byte[]? GetSignedPreKeyPrivate()
        {
            if (_disposed) throw new ObjectDisposedException(nameof(X3DHKeyBundle));
            return _signedPreKeyPrivate?.ToArray();
        }

        /// <summary>
        /// Sets the private signed prekey, securely storing a copy.
        /// Clears any previously stored key.
        /// </summary>
        /// <param name="value">The private key bytes to store.</param>
        /// <exception cref="ObjectDisposedException">Thrown if the bundle has been disposed.</exception>
        public void SetSignedPreKeyPrivate(byte[]? value)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(X3DHKeyBundle));
            if (_signedPreKeyPrivate != null)
            {
                SecureMemory.SecureClear(_signedPreKeyPrivate);
            }

            if (value == null)
            {
                _signedPreKeyPrivate = null;
            }
            else
            {
                _signedPreKeyPrivate = new byte[value.Length];
                value.AsSpan().CopyTo(_signedPreKeyPrivate.AsSpan());
            }
        }

        /// <summary>
        /// Gets a copy of the private one-time prekey associated with the given ID.
        /// Caller MUST securely clear the copy when done.
        /// </summary>
        /// <param name="preKeyId">The ID of the one-time prekey.</param>
        /// <returns>A copy of the private key, or null if the ID is not found.</returns>
        /// <exception cref="ObjectDisposedException">Thrown if the bundle has been disposed.</exception>
        public byte[]? GetOneTimePreKeyPrivate(uint preKeyId)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(X3DHKeyBundle));
            if (_oneTimePreKeysPrivate != null && _oneTimePreKeysPrivate.TryGetValue(preKeyId, out byte[]? privateKey))
            {
                return privateKey?.ToArray(); // Return a copy
            }
            return null;
        }

        /// <summary>
        /// Adds or updates a private one-time prekey associated with a specific ID.
        /// Securely stores a copy of the key and clears any pre-existing key for the same ID.
        /// </summary>
        /// <param name="preKeyId">The ID for the prekey (should match a public key ID).</param>
        /// <param name="privateKey">The private key bytes to store.</param>
        /// <exception cref="ArgumentNullException">Thrown if privateKey is null.</exception>
        /// <exception cref="ObjectDisposedException">Thrown if the bundle has been disposed.</exception>
        public void SetOneTimePreKeyPrivate(uint preKeyId, byte[] privateKey)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(X3DHKeyBundle));
            if (privateKey == null) throw new ArgumentNullException(nameof(privateKey));
            // Ensure dictionary is initialized (should be by constructor, but safe check)
            if (_oneTimePreKeysPrivate == null)
            {
                _oneTimePreKeysPrivate = new Dictionary<uint, byte[]>();
            }

            // Clear existing key for this ID if it exists, before adding the new one
            if (_oneTimePreKeysPrivate.TryGetValue(preKeyId, out byte[]? existingKey))
            {
                SecureMemory.SecureClear(existingKey);
                // No need to explicitly remove, the assignment below will overwrite
            }

            // Store a copy of the provided key
            byte[] keyCopy = new byte[privateKey.Length];
            privateKey.AsSpan().CopyTo(keyCopy.AsSpan());

            // Add or update the key in the dictionary
            _oneTimePreKeysPrivate[preKeyId] = keyCopy;
        }

        /// <summary>
        /// Securely clears all private key material (Identity, Signed, and One-Time) from memory.
        /// Call this when the bundle is no longer needed in its complete form.
        /// Consider using the IDisposable pattern (Dispose method).
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

            if (_oneTimePreKeysPrivate != null)
            {
                foreach (var kvp in _oneTimePreKeysPrivate)
                {
                    if (kvp.Value != null) // Check value is not null before clearing
                    {
                        SecureMemory.SecureClear(kvp.Value);
                    }
                }
                _oneTimePreKeysPrivate.Clear();
                // Optionally set _oneTimePreKeysPrivate = null; if you want to prevent adding more after clearing
            }
        }

        /// <summary>
        /// Creates a public bundle containing only the public keys and associated data,
        /// suitable for publishing to a server.
        /// </summary>
        /// <returns>An X3DHPublicBundle instance.</returns>
        /// <exception cref="ObjectDisposedException">Thrown if the bundle has been disposed.</exception>
        /// <exception cref="InvalidOperationException">Thrown if essential public components are missing.</exception>
        public X3DHPublicBundle ToPublicBundle()
        {
            if (_disposed) throw new ObjectDisposedException(nameof(X3DHKeyBundle));
            // Ensure required public components are present before creating public bundle
            if (IdentityKey == null || SignedPreKey == null || SignedPreKeySignature == null || OneTimePreKeys == null || OneTimePreKeyIds == null)
            {
                throw new InvalidOperationException("Cannot create public bundle, essential components are missing.");
            }

            // Create copies of mutable collections if necessary to prevent external modification
            var publicOneTimePreKeys = OneTimePreKeys.Select(k => (byte[])k.Clone()).ToList();
            var publicOneTimePreKeyIds = new List<uint>(OneTimePreKeyIds);


            return new X3DHPublicBundle
            {
                IdentityKey = (byte[]?)this.IdentityKey.Clone(), // Clone byte arrays for safety
                SignedPreKey = (byte[]?)this.SignedPreKey.Clone(),
                SignedPreKeySignature = (byte[]?)this.SignedPreKeySignature.Clone(),
                OneTimePreKeys = publicOneTimePreKeys, // Use the copied list
                SignedPreKeyId = this.SignedPreKeyId,
                OneTimePreKeyIds = publicOneTimePreKeyIds, // Use the copied list
                ProtocolVersion = this.ProtocolVersion,
                CreationTimestamp = this.CreationTimestamp
            };
        }

        /// <summary>
        /// Removes a specific one-time pre-key (both public and private parts) by ID.
        /// </summary>
        /// <param name="preKeyId">ID of the pre-key to remove.</param>
        /// <returns>True if the pre-key was found and removed, false otherwise.</returns>
        /// <exception cref="ObjectDisposedException">Thrown if the bundle has been disposed.</exception>
        public bool RemoveOneTimePreKey(uint preKeyId)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(X3DHKeyBundle));
            if (OneTimePreKeyIds == null || OneTimePreKeys == null || _oneTimePreKeysPrivate == null)
                return false;

            int index = OneTimePreKeyIds.IndexOf(preKeyId);
            bool removed = false;

            if (index != -1) // Found in public lists
            {
                if (index < OneTimePreKeys.Count) // Basic sanity check
                {
                    OneTimePreKeys.RemoveAt(index);
                }
                OneTimePreKeyIds.RemoveAt(index); // Remove ID regardless of key list state
                removed = true; // At least public parts removed
            }

            // Securely clear and remove private part if it exists
            if (_oneTimePreKeysPrivate.TryGetValue(preKeyId, out byte[]? privateKey))
            {
                if (privateKey != null) // Check before clearing
                {
                    SecureMemory.SecureClear(privateKey);
                }
                _oneTimePreKeysPrivate.Remove(preKeyId);
                removed = true; // Confirmed private part also removed (or didn't exist matching ID)
            }

            return removed; // Return true if either public ID or private key was found and removed
        }

        /// <summary>
        /// Releases resources and securely clears private keys.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this); // Prevent finalizer from running if Dispose was called
        }

        /// <summary>
        /// Protected implementation of Dispose pattern.
        /// </summary>
        /// <param name="disposing">True if called from Dispose(), false if called from finalizer.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    // Dispose managed state (managed objects).
                    // No other complex managed objects owned directly by this class
                }

                // Free unmanaged resources (unmanaged objects) and override finalizer
                // Securely clear private keys - THIS IS CRITICAL
                ClearPrivateKeys();

                // Set large fields/collections to null to help GC and prevent use after dispose
                IdentityKey = null;
                SignedPreKey = null;
                SignedPreKeySignature = null;
                OneTimePreKeys?.Clear(); // Clear lists
                OneTimePreKeys = null;
                OneTimePreKeyIds?.Clear();
                OneTimePreKeyIds = null;
                _oneTimePreKeysPrivate?.Clear(); // Already cleared in ClearPrivateKeys, but defense in depth
                _oneTimePreKeysPrivate = null;


                _disposed = true;
            }
        }

        // Optional: Finalizer for safety net, though explicit Dispose is preferred
        ~X3DHKeyBundle()
        {
            Dispose(false);
        }
    }
}