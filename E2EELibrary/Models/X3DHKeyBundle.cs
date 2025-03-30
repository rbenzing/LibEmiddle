
using E2EELibrary.Core;

namespace E2EELibrary.Models
{
    /// <summary>
    /// X3DH key bundle for initial key exchange
    /// </summary>
    public class X3DHKeyBundle
    {
        /// <summary>
        /// The identity key pair
        /// </summary>
        public byte[]? IdentityKey { get; set; }

        /// <summary>
        /// The signed prekey
        /// </summary>
        public byte[]? SignedPreKey { get; set; }

        /// <summary>
        /// The signed prekey signature
        /// </summary>
        public byte[]? SignedPreKeySignature { get; set; }

        /// <summary>
        /// The one time prekey
        /// </summary>
        public List<byte[]>? OneTimePreKeys { get; set; }

        // Private fields instead of properties
        private byte[]? _identityKeyPrivate;
        private byte[]? _signedPreKeyPrivate;

        /// <summary>
        /// Gets the private identity key
        /// </summary>
        /// <returns>The private identity key</returns>
        public byte[]? GetIdentityKeyPrivate()
        {
            // Return a copy to prevent modification of the original
            if (_identityKeyPrivate == null) return null;
            byte[] copy = new byte[_identityKeyPrivate.Length];
            _identityKeyPrivate.AsSpan().CopyTo(copy.AsSpan());
            return copy;
        }

        /// <summary>
        /// Sets the private identity key
        /// </summary>
        /// <param name="value"></param>
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

            _identityKeyPrivate = new byte[value.Length];
            value.AsSpan().CopyTo(_identityKeyPrivate.AsSpan());
        }

        /// <summary>
        /// Gets the signed private prekey
        /// </summary>
        /// <returns></returns>
        public byte[]? GetSignedPreKeyPrivate()
        {
            if (_signedPreKeyPrivate == null) return null;
            byte[] copy = new byte[_signedPreKeyPrivate.Length];
            _signedPreKeyPrivate.AsSpan().CopyTo(copy.AsSpan());
            return copy;
        }

        /// <summary>
        /// Sets the signed private prekey
        /// </summary>
        /// <param name="value"></param>
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

            _signedPreKeyPrivate = new byte[value.Length];
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
    }
}
