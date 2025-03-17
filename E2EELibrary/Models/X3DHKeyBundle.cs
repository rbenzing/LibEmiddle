
using E2EELibrary.Core;

namespace E2EELibrary.Models
{
    /// <summary>
    /// X3DH key bundle for initial key exchange
    /// </summary>
    public class X3DHKeyBundle
    {
        // Public properties remain the same
        public byte[]? IdentityKey { get; set; }
        public byte[]? SignedPreKey { get; set; }
        public byte[]? SignedPreKeySignature { get; set; }
        public List<byte[]>? OneTimePreKeys { get; set; }

        // Private fields instead of properties
        private byte[]? _identityKeyPrivate;
        private byte[]? _signedPreKeyPrivate;

        // Public access methods for tests and internal usage
        public byte[]? GetIdentityKeyPrivate()
        {
            // Return a copy to prevent modification of the original
            if (_identityKeyPrivate == null) return null;
            byte[] copy = new byte[_identityKeyPrivate.Length];
            _identityKeyPrivate.AsSpan().CopyTo(copy.AsSpan());
            return copy;
        }

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

        public byte[]? GetSignedPreKeyPrivate()
        {
            if (_signedPreKeyPrivate == null) return null;
            byte[] copy = new byte[_signedPreKeyPrivate.Length];
            _signedPreKeyPrivate.AsSpan().CopyTo(copy.AsSpan());
            return copy;
        }

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

        // Method to securely clear private keys when no longer needed
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
