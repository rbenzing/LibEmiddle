
namespace E2EELibrary.Models
{
    /// <summary>
    /// Public portion of X3DH key bundle
    /// </summary>
    public class X3DHPublicBundle
    {
        /// <summary>
        /// Long-term identity public key
        /// </summary>
        public byte[]? IdentityKey { get; set; }

        /// <summary>
        /// Signed pre-key
        /// </summary>
        public byte[]? SignedPreKey { get; set; }

        /// <summary>
        /// Signature of signed pre-key
        /// </summary>
        public byte[]? SignedPreKeySignature { get; set; }

        /// <summary>
        /// List of one-time pre-keys
        /// </summary>
        public List<byte[]>? OneTimePreKeys { get; set; }
    }
}
