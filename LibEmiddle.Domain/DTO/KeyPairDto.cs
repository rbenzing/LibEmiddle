#pragma warning disable IDE0130 // Namespace does not match folder structure
namespace LibEmiddle.Domain
#pragma warning restore IDE0130 // Namespace does not match folder structure
{
    /// <summary>
    /// DTO for serializing and deserializing a key pair.
    /// </summary>
    public class KeyPairDto
    {
        /// <summary>
        /// Gets or sets the Base64-encoded public key.
        /// </summary>
        public string PublicKey { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the Base64-encoded private key.
        /// </summary>
        public string PrivateKey { get; set; } = string.Empty;
    }
}
