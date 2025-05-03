namespace LibEmiddle.Domain.DTO
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
