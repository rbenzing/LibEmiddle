namespace LibEmiddle.Domain
{
    /// <summary>
    /// Represents a key pair for Ed25519 signatures.
    /// </summary>
    public readonly struct KeyPair
    {
        /// <summary>
        /// Creates a new key pair instance.
        /// </summary>
        /// <param name="publicKey">The public key.</param>
        /// <param name="privateKey">The private key.</param>
        public KeyPair(byte[] publicKey, byte[] privateKey)
        {
            PublicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
            PrivateKey = privateKey ?? throw new ArgumentNullException(nameof(privateKey));
        }

        /// <summary>
        /// The public key (32 bytes).
        /// </summary>
        public byte[] PublicKey { get; init; }

        /// <summary>
        /// The private key (64 bytes or 32 bytes).
        /// </summary>
        public byte[] PrivateKey { get; init; }
    }
}
