namespace LibEmiddle.Domain
{
    /// <summary>
    /// Represents a key pair for Ed25519 signatures.
    /// </summary>
    /// <remarks>
    /// Creates a new key pair instance.
    /// </remarks>
    /// <param name="publicKey">The public key.</param>
    /// <param name="privateKey">The private key.</param>
    public readonly struct KeyPair(byte[] publicKey, byte[] privateKey)
    {

        /// <summary>
        /// The public key (32 bytes).
        /// </summary>
        public byte[] PublicKey { get; init; } = publicKey ?? throw new ArgumentNullException(nameof(publicKey));

        /// <summary>
        /// The private key (64 bytes or 32 bytes).
        /// </summary>
        public byte[] PrivateKey { get; init; } = privateKey ?? throw new ArgumentNullException(nameof(privateKey));
    }
}
