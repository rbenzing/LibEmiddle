namespace LibEmiddle.Domain.Enums
{
    /// <summary>
    /// Defines the cryptographic key exchange mode to use for session establishment.
    /// </summary>
    public enum KeyExchangeMode
    {
        /// <summary>
        /// Use classical X25519 key exchange (current default behavior).
        /// </summary>
        Classical = 0,

        /// <summary>
        /// Use hybrid classical + post-quantum key exchange.
        /// Combines X25519 with Kyber768 for quantum resistance.
        /// </summary>
        Hybrid = 1,

        /// <summary>
        /// Use post-quantum key exchange only.
        /// Future implementation using Kyber768.
        /// </summary>
        PostQuantum = 2
    }
}