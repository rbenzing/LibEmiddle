namespace LibEmiddle.Domain.Enums
{
    /// <summary>
    /// Types of asymmetric key pairs supported by the library
    /// </summary>
    public enum KeyType
    {
        /// <summary>
        /// Ed25519 keys for digital signatures
        /// </summary>
        Ed25519,

        /// <summary>
        /// X25519 keys for key exchange
        /// </summary>
        X25519
    }
}
