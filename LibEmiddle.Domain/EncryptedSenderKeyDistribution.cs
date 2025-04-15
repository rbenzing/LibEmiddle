namespace LibEmiddle.Domain
{
    /// <summary>
    /// Enhanced EncryptedSenderKeyDistribution class with additional security features
    /// </summary>
    public class EncryptedSenderKeyDistribution
    {
        /// <summary>
        /// Encrypted distribution message
        /// </summary>
        public byte[]? Ciphertext { get; set; }

        /// <summary>
        /// Nonce used for encryption
        /// </summary>
        public byte[]? Nonce { get; set; }

        /// <summary>
        /// Public key of the recipient
        /// </summary>
        public byte[]? RecipientPublicKey { get; set; }

        /// <summary>
        /// Public key of the sender
        /// </summary>
        public byte[]? SenderPublicKey { get; set; }

        /// <summary>
        /// Signature of the ephemeral public key by the sender
        /// </summary>
        public byte[]? Signature { get; set; }

        /// <summary>
        /// Message identifier for replay protection
        /// </summary>
        public Guid MessageId { get; set; } = Guid.NewGuid();

        /// <summary>
        /// Validates this message for security requirements
        /// </summary>
        /// <returns>True if the message is valid</returns>
        public bool Validate()
        {
            // Check for null or empty elements
            if (Ciphertext == null || Ciphertext.Length == 0)
                return false;

            if (Nonce == null || Nonce.Length == 0)
                return false;

            if (SenderPublicKey == null || SenderPublicKey.Length == 0)
                return false;

            return true;
        }
    }
}
