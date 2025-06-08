using LibEmiddle.Domain;

namespace LibEmiddle.Abstractions
{
    /// <summary>
    /// Interface for X3DH (Extended Triple Diffie-Hellman) key agreement protocol.
    /// Handles secure key exchange between two parties using Ed25519 identity keys and X25519 ephemeral keys.
    /// </summary>
    public interface IX3DHProtocol
    {
        /// <summary>
        /// Creates a complete X3DH key bundle for a user.
        /// </summary>
        /// <param name="identityKeyPair">Optional Ed25519 identity key pair. If null, a new one is generated.</param>
        /// <param name="numOneTimeKeys">Number of X25519 one-time prekeys to generate.</param>
        /// <returns>A complete X3DH key bundle containing all necessary keys.</returns>
        Task<X3DHKeyBundle> CreateKeyBundleAsync(KeyPair? identityKeyPair = null, int numOneTimeKeys = 5);

        /// <summary>
        /// Initiates an X3DH session as the sender (Alice).
        /// </summary>
        /// <param name="recipientBundle">The recipient's X3DH public bundle.</param>
        /// <param name="senderIdentityKeyPair">The sender's Ed25519 identity key pair.</param>
        /// <returns>Session result containing the shared secret and initial message data.</returns>
        Task<SenderSessionResult> InitiateSessionAsSenderAsync(X3DHPublicBundle recipientBundle, KeyPair senderIdentityKeyPair);

        /// <summary>
        /// Establishes an X3DH session as the receiver (Bob).
        /// </summary>
        /// <param name="initialMessage">The initial message data from the sender.</param>
        /// <param name="localKeyBundle">The receiver's complete X3DH key bundle.</param>
        /// <returns>The 32-byte shared secret derived from the X3DH key agreement.</returns>
        Task<byte[]> EstablishSessionAsReceiverAsync(InitialMessageData initialMessage, X3DHKeyBundle localKeyBundle);

        /// <summary>
        /// Validates an X3DH public bundle for correctness and security.
        /// </summary>
        /// <param name="bundle">The X3DH public bundle to validate.</param>
        /// <returns>True if the bundle is valid, false otherwise.</returns>
        Task<bool> ValidateKeyBundleAsync(X3DHPublicBundle bundle);
    }
}
