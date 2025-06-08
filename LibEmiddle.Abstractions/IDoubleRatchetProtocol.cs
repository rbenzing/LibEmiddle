using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;

namespace LibEmiddle.Abstractions
{
    /// <summary>
    /// Interface for Double Ratchet protocol implementation.
    /// Provides forward secrecy and post-compromise security for messaging using X25519 key exchange.
    /// </summary>
    public interface IDoubleRatchetProtocol
    {
        /// <summary>
        /// Initializes a Double Ratchet session as the sender (Alice).
        /// </summary>
        /// <param name="sharedKeyFromX3DH">The 32-byte shared secret from X3DH key agreement.</param>
        /// <param name="recipientInitialPublicKey">The recipient's initial X25519 public key (32 bytes).</param>
        /// <param name="sessionId">Unique identifier for this session.</param>
        /// <returns>Initialized Double Ratchet session for the sender.</returns>
        DoubleRatchetSession InitializeSessionAsSender(byte[] sharedKeyFromX3DH, byte[] recipientInitialPublicKey, string sessionId);

        /// <summary>
        /// Initializes a Double Ratchet session as the receiver (Bob).
        /// </summary>
        /// <param name="sharedKeyFromX3DH">The 32-byte shared secret from X3DH key agreement.</param>
        /// <param name="receiverInitialKeyPair">The receiver's initial X25519 key pair.</param>
        /// <param name="senderEphemeralKeyPublic">The sender's ephemeral X25519 public key (32 bytes).</param>
        /// <param name="sessionId">Unique identifier for this session.</param>
        /// <returns>Initialized Double Ratchet session for the receiver.</returns>
        DoubleRatchetSession InitializeSessionAsReceiver(byte[] sharedKeyFromX3DH, KeyPair receiverInitialKeyPair, byte[] senderEphemeralKeyPublic, string sessionId);

        /// <summary>
        /// Encrypts a message using the Double Ratchet protocol.
        /// </summary>
        /// <param name="session">The current Double Ratchet session state.</param>
        /// <param name="message">The plaintext message to encrypt.</param>
        /// <param name="rotationStrategy">The key rotation strategy to use.</param>
        /// <returns>A tuple containing the updated session state and the encrypted message.</returns>
        (DoubleRatchetSession?, EncryptedMessage?) EncryptAsync(DoubleRatchetSession session, string message, KeyRotationStrategy rotationStrategy = KeyRotationStrategy.Standard);

        /// <summary>
        /// Decrypts a message using the Double Ratchet protocol.
        /// </summary>
        /// <param name="session">The current Double Ratchet session state.</param>
        /// <param name="encryptedMessage">The encrypted message to decrypt.</param>
        /// <returns>A tuple containing the updated session state and the decrypted message.</returns>
        (DoubleRatchetSession?, string?) DecryptAsync(DoubleRatchetSession session, EncryptedMessage encryptedMessage);
    }
}
