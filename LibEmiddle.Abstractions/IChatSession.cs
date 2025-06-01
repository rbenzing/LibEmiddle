using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;

namespace LibEmiddle.Abstractions
{
    /// <summary>
    /// Interface for a secure chat session between two parties.
    /// </summary>
    public interface IChatSession : ISession
    {
        /// <summary>
        /// The remote party's public key.
        /// </summary>
        byte[] RemotePublicKey { get; }

        /// <summary>
        /// The local party's public key.
        /// </summary>
        byte[] LocalPublicKey { get; }

        /// <summary>
        /// The key rotation strategy for the session.
        /// </summary>
        KeyRotationStrategy RotationStrategy { get; set; }

        /// <summary>
        /// Event that fires when a new message is received.
        /// </summary>
        event EventHandler<MessageReceivedEventArgs>? MessageReceived;

        /// <summary>
        /// Sends a message to the remote party.
        /// </summary>
        /// <param name="message">The plaintext message to send.</param>
        /// <returns>True if the message was sent successfully, otherwise false.</returns>
        Task<bool> SendMessageAsync(string message);

        /// <summary>
        /// Async Encrypt a message
        /// </summary>
        /// <param name="message"></param>
        /// <returns></returns>
        Task<EncryptedMessage?> EncryptAsync(string message);

        /// <summary>
        /// Async Decrypt a message
        /// </summary>
        /// <param name="encryptedMessage"></param>
        /// <returns></returns>
        Task<string?> DecryptAsync(EncryptedMessage encryptedMessage);

        /// <summary>
        /// Processes an incoming encrypted message.
        /// </summary>
        /// <param name="encryptedMessage">The encrypted message to process.</param>
        /// <returns>The decrypted message, or null if decryption failed.</returns>
        Task<string?> ProcessIncomingMessageAsync(EncryptedMessage encryptedMessage);

        /// <summary>
        /// Returns the message history for this session.
        /// </summary>
        /// <param name="limit">Maximum number of messages to return.</param>
        /// <param name="startIndex">Index to start from.</param>
        /// <returns>Collection of message records.</returns>
        IReadOnlyCollection<MessageRecord> GetMessageHistory(int limit = 100, int startIndex = 0);

        /// <summary>
        /// Gets the count of messages in the history.
        /// </summary>
        /// <returns>Number of messages.</returns>
        int GetMessageCount();

        /// <summary>
        /// Clears the message history.
        /// </summary>
        /// <returns>Number of messages cleared.</returns>
        int ClearMessageHistory();

        /// <summary>
        /// Sets a metadata value.
        /// </summary>
        /// <param name="key">The metadata key.</param>
        /// <param name="value">The metadata value.</param>
        void SetMetadata(string key, string value);

        /// <summary>
        /// Gets the underlying Double Ratchet session state.
        /// </summary>
        /// <returns>The current crypto session state.</returns>
        DoubleRatchetSession GetCryptoSessionState();

        /// <summary>
        /// Checks if the session is valid and not terminated or disposed.
        /// Performs basic checks on the crypto session state.
        /// </summary>
        bool IsValid();
    }
}