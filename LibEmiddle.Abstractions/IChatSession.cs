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

        // --- v2.5 Enhanced Methods (Optional - requires V25Features.EnableAsyncMessageStreams) ---

        /// <summary>
        /// Gets an async stream of incoming messages (v2.5).
        /// This runs in parallel with the MessageReceived event.
        /// Requires V25Features.EnableAsyncMessageStreams = true.
        /// </summary>
        /// <param name="cancellationToken">Token to cancel the stream.</param>
        /// <returns>Async enumerable of message received events.</returns>
        IAsyncEnumerable<MessageReceivedEventArgs> GetMessageStreamAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets an async stream of incoming messages with optional filtering (v2.5).
        /// This runs in parallel with the MessageReceived event.
        /// Requires V25Features.EnableAsyncMessageStreams = true.
        /// </summary>
        /// <param name="messageFilter">Optional filter predicate for messages.</param>
        /// <param name="cancellationToken">Token to cancel the stream.</param>
        /// <returns>Async enumerable of filtered message received events.</returns>
        IAsyncEnumerable<MessageReceivedEventArgs> GetFilteredMessageStreamAsync(
            Func<MessageReceivedEventArgs, bool>? messageFilter = null,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Sends a message with optional batching (v2.5).
        /// If batching is enabled, the message may be queued for later transmission.
        /// Requires V25Features.EnableMessageBatching = true.
        /// </summary>
        /// <param name="message">The plaintext message to send.</param>
        /// <param name="priority">Priority level for batching.</param>
        /// <param name="forceSend">If true, bypasses batching and sends immediately.</param>
        /// <returns>True if the message was sent or queued successfully.</returns>
        Task<bool> SendMessageAsync(string message, MessagePriority priority, bool forceSend = false);

        /// <summary>
        /// Gets the current message batcher if batching is enabled (v2.5).
        /// Requires V25Features.EnableMessageBatching = true.
        /// </summary>
        /// <returns>The message batcher, or null if batching is not enabled.</returns>
        IMessageBatcher? GetMessageBatcher();

        /// <summary>
        /// Forces any pending batched messages to be sent immediately (v2.5).
        /// Requires V25Features.EnableMessageBatching = true.
        /// </summary>
        /// <returns>The number of messages flushed.</returns>
        Task<int> FlushPendingMessagesAsync();
    }
}