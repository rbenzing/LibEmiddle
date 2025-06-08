using LibEmiddle.Domain;

namespace LibEmiddle.Abstractions;

/// <summary>
/// Defines the contract for centralized management of both individual and group chat sessions.
/// Provides session lifecycle management, persistence, and protocol integration capabilities.
/// </summary>
public interface ISessionManager : IDisposable
{
    /// <summary>
    /// Creates a new session (chat or group) based on the provided options.
    /// </summary>
    /// <param name="recipientKey">The recipient's public key or key bundle data.</param>
    /// <param name="options">Session creation options. Use <see cref="ChatSessionOptions"/> for chat sessions 
    /// or <see cref="GroupSessionOptions"/> for group sessions.</param>
    /// <returns>A task that represents the asynchronous operation. The task result contains the created session.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="recipientKey"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when the recipient key format is invalid.</exception>
    /// <exception cref="InvalidOperationException">Thrown when session creation fails.</exception>
    Task<ISession> CreateSessionAsync(byte[] recipientKey, object? options = null);

    /// <summary>
    /// Retrieves an existing session by its unique identifier.
    /// First checks in-memory cache, then attempts to load from persistent storage.
    /// </summary>
    /// <param name="sessionId">The unique identifier of the session to retrieve.</param>
    /// <returns>A task that represents the asynchronous operation. The task result contains the requested session.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="sessionId"/> is null or empty.</exception>
    /// <exception cref="KeyNotFoundException">Thrown when the session is not found in cache or storage.</exception>
    Task<ISession> GetSessionAsync(string sessionId);

    /// <summary>
    /// Saves a session to both in-memory cache and persistent storage.
    /// </summary>
    /// <param name="session">The session to save.</param>
    /// <returns>A task that represents the asynchronous operation. The task result indicates whether the save operation was successful.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="session"/> is null.</exception>
    Task<bool> SaveSessionAsync(ISession session);

    /// <summary>
    /// Deletes a session from both in-memory cache and persistent storage.
    /// </summary>
    /// <param name="sessionId">The unique identifier of the session to delete.</param>
    /// <returns>A task that represents the asynchronous operation. The task result indicates whether the deletion was successful.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="sessionId"/> is null or empty.</exception>
    Task<bool> DeleteSessionAsync(string sessionId);

    /// <summary>
    /// Lists all available session identifiers from persistent storage.
    /// </summary>
    /// <returns>A task that represents the asynchronous operation. The task result contains an array of session identifiers.</returns>
    Task<string?[]> ListSessionsAsync();

    /// <summary>
    /// Creates a direct message (chat) session with a specific recipient.
    /// This is a convenience method that wraps <see cref="CreateSessionAsync"/> with chat-specific options.
    /// </summary>
    /// <param name="recipientIdentityKey">The recipient's identity public key.</param>
    /// <param name="recipientUserId">The recipient's user identifier.</param>
    /// <returns>A task that represents the asynchronous operation. The task result contains the created chat session.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="recipientIdentityKey"/> or <paramref name="recipientUserId"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when the recipient identity key format is invalid.</exception>
    Task<IChatSession> CreateDirectMessageSessionAsync(byte[] recipientIdentityKey, string recipientUserId);

    /// <summary>
    /// Processes an incoming key exchange message to establish a new chat session.
    /// This method handles the receiver side of the X3DH key exchange protocol.
    /// </summary>
    /// <param name="mailboxMessage">The incoming mailbox message containing the key exchange data.</param>
    /// <param name="recipientBundle">The local X3DH key bundle for processing the exchange.</param>
    /// <param name="options">Optional chat session configuration options.</param>
    /// <returns>A task that represents the asynchronous operation. The task result contains the created chat session, or null if processing failed.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="mailboxMessage"/> or <paramref name="recipientBundle"/> is null.</exception>
    /// <remarks>
    /// This method extracts X3DH initial message data from the mailbox message, establishes a Double Ratchet session,
    /// and creates a new chat session with the sender. Returns null if the key exchange data is invalid or malformed.
    /// </remarks>
    Task<IChatSession?> ProcessKeyExchangeMessageAsync(
        MailboxMessage mailboxMessage,
        X3DHKeyBundle recipientBundle,
        ChatSessionOptions? options = null);

    /// <summary>
    /// Creates a local X3DH key bundle for receiving messages.
    /// This bundle contains the identity key, signed prekey, and one-time prekeys needed for the X3DH protocol.
    /// </summary>
    /// <param name="numOneTimeKeys">The number of one-time prekeys to generate. Defaults to 10.</param>
    /// <returns>A task that represents the asynchronous operation. The task result contains the complete X3DH key bundle.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="numOneTimeKeys"/> is less than 1.</exception>
    /// <exception cref="InvalidOperationException">Thrown when key bundle creation fails.</exception>
    /// <remarks>
    /// The generated key bundle should be uploaded to a key server or distributed through other means
    /// to allow other parties to initiate secure communication sessions.
    /// </remarks>
    Task<X3DHKeyBundle> CreateLocalKeyBundleAsync(int numOneTimeKeys = 10);
}