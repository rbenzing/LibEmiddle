using LibEmiddle.Domain;

namespace LibEmiddle.Abstractions
{
    /// <summary>
    /// Defines a manager for cryptographic communication sessions, providing operations for
    /// creating, retrieving, saving, and deleting sessions for both individual and group communications.
    /// </summary>
    public interface ISessionManager
    {
        /// <summary>
        /// Creates a new cryptographic session with the specified recipient.
        /// </summary>
        /// <param name="recipientKey">The recipient's public key or identity key.</param>
        /// <param name="options">Optional configuration parameters for the session, such as ChatSessionOptions 
        /// for individual chats or GroupSessionOptions for group chats.</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains the created session.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="recipientKey"/> is null.</exception>
        /// <exception cref="ArgumentException">Thrown when <paramref name="recipientKey"/> is invalid or when session creation fails.</exception>
        Task<ISession> CreateSessionAsync(byte[] recipientKey, object? options = null);

        /// <summary>
        /// Retrieves an existing session by its unique identifier.
        /// </summary>
        /// <param name="sessionId">The unique identifier of the session to retrieve.</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains the retrieved session.</returns>
        /// <exception cref="ArgumentException">Thrown when <paramref name="sessionId"/> is null or empty.</exception>
        /// <exception cref="KeyNotFoundException">Thrown when no session with the specified ID exists.</exception>
        Task<ISession> GetSessionAsync(string sessionId);

        /// <summary>
        /// Saves a session's state to persistent storage.
        /// </summary>
        /// <param name="session">The session to save.</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains a boolean indicating whether the save operation succeeded.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="session"/> is null.</exception>
        Task<bool> SaveSessionAsync(ISession session);

        /// <summary>
        /// Deletes a session from persistent storage.
        /// </summary>
        /// <param name="sessionId">The unique identifier of the session to delete.</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains a boolean indicating whether the deletion succeeded.</returns>
        /// <exception cref="ArgumentException">Thrown when <paramref name="sessionId"/> is null or empty.</exception>
        Task<bool> DeleteSessionAsync(string sessionId);

        /// <summary>
        /// Creates a new direct messaging session with another user.
        /// </summary>
        /// <param name="recipientIdentityKey">The recipient's identity key.</param>
        /// <param name="recipientUserId">Optional user ID for the recipient.</param>
        /// <returns>A fully initialized chat session.</returns>
        Task<IChatSession> CreateDirectMessageSessionAsync(byte[] recipientIdentityKey, string recipientUserId);

        /// <summary>
        /// Processes an incoming X3DH key exchange message and creates a new chat session.
        /// </summary>
        /// <param name="mailboxMessage">The mailbox message containing X3DH data.</param>
        /// <param name="recipientBundle">The local recipient's key bundle.</param>
        /// <param name="options">Optional chat session options.</param>
        /// <returns>The created chat session.</returns>
        Task<IChatSession?> ProcessKeyExchangeMessageAsync(MailboxMessage mailboxMessage, X3DHKeyBundle recipientBundle, ChatSessionOptions? options = null);
    }
}