using System.Security.Cryptography;
using LibEmiddle.Abstractions;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;
using LibEmiddle.KeyManagement;
using LibEmiddle.Messaging.Group;
using LibEmiddle.MultiDevice;
using LibEmiddle.Protocol;
using LibEmiddle.Sessions;
using LibEmiddle.Messaging.Transport;
using LibEmiddle.Messaging.Chat;
using LibEmiddle.Diagnostics;

namespace LibEmiddle.API;

public sealed partial class LibEmiddleClient
{
    /// <summary>
    /// Creates a new chat session with the specified recipient.
    /// </summary>
    /// <param name="recipientPublicKey">The recipient's public key</param>
    /// <param name="recipientUserId">Optional user identifier for the recipient</param>
    /// <param name="options">Optional chat session configuration</param>
    /// <returns>The created chat session</returns>
    public async Task<IChatSession> CreateChatSessionAsync(
        byte[] recipientPublicKey,
        string? recipientUserId = null,
        ChatSessionOptions? options = null)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentNullException.ThrowIfNull(recipientPublicKey);

        try
        {
            options ??= new ChatSessionOptions();
            if (!string.IsNullOrEmpty(recipientUserId))
            {
                options.RemoteUserId = recipientUserId;
            }

            var session = await _sessionManager.CreateSessionAsync(recipientPublicKey, options);
            if (session is IChatSession chatSession)
            {
                LoggingManager.LogInformation(nameof(LibEmiddleClient), $"Created chat session {session.SessionId}");
                return chatSession;
            }

            throw new InvalidOperationException("Failed to create chat session");
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient), $"Failed to create chat session: {ex.Message}");
            throw;
        }
    }

    /// <summary>
    /// Gets an existing chat session by ID.
    /// </summary>
    /// <param name="sessionId">The session identifier</param>
    /// <returns>The chat session if found</returns>
    public async Task<IChatSession> GetChatSessionAsync(string sessionId)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentException.ThrowIfNullOrEmpty(sessionId);

        try
        {
            var session = await _sessionManager.GetSessionAsync(sessionId);
            if (session is IChatSession chatSession)
            {
                return chatSession;
            }

            throw new InvalidOperationException($"Session {sessionId} is not a chat session");
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient), $"Failed to get chat session {sessionId}: {ex.Message}");
            throw;
        }
    }

    /// <summary>
    /// Processes an incoming key exchange message to establish a chat session.
    /// </summary>
    /// <param name="mailboxMessage">The incoming mailbox message</param>
    /// <param name="options">Optional chat session configuration</param>
    /// <returns>The established chat session if successful</returns>
    public async Task<IChatSession?> ProcessKeyExchangeMessageAsync(
        MailboxMessage mailboxMessage,
        ChatSessionOptions? options = null)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentNullException.ThrowIfNull(mailboxMessage);

        try
        {
            // Create a local key bundle for the exchange
            var keyBundle = await CreateLocalKeyBundleAsync();

            var session = await _sessionManager.ProcessKeyExchangeMessageAsync(
                mailboxMessage, keyBundle, options);

            if (session != null)
            {
                LoggingManager.LogInformation(nameof(LibEmiddleClient),
                    $"Processed key exchange and created session {session.SessionId}");
            }

            return session;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Failed to process key exchange message: {ex.Message}");
            return null;
        }
    }

    /// <summary>
    /// Sends a message to an individual chat session.
    /// </summary>
    /// <param name="sessionId">The chat session identifier</param>
    /// <param name="message">The message to send</param>
    /// <returns>The encrypted message ready for transport</returns>
    public async Task<EncryptedMessage?> SendChatMessageAsync(string sessionId, string message)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentException.ThrowIfNullOrEmpty(sessionId);
        ArgumentException.ThrowIfNullOrEmpty(message);

        try
        {
            var chatSession = await GetChatSessionAsync(sessionId);
            var encryptedMessage = await chatSession.EncryptAsync(message);

            if (encryptedMessage != null)
            {
                LoggingManager.LogInformation(nameof(LibEmiddleClient),
                    $"Encrypted message for chat session {sessionId}");
            }

            return encryptedMessage;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Failed to send message to chat session {sessionId}: {ex.Message}");
            throw;
        }
    }

    /// <summary>
    /// Sends a message to an individual chat by recipient public key.
    /// Creates a session if one doesn't exist.
    /// </summary>
    /// <param name="recipientPublicKey">The recipient's public key</param>
    /// <param name="message">The message to send</param>
    /// <param name="recipientUserId">Optional user identifier for the recipient</param>
    /// <returns>The encrypted message ready for transport</returns>
    public async Task<EncryptedMessage?> SendChatMessageAsync(
        byte[] recipientPublicKey,
        string message,
        string? recipientUserId = null)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentNullException.ThrowIfNull(recipientPublicKey);
        ArgumentException.ThrowIfNullOrEmpty(message);

        try
        {
            // SessionManager maintains the active session cache; ask it directly.
            // GetOrCreateChatSessionAsync locates an existing session for the recipient
            // or creates one transparently, eliminating the need for a fragile key-based search.
            var chatSession = await _sessionManager.GetOrCreateChatSessionAsync(
                recipientPublicKey, recipientUserId);

            var encryptedMessage = await chatSession.EncryptAsync(message);

            if (encryptedMessage != null)
            {
                LoggingManager.LogInformation(nameof(LibEmiddleClient),
                    $"Encrypted message for recipient {Convert.ToBase64String(recipientPublicKey)[..8]}");
            }

            return encryptedMessage;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Failed to send message to recipient: {ex.Message}");
            throw;
        }
    }

    /// <summary>
    /// Processes a received encrypted chat message.
    /// </summary>
    /// <param name="encryptedMessage">The encrypted message to process</param>
    /// <returns>The decrypted message content</returns>
    public async Task<string?> ProcessChatMessageAsync(EncryptedMessage encryptedMessage)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentNullException.ThrowIfNull(encryptedMessage);

        try
        {
            // Find the appropriate chat session
            var sessionIds = await _sessionManager.ListSessionsAsync();

            foreach (var sessionId in sessionIds)
            {
                if (sessionId != null && sessionId.StartsWith("chat-"))
                {
                    try
                    {
                        var session = await _sessionManager.GetSessionAsync(sessionId);
                        if (session is IChatSession chatSession)
                        {
                            // Try to decrypt with this session
                            var decryptedMessage = await chatSession.DecryptAsync(encryptedMessage);
                            if (decryptedMessage != null)
                            {
                                LoggingManager.LogInformation(nameof(LibEmiddleClient),
                                    $"Decrypted message in chat session {sessionId}");
                                return decryptedMessage;
                            }
                        }
                    }
                    catch
                    {
                        // Continue trying other sessions if this one fails
                        continue;
                    }
                }
            }

            LoggingManager.LogWarning(nameof(LibEmiddleClient),
                "Could not decrypt message with any existing chat session");
            return null;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Failed to process chat message: {ex.Message}");
            return null;
        }
    }

    /// <summary>
    /// Gets message history for a chat session with pagination support.
    /// </summary>
    /// <param name="sessionId">The session ID</param>
    /// <param name="limit">Maximum number of messages to retrieve (default: 50, max: 1000)</param>
    /// <param name="startIndex">Starting index for pagination (default: 0)</param>
    /// <returns>Collection of message records</returns>
    public async Task<IReadOnlyCollection<MessageRecord>?> GetChatMessageHistoryAsync(
        string sessionId,
        int limit = 50,
        int startIndex = 0)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentException.ThrowIfNullOrEmpty(sessionId);

        // Security: Limit the maximum number of messages that can be retrieved at once
        if (limit <= 0 || limit > 1000)
        {
            limit = Math.Min(Math.Max(limit, 1), 1000);
            LoggingManager.LogWarning(nameof(LibEmiddleClient), $"Message history limit adjusted to {limit}");
        }

        if (startIndex < 0)
        {
            startIndex = 0;
        }

        try
        {
            var chatSession = await GetChatSessionAsync(sessionId);
            var history = chatSession.GetMessageHistory(limit, startIndex);
            LoggingManager.LogDebug(nameof(LibEmiddleClient),
                $"Retrieved {history.Count} messages from session {sessionId}");
            return history;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Failed to get message history for session {sessionId}: {ex.Message}");
            return null;
        }
    }

    /// <summary>
    /// Gets the message count for a chat session.
    /// </summary>
    /// <param name="sessionId">The session ID</param>
    /// <returns>Number of messages in the session, or -1 if session not found</returns>
    public async Task<int> GetChatMessageCountAsync(string sessionId)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentException.ThrowIfNullOrEmpty(sessionId);

        try
        {
            var chatSession = await GetChatSessionAsync(sessionId);
            var count = chatSession.GetMessageCount();
            LoggingManager.LogDebug(nameof(LibEmiddleClient),
                $"Session {sessionId} has {count} messages");
            return count;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Failed to get message count for session {sessionId}: {ex.Message}");
            return -1;
        }
    }

    /// <summary>
    /// Clears message history for a chat session.
    /// </summary>
    /// <param name="sessionId">The session ID</param>
    /// <returns>Number of messages cleared, or -1 if failed</returns>
    public async Task<int> ClearChatMessageHistoryAsync(string sessionId)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentException.ThrowIfNullOrEmpty(sessionId);

        try
        {
            var chatSession = await GetChatSessionAsync(sessionId);
            var clearedCount = chatSession.ClearMessageHistory();
            LoggingManager.LogInformation(nameof(LibEmiddleClient),
                $"Cleared {clearedCount} messages from session {sessionId}");
            return clearedCount;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Failed to clear message history for session {sessionId}: {ex.Message}");
            return -1;
        }
    }
}
