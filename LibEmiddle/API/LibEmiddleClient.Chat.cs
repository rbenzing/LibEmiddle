using System.Security.Cryptography;
using LibEmiddle.Abstractions;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;
using LibEmiddle.Domain.Exceptions;
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
    /// <inheritdoc/>
    public async Task<IChatSession> CreateChatSessionAsync(
        byte[] recipientIdentityKey,
        string? recipientUserId = null,
        ChatSessionOptions? options = null)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentNullException.ThrowIfNull(recipientIdentityKey);

        try
        {
            options ??= new ChatSessionOptions();
            if (!string.IsNullOrEmpty(recipientUserId))
            {
                options.RemoteUserId = recipientUserId;
            }

            // Try to create session using cached bundle first.  If the cache miss
            // throws (ArgumentException from GetOrCreateRecipientBundleAsync), attempt
            // a transport fetch.  Any fetch failure is wrapped as KeyNotFound.
            try
            {
                var session = await _sessionManager.CreateSessionAsync(recipientIdentityKey, options);
                if (session is IChatSession chatSession)
                {
                    LoggingManager.LogInformation(nameof(LibEmiddleClient),
                        $"Created chat session {session.SessionId} from local cache");
                    return chatSession;
                }
                throw new InvalidOperationException("Failed to create chat session");
            }
            catch (ArgumentException)
            {
                // No locally cached bundle — try to fetch from the transport.
                LoggingManager.LogInformation(nameof(LibEmiddleClient),
                    "No cached bundle found; attempting transport fetch for recipient key");
            }

            X3DHPublicBundle bundle;
            try
            {
                bundle = await FetchRecipientKeyBundleAsync(recipientIdentityKey);
            }
            catch (Exception fetchEx)
            {
                throw new LibEmiddleException(
                    "Cannot create chat session: no key bundle is available for the specified recipient. " +
                    "Ensure the recipient has uploaded their bundle, or supply the bundle directly " +
                    $"using the CreateChatSessionAsync(X3DHPublicBundle, ...) overload. Inner: {fetchEx.Message}",
                    LibEmiddleErrorCode.KeyNotFound,
                    fetchEx);
            }

            // Bundle has been fetched and cached by FetchRecipientKeyBundleAsync;
            // create the session using the identity key from the returned bundle.
            var fetchedSession = await _sessionManager.CreateSessionAsync(bundle.IdentityKey!, options);
            if (fetchedSession is IChatSession fetchedChatSession)
            {
                LoggingManager.LogInformation(nameof(LibEmiddleClient),
                    $"Created chat session {fetchedSession.SessionId} after transport fetch");
                return fetchedChatSession;
            }

            throw new InvalidOperationException("Failed to create chat session after transport bundle fetch");
        }
        catch (LibEmiddleException)
        {
            throw;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient), $"Failed to create chat session: {ex.Message}");
            throw;
        }
    }

    /// <inheritdoc/>
    public async Task<IChatSession> CreateChatSessionAsync(
        X3DHPublicBundle recipientBundle,
        string? recipientUserId = null,
        ChatSessionOptions? options = null)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentNullException.ThrowIfNull(recipientBundle);

        try
        {
            options ??= new ChatSessionOptions();
            if (!string.IsNullOrEmpty(recipientUserId))
            {
                options.RemoteUserId = recipientUserId;
            }

            // Cache the bundle locally so the session manager can resolve it by identity key.
            await _sessionManager.CacheRecipientBundleAsync(recipientBundle);

            var session = await _sessionManager.CreateSessionAsync(recipientBundle.IdentityKey!, options);
            if (session is IChatSession chatSession)
            {
                LoggingManager.LogInformation(nameof(LibEmiddleClient),
                    $"Created chat session {session.SessionId} from supplied bundle");
                return chatSession;
            }

            throw new InvalidOperationException("Failed to create chat session from supplied bundle");
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Failed to create chat session from bundle: {ex.Message}");
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
    /// When the message contains a <see cref="EncryptedMessage.SenderIdentityKey"/> the
    /// correct session is located in O(1) via the sender-key index maintained by
    /// <see cref="SessionManager"/>. For legacy messages without that field the method
    /// falls back to an O(n) scan over all active chat sessions.
    /// </summary>
    /// <param name="encryptedMessage">The encrypted message to process</param>
    /// <returns>The decrypted message content, or null if no matching session was found</returns>
    public async Task<string?> ProcessChatMessageAsync(EncryptedMessage encryptedMessage)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentNullException.ThrowIfNull(encryptedMessage);

        try
        {
            // --- O(1) fast path: message carries the sender's identity key ---
            if (encryptedMessage.SenderIdentityKey != null && encryptedMessage.SenderIdentityKey.Length > 0)
            {
                if (_sessionManager.TryGetSessionIdBySenderKey(encryptedMessage.SenderIdentityKey, out var sessionId) &&
                    sessionId != null)
                {
                    try
                    {
                        var session = await _sessionManager.GetSessionAsync(sessionId);
                        if (session is IChatSession chatSession)
                        {
                            var decrypted = await chatSession.DecryptAsync(encryptedMessage);
                            if (decrypted != null)
                            {
                                LoggingManager.LogInformation(nameof(LibEmiddleClient),
                                    $"Decrypted message via O(1) routing in chat session {sessionId}");
                                return decrypted;
                            }

                            // Decryption failed for the indexed session — reject without fallback
                            // to avoid silently trying unrelated sessions.
                            LoggingManager.LogWarning(nameof(LibEmiddleClient),
                                $"Decryption failed for message in indexed session {sessionId}; rejecting message");
                            return null;
                        }
                    }
                    catch (Exception ex)
                    {
                        LoggingManager.LogError(nameof(LibEmiddleClient),
                            $"Error decrypting message in indexed session {sessionId}: {ex.Message}");
                        return null;
                    }
                }

                // Sender key present but no index entry — unknown sender
                LoggingManager.LogWarning(nameof(LibEmiddleClient),
                    "Received message with SenderIdentityKey but no matching session found in index");
                return null;
            }

            // --- O(n) fallback path: legacy messages without SenderIdentityKey ---
            LoggingManager.LogDebug(nameof(LibEmiddleClient),
                "Message has no SenderIdentityKey; falling back to O(n) session scan");

            var sessionIds = await _sessionManager.ListSessionsAsync();

            foreach (var sid in sessionIds)
            {
                if (sid != null && sid.StartsWith("chat-"))
                {
                    ISession? session = null;
                    try
                    {
                        session = await _sessionManager.GetSessionAsync(sid);
                    }
                    catch (Exception ex)
                    {
                        LoggingManager.LogWarning(nameof(LibEmiddleClient),
                            $"Could not load session {sid} during fallback scan: {ex.Message}");
                        continue;
                    }

                    if (session is IChatSession chatSession)
                    {
                        string? decryptedMessage = null;
                        try
                        {
                            decryptedMessage = await chatSession.DecryptAsync(encryptedMessage);
                        }
                        catch (Exception ex)
                        {
                            LoggingManager.LogDebug(nameof(LibEmiddleClient),
                                $"Decryption attempt failed for session {sid}: {ex.Message}");
                            continue;
                        }

                        if (decryptedMessage != null)
                        {
                            LoggingManager.LogInformation(nameof(LibEmiddleClient),
                                $"Decrypted message via O(n) fallback in chat session {sid}");
                            return decryptedMessage;
                        }
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
