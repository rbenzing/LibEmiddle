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
    /// Creates a new group chat session.
    /// </summary>
    /// <param name="groupId">Unique identifier for the group</param>
    /// <param name="groupName">Display name for the group</param>
    /// <param name="options">Optional group session configuration</param>
    /// <returns>The created group session</returns>
    public async Task<IGroupSession> CreateGroupAsync(
        string groupId,
        string groupName,
        GroupSessionOptions? options = null)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentException.ThrowIfNullOrEmpty(groupId);
        ArgumentException.ThrowIfNullOrEmpty(groupName);

        try
        {
            options ??= new GroupSessionOptions
            {
                GroupId = groupId,
                GroupName = groupName,
                RotationStrategy = KeyRotationStrategy.Standard
            };
            options.GroupId   = groupId;
            options.GroupName = groupName;

            // Route through SessionManager so persistence, caching, and logging stay consistent
            var session = await _sessionManager.CreateSessionAsync(_identityKeyPair.PublicKey!, options);
            if (session is not IGroupSession groupSession)
                throw new InvalidOperationException("SessionManager did not return an IGroupSession");

            LoggingManager.LogInformation(nameof(LibEmiddleClient),
                $"Created group session {session.SessionId} for group {groupId}");

            return groupSession;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Failed to create group {groupId}: {ex.Message}");
            throw;
        }
    }

    /// <summary>
    /// Gets an existing group session by group ID.
    /// </summary>
    /// <param name="groupId">The group identifier</param>
    /// <returns>The group session if found</returns>
    public async Task<IGroupSession> GetGroupAsync(string groupId)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentException.ThrowIfNullOrEmpty(groupId);

        try
        {
            // List all sessions and find the group session
            var sessionIds = await _sessionManager.ListSessionsAsync();

            foreach (var sessionId in sessionIds)
            {
                if (sessionId != null && sessionId.StartsWith($"group-{groupId}-"))
                {
                    var session = await _sessionManager.GetSessionAsync(sessionId);
                    if (session is IGroupSession groupSession && groupSession.GroupId == groupId)
                    {
                        return groupSession;
                    }
                }
            }

            throw new KeyNotFoundException($"Group {groupId} not found");
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Failed to get group {groupId}: {ex.Message}");
            throw;
        }
    }

    /// <summary>
    /// Joins an existing group using a sender key distribution message.
    /// </summary>
    /// <param name="distribution">The sender key distribution message</param>
    /// <param name="rotationStrategy">Optional key rotation strategy</param>
    /// <returns>The joined group session</returns>
    public async Task<IGroupSession> JoinGroupAsync(
        SenderKeyDistributionMessage distribution,
        KeyRotationStrategy rotationStrategy = KeyRotationStrategy.Standard)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentNullException.ThrowIfNull(distribution);
        ArgumentException.ThrowIfNullOrEmpty(distribution.GroupId);

        try
        {
            // Check if we're already in this group
            try
            {
                var existingSession = await GetGroupAsync(distribution.GroupId);
                if (existingSession != null)
                {
                    // Process the distribution message to update our keys
                    if (existingSession is GroupSession groupSession)
                    {
                        groupSession.ProcessDistributionMessage(distribution);
                        await _sessionManager.SaveSessionAsync(existingSession);
                    }
                    return existingSession;
                }
            }
            catch (KeyNotFoundException)
            {
                // Group doesn't exist, we'll create it
            }

            // Create a new group session
            var newGroupSession = new GroupSession(
                distribution.GroupId,
                distribution.GroupName ?? "Untitled",
                _identityKeyPair,
                rotationStrategy);

            // Add ourselves as a member first
            await newGroupSession.AddMemberAsync(_identityKeyPair.PublicKey);

            // Add the sender of the distribution message as a member (they're likely the group creator)
            if (distribution.SenderIdentityKey != null &&
                !CryptographicOperations.FixedTimeEquals(distribution.SenderIdentityKey, _identityKeyPair.PublicKey))
            {
                await newGroupSession.AddMemberAsync(distribution.SenderIdentityKey);
            }

            // Process the distribution message
            if (!newGroupSession.ProcessDistributionMessage(distribution))
            {
                throw new InvalidOperationException("Failed to process distribution message");
            }

            // Activate the session
            await newGroupSession.ActivateAsync();

            // Save the session
            await _sessionManager.SaveSessionAsync(newGroupSession);

            LoggingManager.LogInformation(nameof(LibEmiddleClient),
                $"Joined group {distribution.GroupId}");

            return newGroupSession;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Failed to join group {distribution.GroupId}: {ex.Message}");
            throw;
        }
    }

    /// <summary>
    /// Leaves a group chat.
    /// </summary>
    /// <param name="groupId">The group identifier</param>
    /// <returns>True if the group was left successfully</returns>
    public async Task<bool> LeaveGroupAsync(string groupId)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentException.ThrowIfNullOrEmpty(groupId);

        try
        {
            var groupSession = await GetGroupAsync(groupId);

            // Terminate the session
            await groupSession.TerminateAsync();

            // Delete the session
            await _sessionManager.DeleteSessionAsync(groupSession.SessionId);

            LoggingManager.LogInformation(nameof(LibEmiddleClient), $"Left group {groupId}");
            return true;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Failed to leave group {groupId}: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Sends a message to a group.
    /// </summary>
    /// <param name="groupId">The group identifier</param>
    /// <param name="message">The message to send</param>
    /// <returns>The encrypted message ready for transport</returns>
    public async Task<EncryptedGroupMessage?> SendGroupMessageAsync(string groupId, string message)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentException.ThrowIfNullOrEmpty(groupId);
        ArgumentException.ThrowIfNullOrEmpty(message);

        try
        {
            var groupSession = await GetGroupAsync(groupId);
            var encryptedMessage = await groupSession.EncryptMessageAsync(message);

            if (encryptedMessage != null)
            {
                LoggingManager.LogInformation(nameof(LibEmiddleClient),
                    $"Encrypted message for group {groupId}");
            }

            return encryptedMessage;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Failed to send message to group {groupId}: {ex.Message}");
            throw;
        }
    }

    /// <summary>
    /// Processes a received encrypted group message.
    /// </summary>
    /// <param name="encryptedMessage">The encrypted message to process</param>
    /// <returns>The decrypted message content</returns>
    public async Task<string?> ProcessGroupMessageAsync(EncryptedGroupMessage encryptedMessage)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentNullException.ThrowIfNull(encryptedMessage);

        try
        {
            var groupSession = await GetGroupAsync(encryptedMessage.GroupId);
            var decryptedMessage = await groupSession.DecryptMessageAsync(encryptedMessage);

            if (decryptedMessage != null)
            {
                LoggingManager.LogInformation(nameof(LibEmiddleClient),
                    $"Decrypted message from group {encryptedMessage.GroupId}");
            }

            return decryptedMessage;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Failed to process group message: {ex.Message}");
            return null;
        }
    }

    /// <summary>
    /// Gets information about a group session.
    /// </summary>
    /// <param name="groupId">The group identifier</param>
    /// <returns>Group session information or null if not found</returns>
    public async Task<IGroupSession?> GetGroupInfoAsync(string groupId)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentException.ThrowIfNullOrEmpty(groupId);

        try
        {
            var groupSession = await GetGroupAsync(groupId);
            LoggingManager.LogDebug(nameof(LibEmiddleClient), $"Retrieved group info for {groupId}");
            return groupSession;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Failed to get group info for {groupId}: {ex.Message}");
            return null;
        }
    }
}
