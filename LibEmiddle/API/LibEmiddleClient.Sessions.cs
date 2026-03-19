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
    /// Lists all active session IDs.
    /// </summary>
    /// <returns>Array of session IDs</returns>
    public async Task<string?[]> ListSessionsAsync()
    {
        ThrowIfDisposed();
        EnsureInitialized();

        try
        {
            return await _sessionManager.ListSessionsAsync();
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Failed to list sessions: {ex.Message}");
            throw;
        }
    }

    /// <summary>
    /// Deletes a session and all associated data.
    /// </summary>
    /// <param name="sessionId">The session ID to delete</param>
    /// <returns>True if the session was deleted successfully</returns>
    public async Task<bool> DeleteSessionAsync(string sessionId)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentException.ThrowIfNullOrEmpty(sessionId);

        try
        {
            var result = await _sessionManager.DeleteSessionAsync(sessionId);
            if (result)
            {
                LoggingManager.LogInformation(nameof(LibEmiddleClient), $"Deleted session {sessionId}");
            }
            return result;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Failed to delete session {sessionId}: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Gets detailed information about a session.
    /// </summary>
    /// <param name="sessionId">The session ID</param>
    /// <returns>Session information or null if not found</returns>
    public async Task<ISession?> GetSessionInfoAsync(string sessionId)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentException.ThrowIfNullOrEmpty(sessionId);

        try
        {
            var session = await _sessionManager.GetSessionAsync(sessionId);
            LoggingManager.LogDebug(nameof(LibEmiddleClient), $"Retrieved session info for {sessionId}");
            return session;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Failed to get session info for {sessionId}: {ex.Message}");
            return null;
        }
    }
}
