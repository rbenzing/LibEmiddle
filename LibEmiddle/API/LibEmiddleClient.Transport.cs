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
    /// Starts listening for incoming messages.
    /// </summary>
    /// <param name="pollingInterval">Polling interval in milliseconds (minimum 1000ms)</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>True if listening started successfully</returns>
    public async Task<bool> StartListeningAsync(int pollingInterval = 5000, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        EnsureInitialized();

        if (_isListening)
        {
            LoggingManager.LogWarning(nameof(LibEmiddleClient), "Already listening for messages");
            return true;
        }

        // Validate polling interval for security (prevent resource exhaustion)
        if (pollingInterval < 1000)
        {
            LoggingManager.LogWarning(nameof(LibEmiddleClient), "Polling interval too low, setting to minimum 1000ms");
            pollingInterval = 1000;
        }

        try
        {
            await _transport.StartListeningAsync(_identityKeyPair.PublicKey, pollingInterval, cancellationToken);
            _isListening = true;
            LoggingManager.LogInformation(nameof(LibEmiddleClient), $"Started listening for messages with {pollingInterval}ms interval");
            return true;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient), $"Failed to start listening: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Stops listening for incoming messages.
    /// </summary>
    /// <returns>True if listening stopped successfully</returns>
    public async Task<bool> StopListeningAsync()
    {
        ThrowIfDisposed();

        if (!_isListening)
        {
            return true;
        }

        try
        {
            await _transport.StopListeningAsync();
            _isListening = false;
            LoggingManager.LogInformation(nameof(LibEmiddleClient), "Stopped listening for messages");
            return true;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient), $"Failed to stop listening: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Marks a message as read and optionally sends a read receipt.
    /// </summary>
    /// <param name="messageId">The message ID to mark as read</param>
    /// <returns>True if the message was marked as read successfully</returns>
    public async Task<bool> MarkMessageAsReadAsync(string messageId)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentException.ThrowIfNullOrEmpty(messageId);

        try
        {
            var result = await _mailboxManager.MarkMessageAsReadAsync(messageId);
            if (result)
            {
                LoggingManager.LogDebug(nameof(LibEmiddleClient), $"Marked message {messageId} as read");
            }
            return result;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient), $"Failed to mark message as read: {ex.Message}");
            return false;
        }
    }
}
