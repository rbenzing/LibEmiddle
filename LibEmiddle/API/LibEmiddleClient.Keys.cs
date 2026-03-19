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
    /// Creates a local X3DH key bundle for receiving messages.
    /// </summary>
    /// <param name="numOneTimeKeys">Number of one-time prekeys to generate</param>
    /// <returns>A complete X3DH key bundle</returns>
    public async Task<X3DHKeyBundle> CreateLocalKeyBundleAsync(int numOneTimeKeys = 10)
    {
        ThrowIfDisposed();
        EnsureInitialized();

        try
        {
            return await _sessionManager.CreateLocalKeyBundleAsync(numOneTimeKeys);
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Failed to create local key bundle: {ex.Message}");
            throw;
        }
    }

    /// <summary>
    /// Gets the public components of the local key bundle that can be shared.
    /// </summary>
    /// <param name="numOneTimeKeys">Number of one-time prekeys to include</param>
    /// <returns>A public key bundle that can be safely shared</returns>
    public async Task<X3DHPublicBundle> GetPublicKeyBundleAsync(int numOneTimeKeys = 10)
    {
        ThrowIfDisposed();
        EnsureInitialized();

        try
        {
            var keyBundle = await CreateLocalKeyBundleAsync(numOneTimeKeys);
            return keyBundle.ToPublicBundle();
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Failed to get public key bundle: {ex.Message}");
            throw;
        }
    }
}
