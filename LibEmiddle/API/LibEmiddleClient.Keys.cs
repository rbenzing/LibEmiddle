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

    /// <inheritdoc/>
    /// <exception cref="NotSupportedException">
    /// Thrown when the configured transport does not implement <see cref="IKeyBundleTransport"/>.
    /// </exception>
    public async Task UploadKeyBundleAsync()
    {
        ThrowIfDisposed();
        EnsureInitialized();

        if (_transport is not IKeyBundleTransport keyBundleTransport)
        {
            throw new NotSupportedException(
                "The configured transport does not support key bundle upload. " +
                "The transport must implement IKeyBundleTransport.");
        }

        try
        {
            var publicBundle = await GetPublicKeyBundleAsync();
            await keyBundleTransport.UploadKeyBundleAsync(publicBundle);
            LoggingManager.LogInformation(nameof(LibEmiddleClient), "Key bundle uploaded to transport");
        }
        catch (NotSupportedException)
        {
            throw;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Failed to upload key bundle: {ex.Message}");
            throw;
        }
    }

    /// <inheritdoc/>
    /// <exception cref="NotSupportedException">
    /// Thrown when the configured transport does not implement <see cref="IKeyBundleTransport"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when no bundle is found for the given identity key.
    /// </exception>
    public async Task<X3DHPublicBundle> FetchRecipientKeyBundleAsync(byte[] recipientIdentityKey)
    {
        ThrowIfDisposed();
        EnsureInitialized();
        ArgumentNullException.ThrowIfNull(recipientIdentityKey);

        if (_transport is not IKeyBundleTransport keyBundleTransport)
        {
            throw new NotSupportedException(
                "The configured transport does not support key bundle fetching. " +
                "The transport must implement IKeyBundleTransport.");
        }

        try
        {
            var bundle = await keyBundleTransport.FetchKeyBundleAsync(recipientIdentityKey);

            if (bundle is null)
            {
                throw new LibEmiddleException(
                    "No key bundle found for the specified recipient identity key. " +
                    "The recipient must upload their bundle first.",
                    LibEmiddleErrorCode.KeyNotFound);
            }

            // Validate the bundle signature before caching — use the injected provider, not a new instance
            var x3dhProtocol = new Protocol.X3DHProtocol(_cryptoProvider);
            bool isValid = await x3dhProtocol.ValidateKeyBundleAsync(bundle);
            if (!isValid)
            {
                throw new LibEmiddleException(
                    "Bundle signature validation failed. The fetched bundle may be tampered with.",
                    LibEmiddleErrorCode.InvalidBundle);
            }

            // Cache the validated bundle so subsequent CreateChatSessionAsync calls can use it
            await _sessionManager.CacheRecipientBundleAsync(bundle);

            LoggingManager.LogInformation(nameof(LibEmiddleClient),
                $"Fetched, validated, and cached key bundle for recipient " +
                $"{Convert.ToBase64String(recipientIdentityKey)[..Math.Min(8, recipientIdentityKey.Length)]}");

            return bundle;
        }
        catch (NotSupportedException)
        {
            throw;
        }
        catch (LibEmiddleException)
        {
            throw;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Failed to fetch recipient key bundle: {ex.Message}");
            throw;
        }
    }
}
