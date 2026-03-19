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
    private KeyPair LoadOrGenerateIdentityKey()
    {
        // CryptoProvider.RetrieveKeyAsync / StoreKeyAsync are backed by Task.FromResult
        // (synchronous, no SynchronizationContext involved), so .GetResult() is safe here.
        //
        // Scope the key ID to the configured identity path (or session path as fallback) so
        // that multiple clients in the same process don't overwrite each other's keys.
        string scope = _options.IdentityKeyPath
            ?? _options.SessionStoragePath
            ?? "default";
        string privateKeyId = $"libemiddle:identity:{scope}:private";
        string publicKeyId  = $"libemiddle:identity:{scope}:public";

        try
        {
            var privateKeyBytes = _cryptoProvider.RetrieveKeyAsync(privateKeyId).GetAwaiter().GetResult();
            var publicKeyBytes  = _cryptoProvider.RetrieveKeyAsync(publicKeyId).GetAwaiter().GetResult();

            if (privateKeyBytes?.Length == 64 && publicKeyBytes?.Length == 32)
            {
                LoggingManager.LogInformation(nameof(LibEmiddleClient), "Loaded existing identity key");
                return new KeyPair { PrivateKey = privateKeyBytes, PublicKey = publicKeyBytes };
            }
        }
        catch (Exception ex)
        {
            LoggingManager.LogWarning(nameof(LibEmiddleClient),
                $"Failed to load identity key: {ex.Message}. Generating new key.");
        }

        // Generate and persist a new key pair
        var keyPair = Sodium.GenerateEd25519KeyPair();

        try
        {
            _cryptoProvider.StoreKeyAsync(privateKeyId, keyPair.PrivateKey!).GetAwaiter().GetResult();
            _cryptoProvider.StoreKeyAsync(publicKeyId,  keyPair.PublicKey!).GetAwaiter().GetResult();
            LoggingManager.LogInformation(nameof(LibEmiddleClient), "Generated and persisted new identity key");
        }
        catch (Exception ex)
        {
            LoggingManager.LogWarning(nameof(LibEmiddleClient),
                $"Failed to persist identity key: {ex.Message}. Key will be ephemeral this session.");
        }

        return keyPair;
    }

    private IMailboxTransport CreateTransport()
    {
        return _options.TransportType switch
        {
            TransportType.InMemory => new InMemoryMailboxTransport(_cryptoProvider),
            TransportType.Http => new HttpMailboxTransport(_cryptoProvider, new HttpClient(), _options.ServerEndpoint ?? "http://localhost:8080"),
            TransportType.WebSocket => CreateWebSocketTransport(),
            _ => new InMemoryMailboxTransport(_cryptoProvider)
        };
    }

    private IMailboxTransport CreateWebSocketTransport()
    {
        // For WebSocket transport, we would need a WebSocketMailboxTransport implementation
        // For now, fall back to HTTP transport as WebSocket transport needs server-side support
        LoggingManager.LogWarning(nameof(LibEmiddleClient), "WebSocket transport not fully implemented, falling back to HTTP");
        return new HttpMailboxTransport(_cryptoProvider, new HttpClient(), _options.ServerEndpoint ?? "ws://localhost:8080");
    }

    private void OnMailboxMessageReceived(object? sender, MailboxMessageEventArgs e)
    {
        try
        {
            // Forward the event to client consumers
            MessageReceived?.Invoke(this, e);
            LoggingManager.LogDebug(nameof(LibEmiddleClient), $"Forwarded message received event for message {e.Message.Id}");
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient), $"Error in message received event handler: {ex.Message}");
        }
    }

    private void EnsureInitialized()
    {
        if (!_initialized)
            throw new InvalidOperationException("Client must be initialized before use. Call InitializeAsync() first.");
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(LibEmiddleClient));
    }
}
