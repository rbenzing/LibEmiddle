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
        // Allow callers to inject a custom transport (primarily for testing).
        if (_options.CustomTransport != null)
            return _options.CustomTransport;

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
        // Always forward the raw event to client consumers first so they are notified
        // regardless of whether internal routing succeeds.
        try
        {
            MessageReceived?.Invoke(this, e);
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient), $"Error notifying MessageReceived subscribers for message {e.Message.Id}: {ex.Message}");
        }

        // Route the incoming message to the appropriate processing path.
        // Each case is fire-and-forget; errors are logged and swallowed so that
        // one bad message never stops the polling loop.
        _ = RouteIncomingMailboxMessageAsync(e.Message);
    }

    /// <summary>
    /// Routes an incoming <see cref="MailboxMessage"/> to the correct processing method
    /// based on its <see cref="MessageType"/>.
    /// Errors are logged and swallowed — a single bad message must never halt polling.
    /// </summary>
    /// <param name="message">The incoming mailbox message.</param>
    private async Task RouteIncomingMailboxMessageAsync(MailboxMessage message)
    {
        try
        {
            switch (message.Type)
            {
                case MessageType.Chat:
                case MessageType.KeyExchange:
                    await RouteChatMessageAsync(message);
                    break;

                case MessageType.GroupChat:
                    await RouteGroupMessageAsync(message);
                    break;

                case MessageType.DeliveryReceipt:
                case MessageType.ReadReceipt:
                case MessageType.DeviceSync:
                case MessageType.DeviceRevocation:
                case MessageType.Control:
                case MessageType.SenderKeyDistribution:
                case MessageType.SenderKeyRequest:
                case MessageType.PreKeyBundle:
                case MessageType.FileTransfer:
                    // These types are handled at a higher level (e.g., transport or device layer)
                    // or are informational; no additional routing needed here.
                    LoggingManager.LogDebug(nameof(LibEmiddleClient),
                        $"Received message {message.Id} of type {message.Type} — no routing action");
                    break;

                default:
                    LoggingManager.LogWarning(nameof(LibEmiddleClient),
                        $"Received message {message.Id} with unrecognised type {message.Type} — skipping");
                    break;
            }
        }
        catch (Exception ex)
        {
            // Log and continue — do NOT rethrow.
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Unhandled error routing message {message.Id} (type={message.Type}): {ex.Message}");
        }
    }

    /// <summary>
    /// Routes a chat-type mailbox message to <see cref="ProcessChatMessageAsync"/>.
    /// </summary>
    private async Task RouteChatMessageAsync(MailboxMessage message)
    {
        try
        {
            var result = await ProcessChatMessageAsync(message.EncryptedPayload);
            if (result != null)
            {
                LoggingManager.LogDebug(nameof(LibEmiddleClient),
                    $"Routed and decrypted chat message {message.Id}");
            }
            else
            {
                LoggingManager.LogWarning(nameof(LibEmiddleClient),
                    $"Chat message {message.Id} could not be decrypted (no matching session)");
            }
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Error processing chat message {message.Id}: {ex.Message}");
        }
    }

    /// <summary>
    /// Routes a group-chat mailbox message to <see cref="ProcessGroupMessageAsync"/>.
    /// The <see cref="EncryptedGroupMessage"/> is reconstructed from the fields available
    /// in the <see cref="MailboxMessage"/>: the ciphertext/nonce come from
    /// <see cref="MailboxMessage.EncryptedPayload"/>, the group identifier comes from
    /// <see cref="MailboxMessage.Metadata"/> (key <c>"GroupId"</c>), and the sender
    /// identity key comes from <see cref="MailboxMessage.SenderKey"/>.
    /// </summary>
    private async Task RouteGroupMessageAsync(MailboxMessage message)
    {
        try
        {
            // Extract GroupId from message metadata.
            string? groupId = null;
            message.Metadata?.TryGetValue("GroupId", out groupId);

            if (string.IsNullOrEmpty(groupId))
            {
                LoggingManager.LogWarning(nameof(LibEmiddleClient),
                    $"Group message {message.Id} is missing GroupId metadata — cannot route");
                return;
            }

            // Reconstruct EncryptedGroupMessage from mailbox message fields.
            var encryptedGroupMessage = new EncryptedGroupMessage
            {
                MessageId = message.EncryptedPayload.MessageId ?? message.Id,
                GroupId = groupId,
                SenderIdentityKey = message.SenderKey,
                Ciphertext = message.EncryptedPayload.Ciphertext ?? Array.Empty<byte>(),
                Nonce = message.EncryptedPayload.Nonce ?? Array.Empty<byte>(),
                Timestamp = message.Timestamp,
            };

            var result = await ProcessGroupMessageAsync(encryptedGroupMessage);
            if (result != null)
            {
                LoggingManager.LogDebug(nameof(LibEmiddleClient),
                    $"Routed and decrypted group message {message.Id} for group {groupId}");
            }
            else
            {
                LoggingManager.LogWarning(nameof(LibEmiddleClient),
                    $"Group message {message.Id} for group {groupId} could not be decrypted");
            }
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient),
                $"Error processing group message {message.Id}: {ex.Message}");
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
