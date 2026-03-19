using LibEmiddle.Abstractions;
using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;
using LibEmiddle.Messaging.Transport;

namespace LibEmiddle.API;

/// <summary>
/// Abstraction for the LibEmiddle client, suitable for dependency injection and unit testing.
/// Register the concrete <see cref="LibEmiddleClient"/> against this interface in your DI container
/// (see <c>LibEmiddleServiceCollectionExtensions.AddLibEmiddle</c>).
/// </summary>
public interface ILibEmiddleClient : IDisposable
{
    // ── Identity ────────────────────────────────────────────────────────────
    byte[] IdentityPublicKey { get; }

    // ── Lifecycle ───────────────────────────────────────────────────────────
    Task<bool> InitializeAsync();
    bool IsListening { get; }
    event EventHandler<MailboxMessageEventArgs>? MessageReceived;

    // ── Individual chat ─────────────────────────────────────────────────────
    Task<IChatSession> CreateChatSessionAsync(
        byte[] recipientPublicKey,
        string? recipientUserId = null,
        ChatSessionOptions? options = null);

    Task<IChatSession> GetChatSessionAsync(string sessionId);

    Task<IChatSession?> ProcessKeyExchangeMessageAsync(
        MailboxMessage mailboxMessage,
        ChatSessionOptions? options = null);

    Task<EncryptedMessage?> SendChatMessageAsync(string sessionId, string message);

    Task<EncryptedMessage?> SendChatMessageAsync(
        byte[] recipientPublicKey,
        string message,
        string? recipientUserId = null);

    Task<string?> ProcessChatMessageAsync(EncryptedMessage encryptedMessage);
    Task<IReadOnlyCollection<MessageRecord>?> GetChatMessageHistoryAsync(string sessionId, int limit = 50, int startIndex = 0);
    Task<int> GetChatMessageCountAsync(string sessionId);
    Task<int> ClearChatMessageHistoryAsync(string sessionId);

    // ── Group chat ──────────────────────────────────────────────────────────
    Task<IGroupSession> CreateGroupAsync(string groupId, string groupName, GroupSessionOptions? options = null);
    Task<IGroupSession> GetGroupAsync(string groupId);
    Task<IGroupSession> JoinGroupAsync(SenderKeyDistributionMessage distribution, KeyRotationStrategy rotationStrategy = KeyRotationStrategy.Standard);
    Task<bool> LeaveGroupAsync(string groupId);
    Task<EncryptedGroupMessage?> SendGroupMessageAsync(string groupId, string message);
    Task<string?> ProcessGroupMessageAsync(EncryptedGroupMessage encryptedMessage);
    Task<IGroupSession?> GetGroupInfoAsync(string groupId);

    // ── Key management ──────────────────────────────────────────────────────
    Task<X3DHKeyBundle> CreateLocalKeyBundleAsync(int numOneTimeKeys = 10);
    Task<X3DHPublicBundle> GetPublicKeyBundleAsync(int numOneTimeKeys = 10);

    // ── Session management ──────────────────────────────────────────────────
    Task<string?[]> ListSessionsAsync();
    Task<bool> DeleteSessionAsync(string sessionId);
    Task<ISession?> GetSessionInfoAsync(string sessionId);

    // ── Transport ───────────────────────────────────────────────────────────
    Task<bool> StartListeningAsync(int pollingInterval = 5000, CancellationToken cancellationToken = default);
    Task<bool> StopListeningAsync();
    Task<bool> MarkMessageAsReadAsync(string messageId);

    // ── Multi-device ────────────────────────────────────────────────────────
    IDeviceManager DeviceManager { get; }
    EncryptedMessage CreateDeviceLinkMessage(byte[] newDevicePublicKey);
    bool ProcessDeviceLinkMessage(EncryptedMessage encryptedMessage, byte[] expectedMainDevicePublicKey);
    Dictionary<string, EncryptedMessage> CreateSyncMessages(byte[] syncData);
    int GetLinkedDeviceCount();
    bool RemoveLinkedDevice(byte[] devicePublicKey);
}
