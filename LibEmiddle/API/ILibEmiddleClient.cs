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
public interface ILibEmiddleClient : IDisposable, IAsyncDisposable
{
    // ── Identity ────────────────────────────────────────────────────────────
    byte[] IdentityPublicKey { get; }

    // ── Lifecycle ───────────────────────────────────────────────────────────
    Task<bool> InitializeAsync();
    bool IsListening { get; }
    event EventHandler<MailboxMessageEventArgs>? MessageReceived;

    // ── Individual chat ─────────────────────────────────────────────────────

    /// <summary>
    /// Creates a new chat session with the specified recipient by their identity key.
    /// If no bundle is locally cached for the recipient, this overload attempts to fetch
    /// one from the transport layer. Throws <see cref="LibEmiddle.Domain.Exceptions.LibEmiddleException"/>
    /// with error code <see cref="LibEmiddle.Domain.Exceptions.LibEmiddleErrorCode.KeyNotFound"/>
    /// when the fetch fails and no locally cached bundle is available.
    /// </summary>
    /// <param name="recipientIdentityKey">
    /// The Ed25519 identity public key of the recipient (32 bytes).
    /// Used to look up the recipient's full X3DH bundle — either from the local
    /// cache or from the transport via <see cref="FetchRecipientKeyBundleAsync"/>.
    /// </param>
    /// <param name="recipientUserId">Optional display / routing identifier for the recipient.</param>
    /// <param name="options">Optional chat session configuration.</param>
    /// <returns>The newly created <see cref="IChatSession"/>.</returns>
    /// <exception cref="LibEmiddle.Domain.Exceptions.LibEmiddleException">
    /// Thrown with <see cref="LibEmiddle.Domain.Exceptions.LibEmiddleErrorCode.KeyNotFound"/>
    /// when no bundle can be obtained for the recipient.
    /// </exception>
    Task<IChatSession> CreateChatSessionAsync(
        byte[] recipientIdentityKey,
        string? recipientUserId = null,
        ChatSessionOptions? options = null);

    /// <summary>
    /// Creates a new chat session using a directly supplied <see cref="X3DHPublicBundle"/>.
    /// The bundle is cached locally before the session is created, so no network call is made.
    /// Use this overload when the caller already holds the recipient's validated bundle
    /// (e.g., obtained out-of-band or via <see cref="FetchRecipientKeyBundleAsync"/>).
    /// </summary>
    /// <param name="recipientBundle">
    /// The recipient's validated X3DH public key bundle. Must include a non-empty
    /// <see cref="X3DHPublicBundle.IdentityKey"/>.
    /// </param>
    /// <param name="recipientUserId">Optional display / routing identifier for the recipient.</param>
    /// <param name="options">Optional chat session configuration.</param>
    /// <returns>The newly created <see cref="IChatSession"/>.</returns>
    Task<IChatSession> CreateChatSessionAsync(
        X3DHPublicBundle recipientBundle,
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

    // ── Prekey bundle API ────────────────────────────────────────────────────
    /// <summary>
    /// Uploads the client's own public key bundle to the transport so that other
    /// parties can initiate X3DH sessions without a pre-cached bundle.
    /// Requires the configured transport to implement
    /// <see cref="LibEmiddle.Abstractions.IKeyBundleTransport"/>.
    /// </summary>
    /// <exception cref="NotSupportedException">
    /// Thrown when the current transport does not support key bundle upload.
    /// </exception>
    Task UploadKeyBundleAsync();

    /// <summary>
    /// Fetches the public key bundle for <paramref name="recipientIdentityKey"/> from the
    /// transport, validates the bundle signature, caches it locally, and returns it.
    /// Requires the configured transport to implement
    /// <see cref="LibEmiddle.Abstractions.IKeyBundleTransport"/>.
    /// </summary>
    /// <param name="recipientIdentityKey">The Ed25519 identity public key of the recipient.</param>
    /// <returns>The validated <see cref="X3DHPublicBundle"/> for the recipient.</returns>
    /// <exception cref="NotSupportedException">
    /// Thrown when the current transport does not support key bundle fetching.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when no bundle is found for the given identity key, or when signature
    /// validation fails.
    /// </exception>
    Task<X3DHPublicBundle> FetchRecipientKeyBundleAsync(byte[] recipientIdentityKey);

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

    /// <summary>
    /// Sends an encrypted message to a specific linked device identified by <paramref name="deviceId"/>.
    /// The device ID must correspond to a device that is already linked via <see cref="IDeviceManager"/>.
    /// Device routing information is embedded in the message headers before dispatch.
    /// </summary>
    /// <param name="deviceId">
    /// The base-64–encoded X25519 public key that identifies the target device,
    /// matching the key stored in <see cref="IDeviceManager"/>.
    /// </param>
    /// <param name="message">The pre-encrypted message to route to the device.</param>
    /// <returns>A task that completes when the message has been accepted by the transport.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="deviceId"/> is null or empty, or when
    /// <paramref name="message"/> is null.
    /// </exception>
    /// <exception cref="LibEmiddle.Domain.Exceptions.LibEmiddleException">
    /// Thrown with <see cref="LibEmiddle.Domain.Exceptions.LibEmiddleErrorCode.DeviceNotFound"/>
    /// when <paramref name="deviceId"/> does not correspond to a linked device, or with
    /// <see cref="LibEmiddle.Domain.Exceptions.LibEmiddleErrorCode.TransportError"/> when
    /// the transport layer fails to deliver the message.
    /// </exception>
    Task SendToDeviceAsync(string deviceId, EncryptedMessage message);
}
