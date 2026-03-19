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

/// <summary>
/// Main client interface for LibEmiddle providing end-to-end encrypted messaging
/// capabilities with support for individual chats, group messaging, and multi-device synchronization.
/// Updated to work with the consolidated GroupSession implementation.
/// </summary>
public sealed partial class LibEmiddleClient : ILibEmiddleClient
{
    private readonly LibEmiddleClientOptions _options;
    private readonly ICryptoProvider _cryptoProvider;
    private readonly KeyPair _identityKeyPair;
    private readonly SessionManager _sessionManager;
    private readonly DeviceManager _deviceManager;
    private readonly IMailboxTransport _transport;
    private readonly KeyManager _keyManager;
    private readonly MailboxManager _mailboxManager;

    // v2.5 - Diagnostics system (optional)
    private readonly Lazy<ILibEmiddleDiagnostics?> _diagnostics;

    private volatile bool _disposed;
    private bool _initialized;
    private bool _isListening;

    /// <summary>
    /// Gets the client's identity public key.
    /// </summary>
    public byte[] IdentityPublicKey => _identityKeyPair.PublicKey;

    /// <summary>
    /// Gets the current device manager for multi-device operations.
    /// </summary>
    public IDeviceManager DeviceManager => _deviceManager;

    /// <summary>
    /// Event raised when a new message is received.
    /// </summary>
    public event EventHandler<MailboxMessageEventArgs>? MessageReceived;

    /// <summary>
    /// Gets whether the client is currently listening for incoming messages.
    /// </summary>
    public bool IsListening => _isListening;

    /// <summary>
    /// Gets the diagnostic and health monitoring interface (v2.5).
    /// Returns null if health monitoring is not enabled in the feature flags.
    /// </summary>
    public ILibEmiddleDiagnostics? Diagnostics => _diagnostics.Value;

    /// <summary>
    /// Initializes a new instance of the LibEmiddleClient.
    /// </summary>
    /// <param name="options">Configuration options for the client</param>
    /// <exception cref="ArgumentNullException">Thrown when options is null</exception>
    public LibEmiddleClient(LibEmiddleClientOptions options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));

        try
        {
            // Initialize libsodium
            Sodium.Initialize();

            // Create crypto provider
            _cryptoProvider = new CryptoProvider();

            // Load or generate identity key pair
            _identityKeyPair = LoadOrGenerateIdentityKey();

            // Create key manager
            _keyManager = new KeyManager(_cryptoProvider);

            // Create protocols
            var x3dhProtocol = new X3DHProtocol(_cryptoProvider);
            var doubleRatchetProtocol = new DoubleRatchetProtocol();

            // Create session manager
            _sessionManager = new SessionManager(
                _cryptoProvider,
                x3dhProtocol,
                doubleRatchetProtocol,
                _identityKeyPair,
                _options.SessionStoragePath);

            // Create device linking service and device manager
            var deviceLinkingService = new DeviceLinkingService(_cryptoProvider);
            var syncMessageValidator = new SyncMessageValidator(_cryptoProvider);
            _deviceManager = new DeviceManager(
                _identityKeyPair,
                deviceLinkingService,
                _cryptoProvider,
                syncMessageValidator);

            // Create transport
            _transport = CreateTransport();

            // Create mailbox manager with the transport and protocols
            _mailboxManager = new MailboxManager(_identityKeyPair, _transport, doubleRatchetProtocol, _cryptoProvider);

            // Wire up mailbox manager events
            _mailboxManager.MessageReceived += OnMailboxMessageReceived;

            // Initialize diagnostics system - lazy initialization
            _diagnostics = new Lazy<ILibEmiddleDiagnostics?>(() =>
            {
                var diagnosticsImpl = new LibEmiddleDiagnostics();

                // Record client initialization event
                diagnosticsImpl.RecordEvent(Domain.Diagnostics.DiagnosticEvent.OperationCompleted(
                    "LibEmiddleClient", "ClientInitialized", 0));

                return diagnosticsImpl;
            });

            LoggingManager.LogInformation(nameof(LibEmiddleClient), "LibEmiddle client initialized successfully");
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient), $"Failed to initialize client: {ex.Message}");
            Dispose();
            throw;
        }
    }

    /// <summary>
    /// Initializes the client and prepares it for use.
    /// </summary>
    /// <returns>True if initialization was successful</returns>
    public async Task<bool> InitializeAsync()
    {
        ThrowIfDisposed();

        if (_initialized)
            return true;

        try
        {
            // Initialize transport
            if (_transport is IAsyncInitializable asyncTransport)
            {
                await asyncTransport.InitializeAsync();
            }

            _initialized = true;
            LoggingManager.LogInformation(nameof(LibEmiddleClient), "Client initialization completed");
            return true;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient), $"Client initialization failed: {ex.Message}");
            return false;
        }
    }

    public void Dispose()
    {
        if (_disposed)
            return;

        try
        {
            // Stop listening first (synchronously for disposal)
            if (_isListening)
            {
                try
                {
                    // SYNC-REQUIRED: Dispose() cannot be async. Use Task.Run to avoid
                    // deadlocks on sync contexts (ASP.NET, WPF, WinForms).
                    Task.Run(() => _transport?.StopListeningAsync()).GetAwaiter().GetResult();
                    _isListening = false;
                }
                catch (Exception ex)
                {
                    LoggingManager.LogError(nameof(LibEmiddleClient), $"Error stopping listening during disposal: {ex.Message}");
                }
            }

            // Dispose components in reverse order of creation
            _mailboxManager?.Dispose();
            _sessionManager?.Dispose();
            _deviceManager?.Dispose();
            _transport?.Dispose();
            _keyManager?.Dispose();

            // Dispose diagnostics system (v2.5)
            if (_diagnostics.IsValueCreated && _diagnostics.Value is IDisposable disposableDiagnostics)
            {
                disposableDiagnostics.Dispose();
            }
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(LibEmiddleClient), $"Error during disposal: {ex.Message}");
        }

        _disposed = true;
        LoggingManager.LogInformation(nameof(LibEmiddleClient), "LibEmiddle client disposed");
    }
}

/// <summary>
/// Interface for transports that require asynchronous initialization.
/// </summary>
public interface IAsyncInitializable
{
    Task InitializeAsync();
}
