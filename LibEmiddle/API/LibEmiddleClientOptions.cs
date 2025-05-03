using Microsoft.Extensions.Logging;
using LibEmiddle.Abstractions;

namespace LibEmiddle.API
{
    /// <summary>
    /// Configuration options for the LibEmiddle client.
    /// </summary>
    public class LibEmiddleClientOptions
    {
        /// <summary>
        /// Gets or sets the unique identifier for this client.
        /// </summary>
        public string? ClientId { get; set; }

        /// <summary>
        /// Gets or sets the unique identifier for this device.
        /// </summary>
        public string? DeviceId { get; set; }

        /// <summary>
        /// Gets or sets the URL of the messaging server.
        /// </summary>
        public string ServerUrl { get; set; } = "https://api.example.com";

        /// <summary>
        /// Gets or sets the path for storing session data.
        /// </summary>
        public string? SessionStoragePath { get; set; }

        /// <summary>
        /// Gets or sets the path for storing key data.
        /// </summary>
        public string? KeyStoragePath { get; set; }

        /// <summary>
        /// Gets or sets the crypto provider implementation.
        /// </summary>
        public ICryptoProvider? CryptoProvider { get; set; }

        /// <summary>
        /// Gets or sets the mailbox transport implementation.
        /// </summary>
        public IMailboxTransport? MailboxTransport { get; set; }

        /// <summary>
        /// Gets or sets the session manager implementation.
        /// </summary>
        public ISessionManager? SessionManager { get; set; }

        /// <summary>
        /// Gets or sets the key manager implementation.
        /// </summary>
        public IKeyManager? KeyManager { get; set; }

        /// <summary>
        /// Gets or sets the X3DH protocol implementation.
        /// </summary>
        public IX3DHProtocol? X3DHProtocol { get; set; }

        /// <summary>
        /// Gets or sets the Double Ratchet protocol implementation.
        /// </summary>
        public IDoubleRatchetProtocol? DoubleRatchetProtocol { get; set; }

        /// <summary>
        /// Gets or sets the logging level.
        /// </summary>
        public LogLevel? LogLevel { get; set; }

        /// <summary>
        /// Gets or sets the log handler.
        /// </summary>
        public Action<string, string, LogLevel>? LogHandler { get; set; }

        /// <summary>
        /// Gets or sets whether to use secure memory for sensitive operations.
        /// </summary>
        public bool UseSecureMemory { get; set; } = true;

        /// <summary>
        /// Gets or sets the default connection timeout for network operations in milliseconds.
        /// </summary>
        public int ConnectionTimeoutMs { get; set; } = 30000;

        /// <summary>
        /// Gets or sets whether to automatically fetch messages on initialization.
        /// </summary>
        public bool AutoFetchMessages { get; set; } = true;

        /// <summary>
        /// Gets or sets the message polling interval in milliseconds.
        /// </summary>
        public int MessagePollingIntervalMs { get; set; } = 5000;

        /// <summary>
        /// Gets or sets the maximum number of message retries.
        /// </summary>
        public int MaxMessageRetries { get; set; } = 3;

        /// <summary>
        /// Gets or sets whether to automatically rotate keys on schedule.
        /// </summary>
        public bool AutoRotateKeys { get; set; } = true;

        /// <summary>
        /// Gets or sets the key rotation interval in milliseconds.
        /// Default is 7 days.
        /// </summary>
        public long KeyRotationIntervalMs { get; set; } = 7 * 24 * 60 * 60 * 1000;
    }
}
