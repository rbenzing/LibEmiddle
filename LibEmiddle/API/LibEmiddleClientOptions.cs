using LibEmiddle.Domain.Enums;

namespace LibEmiddle.API;

/// <summary>
/// Configuration options for the LibEmiddle client, providing comprehensive
/// settings for cryptographic operations, storage, networking, and security policies.
/// </summary>
public sealed class LibEmiddleClientOptions
{
    /// <summary>
    /// Gets or sets the path where the identity key will be stored.
    /// If null or empty, the key will be generated in memory only.
    /// </summary>
    public string? IdentityKeyPath { get; set; }

    /// <summary>
    /// Gets or sets the path where session data will be persisted.
    /// If null, sessions will be stored in the default application data directory.
    /// </summary>
    public string? SessionStoragePath { get; set; }

    /// <summary>
    /// Gets or sets the path where cryptographic keys will be stored.
    /// If null, keys will be stored in the default application data directory.
    /// </summary>
    public string? KeyStoragePath { get; set; }

    /// <summary>
    /// Gets or sets the transport type to use for communication.
    /// </summary>
    public TransportType TransportType { get; set; } = TransportType.InMemory;

    /// <summary>
    /// Gets or sets the server endpoint URL for HTTP/WebSocket transports.
    /// Required when using Http or WebSocket transport types.
    /// </summary>
    public string? ServerEndpoint { get; set; }

    /// <summary>
    /// Gets or sets the default key rotation strategy for new sessions.
    /// </summary>
    public KeyRotationStrategy DefaultRotationStrategy { get; set; } = KeyRotationStrategy.Standard;

    /// <summary>
    /// Gets or sets the maximum number of one-time prekeys to generate.
    /// </summary>
    public int MaxOneTimePreKeys { get; set; } = 100;

    /// <summary>
    /// Gets or sets the maximum number of skipped message keys to store.
    /// This affects memory usage and out-of-order message handling capability.
    /// </summary>
    public int MaxSkippedMessageKeys { get; set; } = 1000;

    /// <summary>
    /// Gets or sets the timeout for network operations in milliseconds.
    /// </summary>
    public int NetworkTimeoutMs { get; set; } = 30000; // 30 seconds

    /// <summary>
    /// Gets or sets the maximum message age in milliseconds for replay protection.
    /// Messages older than this will be rejected.
    /// </summary>
    public long MaxMessageAgeMs { get; set; } = 300000; // 5 minutes

    /// <summary>
    /// Gets or sets whether to enable automatic key rotation based on time.
    /// </summary>
    public bool EnableAutomaticKeyRotation { get; set; } = true;

    /// <summary>
    /// Gets or sets the interval for automatic key rotation checks in milliseconds.
    /// </summary>
    public long KeyRotationCheckIntervalMs { get; set; } = 3600000; // 1 hour

    /// <summary>
    /// Gets or sets whether to enable multi-device support.
    /// </summary>
    public bool EnableMultiDevice { get; set; } = true;

    /// <summary>
    /// Gets or sets the maximum number of linked devices allowed.
    /// </summary>
    public int MaxLinkedDevices { get; set; } = 10;

    /// <summary>
    /// Gets or sets whether to enable message history tracking.
    /// </summary>
    public bool EnableMessageHistory { get; set; } = true;

    /// <summary>
    /// Gets or sets the maximum number of messages to keep in history per session.
    /// </summary>
    public int MaxMessageHistoryPerSession { get; set; } = 1000;

    /// <summary>
    /// Gets or sets whether to enable secure memory operations.
    /// When true, sensitive data will be stored in locked memory pages.
    /// </summary>
    public bool EnableSecureMemory { get; set; } = true;

    /// <summary>
    /// Gets or sets whether to enable session persistence.
    /// When false, sessions will only exist in memory.
    /// </summary>
    public bool EnableSessionPersistence { get; set; } = true;

    /// <summary>
    /// Gets or sets whether to enable strict certificate validation for HTTPS/WSS connections.
    /// </summary>
    public bool EnableStrictCertificateValidation { get; set; } = true;

    /// <summary>
    /// Gets or sets custom headers to include in HTTP requests.
    /// </summary>
    public Dictionary<string, string> CustomHeaders { get; set; } = new();

    /// <summary>
    /// Gets or sets the user agent string for HTTP requests.
    /// </summary>
    public string UserAgent { get; set; } = "LibEmiddle/2.0";

    /// <summary>
    /// Gets or sets whether to enable compression for network communications.
    /// </summary>
    public bool EnableCompression { get; set; } = true;

    /// <summary>
    /// Gets or sets the compression level (1-9) when compression is enabled.
    /// </summary>
    public int CompressionLevel { get; set; } = 6;

    /// <summary>
    /// Gets or sets the maximum size of a single message in bytes.
    /// </summary>
    public int MaxMessageSizeBytes { get; set; } = 1048576; // 1 MB

    /// <summary>
    /// Gets or sets the maximum size of a group in terms of member count.
    /// </summary>
    public int MaxGroupSize { get; set; } = 1000;

    /// <summary>
    /// Gets or sets whether to enable debug logging.
    /// Warning: This may log sensitive information in debug builds.
    /// </summary>
    public bool EnableDebugLogging { get; set; } = false;

    /// <summary>
    /// Gets or sets the log level for the client operations.
    /// </summary>
    public LogLevel LogLevel { get; set; } = LogLevel.Information;

    /// <summary>
    /// Gets or sets whether to enable performance metrics collection.
    /// </summary>
    public bool EnablePerformanceMetrics { get; set; } = false;

    /// <summary>
    /// Gets or sets connection retry settings.
    /// </summary>
    public RetryOptions RetryOptions { get; set; } = new();

    /// <summary>
    /// Gets or sets rate limiting settings.
    /// </summary>
    public RateLimitOptions RateLimitOptions { get; set; } = new();

    /// <summary>
    /// Gets or sets security policy settings.
    /// </summary>
    public SecurityPolicyOptions SecurityPolicy { get; set; } = new();

    /// <summary>
    /// Gets or sets backup and recovery settings.
    /// </summary>
    public BackupOptions BackupOptions { get; set; } = new();

    /// <summary>
    /// Validates the configuration options and returns any validation errors.
    /// </summary>
    /// <returns>List of validation error messages, empty if valid</returns>
    public List<string> Validate()
    {
        var errors = new List<string>();

        // Validate transport-specific settings
        if (TransportType == TransportType.Http || TransportType == TransportType.WebSocket)
        {
            if (string.IsNullOrEmpty(ServerEndpoint))
            {
                errors.Add($"ServerEndpoint is required when using {TransportType} transport");
            }
            else if (!Uri.TryCreate(ServerEndpoint, UriKind.Absolute, out var uri))
            {
                errors.Add("ServerEndpoint must be a valid URL");
            }
            else
            {
                var expectedScheme = TransportType == TransportType.Http ? "http" : "ws";
                var expectedSchemeSecure = TransportType == TransportType.Http ? "https" : "wss";

                if (uri.Scheme != expectedScheme && uri.Scheme != expectedSchemeSecure)
                {
                    errors.Add($"ServerEndpoint scheme must be {expectedScheme} or {expectedSchemeSecure} for {TransportType} transport");
                }
            }
        }

        // Validate numeric ranges
        if (MaxOneTimePreKeys < 1 || MaxOneTimePreKeys > 10000)
        {
            errors.Add("MaxOneTimePreKeys must be between 1 and 10,000");
        }

        if (MaxSkippedMessageKeys < 10 || MaxSkippedMessageKeys > 100000)
        {
            errors.Add("MaxSkippedMessageKeys must be between 10 and 100,000");
        }

        if (NetworkTimeoutMs < 1000 || NetworkTimeoutMs > 300000)
        {
            errors.Add("NetworkTimeoutMs must be between 1,000 and 300,000 (1 second to 5 minutes)");
        }

        if (MaxMessageAgeMs < 60000 || MaxMessageAgeMs > 86400000)
        {
            errors.Add("MaxMessageAgeMs must be between 60,000 and 86,400,000 (1 minute to 24 hours)");
        }

        if (MaxLinkedDevices < 1 || MaxLinkedDevices > 100)
        {
            errors.Add("MaxLinkedDevices must be between 1 and 100");
        }

        if (MaxMessageHistoryPerSession < 0 || MaxMessageHistoryPerSession > 100000)
        {
            errors.Add("MaxMessageHistoryPerSession must be between 0 and 100,000");
        }

        if (CompressionLevel < 1 || CompressionLevel > 9)
        {
            errors.Add("CompressionLevel must be between 1 and 9");
        }

        if (MaxMessageSizeBytes < 1024 || MaxMessageSizeBytes > 104857600) // 1 KB to 100 MB
        {
            errors.Add("MaxMessageSizeBytes must be between 1,024 and 104,857,600 (1 KB to 100 MB)");
        }

        if (MaxGroupSize < 2 || MaxGroupSize > 10000)
        {
            errors.Add("MaxGroupSize must be between 2 and 10,000");
        }

        // Validate paths
        if (!string.IsNullOrEmpty(IdentityKeyPath))
        {
            var directory = Path.GetDirectoryName(IdentityKeyPath);
            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
            {
                try
                {
                    Directory.CreateDirectory(directory);
                }
                catch
                {
                    errors.Add($"Cannot create directory for IdentityKeyPath: {directory}");
                }
            }
        }

        // Validate nested options
        errors.AddRange(RetryOptions.Validate());
        errors.AddRange(RateLimitOptions.Validate());
        errors.AddRange(SecurityPolicy.Validate());
        errors.AddRange(BackupOptions.Validate());

        return errors;
    }

    /// <summary>
    /// Creates a copy of these options with all the same settings.
    /// </summary>
    /// <returns>A new LibEmiddleClientOptions instance with copied settings</returns>
    public LibEmiddleClientOptions Clone()
    {
        return new LibEmiddleClientOptions
        {
            IdentityKeyPath = IdentityKeyPath,
            SessionStoragePath = SessionStoragePath,
            KeyStoragePath = KeyStoragePath,
            TransportType = TransportType,
            ServerEndpoint = ServerEndpoint,
            DefaultRotationStrategy = DefaultRotationStrategy,
            MaxOneTimePreKeys = MaxOneTimePreKeys,
            MaxSkippedMessageKeys = MaxSkippedMessageKeys,
            NetworkTimeoutMs = NetworkTimeoutMs,
            MaxMessageAgeMs = MaxMessageAgeMs,
            EnableAutomaticKeyRotation = EnableAutomaticKeyRotation,
            KeyRotationCheckIntervalMs = KeyRotationCheckIntervalMs,
            EnableMultiDevice = EnableMultiDevice,
            MaxLinkedDevices = MaxLinkedDevices,
            EnableMessageHistory = EnableMessageHistory,
            MaxMessageHistoryPerSession = MaxMessageHistoryPerSession,
            EnableSecureMemory = EnableSecureMemory,
            EnableSessionPersistence = EnableSessionPersistence,
            EnableStrictCertificateValidation = EnableStrictCertificateValidation,
            CustomHeaders = new Dictionary<string, string>(CustomHeaders),
            UserAgent = UserAgent,
            EnableCompression = EnableCompression,
            CompressionLevel = CompressionLevel,
            MaxMessageSizeBytes = MaxMessageSizeBytes,
            MaxGroupSize = MaxGroupSize,
            EnableDebugLogging = EnableDebugLogging,
            LogLevel = LogLevel,
            EnablePerformanceMetrics = EnablePerformanceMetrics,
            RetryOptions = RetryOptions.Clone(),
            RateLimitOptions = RateLimitOptions.Clone(),
            SecurityPolicy = SecurityPolicy.Clone(),
            BackupOptions = BackupOptions.Clone()
        };
    }
}

/// <summary>
/// Log levels for client operations.
/// </summary>
public enum LogLevel
{
    Trace,
    Debug,
    Information,
    Warning,
    Error,
    Critical,
    None
}

/// <summary>
/// Retry configuration options.
/// </summary>
public sealed class RetryOptions
{
    /// <summary>
    /// Gets or sets whether to enable automatic retries.
    /// </summary>
    public bool EnableRetries { get; set; } = true;

    /// <summary>
    /// Gets or sets the maximum number of retry attempts.
    /// </summary>
    public int MaxRetryAttempts { get; set; } = 3;

    /// <summary>
    /// Gets or sets the base delay between retries in milliseconds.
    /// </summary>
    public int BaseDelayMs { get; set; } = 1000;

    /// <summary>
    /// Gets or sets the maximum delay between retries in milliseconds.
    /// </summary>
    public int MaxDelayMs { get; set; } = 30000;

    /// <summary>
    /// Gets or sets whether to use exponential backoff for retry delays.
    /// </summary>
    public bool UseExponentialBackoff { get; set; } = true;

    /// <summary>
    /// Validates the retry options.
    /// </summary>
    public List<string> Validate()
    {
        var errors = new List<string>();

        if (MaxRetryAttempts < 0 || MaxRetryAttempts > 10)
        {
            errors.Add("MaxRetryAttempts must be between 0 and 10");
        }

        if (BaseDelayMs < 100 || BaseDelayMs > 60000)
        {
            errors.Add("BaseDelayMs must be between 100 and 60,000");
        }

        if (MaxDelayMs < BaseDelayMs || MaxDelayMs > 300000)
        {
            errors.Add("MaxDelayMs must be at least BaseDelayMs and no more than 300,000");
        }

        return errors;
    }

    /// <summary>
    /// Creates a copy of these retry options.
    /// </summary>
    public RetryOptions Clone()
    {
        return new RetryOptions
        {
            EnableRetries = EnableRetries,
            MaxRetryAttempts = MaxRetryAttempts,
            BaseDelayMs = BaseDelayMs,
            MaxDelayMs = MaxDelayMs,
            UseExponentialBackoff = UseExponentialBackoff
        };
    }
}

/// <summary>
/// Rate limiting configuration options.
/// </summary>
public sealed class RateLimitOptions
{
    /// <summary>
    /// Gets or sets whether to enable rate limiting.
    /// </summary>
    public bool EnableRateLimit { get; set; } = true;

    /// <summary>
    /// Gets or sets the maximum number of messages per minute.
    /// </summary>
    public int MaxMessagesPerMinute { get; set; } = 60;

    /// <summary>
    /// Gets or sets the maximum number of key exchanges per hour.
    /// </summary>
    public int MaxKeyExchangesPerHour { get; set; } = 10;

    /// <summary>
    /// Gets or sets the maximum burst size for message sending.
    /// </summary>
    public int BurstSize { get; set; } = 10;

    /// <summary>
    /// Validates the rate limit options.
    /// </summary>
    public List<string> Validate()
    {
        var errors = new List<string>();

        if (MaxMessagesPerMinute < 1 || MaxMessagesPerMinute > 1000)
        {
            errors.Add("MaxMessagesPerMinute must be between 1 and 1,000");
        }

        if (MaxKeyExchangesPerHour < 1 || MaxKeyExchangesPerHour > 100)
        {
            errors.Add("MaxKeyExchangesPerHour must be between 1 and 100");
        }

        if (BurstSize < 1 || BurstSize > MaxMessagesPerMinute)
        {
            errors.Add("BurstSize must be between 1 and MaxMessagesPerMinute");
        }

        return errors;
    }

    /// <summary>
    /// Creates a copy of these rate limit options.
    /// </summary>
    public RateLimitOptions Clone()
    {
        return new RateLimitOptions
        {
            EnableRateLimit = EnableRateLimit,
            MaxMessagesPerMinute = MaxMessagesPerMinute,
            MaxKeyExchangesPerHour = MaxKeyExchangesPerHour,
            BurstSize = BurstSize
        };
    }
}

/// <summary>
/// Security policy configuration options.
/// </summary>
public sealed class SecurityPolicyOptions
{
    /// <summary>
    /// Gets or sets whether to require perfect forward secrecy.
    /// </summary>
    public bool RequirePerfectForwardSecrecy { get; set; } = true;

    /// <summary>
    /// Gets or sets whether to require message authentication.
    /// </summary>
    public bool RequireMessageAuthentication { get; set; } = true;

    /// <summary>
    /// Gets or sets the minimum allowed protocol version.
    /// </summary>
    public string MinimumProtocolVersion { get; set; } = "2.0";

    /// <summary>
    /// Gets or sets whether to allow insecure connections (HTTP instead of HTTPS).
    /// </summary>
    public bool AllowInsecureConnections { get; set; } = false;

    /// <summary>
    /// Gets or sets the maximum allowed clock skew in milliseconds.
    /// </summary>
    public long MaxClockSkewMs { get; set; } = 300000; // 5 minutes

    /// <summary>
    /// Validates the security policy options.
    /// </summary>
    public List<string> Validate()
    {
        var errors = new List<string>();

        if (string.IsNullOrEmpty(MinimumProtocolVersion))
        {
            errors.Add("MinimumProtocolVersion cannot be empty");
        }

        if (MaxClockSkewMs < 60000 || MaxClockSkewMs > 3600000)
        {
            errors.Add("MaxClockSkewMs must be between 60,000 and 3,600,000 (1 minute to 1 hour)");
        }

        return errors;
    }

    /// <summary>
    /// Creates a copy of these security policy options.
    /// </summary>
    public SecurityPolicyOptions Clone()
    {
        return new SecurityPolicyOptions
        {
            RequirePerfectForwardSecrecy = RequirePerfectForwardSecrecy,
            RequireMessageAuthentication = RequireMessageAuthentication,
            MinimumProtocolVersion = MinimumProtocolVersion,
            AllowInsecureConnections = AllowInsecureConnections,
            MaxClockSkewMs = MaxClockSkewMs
        };
    }
}

/// <summary>
/// Backup and recovery configuration options.
/// </summary>
public sealed class BackupOptions
{
    /// <summary>
    /// Gets or sets whether to enable automatic backups.
    /// </summary>
    public bool EnableAutoBackup { get; set; } = false;

    /// <summary>
    /// Gets or sets the backup directory path.
    /// </summary>
    public string? BackupDirectory { get; set; }

    /// <summary>
    /// Gets or sets the backup interval in hours.
    /// </summary>
    public int BackupIntervalHours { get; set; } = 24;

    /// <summary>
    /// Gets or sets the maximum number of backup files to keep.
    /// </summary>
    public int MaxBackupFiles { get; set; } = 7;

    /// <summary>
    /// Gets or sets whether to encrypt backup files.
    /// </summary>
    public bool EncryptBackups { get; set; } = true;

    /// <summary>
    /// Validates the backup options.
    /// </summary>
    public List<string> Validate()
    {
        var errors = new List<string>();

        if (EnableAutoBackup && string.IsNullOrEmpty(BackupDirectory))
        {
            errors.Add("BackupDirectory is required when EnableAutoBackup is true");
        }

        if (BackupIntervalHours < 1 || BackupIntervalHours > 168) // 1 hour to 1 week
        {
            errors.Add("BackupIntervalHours must be between 1 and 168");
        }

        if (MaxBackupFiles < 1 || MaxBackupFiles > 100)
        {
            errors.Add("MaxBackupFiles must be between 1 and 100");
        }

        return errors;
    }

    /// <summary>
    /// Creates a copy of these backup options.
    /// </summary>
    public BackupOptions Clone()
    {
        return new BackupOptions
        {
            EnableAutoBackup = EnableAutoBackup,
            BackupDirectory = BackupDirectory,
            BackupIntervalHours = BackupIntervalHours,
            MaxBackupFiles = MaxBackupFiles,
            EncryptBackups = EncryptBackups
        };
    }
}