using LibEmiddle.Domain.Enums;
using LibEmiddle.Domain;

namespace LibEmiddle.API.Builders
{
    /// <summary>
    /// Builder interface for security configuration.
    /// </summary>
    public interface ISecurityOptionsBuilder
    {
        /// <summary>
        /// Requires perfect forward secrecy for all sessions.
        /// </summary>
        ISecurityOptionsBuilder RequirePerfectForwardSecrecy();

        /// <summary>
        /// Requires message authentication for all messages.
        /// </summary>
        ISecurityOptionsBuilder RequireMessageAuthentication();

        /// <summary>
        /// Sets the minimum protocol version.
        /// </summary>
        /// <param name="version">Minimum protocol version string.</param>
        ISecurityOptionsBuilder SetMinimumProtocolVersion(string version);

        /// <summary>
        /// Allows insecure connections (HTTP instead of HTTPS).
        /// </summary>
        ISecurityOptionsBuilder AllowInsecureConnections();

        /// <summary>
        /// Enables post-quantum cryptography fallback.
        /// </summary>
        ISecurityOptionsBuilder EnablePostQuantumFallback();

        /// <summary>
        /// Sets the key exchange mode.
        /// </summary>
        /// <param name="mode">Key exchange mode to use.</param>
        ISecurityOptionsBuilder UseKeyExchangeMode(KeyExchangeMode mode);
    }

    /// <summary>
    /// Builder interface for multi-device configuration.
    /// </summary>
    public interface IMultiDeviceOptionsBuilder
    {
        /// <summary>
        /// Enables multi-device support.
        /// </summary>
        IMultiDeviceOptionsBuilder Enable();

        /// <summary>
        /// Disables multi-device support.
        /// </summary>
        IMultiDeviceOptionsBuilder Disable();

        /// <summary>
        /// Sets the maximum number of linked devices.
        /// </summary>
        /// <param name="maxDevices">Maximum number of devices that can be linked.</param>
        IMultiDeviceOptionsBuilder SetMaxLinkedDevices(int maxDevices);

        /// <summary>
        /// Enables automatic device synchronization.
        /// </summary>
        IMultiDeviceOptionsBuilder EnableAutomaticSync();
    }

    /// <summary>
    /// Builder interface for storage configuration.
    /// </summary>
    public interface IStorageOptionsBuilder
    {
        /// <summary>
        /// Sets the session storage path.
        /// </summary>
        /// <param name="path">Path where session data will be stored.</param>
        IStorageOptionsBuilder SetSessionPath(string path);

        /// <summary>
        /// Sets the key storage path.
        /// </summary>
        /// <param name="path">Path where keys will be stored.</param>
        IStorageOptionsBuilder SetKeyPath(string path);

        /// <summary>
        /// Enables session persistence.
        /// </summary>
        IStorageOptionsBuilder EnableSessionPersistence();

        /// <summary>
        /// Disables session persistence (in-memory only).
        /// </summary>
        IStorageOptionsBuilder DisableSessionPersistence();

        /// <summary>
        /// Enables secure memory for sensitive data.
        /// </summary>
        IStorageOptionsBuilder EnableSecureMemory();

        /// <summary>
        /// Sets the maximum message history per session.
        /// </summary>
        /// <param name="maxMessages">Maximum messages to keep in history.</param>
        IStorageOptionsBuilder SetMaxMessageHistory(int maxMessages);
    }

    /// <summary>
    /// Builder interface for logging configuration.
    /// </summary>
    public interface ILoggingOptionsBuilder
    {
        /// <summary>
        /// Sets the log level.
        /// </summary>
        /// <param name="level">Minimum log level to output.</param>
        ILoggingOptionsBuilder SetLogLevel(LogLevel level);

        /// <summary>
        /// Enables debug logging (warning: may log sensitive data).
        /// </summary>
        ILoggingOptionsBuilder EnableDebugLogging();

        /// <summary>
        /// Enables performance metrics collection.
        /// </summary>
        ILoggingOptionsBuilder EnablePerformanceMetrics();
    }

    /// <summary>
    /// Builder interface for performance configuration.
    /// </summary>
    public interface IPerformanceOptionsBuilder
    {
        /// <summary>
        /// Sets the network timeout.
        /// </summary>
        /// <param name="timeoutMs">Network timeout in milliseconds.</param>
        IPerformanceOptionsBuilder SetNetworkTimeout(int timeoutMs);

        /// <summary>
        /// Sets the maximum message size.
        /// </summary>
        /// <param name="sizeBytes">Maximum message size in bytes.</param>
        IPerformanceOptionsBuilder SetMaxMessageSize(int sizeBytes);

        /// <summary>
        /// Enables compression for network communications.
        /// </summary>
        IPerformanceOptionsBuilder EnableCompression();

        /// <summary>
        /// Sets the compression level.
        /// </summary>
        /// <param name="level">Compression level (1-9).</param>
        IPerformanceOptionsBuilder SetCompressionLevel(int level);

        /// <summary>
        /// Configures message batching.
        /// </summary>
        /// <param name="configure">Action to configure batching options.</param>
        IPerformanceOptionsBuilder WithBatching(Action<IBatchingOptionsBuilder> configure);

        /// <summary>
        /// Configures connection pooling.
        /// </summary>
        /// <param name="configure">Action to configure connection pool options.</param>
        IPerformanceOptionsBuilder WithConnectionPooling(Action<IConnectionPoolOptionsBuilder> configure);

        /// <summary>
        /// Configures resilience patterns (retry, circuit breaker, etc.).
        /// </summary>
        /// <param name="configure">Action to configure resilience options.</param>
        IPerformanceOptionsBuilder WithResilience(Action<IResilienceOptionsBuilder> configure);

        /// <summary>
        /// Configures session backup and restore functionality.
        /// </summary>
        /// <param name="configure">Action to configure backup options.</param>
        IPerformanceOptionsBuilder WithBackup(Action<IBackupOptionsBuilder> configure);
    }

    /// <summary>
    /// Builder interface for v2.5 features configuration.
    /// </summary>
    public interface IV25FeaturesBuilder
    {
        /// <summary>
        /// Enables async message streams.
        /// </summary>
        IV25FeaturesBuilder EnableAsyncMessageStreams();

        /// <summary>
        /// Enables message batching.
        /// </summary>
        IV25FeaturesBuilder EnableMessageBatching();

        /// <summary>
        /// Enables advanced group management.
        /// </summary>
        IV25FeaturesBuilder EnableAdvancedGroupManagement();

        /// <summary>
        /// Enables health monitoring.
        /// </summary>
        IV25FeaturesBuilder EnableHealthMonitoring();

        /// <summary>
        /// Enables pluggable storage providers.
        /// </summary>
        IV25FeaturesBuilder EnablePluggableStorage();

        /// <summary>
        /// Enables post-quantum crypto preparation.
        /// </summary>
        IV25FeaturesBuilder EnablePostQuantumPreparation();

        /// <summary>
        /// Enables WebRTC transport.
        /// </summary>
        IV25FeaturesBuilder EnableWebRTCTransport();

        /// <summary>
        /// Enables connection pooling.
        /// </summary>
        IV25FeaturesBuilder EnableConnectionPooling();

        /// <summary>
        /// Enables session backup and restore.
        /// </summary>
        IV25FeaturesBuilder EnableSessionBackup();

        /// <summary>
        /// Enables all stable v2.5 features.
        /// </summary>
        IV25FeaturesBuilder EnableAllStable();

        /// <summary>
        /// Enables all v2.5 features including experimental ones.
        /// </summary>
        IV25FeaturesBuilder EnableAllExperimental();

        /// <summary>
        /// Configures post-quantum cryptography options.
        /// </summary>
        /// <param name="configure">Action to configure post-quantum options.</param>
        IV25FeaturesBuilder WithPostQuantum(Action<IPostQuantumOptionsBuilder> configure);

        /// <summary>
        /// Configures WebRTC transport options.
        /// </summary>
        /// <param name="configure">Action to configure WebRTC options.</param>
        IV25FeaturesBuilder WithWebRTC(Action<IWebRTCOptionsBuilder> configure);

        /// <summary>
        /// Configures advanced key rotation policy options.
        /// </summary>
        /// <param name="configure">Action to configure key rotation policy.</param>
        IV25FeaturesBuilder WithAdvancedKeyRotation(Action<IKeyRotationPolicyBuilder> configure);
    }

    /// <summary>
    /// Builder interface for batching configuration.
    /// </summary>
    public interface IBatchingOptionsBuilder
    {
        /// <summary>
        /// Sets the maximum batch size.
        /// </summary>
        /// <param name="maxSize">Maximum number of messages per batch.</param>
        IBatchingOptionsBuilder SetMaxBatchSize(int maxSize);

        /// <summary>
        /// Sets the maximum batch delay.
        /// </summary>
        /// <param name="delayMs">Maximum delay in milliseconds before sending a partial batch.</param>
        IBatchingOptionsBuilder SetMaxDelay(int delayMs);

        /// <summary>
        /// Enables compression for batched messages.
        /// </summary>
        IBatchingOptionsBuilder EnableCompression();

        /// <summary>
        /// Sets the compression level for batched messages.
        /// </summary>
        /// <param name="level">Compression level to use.</param>
        IBatchingOptionsBuilder SetCompressionLevel(CompressionLevel level);

        /// <summary>
        /// Uses a preset configuration optimized for real-time messaging.
        /// </summary>
        IBatchingOptionsBuilder UseRealTimePreset();

        /// <summary>
        /// Uses a preset configuration optimized for high throughput.
        /// </summary>
        IBatchingOptionsBuilder UseHighThroughputPreset();

        /// <summary>
        /// Uses a preset configuration optimized for bandwidth-constrained environments.
        /// </summary>
        IBatchingOptionsBuilder UseBandwidthOptimizedPreset();
    }

    /// <summary>
    /// Builder interface for connection pool configuration.
    /// </summary>
    public interface IConnectionPoolOptionsBuilder
    {
        /// <summary>
        /// Sets the maximum number of connections in the pool.
        /// </summary>
        /// <param name="maxConnections">Maximum connections to maintain.</param>
        IConnectionPoolOptionsBuilder SetMaxConnections(int maxConnections);

        /// <summary>
        /// Sets the connection timeout.
        /// </summary>
        /// <param name="timeoutMs">Connection timeout in milliseconds.</param>
        IConnectionPoolOptionsBuilder SetConnectionTimeout(int timeoutMs);

        /// <summary>
        /// Sets the idle timeout for connections.
        /// </summary>
        /// <param name="timeoutMs">Idle timeout in milliseconds.</param>
        IConnectionPoolOptionsBuilder SetIdleTimeout(int timeoutMs);

        /// <summary>
        /// Enables connection validation before returning from pool.
        /// </summary>
        IConnectionPoolOptionsBuilder EnableConnectionValidation();

        /// <summary>
        /// Uses a preset configuration optimized for high performance.
        /// </summary>
        IConnectionPoolOptionsBuilder UseHighPerformancePreset();

        /// <summary>
        /// Uses a preset configuration optimized for resource-constrained environments.
        /// </summary>
        IConnectionPoolOptionsBuilder UseResourceConstrainedPreset();
    }

    /// <summary>
    /// Builder interface for post-quantum cryptography configuration (v2.5).
    /// </summary>
    public interface IPostQuantumOptionsBuilder
    {
        /// <summary>
        /// Sets the preferred post-quantum algorithm.
        /// </summary>
        /// <param name="algorithm">The algorithm to prefer.</param>
        IPostQuantumOptionsBuilder UseAlgorithm(PostQuantumAlgorithm algorithm);

        /// <summary>
        /// Sets the performance profile preference.
        /// </summary>
        /// <param name="profile">The performance profile to optimize for.</param>
        IPostQuantumOptionsBuilder UsePerformanceProfile(PostQuantumPerformance profile);

        /// <summary>
        /// Sets the minimum security level required.
        /// </summary>
        /// <param name="level">Minimum security level in bits.</param>
        IPostQuantumOptionsBuilder RequireSecurityLevel(PostQuantumSecurityLevel level);

        /// <summary>
        /// Requires NIST-approved algorithms only.
        /// </summary>
        IPostQuantumOptionsBuilder RequireNistApproved();

        /// <summary>
        /// Allows non-NIST-approved algorithms for experimentation.
        /// </summary>
        IPostQuantumOptionsBuilder AllowExperimentalAlgorithms();

        /// <summary>
        /// Enables hybrid mode (classical + post-quantum).
        /// </summary>
        IPostQuantumOptionsBuilder EnableHybridMode();

        /// <summary>
        /// Disables hybrid mode (post-quantum only).
        /// </summary>
        IPostQuantumOptionsBuilder DisableHybridMode();

        /// <summary>
        /// Enables side-channel protection.
        /// </summary>
        IPostQuantumOptionsBuilder EnableSideChannelProtection();

        /// <summary>
        /// Sets key expiration time.
        /// </summary>
        /// <param name="expiration">How long keys should be valid.</param>
        IPostQuantumOptionsBuilder SetKeyExpiration(TimeSpan expiration);

        /// <summary>
        /// Sets maximum acceptable key size.
        /// </summary>
        /// <param name="maxSize">Maximum key size in bytes.</param>
        IPostQuantumOptionsBuilder SetMaxKeySize(int maxSize);

        /// <summary>
        /// Sets maximum acceptable signature size.
        /// </summary>
        /// <param name="maxSize">Maximum signature size in bytes.</param>
        IPostQuantumOptionsBuilder SetMaxSignatureSize(int maxSize);

        /// <summary>
        /// Enables key caching for performance.
        /// </summary>
        /// <param name="maxCachedKeys">Maximum number of keys to cache.</param>
        IPostQuantumOptionsBuilder EnableKeyCaching(int maxCachedKeys = 10);

        /// <summary>
        /// Enables performance monitoring.
        /// </summary>
        IPostQuantumOptionsBuilder EnablePerformanceMonitoring();

        /// <summary>
        /// Uses preset configuration optimized for speed.
        /// </summary>
        IPostQuantumOptionsBuilder UseSpeedPreset();

        /// <summary>
        /// Uses preset configuration optimized for security.
        /// </summary>
        IPostQuantumOptionsBuilder UseSecurityPreset();

        /// <summary>
        /// Uses preset configuration optimized for size.
        /// </summary>
        IPostQuantumOptionsBuilder UseSizePreset();

        /// <summary>
        /// Uses preset configuration for hybrid classical + post-quantum mode.
        /// </summary>
        IPostQuantumOptionsBuilder UseHybridPreset();
    }

    /// <summary>
    /// Builder interface for resilience configuration (v2.5).
    /// </summary>
    public interface IResilienceOptionsBuilder
    {
        /// <summary>
        /// Configures retry policy settings.
        /// </summary>
        /// <param name="configure">Action to configure retry policy.</param>
        IResilienceOptionsBuilder WithRetryPolicy(Action<IRetryPolicyBuilder> configure);

        /// <summary>
        /// Configures circuit breaker policy settings.
        /// </summary>
        /// <param name="configure">Action to configure circuit breaker policy.</param>
        IResilienceOptionsBuilder WithCircuitBreaker(Action<ICircuitBreakerPolicyBuilder> configure);

        /// <summary>
        /// Configures timeout policy settings.
        /// </summary>
        /// <param name="configure">Action to configure timeout policy.</param>
        IResilienceOptionsBuilder WithTimeoutPolicy(Action<ITimeoutPolicyBuilder> configure);

        /// <summary>
        /// Enables automatic failover to backup endpoints.
        /// </summary>
        /// <param name="fallbackEndpoints">List of fallback endpoints.</param>
        IResilienceOptionsBuilder EnableFailover(params string[] fallbackEndpoints);

        /// <summary>
        /// Enables jitter in retry delays to prevent thundering herd.
        /// </summary>
        IResilienceOptionsBuilder EnableJitter();

        /// <summary>
        /// Disables jitter in retry delays.
        /// </summary>
        IResilienceOptionsBuilder DisableJitter();

        /// <summary>
        /// Uses preset configuration optimized for aggressive fault tolerance.
        /// </summary>
        IResilienceOptionsBuilder UseAggressivePreset();

        /// <summary>
        /// Uses preset configuration optimized for conservative fault tolerance.
        /// </summary>
        IResilienceOptionsBuilder UseConservativePreset();

        /// <summary>
        /// Disables all resilience features for testing.
        /// </summary>
        IResilienceOptionsBuilder DisableForTesting();
    }

    /// <summary>
    /// Builder interface for retry policy configuration.
    /// </summary>
    public interface IRetryPolicyBuilder
    {
        /// <summary>
        /// Sets the maximum number of retry attempts.
        /// </summary>
        /// <param name="maxRetries">Maximum number of retries.</param>
        IRetryPolicyBuilder SetMaxRetries(int maxRetries);

        /// <summary>
        /// Sets the base delay between retries.
        /// </summary>
        /// <param name="baseDelay">Base delay duration.</param>
        IRetryPolicyBuilder SetBaseDelay(TimeSpan baseDelay);

        /// <summary>
        /// Sets the maximum delay between retries.
        /// </summary>
        /// <param name="maxDelay">Maximum delay duration.</param>
        IRetryPolicyBuilder SetMaxDelay(TimeSpan maxDelay);

        /// <summary>
        /// Sets the exponential backoff multiplier.
        /// </summary>
        /// <param name="multiplier">Backoff multiplier.</param>
        IRetryPolicyBuilder SetBackoffMultiplier(double multiplier);

        /// <summary>
        /// Enables exponential backoff.
        /// </summary>
        IRetryPolicyBuilder EnableExponentialBackoff();

        /// <summary>
        /// Disables exponential backoff (uses linear backoff).
        /// </summary>
        IRetryPolicyBuilder DisableExponentialBackoff();
    }

    /// <summary>
    /// Builder interface for circuit breaker policy configuration.
    /// </summary>
    public interface ICircuitBreakerPolicyBuilder
    {
        /// <summary>
        /// Sets the number of consecutive failures before opening the circuit.
        /// </summary>
        /// <param name="threshold">Failure threshold.</param>
        ICircuitBreakerPolicyBuilder SetFailureThreshold(int threshold);

        /// <summary>
        /// Sets the time to wait before attempting to close the circuit.
        /// </summary>
        /// <param name="timeout">Recovery timeout duration.</param>
        ICircuitBreakerPolicyBuilder SetRecoveryTimeout(TimeSpan timeout);

        /// <summary>
        /// Sets the minimum number of requests in the sampling period.
        /// </summary>
        /// <param name="throughput">Minimum throughput.</param>
        ICircuitBreakerPolicyBuilder SetMinimumThroughput(int throughput);

        /// <summary>
        /// Sets the sampling period for calculating failure rate.
        /// </summary>
        /// <param name="period">Sampling period duration.</param>
        ICircuitBreakerPolicyBuilder SetSamplingPeriod(TimeSpan period);
    }

    /// <summary>
    /// Builder interface for timeout policy configuration.
    /// </summary>
    public interface ITimeoutPolicyBuilder
    {
        /// <summary>
        /// Sets the default timeout for operations.
        /// </summary>
        /// <param name="timeout">Default timeout duration.</param>
        ITimeoutPolicyBuilder SetDefaultTimeout(TimeSpan timeout);

        /// <summary>
        /// Sets the timeout for connection establishment.
        /// </summary>
        /// <param name="timeout">Connection timeout duration.</param>
        ITimeoutPolicyBuilder SetConnectionTimeout(TimeSpan timeout);

        /// <summary>
        /// Sets the timeout for sending data.
        /// </summary>
        /// <param name="timeout">Send timeout duration.</param>
        ITimeoutPolicyBuilder SetSendTimeout(TimeSpan timeout);

        /// <summary>
        /// Sets the timeout for receiving data.
        /// </summary>
        /// <param name="timeout">Receive timeout duration.</param>
        ITimeoutPolicyBuilder SetReceiveTimeout(TimeSpan timeout);
    }

    /// <summary>
    /// Builder interface for backup configuration (v2.5).
    /// </summary>
    public interface IBackupOptionsBuilder
    {
        /// <summary>
        /// Sets the backup directory path.
        /// </summary>
        /// <param name="path">Directory where backups will be stored.</param>
        IBackupOptionsBuilder SetBackupPath(string path);

        /// <summary>
        /// Sets the backup file naming pattern.
        /// </summary>
        /// <param name="pattern">Pattern with placeholders like {timestamp}, {device}, etc.</param>
        IBackupOptionsBuilder SetFilePattern(string pattern);

        /// <summary>
        /// Enables compression for backup files.
        /// </summary>
        IBackupOptionsBuilder EnableCompression();

        /// <summary>
        /// Disables compression for backup files.
        /// </summary>
        IBackupOptionsBuilder DisableCompression();

        /// <summary>
        /// Sets the backup retention period.
        /// </summary>
        /// <param name="retention">How long to keep backup files.</param>
        IBackupOptionsBuilder SetRetention(TimeSpan retention);

        /// <summary>
        /// Sets the maximum number of backup files to keep.
        /// </summary>
        /// <param name="maxFiles">Maximum backup files to retain.</param>
        IBackupOptionsBuilder SetMaxBackupFiles(int maxFiles);

        /// <summary>
        /// Includes message history in backups.
        /// </summary>
        IBackupOptionsBuilder IncludeMessageHistory();

        /// <summary>
        /// Excludes message history from backups.
        /// </summary>
        IBackupOptionsBuilder ExcludeMessageHistory();

        /// <summary>
        /// Includes one-time keys in backups.
        /// </summary>
        IBackupOptionsBuilder IncludeOneTimeKeys();

        /// <summary>
        /// Excludes one-time keys from backups.
        /// </summary>
        IBackupOptionsBuilder ExcludeOneTimeKeys();

        /// <summary>
        /// Enables automatic backup creation.
        /// </summary>
        /// <param name="interval">Interval between automatic backups.</param>
        IBackupOptionsBuilder EnableAutoBackup(TimeSpan interval);

        /// <summary>
        /// Disables automatic backup creation.
        /// </summary>
        IBackupOptionsBuilder DisableAutoBackup();

        /// <summary>
        /// Enables backup verification after creation.
        /// </summary>
        IBackupOptionsBuilder EnableVerification();

        /// <summary>
        /// Disables backup verification after creation.
        /// </summary>
        IBackupOptionsBuilder DisableVerification();

        /// <summary>
        /// Sets a custom encryption key for backups.
        /// </summary>
        /// <param name="encryptionKey">Custom encryption key bytes.</param>
        IBackupOptionsBuilder SetCustomEncryptionKey(byte[] encryptionKey);

        /// <summary>
        /// Uses the identity key for backup encryption (default).
        /// </summary>
        IBackupOptionsBuilder UseIdentityKeyEncryption();

        /// <summary>
        /// Uses preset configuration optimized for minimal storage usage.
        /// </summary>
        IBackupOptionsBuilder UseMinimalStoragePreset();

        /// <summary>
        /// Uses preset configuration optimized for comprehensive data protection.
        /// </summary>
        IBackupOptionsBuilder UseComprehensivePreset();

        /// <summary>
        /// Uses preset configuration optimized for development and testing.
        /// </summary>
        IBackupOptionsBuilder UseDevelopmentPreset();
    }

    /// <summary>
    /// Builder interface for WebRTC configuration (v2.5).
    /// </summary>
    public interface IWebRTCOptionsBuilder
    {
        /// <summary>
        /// Adds a STUN server for NAT traversal.
        /// </summary>
        /// <param name="stunUri">STUN server URI (e.g., "stun:stun.l.google.com:19302").</param>
        IWebRTCOptionsBuilder AddStunServer(string stunUri);

        /// <summary>
        /// Adds multiple STUN servers for NAT traversal.
        /// </summary>
        /// <param name="stunUris">STUN server URIs.</param>
        IWebRTCOptionsBuilder AddStunServers(params string[] stunUris);

        /// <summary>
        /// Adds a TURN server for relay connections.
        /// </summary>
        /// <param name="turnUri">TURN server URI.</param>
        /// <param name="username">Username for authentication.</param>
        /// <param name="credential">Credential for authentication.</param>
        IWebRTCOptionsBuilder AddTurnServer(string turnUri, string username, string credential);

        /// <summary>
        /// Sets the connection timeout.
        /// </summary>
        /// <param name="timeout">Maximum time to wait for connection establishment.</param>
        IWebRTCOptionsBuilder SetConnectionTimeout(TimeSpan timeout);

        /// <summary>
        /// Sets the keep-alive interval.
        /// </summary>
        /// <param name="interval">Interval for sending keep-alive messages.</param>
        IWebRTCOptionsBuilder SetKeepAliveInterval(TimeSpan interval);

        /// <summary>
        /// Enables automatic reconnection on connection loss.
        /// </summary>
        /// <param name="maxAttempts">Maximum number of reconnection attempts.</param>
        /// <param name="delay">Delay between reconnection attempts.</param>
        IWebRTCOptionsBuilder EnableAutoReconnect(int maxAttempts = 5, TimeSpan? delay = null);

        /// <summary>
        /// Disables automatic reconnection.
        /// </summary>
        IWebRTCOptionsBuilder DisableAutoReconnect();

        /// <summary>
        /// Prefers reliable data channels (TCP-like) over unreliable (UDP-like).
        /// </summary>
        IWebRTCOptionsBuilder PreferReliableChannels();

        /// <summary>
        /// Prefers unreliable data channels (UDP-like) for lower latency.
        /// </summary>
        IWebRTCOptionsBuilder PreferUnreliableChannels();

        /// <summary>
        /// Sets the maximum message size.
        /// </summary>
        /// <param name="sizeBytes">Maximum size for individual messages in bytes.</param>
        IWebRTCOptionsBuilder SetMaxMessageSize(int sizeBytes);

        /// <summary>
        /// Sets buffer sizes for data channels.
        /// </summary>
        /// <param name="receiveBufferSize">Buffer size for incoming data.</param>
        /// <param name="sendBufferSize">Buffer size for outgoing data.</param>
        IWebRTCOptionsBuilder SetBufferSizes(int receiveBufferSize, int sendBufferSize);

        /// <summary>
        /// Enables data channel compression.
        /// </summary>
        IWebRTCOptionsBuilder EnableCompression();

        /// <summary>
        /// Disables data channel compression.
        /// </summary>
        IWebRTCOptionsBuilder DisableCompression();

        /// <summary>
        /// Enables additional data channel encryption (beyond DTLS).
        /// </summary>
        IWebRTCOptionsBuilder EnableDataChannelEncryption();

        /// <summary>
        /// Disables additional data channel encryption.
        /// </summary>
        IWebRTCOptionsBuilder DisableDataChannelEncryption();

        /// <summary>
        /// Sets the minimum network quality required to maintain connection.
        /// </summary>
        /// <param name="level">Minimum network quality level.</param>
        IWebRTCOptionsBuilder SetMinNetworkQuality(WebRTCNetworkQualityLevel level);

        /// <summary>
        /// Enables network quality monitoring.
        /// </summary>
        /// <param name="checkInterval">Interval for network quality checks.</param>
        IWebRTCOptionsBuilder EnableNetworkQualityMonitoring(TimeSpan? checkInterval = null);

        /// <summary>
        /// Disables network quality monitoring.
        /// </summary>
        IWebRTCOptionsBuilder DisableNetworkQualityMonitoring();

        /// <summary>
        /// Enables detailed statistics collection.
        /// </summary>
        IWebRTCOptionsBuilder EnableDetailedStatistics();

        /// <summary>
        /// Disables detailed statistics collection.
        /// </summary>
        IWebRTCOptionsBuilder DisableDetailedStatistics();

        /// <summary>
        /// Sets the signaling server endpoint for connection coordination.
        /// </summary>
        /// <param name="endpoint">Signaling server endpoint URL.</param>
        IWebRTCOptionsBuilder SetSignalingServer(string endpoint);

        /// <summary>
        /// Forces relay connections (disables direct P2P).
        /// </summary>
        IWebRTCOptionsBuilder ForceRelay();

        /// <summary>
        /// Allows direct peer-to-peer connections.
        /// </summary>
        IWebRTCOptionsBuilder AllowDirectP2P();

        /// <summary>
        /// Uses preset configuration optimized for low-latency applications.
        /// </summary>
        IWebRTCOptionsBuilder UseLowLatencyPreset();

        /// <summary>
        /// Uses preset configuration optimized for reliability.
        /// </summary>
        IWebRTCOptionsBuilder UseHighReliabilityPreset();

        /// <summary>
        /// Uses preset configuration optimized for mobile devices.
        /// </summary>
        IWebRTCOptionsBuilder UseMobileOptimizedPreset();

        /// <summary>
        /// Uses preset configuration for development and testing.
        /// </summary>
        IWebRTCOptionsBuilder UseDevelopmentPreset();
    }

    /// <summary>
    /// Builder interface for advanced key rotation policy configuration (v2.5).
    /// </summary>
    public interface IKeyRotationPolicyBuilder
    {
        /// <summary>
        /// Sets the key rotation trigger type.
        /// </summary>
        /// <param name="triggerType">Type of trigger to use for rotation.</param>
        IKeyRotationPolicyBuilder SetTriggerType(KeyRotationTriggerType triggerType);

        /// <summary>
        /// Sets the message count threshold for rotation.
        /// </summary>
        /// <param name="messageCount">Number of messages before rotation.</param>
        IKeyRotationPolicyBuilder SetMessageCountThreshold(int messageCount);

        /// <summary>
        /// Sets the time interval threshold for rotation.
        /// </summary>
        /// <param name="interval">Time interval before rotation.</param>
        IKeyRotationPolicyBuilder SetTimeIntervalThreshold(TimeSpan interval);

        /// <summary>
        /// Sets the data volume threshold for rotation.
        /// </summary>
        /// <param name="dataVolume">Data volume in bytes before rotation.</param>
        IKeyRotationPolicyBuilder SetDataVolumeThreshold(long dataVolume);

        /// <summary>
        /// Enables adaptive rotation based on risk assessment.
        /// </summary>
        /// <param name="configure">Action to configure risk factors.</param>
        IKeyRotationPolicyBuilder EnableAdaptiveRotation(Action<IKeyRotationRiskFactorsBuilder>? configure = null);

        /// <summary>
        /// Disables adaptive rotation.
        /// </summary>
        IKeyRotationPolicyBuilder DisableAdaptiveRotation();

        /// <summary>
        /// Sets the minimum rotation interval to prevent excessive rotation.
        /// </summary>
        /// <param name="interval">Minimum time between rotations.</param>
        IKeyRotationPolicyBuilder SetMinRotationInterval(TimeSpan interval);

        /// <summary>
        /// Sets the maximum rotation interval for security compliance.
        /// </summary>
        /// <param name="interval">Maximum time between rotations.</param>
        IKeyRotationPolicyBuilder SetMaxRotationInterval(TimeSpan interval);

        /// <summary>
        /// Enables rotation on session start.
        /// </summary>
        IKeyRotationPolicyBuilder RotateOnSessionStart();

        /// <summary>
        /// Enables rotation on session end.
        /// </summary>
        IKeyRotationPolicyBuilder RotateOnSessionEnd();

        /// <summary>
        /// Enables rotation when a device joins.
        /// </summary>
        IKeyRotationPolicyBuilder RotateOnDeviceJoin();

        /// <summary>
        /// Enables rotation when a device leaves.
        /// </summary>
        IKeyRotationPolicyBuilder RotateOnDeviceLeave();

        /// <summary>
        /// Sets a custom rotation schedule.
        /// </summary>
        /// <param name="configure">Action to configure the schedule.</param>
        IKeyRotationPolicyBuilder SetCustomSchedule(Action<IKeyRotationScheduleBuilder> configure);

        /// <summary>
        /// Configures performance optimization settings.
        /// </summary>
        /// <param name="configure">Action to configure performance settings.</param>
        IKeyRotationPolicyBuilder WithPerformanceSettings(Action<IKeyRotationPerformanceBuilder> configure);

        /// <summary>
        /// Configures compliance settings.
        /// </summary>
        /// <param name="configure">Action to configure compliance settings.</param>
        IKeyRotationPolicyBuilder WithComplianceSettings(Action<IKeyRotationComplianceBuilder> configure);

        /// <summary>
        /// Uses preset configuration for maximum security.
        /// </summary>
        IKeyRotationPolicyBuilder UseMaximumSecurityPreset();

        /// <summary>
        /// Uses preset configuration balanced between security and performance.
        /// </summary>
        IKeyRotationPolicyBuilder UseBalancedPreset();

        /// <summary>
        /// Uses preset configuration optimized for performance.
        /// </summary>
        IKeyRotationPolicyBuilder UsePerformanceOptimizedPreset();

        /// <summary>
        /// Uses preset configuration for regulatory compliance.
        /// </summary>
        IKeyRotationPolicyBuilder UseRegulatoryCompliancePreset();
    }

    /// <summary>
    /// Builder interface for key rotation risk factors configuration.
    /// </summary>
    public interface IKeyRotationRiskFactorsBuilder
    {
        /// <summary>
        /// Sets the failed authentication threshold.
        /// </summary>
        /// <param name="threshold">Number of failed attempts that trigger rotation.</param>
        IKeyRotationRiskFactorsBuilder SetFailedAuthThreshold(int threshold);

        /// <summary>
        /// Sets the suspicious activity threshold.
        /// </summary>
        /// <param name="threshold">Number of suspicious activities that trigger rotation.</param>
        IKeyRotationRiskFactorsBuilder SetSuspiciousActivityThreshold(int threshold);

        /// <summary>
        /// Enables rotation on potential compromise detection.
        /// </summary>
        IKeyRotationRiskFactorsBuilder RotateOnCompromiseDetection();

        /// <summary>
        /// Enables rotation when connecting from a new location.
        /// </summary>
        IKeyRotationRiskFactorsBuilder RotateOnNewLocation();

        /// <summary>
        /// Enables rotation when security software updates are detected.
        /// </summary>
        IKeyRotationRiskFactorsBuilder RotateOnSecurityUpdates();

        /// <summary>
        /// Sets the risk assessment time window.
        /// </summary>
        /// <param name="window">Time window for risk assessment.</param>
        IKeyRotationRiskFactorsBuilder SetRiskAssessmentWindow(TimeSpan window);

        /// <summary>
        /// Uses high security risk factors preset.
        /// </summary>
        IKeyRotationRiskFactorsBuilder UseHighSecurityPreset();

        /// <summary>
        /// Uses moderate security risk factors preset.
        /// </summary>
        IKeyRotationRiskFactorsBuilder UseModeratePreset();
    }

    /// <summary>
    /// Builder interface for key rotation schedule configuration.
    /// </summary>
    public interface IKeyRotationScheduleBuilder
    {
        /// <summary>
        /// Adds a scheduled time for rotation.
        /// </summary>
        /// <param name="time">Time of day for rotation.</param>
        IKeyRotationScheduleBuilder AddScheduledTime(TimeOnly time);

        /// <summary>
        /// Adds multiple scheduled times for rotation.
        /// </summary>
        /// <param name="times">Times of day for rotation.</param>
        IKeyRotationScheduleBuilder AddScheduledTimes(params TimeOnly[] times);

        /// <summary>
        /// Adds a scheduled day for rotation.
        /// </summary>
        /// <param name="day">Day of the week for rotation.</param>
        IKeyRotationScheduleBuilder AddScheduledDay(DayOfWeek day);

        /// <summary>
        /// Adds multiple scheduled days for rotation.
        /// </summary>
        /// <param name="days">Days of the week for rotation.</param>
        IKeyRotationScheduleBuilder AddScheduledDays(params DayOfWeek[] days);

        /// <summary>
        /// Sets the time zone for the schedule.
        /// </summary>
        /// <param name="timeZone">Time zone identifier.</param>
        IKeyRotationScheduleBuilder SetTimeZone(string timeZone);

        /// <summary>
        /// Enables the rotation schedule.
        /// </summary>
        IKeyRotationScheduleBuilder Enable();

        /// <summary>
        /// Disables the rotation schedule.
        /// </summary>
        IKeyRotationScheduleBuilder Disable();
    }

    /// <summary>
    /// Builder interface for key rotation performance settings.
    /// </summary>
    public interface IKeyRotationPerformanceBuilder
    {
        /// <summary>
        /// Enables batching of multiple rotations.
        /// </summary>
        /// <param name="maxBatchSize">Maximum number of rotations to batch.</param>
        /// <param name="batchTimeout">Maximum time to wait for batch completion.</param>
        IKeyRotationPerformanceBuilder EnableBatching(int maxBatchSize = 5, TimeSpan? batchTimeout = null);

        /// <summary>
        /// Disables batching of rotations.
        /// </summary>
        IKeyRotationPerformanceBuilder DisableBatching();

        /// <summary>
        /// Enables background rotation to avoid blocking operations.
        /// </summary>
        IKeyRotationPerformanceBuilder EnableBackgroundRotation();

        /// <summary>
        /// Disables background rotation.
        /// </summary>
        IKeyRotationPerformanceBuilder DisableBackgroundRotation();

        /// <summary>
        /// Sets the priority for rotation operations.
        /// </summary>
        /// <param name="priority">Priority level for rotations.</param>
        IKeyRotationPerformanceBuilder SetPriority(KeyRotationPriority priority);

        /// <summary>
        /// Sets the maximum time for a single rotation operation.
        /// </summary>
        /// <param name="maxTime">Maximum rotation time.</param>
        IKeyRotationPerformanceBuilder SetMaxRotationTime(TimeSpan maxTime);

        /// <summary>
        /// Uses high performance settings preset.
        /// </summary>
        IKeyRotationPerformanceBuilder UseHighPerformancePreset();

        /// <summary>
        /// Uses balanced performance settings preset.
        /// </summary>
        IKeyRotationPerformanceBuilder UseBalancedPreset();
    }

    /// <summary>
    /// Builder interface for key rotation compliance settings.
    /// </summary>
    public interface IKeyRotationComplianceBuilder
    {
        /// <summary>
        /// Enables audit logging of all key rotations.
        /// </summary>
        IKeyRotationComplianceBuilder EnableAuditLogging();

        /// <summary>
        /// Disables audit logging.
        /// </summary>
        IKeyRotationComplianceBuilder DisableAuditLogging();

        /// <summary>
        /// Requires confirmation from multiple parties for rotation.
        /// </summary>
        /// <param name="minParties">Minimum number of parties required for confirmation.</param>
        IKeyRotationComplianceBuilder RequireMultiPartyConfirmation(int minParties = 2);

        /// <summary>
        /// Disables multi-party confirmation requirement.
        /// </summary>
        IKeyRotationComplianceBuilder DisableMultiPartyConfirmation();

        /// <summary>
        /// Enforces strict rotation timing requirements.
        /// </summary>
        IKeyRotationComplianceBuilder EnforceStrictTiming();

        /// <summary>
        /// Sets the compliance standard being followed.
        /// </summary>
        /// <param name="standard">Compliance standard name.</param>
        IKeyRotationComplianceBuilder SetComplianceStandard(string standard);

        /// <summary>
        /// Prevents rotation rollback for compliance.
        /// </summary>
        IKeyRotationComplianceBuilder PreventRollback();

        /// <summary>
        /// Allows rotation rollback.
        /// </summary>
        IKeyRotationComplianceBuilder AllowRollback();

        /// <summary>
        /// Uses strict compliance settings preset.
        /// </summary>
        IKeyRotationComplianceBuilder UseStrictCompliancePreset();
    }
}