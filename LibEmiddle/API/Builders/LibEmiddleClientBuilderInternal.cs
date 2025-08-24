using LibEmiddle.Domain.Enums;
using LibEmiddle.Domain;
using Microsoft.Extensions.Logging;

namespace LibEmiddle.API.Builders
{
    /// <summary>
    /// Implementation of the fluent client builder (v2.5).
    /// Builds LibEmiddleClientOptions and creates clients using the existing constructor.
    /// </summary>
    internal class LibEmiddleClientBuilderInternal : ILibEmiddleClientBuilder
    {
        private readonly LibEmiddleClientOptions _options = new();

        public ILibEmiddleClientBuilder WithIdentity(string keyPath)
        {
            _options.IdentityKeyPath = keyPath;
            return this;
        }

        public ILibEmiddleClientBuilder WithTransport<T>() where T : class
        {
            // Map common transport types
            var transportType = typeof(T).Name switch
            {
                "HttpMailboxTransport" => TransportType.Http,
                "WebSocketTransport" => TransportType.WebSocket,
                "WebRTCMailboxTransport" => TransportType.WebRTC,
                "InMemoryMailboxTransport" => TransportType.InMemory,
                _ => throw new ArgumentException($"Unknown transport type: {typeof(T).Name}")
            };

            _options.TransportType = transportType;
            return this;
        }

        public ILibEmiddleClientBuilder WithTransport(TransportType transportType, string? endpoint = null)
        {
            _options.TransportType = transportType;
            if (endpoint != null)
                _options.ServerEndpoint = endpoint;
            return this;
        }

        public ILibEmiddleClientBuilder WithSecurity(Action<ISecurityOptionsBuilder> configure)
        {
            var builder = new SecurityOptionsBuilder(_options);
            configure(builder);
            return this;
        }

        public ILibEmiddleClientBuilder WithMultiDevice(Action<IMultiDeviceOptionsBuilder> configure)
        {
            var builder = new MultiDeviceOptionsBuilder(_options);
            configure(builder);
            return this;
        }

        public ILibEmiddleClientBuilder WithStorage(Action<IStorageOptionsBuilder> configure)
        {
            var builder = new StorageOptionsBuilder(_options);
            configure(builder);
            return this;
        }

        public ILibEmiddleClientBuilder WithLogging(ILogger logger)
        {
            // Store the logger instance in the options for use by the client
            // This would require adding a Logger property to LibEmiddleClientOptions
            // For now, we'll set debug logging if a logger is provided
            _options.EnableDebugLogging = true;
            _options.LogLevel = LogLevel.Debug;
            return this;
        }

        public ILibEmiddleClientBuilder WithLogging(Action<ILoggingOptionsBuilder> configure)
        {
            var builder = new LoggingOptionsBuilder(_options);
            configure(builder);
            return this;
        }

        public ILibEmiddleClientBuilder WithPerformance(Action<IPerformanceOptionsBuilder> configure)
        {
            var builder = new PerformanceOptionsBuilder(_options);
            configure(builder);
            return this;
        }

        public ILibEmiddleClientBuilder WithV25Features(Action<IV25FeaturesBuilder> configure)
        {
            var builder = new V25FeaturesBuilder(_options);
            configure(builder);
            return this;
        }

        public ILibEmiddleClientBuilder EnableStableBeta()
        {
            // Enable all stable v2.5 features for beta testing
            var builder = new V25FeaturesBuilder(_options);
            builder.EnableAllStable();
            return this;
        }

        public ILibEmiddleClientBuilder WithCustomOptions(Action<LibEmiddleClientOptions> configure)
        {
            configure(_options);
            return this;
        }

        public LibEmiddleClient Build()
        {
            return new LibEmiddleClient(_options);
        }

        public LibEmiddleClientOptions BuildOptions()
        {
            return _options;
        }
    }

    internal class SecurityOptionsBuilder : ISecurityOptionsBuilder
    {
        private readonly LibEmiddleClientOptions _options;

        public SecurityOptionsBuilder(LibEmiddleClientOptions options)
        {
            _options = options;
        }

        public ISecurityOptionsBuilder RequirePerfectForwardSecrecy()
        {
            _options.SecurityPolicy.RequirePerfectForwardSecrecy = true;
            return this;
        }

        public ISecurityOptionsBuilder RequireMessageAuthentication()
        {
            _options.SecurityPolicy.RequireMessageAuthentication = true;
            return this;
        }

        public ISecurityOptionsBuilder SetMinimumProtocolVersion(string version)
        {
            _options.SecurityPolicy.MinimumProtocolVersion = version;
            return this;
        }

        public ISecurityOptionsBuilder AllowInsecureConnections()
        {
            _options.SecurityPolicy.AllowInsecureConnections = true;
            return this;
        }

        public ISecurityOptionsBuilder EnablePostQuantumFallback()
        {
            _options.SecurityPolicy.EnablePostQuantumFallback = true;
            return this;
        }

        public ISecurityOptionsBuilder UseKeyExchangeMode(KeyExchangeMode mode)
        {
            _options.SecurityPolicy.KeyExchangeMode = mode;
            return this;
        }
    }

    internal class MultiDeviceOptionsBuilder : IMultiDeviceOptionsBuilder
    {
        private readonly LibEmiddleClientOptions _options;

        public MultiDeviceOptionsBuilder(LibEmiddleClientOptions options)
        {
            _options = options;
        }

        public IMultiDeviceOptionsBuilder Enable()
        {
            _options.MultiDeviceOptions.Enabled = true;
            return this;
        }

        public IMultiDeviceOptionsBuilder Disable()
        {
            _options.MultiDeviceOptions.Enabled = false;
            return this;
        }

        public IMultiDeviceOptionsBuilder SetMaxLinkedDevices(int maxDevices)
        {
            _options.MultiDeviceOptions.MaxLinkedDevices = maxDevices;
            return this;
        }

        public IMultiDeviceOptionsBuilder EnableAutomaticSync()
        {
            _options.MultiDeviceOptions.AutomaticSyncEnabled = true;
            return this;
        }
    }

    internal class StorageOptionsBuilder : IStorageOptionsBuilder
    {
        private readonly LibEmiddleClientOptions _options;

        public StorageOptionsBuilder(LibEmiddleClientOptions options)
        {
            _options = options;
        }

        public IStorageOptionsBuilder SetSessionPath(string path)
        {
            _options.SessionStoragePath = path;
            return this;
        }

        public IStorageOptionsBuilder SetKeyPath(string path)
        {
            _options.KeyStoragePath = path;
            return this;
        }

        public IStorageOptionsBuilder EnableSessionPersistence()
        {
            _options.EnableSessionPersistence = true;
            return this;
        }

        public IStorageOptionsBuilder DisableSessionPersistence()
        {
            _options.EnableSessionPersistence = false;
            return this;
        }

        public IStorageOptionsBuilder EnableSecureMemory()
        {
            _options.EnableSecureMemory = true;
            return this;
        }

        public IStorageOptionsBuilder SetMaxMessageHistory(int maxMessages)
        {
            _options.MaxMessageHistoryPerSession = maxMessages;
            return this;
        }
    }

    internal class LoggingOptionsBuilder : ILoggingOptionsBuilder
    {
        private readonly LibEmiddleClientOptions _options;

        public LoggingOptionsBuilder(LibEmiddleClientOptions options)
        {
            _options = options;
        }

        public ILoggingOptionsBuilder SetLogLevel(LogLevel level)
        {
            _options.LogLevel = level;
            return this;
        }

        public ILoggingOptionsBuilder EnableDebugLogging()
        {
            _options.EnableDebugLogging = true;
            return this;
        }

        public ILoggingOptionsBuilder EnablePerformanceMetrics()
        {
            _options.EnablePerformanceMetrics = true;
            return this;
        }
    }

    internal class PerformanceOptionsBuilder : IPerformanceOptionsBuilder
    {
        private readonly LibEmiddleClientOptions _options;

        public PerformanceOptionsBuilder(LibEmiddleClientOptions options)
        {
            _options = options;
        }

        public IPerformanceOptionsBuilder SetNetworkTimeout(int timeoutMs)
        {
            _options.NetworkTimeoutMs = timeoutMs;
            return this;
        }

        public IPerformanceOptionsBuilder SetMaxMessageSize(int sizeBytes)
        {
            _options.MaxMessageSizeBytes = sizeBytes;
            return this;
        }

        public IPerformanceOptionsBuilder EnableCompression()
        {
            _options.EnableCompression = true;
            return this;
        }

        public IPerformanceOptionsBuilder SetCompressionLevel(int level)
        {
            _options.CompressionLevel = level;
            return this;
        }

        public IPerformanceOptionsBuilder WithBatching(Action<IBatchingOptionsBuilder> configure)
        {
            _options.V25Features.EnableMessageBatching = true;
            _options.BatchingOptions ??= new Domain.BatchingOptions();
            
            var builder = new BatchingOptionsBuilder(_options.BatchingOptions);
            configure(builder);
            return this;
        }

        public IPerformanceOptionsBuilder WithConnectionPooling(Action<IConnectionPoolOptionsBuilder> configure)
        {
            _options.V25Features.EnableConnectionPooling = true;
            _options.ConnectionPoolOptions ??= new Domain.ConnectionPoolOptions();
            
            var builder = new ConnectionPoolOptionsBuilder(_options.ConnectionPoolOptions);
            configure(builder);
            return this;
        }

        public IPerformanceOptionsBuilder WithResilience(Action<IResilienceOptionsBuilder> configure)
        {
            _options.ResilienceOptions ??= new Domain.ResilienceOptions();
            
            var builder = new ResilienceOptionsBuilder(_options.ResilienceOptions);
            configure(builder);
            return this;
        }

        public IPerformanceOptionsBuilder WithBackup(Action<IBackupOptionsBuilder> configure)
        {
            _options.V25Features.EnableSessionBackup = true;
            _options.EnhancedBackupOptions ??= new Domain.BackupOptions();
            
            var builder = new BackupOptionsBuilder(_options.EnhancedBackupOptions);
            configure(builder);
            return this;
        }
    }

    internal class V25FeaturesBuilder : IV25FeaturesBuilder
    {
        private readonly LibEmiddleClientOptions _options;

        public V25FeaturesBuilder(LibEmiddleClientOptions options)
        {
            _options = options;
        }

        public IV25FeaturesBuilder EnableAsyncMessageStreams()
        {
            _options.V25Features.EnableAsyncMessageStreams = true;
            return this;
        }

        public IV25FeaturesBuilder EnableMessageBatching()
        {
            _options.V25Features.EnableMessageBatching = true;
            return this;
        }

        public IV25FeaturesBuilder EnableAdvancedGroupManagement()
        {
            _options.V25Features.EnableAdvancedGroupManagement = true;
            return this;
        }

        public IV25FeaturesBuilder EnableHealthMonitoring()
        {
            _options.V25Features.EnableHealthMonitoring = true;
            return this;
        }

        public IV25FeaturesBuilder EnablePluggableStorage()
        {
            _options.V25Features.EnablePluggableStorage = true;
            return this;
        }

        public IV25FeaturesBuilder EnablePostQuantumPreparation()
        {
            _options.V25Features.EnablePostQuantumPreparation = true;
            return this;
        }

        public IV25FeaturesBuilder EnableWebRTCTransport()
        {
            _options.V25Features.EnableWebRTCTransport = true;
            return this;
        }

        public IV25FeaturesBuilder EnableConnectionPooling()
        {
            _options.V25Features.EnableConnectionPooling = true;
            return this;
        }

        public IV25FeaturesBuilder EnableSessionBackup()
        {
            _options.V25Features.EnableSessionBackup = true;
            return this;
        }

        public IV25FeaturesBuilder EnableAllStable()
        {
            _options.V25Features.EnableMessageBatching = true;
            _options.V25Features.EnableAdvancedGroupManagement = true;
            _options.V25Features.EnableHealthMonitoring = true;
            _options.V25Features.EnablePluggableStorage = true;
            _options.V25Features.EnableConnectionPooling = true;
            _options.V25Features.EnableSessionBackup = true;
            return this;
        }

        public IV25FeaturesBuilder EnableAllExperimental()
        {
            EnableAllStable();
            _options.V25Features.EnableAsyncMessageStreams = true;
            _options.V25Features.EnablePostQuantumPreparation = true;
            _options.V25Features.EnableWebRTCTransport = true;
            return this;
        }

        public IV25FeaturesBuilder WithPostQuantum(Action<IPostQuantumOptionsBuilder> configure)
        {
            _options.V25Features.EnablePostQuantumPreparation = true;
            _options.PostQuantumOptions ??= new Domain.PostQuantumOptions();
            
            var builder = new PostQuantumOptionsBuilder(_options.PostQuantumOptions);
            configure(builder);
            return this;
        }

        public IV25FeaturesBuilder WithWebRTC(Action<IWebRTCOptionsBuilder> configure)
        {
            _options.V25Features.EnableWebRTCTransport = true;
            _options.WebRTCOptions ??= new Domain.WebRTCOptions();
            
            var builder = new WebRTCOptionsBuilder(_options.WebRTCOptions);
            configure(builder);
            return this;
        }

        public IV25FeaturesBuilder WithAdvancedKeyRotation(Action<IKeyRotationPolicyBuilder> configure)
        {
            _options.AdvancedKeyRotationPolicy ??= new Domain.KeyRotationPolicy();
            
            var builder = new KeyRotationPolicyBuilder(_options.AdvancedKeyRotationPolicy);
            configure(builder);
            return this;
        }
    }

    internal class BatchingOptionsBuilder : IBatchingOptionsBuilder
    {
        private readonly Domain.BatchingOptions _options;

        public BatchingOptionsBuilder(Domain.BatchingOptions options)
        {
            _options = options;
        }

        public IBatchingOptionsBuilder SetMaxBatchSize(int maxSize)
        {
            _options.MaxBatchSize = maxSize;
            return this;
        }

        public IBatchingOptionsBuilder SetMaxDelay(int delayMs)
        {
            _options.MaxBatchDelay = TimeSpan.FromMilliseconds(delayMs);
            return this;
        }

        public IBatchingOptionsBuilder EnableCompression()
        {
            _options.EnableCompression = true;
            return this;
        }

        public IBatchingOptionsBuilder SetCompressionLevel(CompressionLevel level)
        {
            _options.CompressionLevel = level;
            return this;
        }

        public IBatchingOptionsBuilder UseRealTimePreset()
        {
            var preset = Domain.BatchingOptions.RealTime;
            _options.MaxBatchSize = preset.MaxBatchSize;
            _options.MaxBatchDelay = preset.MaxBatchDelay;
            _options.EnableCompression = preset.EnableCompression;
            _options.CompressionLevel = preset.CompressionLevel;
            return this;
        }

        public IBatchingOptionsBuilder UseHighThroughputPreset()
        {
            var preset = Domain.BatchingOptions.HighThroughput;
            _options.MaxBatchSize = preset.MaxBatchSize;
            _options.MaxBatchDelay = preset.MaxBatchDelay;
            _options.EnableCompression = preset.EnableCompression;
            _options.CompressionLevel = preset.CompressionLevel;
            return this;
        }

        public IBatchingOptionsBuilder UseBandwidthOptimizedPreset()
        {
            var preset = Domain.BatchingOptions.BandwidthOptimized;
            _options.MaxBatchSize = preset.MaxBatchSize;
            _options.MaxBatchDelay = preset.MaxBatchDelay;
            _options.EnableCompression = preset.EnableCompression;
            _options.CompressionLevel = preset.CompressionLevel;
            return this;
        }
    }

    internal class ConnectionPoolOptionsBuilder : IConnectionPoolOptionsBuilder
    {
        private readonly Domain.ConnectionPoolOptions _options;

        public ConnectionPoolOptionsBuilder(Domain.ConnectionPoolOptions options)
        {
            _options = options;
        }

        public IConnectionPoolOptionsBuilder SetMaxConnections(int maxConnections)
        {
            _options.MaxConnections = maxConnections;
            return this;
        }

        public IConnectionPoolOptionsBuilder SetConnectionTimeout(int timeoutMs)
        {
            _options.ConnectionTimeout = TimeSpan.FromMilliseconds(timeoutMs);
            return this;
        }

        public IConnectionPoolOptionsBuilder SetIdleTimeout(int timeoutMs)
        {
            _options.IdleTimeout = TimeSpan.FromMilliseconds(timeoutMs);
            return this;
        }

        public IConnectionPoolOptionsBuilder EnableConnectionValidation()
        {
            _options.ValidateOnReturn = true;
            return this;
        }

        public IConnectionPoolOptionsBuilder UseHighPerformancePreset()
        {
            var preset = Domain.ConnectionPoolOptions.HighPerformance;
            _options.MaxConnections = preset.MaxConnections;
            _options.MinConnections = preset.MinConnections;
            _options.ConnectionTimeout = preset.ConnectionTimeout;
            _options.IdleTimeout = preset.IdleTimeout;
            _options.ValidateOnReturn = preset.ValidateOnReturn;
            return this;
        }

        public IConnectionPoolOptionsBuilder UseResourceConstrainedPreset()
        {
            var preset = Domain.ConnectionPoolOptions.ResourceConstrained;
            _options.MaxConnections = preset.MaxConnections;
            _options.MinConnections = preset.MinConnections;
            _options.ConnectionTimeout = preset.ConnectionTimeout;
            _options.IdleTimeout = preset.IdleTimeout;
            _options.ValidateOnReturn = preset.ValidateOnReturn;
            return this;
        }
    }

    internal class ResilienceOptionsBuilder : IResilienceOptionsBuilder
    {
        private readonly Domain.ResilienceOptions _options;

        public ResilienceOptionsBuilder(Domain.ResilienceOptions options)
        {
            _options = options;
        }

        public IResilienceOptionsBuilder WithRetryPolicy(Action<IRetryPolicyBuilder> configure)
        {
            // Implementation for retry policy configuration
            // This would configure retry policy settings in _options
            return this;
        }

        public IResilienceOptionsBuilder WithCircuitBreaker(Action<ICircuitBreakerPolicyBuilder> configure)
        {
            // Implementation for circuit breaker configuration
            // This would configure circuit breaker settings in _options
            return this;
        }

        public IResilienceOptionsBuilder WithTimeoutPolicy(Action<ITimeoutPolicyBuilder> configure)
        {
            // Implementation for timeout policy configuration
            // This would configure timeout settings in _options
            return this;
        }

        public IResilienceOptionsBuilder EnableFailover(params string[] fallbackEndpoints)
        {
            // Implementation for failover configuration
            return this;
        }

        public IResilienceOptionsBuilder EnableJitter()
        {
            // Implementation for enabling jitter
            return this;
        }

        public IResilienceOptionsBuilder DisableJitter()
        {
            // Implementation for disabling jitter
            return this;
        }

        public IResilienceOptionsBuilder UseAggressivePreset()
        {
            // Implementation for aggressive preset
            return this;
        }

        public IResilienceOptionsBuilder UseConservativePreset()
        {
            // Implementation for conservative preset
            return this;
        }

        public IResilienceOptionsBuilder DisableForTesting()
        {
            // Implementation for disabling resilience for testing
            return this;
        }
    }

    internal class BackupOptionsBuilder : IBackupOptionsBuilder
    {
        private readonly Domain.BackupOptions _options;

        public BackupOptionsBuilder(Domain.BackupOptions options)
        {
            _options = options;
        }

        public IBackupOptionsBuilder SetBackupPath(string path)
        {
            _options.BackupPath = path;
            return this;
        }

        public IBackupOptionsBuilder SetFilePattern(string pattern)
        {
            _options.BackupFilePattern = pattern;
            return this;
        }

        public IBackupOptionsBuilder EnableCompression()
        {
            _options.CompressBackups = true;
            return this;
        }

        public IBackupOptionsBuilder DisableCompression()
        {
            _options.CompressBackups = false;
            return this;
        }

        public IBackupOptionsBuilder SetRetention(TimeSpan retention)
        {
            _options.BackupRetention = retention;
            return this;
        }

        public IBackupOptionsBuilder SetMaxBackupFiles(int maxFiles)
        {
            _options.MaxBackupFiles = maxFiles;
            return this;
        }

        public IBackupOptionsBuilder IncludeMessageHistory()
        {
            _options.IncludeMessageHistory = true;
            return this;
        }

        public IBackupOptionsBuilder ExcludeMessageHistory()
        {
            _options.IncludeMessageHistory = false;
            return this;
        }

        public IBackupOptionsBuilder IncludeOneTimeKeys()
        {
            _options.IncludeOneTimeKeys = true;
            return this;
        }

        public IBackupOptionsBuilder ExcludeOneTimeKeys()
        {
            _options.IncludeOneTimeKeys = false;
            return this;
        }

        public IBackupOptionsBuilder EnableAutoBackup(TimeSpan interval)
        {
            _options.AutoBackupInterval = interval;
            return this;
        }

        public IBackupOptionsBuilder DisableAutoBackup()
        {
            _options.AutoBackupInterval = TimeSpan.Zero;
            return this;
        }

        public IBackupOptionsBuilder EnableVerification()
        {
            _options.VerifyAfterBackup = true;
            return this;
        }

        public IBackupOptionsBuilder DisableVerification()
        {
            _options.VerifyAfterBackup = false;
            return this;
        }

        public IBackupOptionsBuilder SetCustomEncryptionKey(byte[] encryptionKey)
        {
            _options.EncryptionKey = encryptionKey;
            return this;
        }

        public IBackupOptionsBuilder UseIdentityKeyEncryption()
        {
            _options.EncryptionKey = null;
            return this;
        }

        public IBackupOptionsBuilder UseMinimalStoragePreset()
        {
            var preset = Domain.BackupOptions.MinimalStorage;
            _options.IncludeMessageHistory = preset.IncludeMessageHistory;
            _options.IncludeOneTimeKeys = preset.IncludeOneTimeKeys;
            _options.CompressBackups = preset.CompressBackups;
            return this;
        }

        public IBackupOptionsBuilder UseComprehensivePreset()
        {
            var preset = Domain.BackupOptions.Comprehensive;
            _options.IncludeMessageHistory = preset.IncludeMessageHistory;
            _options.IncludeOneTimeKeys = preset.IncludeOneTimeKeys;
            _options.CompressBackups = preset.CompressBackups;
            _options.VerifyAfterBackup = preset.VerifyAfterBackup;
            return this;
        }

        public IBackupOptionsBuilder UseDevelopmentPreset()
        {
            var preset = Domain.BackupOptions.Development;
            _options.BackupPath = preset.BackupPath;
            _options.CompressBackups = preset.CompressBackups;
            _options.AutoBackupInterval = preset.AutoBackupInterval;
            return this;
        }
    }

    // Stub implementations for complex builders - these would need full implementation
    internal class PostQuantumOptionsBuilder : IPostQuantumOptionsBuilder
    {
        private readonly Domain.PostQuantumOptions _options;

        public PostQuantumOptionsBuilder(Domain.PostQuantumOptions options)
        {
            _options = options;
        }

        public IPostQuantumOptionsBuilder UseAlgorithm(PostQuantumAlgorithm algorithm) => this;
        public IPostQuantumOptionsBuilder UsePerformanceProfile(PostQuantumPerformance profile) => this;
        public IPostQuantumOptionsBuilder RequireSecurityLevel(PostQuantumSecurityLevel level) => this;
        public IPostQuantumOptionsBuilder RequireNistApproved() => this;
        public IPostQuantumOptionsBuilder AllowExperimentalAlgorithms() => this;
        public IPostQuantumOptionsBuilder EnableHybridMode() => this;
        public IPostQuantumOptionsBuilder DisableHybridMode() => this;
        public IPostQuantumOptionsBuilder EnableSideChannelProtection() => this;
        public IPostQuantumOptionsBuilder SetKeyExpiration(TimeSpan expiration) => this;
        public IPostQuantumOptionsBuilder SetMaxKeySize(int maxSize) => this;
        public IPostQuantumOptionsBuilder SetMaxSignatureSize(int maxSize) => this;
        public IPostQuantumOptionsBuilder EnableKeyCaching(int maxCachedKeys = 10) => this;
        public IPostQuantumOptionsBuilder EnablePerformanceMonitoring() => this;
        public IPostQuantumOptionsBuilder UseSpeedPreset() => this;
        public IPostQuantumOptionsBuilder UseSecurityPreset() => this;
        public IPostQuantumOptionsBuilder UseSizePreset() => this;
        public IPostQuantumOptionsBuilder UseHybridPreset() => this;
    }

    internal class WebRTCOptionsBuilder : IWebRTCOptionsBuilder
    {
        private readonly Domain.WebRTCOptions _options;

        public WebRTCOptionsBuilder(Domain.WebRTCOptions options)
        {
            _options = options;
        }

        public IWebRTCOptionsBuilder AddStunServer(string stunUri) => this;
        public IWebRTCOptionsBuilder AddStunServers(params string[] stunUris) => this;
        public IWebRTCOptionsBuilder AddTurnServer(string turnUri, string username, string credential) => this;
        public IWebRTCOptionsBuilder SetConnectionTimeout(TimeSpan timeout) => this;
        public IWebRTCOptionsBuilder SetKeepAliveInterval(TimeSpan interval) => this;
        public IWebRTCOptionsBuilder EnableAutoReconnect(int maxAttempts = 5, TimeSpan? delay = null) => this;
        public IWebRTCOptionsBuilder DisableAutoReconnect() => this;
        public IWebRTCOptionsBuilder PreferReliableChannels() => this;
        public IWebRTCOptionsBuilder PreferUnreliableChannels() => this;
        public IWebRTCOptionsBuilder SetMaxMessageSize(int sizeBytes) => this;
        public IWebRTCOptionsBuilder SetBufferSizes(int receiveBufferSize, int sendBufferSize) => this;
        public IWebRTCOptionsBuilder EnableCompression() => this;
        public IWebRTCOptionsBuilder DisableCompression() => this;
        public IWebRTCOptionsBuilder EnableDataChannelEncryption() => this;
        public IWebRTCOptionsBuilder DisableDataChannelEncryption() => this;
        public IWebRTCOptionsBuilder SetMinNetworkQuality(WebRTCNetworkQualityLevel level) => this;
        public IWebRTCOptionsBuilder EnableNetworkQualityMonitoring(TimeSpan? checkInterval = null) => this;
        public IWebRTCOptionsBuilder DisableNetworkQualityMonitoring() => this;
        public IWebRTCOptionsBuilder EnableDetailedStatistics() => this;
        public IWebRTCOptionsBuilder DisableDetailedStatistics() => this;
        public IWebRTCOptionsBuilder SetSignalingServer(string endpoint) => this;
        public IWebRTCOptionsBuilder ForceRelay() => this;
        public IWebRTCOptionsBuilder AllowDirectP2P() => this;
        public IWebRTCOptionsBuilder UseLowLatencyPreset() => this;
        public IWebRTCOptionsBuilder UseHighReliabilityPreset() => this;
        public IWebRTCOptionsBuilder UseMobileOptimizedPreset() => this;
        public IWebRTCOptionsBuilder UseDevelopmentPreset() => this;
    }

    internal class KeyRotationPolicyBuilder : IKeyRotationPolicyBuilder
    {
        private readonly Domain.KeyRotationPolicy _options;

        public KeyRotationPolicyBuilder(Domain.KeyRotationPolicy options)
        {
            _options = options;
        }

        public IKeyRotationPolicyBuilder SetTriggerType(KeyRotationTriggerType triggerType) => this;
        public IKeyRotationPolicyBuilder SetMessageCountThreshold(int messageCount) => this;
        public IKeyRotationPolicyBuilder SetTimeIntervalThreshold(TimeSpan interval) => this;
        public IKeyRotationPolicyBuilder SetDataVolumeThreshold(long dataVolume) => this;
        public IKeyRotationPolicyBuilder EnableAdaptiveRotation(Action<IKeyRotationRiskFactorsBuilder>? configure = null) => this;
        public IKeyRotationPolicyBuilder DisableAdaptiveRotation() => this;
        public IKeyRotationPolicyBuilder SetMinRotationInterval(TimeSpan interval) => this;
        public IKeyRotationPolicyBuilder SetMaxRotationInterval(TimeSpan interval) => this;
        public IKeyRotationPolicyBuilder RotateOnSessionStart() => this;
        public IKeyRotationPolicyBuilder RotateOnSessionEnd() => this;
        public IKeyRotationPolicyBuilder RotateOnDeviceJoin() => this;
        public IKeyRotationPolicyBuilder RotateOnDeviceLeave() => this;
        public IKeyRotationPolicyBuilder SetCustomSchedule(Action<IKeyRotationScheduleBuilder> configure) => this;
        public IKeyRotationPolicyBuilder WithPerformanceSettings(Action<IKeyRotationPerformanceBuilder> configure) => this;
        public IKeyRotationPolicyBuilder WithComplianceSettings(Action<IKeyRotationComplianceBuilder> configure) => this;
        public IKeyRotationPolicyBuilder UseMaximumSecurityPreset() => this;
        public IKeyRotationPolicyBuilder UseBalancedPreset() => this;
        public IKeyRotationPolicyBuilder UsePerformanceOptimizedPreset() => this;
        public IKeyRotationPolicyBuilder UseRegulatoryCompliancePreset() => this;
    }
}