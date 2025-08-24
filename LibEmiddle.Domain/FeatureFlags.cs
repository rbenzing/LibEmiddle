namespace LibEmiddle.Domain
{
    /// <summary>
    /// Feature flags for LibEmiddle v2.5 functionality.
    /// Allows gradual rollout and opt-in to new capabilities while maintaining backward compatibility.
    /// </summary>
    public class FeatureFlags
    {
        /// <summary>
        /// Enable async message stream processing alongside traditional events.
        /// When enabled, provides IAsyncEnumerable&lt;MessageReceivedEventArgs&gt; for reactive programming.
        /// </summary>
        public bool EnableAsyncMessageStreams { get; set; } = false;

        /// <summary>
        /// Enable message batching and compression for improved throughput.
        /// When enabled, multiple messages can be sent together with optional compression.
        /// </summary>
        public bool EnableMessageBatching { get; set; } = false;

        /// <summary>
        /// Enable advanced group management features including granular permissions.
        /// When enabled, provides fine-grained control over group member capabilities.
        /// </summary>
        public bool EnableAdvancedGroupManagement { get; set; } = false;

        /// <summary>
        /// Enable health monitoring and diagnostic capabilities.
        /// When enabled, provides real-time metrics and diagnostic information.
        /// </summary>
        public bool EnableHealthMonitoring { get; set; } = false;

        /// <summary>
        /// Enable the fluent builder API for client configuration.
        /// When enabled, allows using LibEmiddleClientBuilder for configuration.
        /// </summary>
        public bool EnableFluentBuilder { get; set; } = false;

        /// <summary>
        /// Enable pluggable storage providers for session and key persistence.
        /// When enabled, allows custom storage implementations beyond file system.
        /// </summary>
        public bool EnablePluggableStorage { get; set; } = false;

        /// <summary>
        /// Enable post-quantum cryptography preparation interfaces.
        /// When enabled, exposes post-quantum crypto interfaces (implementation TBD).
        /// </summary>
        public bool EnablePostQuantumPreparation { get; set; } = false;

        /// <summary>
        /// Enable WebRTC transport for peer-to-peer communication.
        /// When enabled, allows direct encrypted communication between clients.
        /// </summary>
        public bool EnableWebRTCTransport { get; set; } = false;

        /// <summary>
        /// Enable connection pooling and resilience patterns for transports.
        /// When enabled, provides connection reuse, retry logic, and circuit breakers.
        /// </summary>
        public bool EnableConnectionPooling { get; set; } = false;

        /// <summary>
        /// Enable session backup and restore capabilities.
        /// When enabled, allows encrypted backup and restoration of session data.
        /// </summary>
        public bool EnableSessionBackup { get; set; } = false;

        /// <summary>
        /// Convenience method for beta testers to enable stable v2.5 features.
        /// Does not enable experimental features like WebRTC or post-quantum crypto.
        /// </summary>
        /// <returns>FeatureFlags with stable v2.5 features enabled.</returns>
        public static FeatureFlags EnableStableBeta() => new()
        {
            EnableAsyncMessageStreams = true,
            EnableMessageBatching = true,
            EnableAdvancedGroupManagement = true,
            EnableHealthMonitoring = true,
            EnableFluentBuilder = true,
            EnablePluggableStorage = true,
            EnableConnectionPooling = true,
            EnableSessionBackup = true
        };

        /// <summary>
        /// Convenience method for early adopters to enable all v2.5 features including experimental ones.
        /// Use with caution as experimental features may have limited stability.
        /// </summary>
        /// <returns>FeatureFlags with all v2.5 features enabled.</returns>
        public static FeatureFlags EnableAllExperimental() => new()
        {
            EnableAsyncMessageStreams = true,
            EnableMessageBatching = true,
            EnableAdvancedGroupManagement = true,
            EnableHealthMonitoring = true,
            EnableFluentBuilder = true,
            EnablePluggableStorage = true,
            EnablePostQuantumPreparation = true,
            EnableWebRTCTransport = true,
            EnableConnectionPooling = true,
            EnableSessionBackup = true
        };

        /// <summary>
        /// Validates that the current feature flag configuration is supported.
        /// </summary>
        /// <returns>True if the configuration is valid, false otherwise.</returns>
        public bool IsValid()
        {
            // Post-quantum features require preparation to be enabled
            if (EnablePostQuantumPreparation && EnableWebRTCTransport)
            {
                // These features may conflict in current implementation
                return false;
            }

            return true;
        }
    }
}