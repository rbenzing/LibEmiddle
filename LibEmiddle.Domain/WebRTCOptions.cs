using LibEmiddle.Domain.Enums;

namespace LibEmiddle.Domain
{
    /// <summary>
    /// Configuration options for WebRTC transport (v2.5).
    /// Controls peer-to-peer connection establishment and behavior.
    /// </summary>
    public class WebRTCOptions
    {
        /// <summary>
        /// List of STUN servers for NAT traversal.
        /// </summary>
        public List<string> StunServers { get; set; } = new()
        {
            "stun:stun.l.google.com:19302",
            "stun:stun1.l.google.com:19302"
        };

        /// <summary>
        /// List of TURN servers for relay connections.
        /// </summary>
        public List<WebRTCTurnServer> TurnServers { get; set; } = new();

        /// <summary>
        /// Maximum time to wait for connection establishment.
        /// </summary>
        public TimeSpan ConnectionTimeout { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>
        /// Interval for sending keep-alive messages.
        /// </summary>
        public TimeSpan KeepAliveInterval { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>
        /// Whether to enable automatic reconnection on connection loss.
        /// </summary>
        public bool EnableAutoReconnect { get; set; } = true;

        /// <summary>
        /// Maximum number of reconnection attempts.
        /// </summary>
        public int MaxReconnectAttempts { get; set; } = 5;

        /// <summary>
        /// Delay between reconnection attempts.
        /// </summary>
        public TimeSpan ReconnectDelay { get; set; } = TimeSpan.FromSeconds(5);

        /// <summary>
        /// Whether to prefer reliable data channels (TCP-like) over unreliable (UDP-like).
        /// </summary>
        public bool PreferReliableChannels { get; set; } = true;

        /// <summary>
        /// Maximum size for individual messages in bytes.
        /// </summary>
        public int MaxMessageSize { get; set; } = 65536; // 64 KB

        /// <summary>
        /// Buffer size for incoming data.
        /// </summary>
        public int ReceiveBufferSize { get; set; } = 1048576; // 1 MB

        /// <summary>
        /// Buffer size for outgoing data.
        /// </summary>
        public int SendBufferSize { get; set; } = 1048576; // 1 MB

        /// <summary>
        /// Whether to enable data channel compression.
        /// </summary>
        public bool EnableCompression { get; set; } = false;

        /// <summary>
        /// Whether to enable data channel encryption (in addition to DTLS).
        /// </summary>
        public bool EnableDataChannelEncryption { get; set; } = true;

        /// <summary>
        /// Minimum network quality required to maintain connection.
        /// </summary>
        public WebRTCNetworkQualityLevel MinNetworkQuality { get; set; } = WebRTCNetworkQualityLevel.Low;

        /// <summary>
        /// Whether to enable network quality monitoring.
        /// </summary>
        public bool EnableNetworkQualityMonitoring { get; set; } = true;

        /// <summary>
        /// Interval for network quality checks.
        /// </summary>
        public TimeSpan NetworkQualityCheckInterval { get; set; } = TimeSpan.FromSeconds(10);

        /// <summary>
        /// Whether to enable detailed statistics collection.
        /// </summary>
        public bool EnableDetailedStatistics { get; set; } = false;

        /// <summary>
        /// Custom signaling server endpoint for connection coordination.
        /// </summary>
        public string? SignalingServerEndpoint { get; set; }

        /// <summary>
        /// Whether to force relay connections (disable direct P2P).
        /// Useful for testing or strict security requirements.
        /// </summary>
        public bool ForceRelay { get; set; } = false;

        /// <summary>
        /// Custom data channel labels for different message types.
        /// </summary>
        public Dictionary<string, string> DataChannelLabels { get; set; } = new()
        {
            ["reliable"] = "libemiddle-reliable",
            ["unreliable"] = "libemiddle-unreliable"
        };

        /// <summary>
        /// Validates the WebRTC configuration.
        /// </summary>
        /// <returns>List of validation errors, empty if valid.</returns>
        public List<string> Validate()
        {
            var errors = new List<string>();

            if (StunServers.Count == 0 && TurnServers.Count == 0)
            {
                errors.Add("At least one STUN or TURN server must be configured");
            }

            if (ConnectionTimeout <= TimeSpan.Zero || ConnectionTimeout > TimeSpan.FromMinutes(5))
            {
                errors.Add("ConnectionTimeout must be between 1 second and 5 minutes");
            }

            if (KeepAliveInterval <= TimeSpan.Zero || KeepAliveInterval > TimeSpan.FromMinutes(10))
            {
                errors.Add("KeepAliveInterval must be between 1 second and 10 minutes");
            }

            if (MaxReconnectAttempts < 0 || MaxReconnectAttempts > 100)
            {
                errors.Add("MaxReconnectAttempts must be between 0 and 100");
            }

            if (ReconnectDelay <= TimeSpan.Zero || ReconnectDelay > TimeSpan.FromMinutes(5))
            {
                errors.Add("ReconnectDelay must be between 1 second and 5 minutes");
            }

            if (MaxMessageSize < 1024 || MaxMessageSize > 16777216) // 1 KB to 16 MB
            {
                errors.Add("MaxMessageSize must be between 1,024 and 16,777,216 bytes");
            }

            if (ReceiveBufferSize < MaxMessageSize || ReceiveBufferSize > 268435456) // Max message size to 256 MB
            {
                errors.Add("ReceiveBufferSize must be at least MaxMessageSize and no more than 268,435,456 bytes");
            }

            if (SendBufferSize < MaxMessageSize || SendBufferSize > 268435456)
            {
                errors.Add("SendBufferSize must be at least MaxMessageSize and no more than 268,435,456 bytes");
            }

            if (NetworkQualityCheckInterval <= TimeSpan.Zero || NetworkQualityCheckInterval > TimeSpan.FromMinutes(10))
            {
                errors.Add("NetworkQualityCheckInterval must be between 1 second and 10 minutes");
            }

            // Validate TURN servers
            foreach (var turnServer in TurnServers)
            {
                var turnErrors = turnServer.Validate();
                errors.AddRange(turnErrors.Select(e => $"TURN server validation: {e}"));
            }

            return errors;
        }

        /// <summary>
        /// Creates a copy of these WebRTC options.
        /// </summary>
        /// <returns>A new WebRTCOptions instance with copied settings.</returns>
        public WebRTCOptions Clone()
        {
            return new WebRTCOptions
            {
                StunServers = new List<string>(StunServers),
                TurnServers = TurnServers.Select(t => t.Clone()).ToList(),
                ConnectionTimeout = ConnectionTimeout,
                KeepAliveInterval = KeepAliveInterval,
                EnableAutoReconnect = EnableAutoReconnect,
                MaxReconnectAttempts = MaxReconnectAttempts,
                ReconnectDelay = ReconnectDelay,
                PreferReliableChannels = PreferReliableChannels,
                MaxMessageSize = MaxMessageSize,
                ReceiveBufferSize = ReceiveBufferSize,
                SendBufferSize = SendBufferSize,
                EnableCompression = EnableCompression,
                EnableDataChannelEncryption = EnableDataChannelEncryption,
                MinNetworkQuality = MinNetworkQuality,
                EnableNetworkQualityMonitoring = EnableNetworkQualityMonitoring,
                NetworkQualityCheckInterval = NetworkQualityCheckInterval,
                EnableDetailedStatistics = EnableDetailedStatistics,
                SignalingServerEndpoint = SignalingServerEndpoint,
                ForceRelay = ForceRelay,
                DataChannelLabels = new Dictionary<string, string>(DataChannelLabels)
            };
        }

        /// <summary>
        /// Returns a configuration optimized for low-latency gaming or real-time applications.
        /// </summary>
        public static WebRTCOptions LowLatency => new()
        {
            ConnectionTimeout = TimeSpan.FromSeconds(15),
            KeepAliveInterval = TimeSpan.FromSeconds(15),
            PreferReliableChannels = false,
            MaxMessageSize = 8192, // 8 KB for small messages
            EnableCompression = false,
            MinNetworkQuality = WebRTCNetworkQualityLevel.Medium,
            NetworkQualityCheckInterval = TimeSpan.FromSeconds(5),
            EnableDetailedStatistics = true
        };

        /// <summary>
        /// Returns a configuration optimized for reliability and data integrity.
        /// </summary>
        public static WebRTCOptions HighReliability => new()
        {
            ConnectionTimeout = TimeSpan.FromMinutes(1),
            KeepAliveInterval = TimeSpan.FromSeconds(30),
            EnableAutoReconnect = true,
            MaxReconnectAttempts = 10,
            ReconnectDelay = TimeSpan.FromSeconds(3),
            PreferReliableChannels = true,
            EnableCompression = true,
            EnableDataChannelEncryption = true,
            MinNetworkQuality = WebRTCNetworkQualityLevel.Low,
            EnableNetworkQualityMonitoring = true
        };

        /// <summary>
        /// Returns a configuration optimized for mobile devices with battery considerations.
        /// </summary>
        public static WebRTCOptions MobileOptimized => new()
        {
            ConnectionTimeout = TimeSpan.FromSeconds(20),
            KeepAliveInterval = TimeSpan.FromMinutes(1),
            EnableAutoReconnect = true,
            MaxReconnectAttempts = 3,
            MaxMessageSize = 32768, // 32 KB
            ReceiveBufferSize = 524288, // 512 KB
            SendBufferSize = 524288, // 512 KB
            EnableCompression = true,
            MinNetworkQuality = WebRTCNetworkQualityLevel.Low,
            NetworkQualityCheckInterval = TimeSpan.FromSeconds(30),
            EnableDetailedStatistics = false
        };

        /// <summary>
        /// Returns a configuration for development and testing with verbose logging.
        /// </summary>
        public static WebRTCOptions Development => new()
        {
            ConnectionTimeout = TimeSpan.FromSeconds(10),
            KeepAliveInterval = TimeSpan.FromSeconds(10),
            EnableAutoReconnect = false,
            MaxReconnectAttempts = 1,
            EnableDetailedStatistics = true,
            EnableNetworkQualityMonitoring = true,
            NetworkQualityCheckInterval = TimeSpan.FromSeconds(5),
            ForceRelay = false // Allow direct P2P for development
        };
    }

    /// <summary>
    /// Configuration for a TURN server.
    /// </summary>
    public class WebRTCTurnServer
    {
        /// <summary>
        /// TURN server URI (e.g., "turn:turnserver.example.com:3478").
        /// </summary>
        public string Uri { get; set; } = string.Empty;

        /// <summary>
        /// Username for TURN server authentication.
        /// </summary>
        public string Username { get; set; } = string.Empty;

        /// <summary>
        /// Credential for TURN server authentication.
        /// </summary>
        public string Credential { get; set; } = string.Empty;

        /// <summary>
        /// Type of credential (password, token, etc.).
        /// </summary>
        public string CredentialType { get; set; } = "password";

        /// <summary>
        /// Validates the TURN server configuration.
        /// </summary>
        /// <returns>List of validation errors, empty if valid.</returns>
        public List<string> Validate()
        {
            var errors = new List<string>();

            if (string.IsNullOrWhiteSpace(Uri))
            {
                errors.Add("TURN server URI cannot be empty");
            }
            else if (!Uri.StartsWith("turn:") && !Uri.StartsWith("turns:"))
            {
                errors.Add("TURN server URI must start with 'turn:' or 'turns:'");
            }

            if (string.IsNullOrWhiteSpace(Username))
            {
                errors.Add("TURN server username cannot be empty");
            }

            if (string.IsNullOrWhiteSpace(Credential))
            {
                errors.Add("TURN server credential cannot be empty");
            }

            return errors;
        }

        /// <summary>
        /// Creates a copy of this TURN server configuration.
        /// </summary>
        /// <returns>A new WebRTCTurnServer instance with copied settings.</returns>
        public WebRTCTurnServer Clone()
        {
            return new WebRTCTurnServer
            {
                Uri = Uri,
                Username = Username,
                Credential = Credential,
                CredentialType = CredentialType
            };
        }
    }
}