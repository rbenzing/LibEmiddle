using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;

namespace LibEmiddle.Abstractions
{
    /// <summary>
    /// Interface for WebRTC transport implementation (v2.5).
    /// Provides peer-to-peer encrypted communication capabilities.
    /// </summary>
    public interface IWebRTCTransport : IDisposable
    {
        /// <summary>
        /// Unique identifier for this WebRTC transport instance.
        /// </summary>
        string TransportId { get; }

        /// <summary>
        /// Current connection state of the WebRTC transport.
        /// </summary>
        WebRTCConnectionState ConnectionState { get; }

        /// <summary>
        /// Local peer ID for this transport.
        /// </summary>
        string LocalPeerId { get; }

        /// <summary>
        /// Remote peer ID (when connected).
        /// </summary>
        string? RemotePeerId { get; }

        /// <summary>
        /// Configuration options for this WebRTC transport.
        /// </summary>
        WebRTCOptions Options { get; }

        /// <summary>
        /// Initiates a WebRTC connection to a remote peer.
        /// </summary>
        /// <param name="remotePeerId">ID of the remote peer to connect to.</param>
        /// <param name="signaling">Signaling mechanism for connection establishment.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>True if connection was successfully established.</returns>
        Task<bool> ConnectAsync(
            string remotePeerId,
            IWebRTCSignaling signaling,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Accepts an incoming WebRTC connection from a remote peer.
        /// </summary>
        /// <param name="offer">WebRTC offer from the remote peer.</param>
        /// <param name="signaling">Signaling mechanism for connection establishment.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>True if connection was successfully accepted.</returns>
        Task<bool> AcceptConnectionAsync(
            WebRTCOffer offer,
            IWebRTCSignaling signaling,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Sends data to the connected remote peer.
        /// </summary>
        /// <param name="data">Data to send.</param>
        /// <param name="reliable">Whether to use reliable (ordered) or unreliable (fast) delivery.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>True if data was successfully sent.</returns>
        Task<bool> SendAsync(
            byte[] data,
            bool reliable = true,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Receives data from the connected remote peer.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Received data or null if no data available.</returns>
        Task<byte[]?> ReceiveAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Disconnects from the current peer.
        /// </summary>
        /// <param name="reason">Reason for disconnection.</param>
        Task DisconnectAsync(string? reason = null);

        /// <summary>
        /// Gets statistics about the WebRTC connection.
        /// </summary>
        /// <returns>Connection statistics.</returns>
        Task<WebRTCStatistics> GetStatisticsAsync();

        /// <summary>
        /// Gets the current network quality metrics.
        /// </summary>
        /// <returns>Network quality information.</returns>
        Task<WebRTCNetworkQuality> GetNetworkQualityAsync();

        /// <summary>
        /// Event fired when connection state changes.
        /// </summary>
        event EventHandler<WebRTCConnectionStateChangedEventArgs>? ConnectionStateChanged;

        /// <summary>
        /// Event fired when data is received from remote peer.
        /// </summary>
        event EventHandler<WebRTCDataReceivedEventArgs>? DataReceived;

        /// <summary>
        /// Event fired when a connection error occurs.
        /// </summary>
        event EventHandler<WebRTCErrorEventArgs>? ErrorOccurred;

        /// <summary>
        /// Event fired when network quality changes significantly.
        /// </summary>
        event EventHandler<WebRTCNetworkQuality>? NetworkQualityChanged;
    }

    /// <summary>
    /// Interface for WebRTC signaling mechanism (v2.5).
    /// Handles the signaling process for WebRTC connection establishment.
    /// </summary>
    public interface IWebRTCSignaling : IDisposable
    {
        /// <summary>
        /// Sends a signaling message to a remote peer.
        /// </summary>
        /// <param name="remotePeerId">ID of the remote peer.</param>
        /// <param name="message">Signaling message to send.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        Task SendSignalingMessageAsync(
            string remotePeerId,
            WebRTCSignalingMessage message,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Receives signaling messages for the local peer.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Received signaling message or null if none available.</returns>
        Task<WebRTCSignalingMessage?> ReceiveSignalingMessageAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Event fired when a signaling message is received.
        /// </summary>
        event EventHandler<WebRTCSignalingMessageReceivedEventArgs>? MessageReceived;
    }


    /// <summary>
    /// WebRTC offer information for connection establishment.
    /// </summary>
    public class WebRTCOffer
    {
        /// <summary>
        /// Session description protocol (SDP) offer.
        /// </summary>
        public string Sdp { get; set; } = string.Empty;

        /// <summary>
        /// Type of the SDP offer.
        /// </summary>
        public string Type { get; set; } = "offer";

        /// <summary>
        /// Timestamp when the offer was created.
        /// </summary>
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// ID of the peer making the offer.
        /// </summary>
        public string OfferingPeerId { get; set; } = string.Empty;

        /// <summary>
        /// Additional metadata for the offer.
        /// </summary>
        public Dictionary<string, string> Metadata { get; set; } = new();
    }

    /// <summary>
    /// WebRTC signaling message for connection establishment.
    /// </summary>
    public class WebRTCSignalingMessage
    {
        /// <summary>
        /// Type of signaling message.
        /// </summary>
        public WebRTCSignalingMessageType Type { get; set; }

        /// <summary>
        /// ID of the sender peer.
        /// </summary>
        public string FromPeerId { get; set; } = string.Empty;

        /// <summary>
        /// ID of the recipient peer.
        /// </summary>
        public string ToPeerId { get; set; } = string.Empty;

        /// <summary>
        /// Message payload (SDP, ICE candidate, etc.).
        /// </summary>
        public string Payload { get; set; } = string.Empty;

        /// <summary>
        /// Timestamp when the message was created.
        /// </summary>
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Additional metadata for the message.
        /// </summary>
        public Dictionary<string, string> Metadata { get; set; } = new();
    }

    /// <summary>
    /// WebRTC connection statistics.
    /// </summary>
    public class WebRTCStatistics
    {
        /// <summary>
        /// Total bytes sent over the connection.
        /// </summary>
        public long BytesSent { get; set; }

        /// <summary>
        /// Total bytes received over the connection.
        /// </summary>
        public long BytesReceived { get; set; }

        /// <summary>
        /// Current round-trip time in milliseconds.
        /// </summary>
        public double RoundTripTimeMs { get; set; }

        /// <summary>
        /// Packet loss percentage (0.0 to 1.0).
        /// </summary>
        public double PacketLossPercentage { get; set; }

        /// <summary>
        /// Current available bandwidth in bits per second.
        /// </summary>
        public long AvailableBandwidthBps { get; set; }

        /// <summary>
        /// Number of successful connections established.
        /// </summary>
        public int ConnectionsEstablished { get; set; }

        /// <summary>
        /// Number of connection failures.
        /// </summary>
        public int ConnectionFailures { get; set; }

        /// <summary>
        /// Duration of the current connection.
        /// </summary>
        public TimeSpan ConnectionDuration { get; set; }

        /// <summary>
        /// ICE connection state.
        /// </summary>
        public string IceConnectionState { get; set; } = string.Empty;

        /// <summary>
        /// DTLS connection state.
        /// </summary>
        public string DtlsState { get; set; } = string.Empty;
    }

    /// <summary>
    /// WebRTC network quality information.
    /// </summary>
    public class WebRTCNetworkQuality
    {
        /// <summary>
        /// Overall network quality level.
        /// </summary>
        public WebRTCNetworkQualityLevel Level { get; set; }

        /// <summary>
        /// Network quality score (0-100).
        /// </summary>
        public int Score { get; set; }

        /// <summary>
        /// Current latency in milliseconds.
        /// </summary>
        public double LatencyMs { get; set; }

        /// <summary>
        /// Bandwidth utilization percentage.
        /// </summary>
        public double BandwidthUtilization { get; set; }

        /// <summary>
        /// Whether the connection is stable.
        /// </summary>
        public bool IsStable { get; set; }

        /// <summary>
        /// Timestamp when quality was measured.
        /// </summary>
        public DateTime MeasuredAt { get; set; } = DateTime.UtcNow;
    }

    /// <summary>
    /// Event arguments for WebRTC connection state changes.
    /// </summary>
    public class WebRTCConnectionStateChangedEventArgs : EventArgs
    {
        /// <summary>
        /// Previous connection state.
        /// </summary>
        public WebRTCConnectionState PreviousState { get; set; }

        /// <summary>
        /// New connection state.
        /// </summary>
        public WebRTCConnectionState NewState { get; set; }

        /// <summary>
        /// Reason for the state change.
        /// </summary>
        public string? Reason { get; set; }

        /// <summary>
        /// Remote peer ID (if applicable).
        /// </summary>
        public string? RemotePeerId { get; set; }
    }

    /// <summary>
    /// Event arguments for WebRTC data received events.
    /// </summary>
    public class WebRTCDataReceivedEventArgs : EventArgs
    {
        /// <summary>
        /// Received data.
        /// </summary>
        public byte[] Data { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Whether the data was received via reliable channel.
        /// </summary>
        public bool IsReliable { get; set; }

        /// <summary>
        /// Remote peer ID that sent the data.
        /// </summary>
        public string RemotePeerId { get; set; } = string.Empty;

        /// <summary>
        /// Timestamp when data was received.
        /// </summary>
        public DateTime ReceivedAt { get; set; } = DateTime.UtcNow;
    }

    /// <summary>
    /// Event arguments for WebRTC error events.
    /// </summary>
    public class WebRTCErrorEventArgs : EventArgs
    {
        /// <summary>
        /// The error that occurred.
        /// </summary>
        public Exception Error { get; set; } = new Exception();

        /// <summary>
        /// Context where the error occurred.
        /// </summary>
        public string Context { get; set; } = string.Empty;

        /// <summary>
        /// Whether the error is recoverable.
        /// </summary>
        public bool IsRecoverable { get; set; }

        /// <summary>
        /// Remote peer ID (if applicable).
        /// </summary>
        public string? RemotePeerId { get; set; }
    }

    /// <summary>
    /// Event arguments for WebRTC signaling message received events.
    /// </summary>
    public class WebRTCSignalingMessageReceivedEventArgs : EventArgs
    {
        /// <summary>
        /// The received signaling message.
        /// </summary>
        public WebRTCSignalingMessage Message { get; set; } = new();

        /// <summary>
        /// Timestamp when message was received.
        /// </summary>
        public DateTime ReceivedAt { get; set; } = DateTime.UtcNow;
    }
}