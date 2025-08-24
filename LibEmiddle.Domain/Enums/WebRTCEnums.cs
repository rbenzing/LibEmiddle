namespace LibEmiddle.Domain.Enums
{
    /// <summary>
    /// WebRTC connection states (v2.5).
    /// </summary>
    public enum WebRTCConnectionState
    {
        Disconnected,
        Connecting,
        Connected,
        Reconnecting,
        Failed,
        Closed
    }

    /// <summary>
    /// Network quality levels for WebRTC connections (v2.5).
    /// </summary>
    public enum WebRTCNetworkQualityLevel
    {
        Unknown,
        Poor,
        Low,
        Medium,
        High,
        Excellent
    }

    /// <summary>
    /// Types of WebRTC signaling messages (v2.5).
    /// </summary>
    public enum WebRTCSignalingMessageType
    {
        Offer,
        Answer,
        IceCandidate,
        IceCandidateEnd,
        Bye
    }
}