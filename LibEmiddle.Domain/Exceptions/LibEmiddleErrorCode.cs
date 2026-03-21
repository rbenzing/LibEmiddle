namespace LibEmiddle.Domain.Exceptions
{
    /// <summary>
    /// Error codes for <see cref="LibEmiddleException"/>, allowing callers to
    /// distinguish transient failures from permanent ones and to route errors
    /// to the appropriate recovery path.
    /// </summary>
    public enum LibEmiddleErrorCode
    {
        /// <summary>An unclassified or unexpected error occurred.</summary>
        Unknown = 0,

        /// <summary>The supplied key bundle is missing required fields or is structurally invalid.</summary>
        InvalidBundle,

        /// <summary>A replayed message was detected and rejected.</summary>
        ReplayDetected,

        /// <summary>Decryption of a message or payload failed.</summary>
        DecryptionFailed,

        /// <summary>A transport-level error occurred (e.g. WebSocket send/receive failure).</summary>
        TransportError,

        /// <summary>The requested cryptographic key could not be found.</summary>
        KeyNotFound,

        /// <summary>The requested session could not be found.</summary>
        SessionNotFound,

        /// <summary>The requested device could not be found.</summary>
        DeviceNotFound,

        /// <summary>All one-time pre-keys (OPKs) have been exhausted.</summary>
        OPKExhausted,

        /// <summary>A supplied key is invalid (wrong length, wrong curve, corrupt data, etc.).</summary>
        InvalidKey,

        /// <summary>A supplied message is invalid (malformed, missing fields, etc.).</summary>
        InvalidMessage,

        /// <summary>The operation is not permitted given the caller's current privileges.</summary>
        PermissionDenied,
    }
}
