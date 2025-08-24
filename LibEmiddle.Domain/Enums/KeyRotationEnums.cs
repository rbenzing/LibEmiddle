namespace LibEmiddle.Domain.Enums
{
    /// <summary>
    /// Types of triggers for key rotation (v2.5).
    /// </summary>
    public enum KeyRotationTriggerType
    {
        /// <summary>
        /// Rotate after a specific number of messages.
        /// </summary>
        MessageCount = 0,

        /// <summary>
        /// Rotate after a specific time interval.
        /// </summary>
        TimeInterval = 1,

        /// <summary>
        /// Rotate after a specific volume of data has been encrypted.
        /// </summary>
        DataVolume = 2,

        /// <summary>
        /// Use a combination of message count, time interval, and data volume.
        /// Rotation occurs when any threshold is reached.
        /// </summary>
        Composite = 3,

        /// <summary>
        /// Use a custom schedule for rotation.
        /// </summary>
        Schedule = 4,

        /// <summary>
        /// Rotate based on adaptive risk assessment.
        /// </summary>
        Adaptive = 5,

        /// <summary>
        /// Manual rotation only (triggered by explicit calls).
        /// </summary>
        Manual = 6
    }

    /// <summary>
    /// Priority levels for key rotation operations (v2.5).
    /// </summary>
    public enum KeyRotationPriority
    {
        /// <summary>
        /// Low priority - rotation can be delayed for performance.
        /// </summary>
        Low = 0,

        /// <summary>
        /// Normal priority - standard rotation timing.
        /// </summary>
        Normal = 1,

        /// <summary>
        /// High priority - rotation should happen quickly.
        /// </summary>
        High = 2,

        /// <summary>
        /// Critical priority - immediate rotation required.
        /// </summary>
        Critical = 3
    }

    /// <summary>
    /// Reasons for key rotation (v2.5).
    /// </summary>
    public enum KeyRotationReason
    {
        /// <summary>
        /// Scheduled rotation based on policy.
        /// </summary>
        Scheduled = 0,

        /// <summary>
        /// Message count threshold reached.
        /// </summary>
        MessageCountThreshold = 1,

        /// <summary>
        /// Time interval threshold reached.
        /// </summary>
        TimeThreshold = 2,

        /// <summary>
        /// Data volume threshold reached.
        /// </summary>
        DataVolumeThreshold = 3,

        /// <summary>
        /// Manual rotation requested.
        /// </summary>
        Manual = 4,

        /// <summary>
        /// Security incident detected.
        /// </summary>
        SecurityIncident = 5,

        /// <summary>
        /// Device joined the session/group.
        /// </summary>
        DeviceJoined = 6,

        /// <summary>
        /// Device left the session/group.
        /// </summary>
        DeviceLeft = 7,

        /// <summary>
        /// Session started.
        /// </summary>
        SessionStart = 8,

        /// <summary>
        /// Session ended.
        /// </summary>
        SessionEnd = 9,

        /// <summary>
        /// Potential compromise detected.
        /// </summary>
        CompromiseDetection = 10,

        /// <summary>
        /// Failed authentication attempts exceeded threshold.
        /// </summary>
        FailedAuthentication = 11,

        /// <summary>
        /// Suspicious activity detected.
        /// </summary>
        SuspiciousActivity = 12,

        /// <summary>
        /// Compliance requirement triggered rotation.
        /// </summary>
        ComplianceRequirement = 13,

        /// <summary>
        /// Emergency rotation for immediate security.
        /// </summary>
        Emergency = 14
    }

    /// <summary>
    /// Status of a key rotation operation (v2.5).
    /// </summary>
    public enum KeyRotationStatus
    {
        /// <summary>
        /// Rotation is pending/queued.
        /// </summary>
        Pending = 0,

        /// <summary>
        /// Rotation is currently in progress.
        /// </summary>
        InProgress = 1,

        /// <summary>
        /// Rotation completed successfully.
        /// </summary>
        Completed = 2,

        /// <summary>
        /// Rotation failed.
        /// </summary>
        Failed = 3,

        /// <summary>
        /// Rotation was cancelled.
        /// </summary>
        Cancelled = 4,

        /// <summary>
        /// Rotation timed out.
        /// </summary>
        TimedOut = 5,

        /// <summary>
        /// Rotation is waiting for confirmation.
        /// </summary>
        AwaitingConfirmation = 6,

        /// <summary>
        /// Rotation was rejected.
        /// </summary>
        Rejected = 7
    }

    /// <summary>
    /// Types of keys that can be rotated (v2.5).
    /// </summary>
    public enum KeyRotationType
    {
        /// <summary>
        /// Double ratchet sending keys.
        /// </summary>
        SendingKeys = 0,

        /// <summary>
        /// Double ratchet receiving keys.
        /// </summary>
        ReceivingKeys = 1,

        /// <summary>
        /// Both sending and receiving keys.
        /// </summary>
        BothKeys = 2,

        /// <summary>
        /// Group session keys.
        /// </summary>
        GroupKeys = 3,

        /// <summary>
        /// One-time prekeys.
        /// </summary>
        OneTimeKeys = 4,

        /// <summary>
        /// Identity keys (rare, high-impact operation).
        /// </summary>
        IdentityKeys = 5,

        /// <summary>
        /// All applicable keys for the session type.
        /// </summary>
        AllKeys = 6
    }

    /// <summary>
    /// Key rotation metrics for monitoring (v2.5).
    /// </summary>
    public enum KeyRotationMetric
    {
        /// <summary>
        /// Total number of rotations performed.
        /// </summary>
        TotalRotations = 0,

        /// <summary>
        /// Number of successful rotations.
        /// </summary>
        SuccessfulRotations = 1,

        /// <summary>
        /// Number of failed rotations.
        /// </summary>
        FailedRotations = 2,

        /// <summary>
        /// Average time per rotation.
        /// </summary>
        AverageRotationTime = 3,

        /// <summary>
        /// Maximum time for a rotation.
        /// </summary>
        MaxRotationTime = 4,

        /// <summary>
        /// Number of rotations triggered by security incidents.
        /// </summary>
        SecurityTriggeredRotations = 5,

        /// <summary>
        /// Number of rotations triggered by policy.
        /// </summary>
        PolicyTriggeredRotations = 6,

        /// <summary>
        /// Current rotation frequency (rotations per hour).
        /// </summary>
        RotationFrequency = 7,

        /// <summary>
        /// Time since last rotation.
        /// </summary>
        TimeSinceLastRotation = 8
    }
}