using LibEmiddle.Domain.Enums;

namespace LibEmiddle.Domain
{
    /// <summary>
    /// Advanced key rotation policy configuration (v2.5).
    /// Provides fine-grained control over key rotation behavior.
    /// </summary>
    public class KeyRotationPolicy
    {
        /// <summary>
        /// Type of key rotation trigger.
        /// </summary>
        public KeyRotationTriggerType TriggerType { get; set; } = KeyRotationTriggerType.MessageCount;

        /// <summary>
        /// Number of messages after which to rotate keys (when using MessageCount trigger).
        /// </summary>
        public int MessageCountThreshold { get; set; } = 20;

        /// <summary>
        /// Time interval after which to rotate keys (when using TimeInterval trigger).
        /// </summary>
        public TimeSpan TimeIntervalThreshold { get; set; } = TimeSpan.FromHours(1);

        /// <summary>
        /// Data volume threshold for key rotation (when using DataVolume trigger).
        /// </summary>
        public long DataVolumeThreshold { get; set; } = 1048576; // 1 MB

        /// <summary>
        /// Whether to enable adaptive rotation based on risk assessment.
        /// </summary>
        public bool EnableAdaptiveRotation { get; set; } = false;

        /// <summary>
        /// Risk factors that trigger additional key rotations.
        /// </summary>
        public KeyRotationRiskFactors RiskFactors { get; set; } = new();

        /// <summary>
        /// Minimum time between key rotations to prevent excessive rotation.
        /// </summary>
        public TimeSpan MinRotationInterval { get; set; } = TimeSpan.FromMinutes(1);

        /// <summary>
        /// Maximum time between key rotations for security compliance.
        /// </summary>
        public TimeSpan MaxRotationInterval { get; set; } = TimeSpan.FromDays(7);

        /// <summary>
        /// Whether to rotate keys on session start.
        /// </summary>
        public bool RotateOnSessionStart { get; set; } = false;

        /// <summary>
        /// Whether to rotate keys on session end.
        /// </summary>
        public bool RotateOnSessionEnd { get; set; } = true;

        /// <summary>
        /// Whether to rotate keys when a new device joins a group.
        /// </summary>
        public bool RotateOnDeviceJoin { get; set; } = true;

        /// <summary>
        /// Whether to rotate keys when a device leaves a group.
        /// </summary>
        public bool RotateOnDeviceLeave { get; set; } = true;

        /// <summary>
        /// Custom rotation schedule for predictable rotations.
        /// </summary>
        public KeyRotationSchedule? CustomSchedule { get; set; }

        /// <summary>
        /// Performance optimization settings for key rotation.
        /// </summary>
        public KeyRotationPerformanceSettings PerformanceSettings { get; set; } = new();

        /// <summary>
        /// Compliance settings for regulatory requirements.
        /// </summary>
        public KeyRotationComplianceSettings ComplianceSettings { get; set; } = new();

        /// <summary>
        /// Validates the key rotation policy configuration.
        /// </summary>
        /// <returns>List of validation errors, empty if valid.</returns>
        public List<string> Validate()
        {
            var errors = new List<string>();

            if (MessageCountThreshold <= 0)
            {
                errors.Add("MessageCountThreshold must be greater than 0");
            }

            if (TimeIntervalThreshold <= TimeSpan.Zero)
            {
                errors.Add("TimeIntervalThreshold must be greater than zero");
            }

            if (DataVolumeThreshold <= 0)
            {
                errors.Add("DataVolumeThreshold must be greater than 0");
            }

            if (MinRotationInterval <= TimeSpan.Zero)
            {
                errors.Add("MinRotationInterval must be greater than zero");
            }

            if (MaxRotationInterval <= MinRotationInterval)
            {
                errors.Add("MaxRotationInterval must be greater than MinRotationInterval");
            }

            if (MaxRotationInterval > TimeSpan.FromDays(90))
            {
                errors.Add("MaxRotationInterval should not exceed 90 days for security");
            }

            // Validate nested objects
            var riskFactorErrors = RiskFactors.Validate();
            errors.AddRange(riskFactorErrors.Select(e => $"RiskFactors: {e}"));

            var performanceErrors = PerformanceSettings.Validate();
            errors.AddRange(performanceErrors.Select(e => $"PerformanceSettings: {e}"));

            var complianceErrors = ComplianceSettings.Validate();
            errors.AddRange(complianceErrors.Select(e => $"ComplianceSettings: {e}"));

            if (CustomSchedule != null)
            {
                var scheduleErrors = CustomSchedule.Validate();
                errors.AddRange(scheduleErrors.Select(e => $"CustomSchedule: {e}"));
            }

            return errors;
        }

        /// <summary>
        /// Creates a copy of this key rotation policy.
        /// </summary>
        /// <returns>A new KeyRotationPolicy instance with copied settings.</returns>
        public KeyRotationPolicy Clone()
        {
            return new KeyRotationPolicy
            {
                TriggerType = TriggerType,
                MessageCountThreshold = MessageCountThreshold,
                TimeIntervalThreshold = TimeIntervalThreshold,
                DataVolumeThreshold = DataVolumeThreshold,
                EnableAdaptiveRotation = EnableAdaptiveRotation,
                RiskFactors = RiskFactors.Clone(),
                MinRotationInterval = MinRotationInterval,
                MaxRotationInterval = MaxRotationInterval,
                RotateOnSessionStart = RotateOnSessionStart,
                RotateOnSessionEnd = RotateOnSessionEnd,
                RotateOnDeviceJoin = RotateOnDeviceJoin,
                RotateOnDeviceLeave = RotateOnDeviceLeave,
                CustomSchedule = CustomSchedule?.Clone(),
                PerformanceSettings = PerformanceSettings.Clone(),
                ComplianceSettings = ComplianceSettings.Clone()
            };
        }

        /// <summary>
        /// Returns a policy optimized for maximum security.
        /// </summary>
        public static KeyRotationPolicy MaximumSecurity => new()
        {
            TriggerType = KeyRotationTriggerType.Composite,
            MessageCountThreshold = 10,
            TimeIntervalThreshold = TimeSpan.FromMinutes(30),
            DataVolumeThreshold = 524288, // 512 KB
            EnableAdaptiveRotation = true,
            MinRotationInterval = TimeSpan.FromSeconds(30),
            MaxRotationInterval = TimeSpan.FromDays(1),
            RotateOnSessionStart = true,
            RotateOnSessionEnd = true,
            RotateOnDeviceJoin = true,
            RotateOnDeviceLeave = true,
            RiskFactors = KeyRotationRiskFactors.HighSecurity,
            ComplianceSettings = KeyRotationComplianceSettings.StrictCompliance
        };

        /// <summary>
        /// Returns a policy balanced between security and performance.
        /// </summary>
        public static KeyRotationPolicy Balanced => new()
        {
            TriggerType = KeyRotationTriggerType.MessageCount,
            MessageCountThreshold = 100,
            TimeIntervalThreshold = TimeSpan.FromHours(4),
            DataVolumeThreshold = 5242880, // 5 MB
            EnableAdaptiveRotation = true,
            MinRotationInterval = TimeSpan.FromMinutes(5),
            MaxRotationInterval = TimeSpan.FromDays(7),
            RotateOnSessionStart = false,
            RotateOnSessionEnd = true,
            RotateOnDeviceJoin = true,
            RotateOnDeviceLeave = true,
            RiskFactors = KeyRotationRiskFactors.Moderate,
            PerformanceSettings = KeyRotationPerformanceSettings.Balanced
        };

        /// <summary>
        /// Returns a policy optimized for performance with minimal security overhead.
        /// </summary>
        public static KeyRotationPolicy PerformanceOptimized => new()
        {
            TriggerType = KeyRotationTriggerType.TimeInterval,
            MessageCountThreshold = 1000,
            TimeIntervalThreshold = TimeSpan.FromHours(24),
            DataVolumeThreshold = 52428800, // 50 MB
            EnableAdaptiveRotation = false,
            MinRotationInterval = TimeSpan.FromMinutes(30),
            MaxRotationInterval = TimeSpan.FromDays(30),
            RotateOnSessionStart = false,
            RotateOnSessionEnd = false,
            RotateOnDeviceJoin = false,
            RotateOnDeviceLeave = true,
            PerformanceSettings = KeyRotationPerformanceSettings.HighPerformance
        };

        /// <summary>
        /// Returns a policy for compliance with regulatory requirements.
        /// </summary>
        public static KeyRotationPolicy RegulatoryCompliance => new()
        {
            TriggerType = KeyRotationTriggerType.Composite,
            MessageCountThreshold = 50,
            TimeIntervalThreshold = TimeSpan.FromHours(8),
            DataVolumeThreshold = 2097152, // 2 MB
            EnableAdaptiveRotation = true,
            MinRotationInterval = TimeSpan.FromMinutes(10),
            MaxRotationInterval = TimeSpan.FromDays(3),
            RotateOnSessionStart = true,
            RotateOnSessionEnd = true,
            RotateOnDeviceJoin = true,
            RotateOnDeviceLeave = true,
            ComplianceSettings = KeyRotationComplianceSettings.StrictCompliance,
            RiskFactors = KeyRotationRiskFactors.HighSecurity
        };
    }

    /// <summary>
    /// Risk factors that can trigger additional key rotations.
    /// </summary>
    public class KeyRotationRiskFactors
    {
        /// <summary>
        /// Number of failed authentication attempts that trigger rotation.
        /// </summary>
        public int FailedAuthThreshold { get; set; } = 5;

        /// <summary>
        /// Suspicious network activity detection threshold.
        /// </summary>
        public int SuspiciousActivityThreshold { get; set; } = 3;

        /// <summary>
        /// Whether to rotate on potential compromise detection.
        /// </summary>
        public bool RotateOnCompromiseDetection { get; set; } = true;

        /// <summary>
        /// Whether to rotate when connecting from a new location.
        /// </summary>
        public bool RotateOnNewLocation { get; set; } = false;

        /// <summary>
        /// Whether to rotate when security software updates are detected.
        /// </summary>
        public bool RotateOnSecurityUpdates { get; set; } = false;

        /// <summary>
        /// Time window for risk assessment.
        /// </summary>
        public TimeSpan RiskAssessmentWindow { get; set; } = TimeSpan.FromHours(24);

        /// <summary>
        /// Validates the risk factors configuration.
        /// </summary>
        public List<string> Validate()
        {
            var errors = new List<string>();

            if (FailedAuthThreshold <= 0)
                errors.Add("FailedAuthThreshold must be greater than 0");

            if (SuspiciousActivityThreshold <= 0)
                errors.Add("SuspiciousActivityThreshold must be greater than 0");

            if (RiskAssessmentWindow <= TimeSpan.Zero)
                errors.Add("RiskAssessmentWindow must be greater than zero");

            return errors;
        }

        /// <summary>
        /// Creates a copy of these risk factors.
        /// </summary>
        public KeyRotationRiskFactors Clone()
        {
            return new KeyRotationRiskFactors
            {
                FailedAuthThreshold = FailedAuthThreshold,
                SuspiciousActivityThreshold = SuspiciousActivityThreshold,
                RotateOnCompromiseDetection = RotateOnCompromiseDetection,
                RotateOnNewLocation = RotateOnNewLocation,
                RotateOnSecurityUpdates = RotateOnSecurityUpdates,
                RiskAssessmentWindow = RiskAssessmentWindow
            };
        }

        /// <summary>
        /// High security risk factors configuration.
        /// </summary>
        public static KeyRotationRiskFactors HighSecurity => new()
        {
            FailedAuthThreshold = 2,
            SuspiciousActivityThreshold = 1,
            RotateOnCompromiseDetection = true,
            RotateOnNewLocation = true,
            RotateOnSecurityUpdates = true,
            RiskAssessmentWindow = TimeSpan.FromHours(1)
        };

        /// <summary>
        /// Moderate security risk factors configuration.
        /// </summary>
        public static KeyRotationRiskFactors Moderate => new()
        {
            FailedAuthThreshold = 5,
            SuspiciousActivityThreshold = 3,
            RotateOnCompromiseDetection = true,
            RotateOnNewLocation = false,
            RotateOnSecurityUpdates = false,
            RiskAssessmentWindow = TimeSpan.FromHours(12)
        };
    }

    /// <summary>
    /// Performance optimization settings for key rotation.
    /// </summary>
    public class KeyRotationPerformanceSettings
    {
        /// <summary>
        /// Whether to batch key rotations to reduce overhead.
        /// </summary>
        public bool EnableBatching { get; set; } = false;

        /// <summary>
        /// Maximum number of rotations to batch together.
        /// </summary>
        public int MaxBatchSize { get; set; } = 5;

        /// <summary>
        /// Maximum time to wait before processing a partial batch.
        /// </summary>
        public TimeSpan BatchTimeout { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>
        /// Whether to use background rotation to avoid blocking operations.
        /// </summary>
        public bool EnableBackgroundRotation { get; set; } = true;

        /// <summary>
        /// Priority level for rotation operations.
        /// </summary>
        public KeyRotationPriority Priority { get; set; } = KeyRotationPriority.Normal;

        /// <summary>
        /// Maximum time to spend on a single rotation operation.
        /// </summary>
        public TimeSpan MaxRotationTime { get; set; } = TimeSpan.FromSeconds(10);

        /// <summary>
        /// Validates the performance settings.
        /// </summary>
        public List<string> Validate()
        {
            var errors = new List<string>();

            if (MaxBatchSize <= 0)
                errors.Add("MaxBatchSize must be greater than 0");

            if (BatchTimeout <= TimeSpan.Zero)
                errors.Add("BatchTimeout must be greater than zero");

            if (MaxRotationTime <= TimeSpan.Zero)
                errors.Add("MaxRotationTime must be greater than zero");

            return errors;
        }

        /// <summary>
        /// Creates a copy of these performance settings.
        /// </summary>
        public KeyRotationPerformanceSettings Clone()
        {
            return new KeyRotationPerformanceSettings
            {
                EnableBatching = EnableBatching,
                MaxBatchSize = MaxBatchSize,
                BatchTimeout = BatchTimeout,
                EnableBackgroundRotation = EnableBackgroundRotation,
                Priority = Priority,
                MaxRotationTime = MaxRotationTime
            };
        }

        /// <summary>
        /// High performance settings configuration.
        /// </summary>
        public static KeyRotationPerformanceSettings HighPerformance => new()
        {
            EnableBatching = true,
            MaxBatchSize = 10,
            BatchTimeout = TimeSpan.FromSeconds(10),
            EnableBackgroundRotation = true,
            Priority = KeyRotationPriority.Low,
            MaxRotationTime = TimeSpan.FromSeconds(5)
        };

        /// <summary>
        /// Balanced performance settings configuration.
        /// </summary>
        public static KeyRotationPerformanceSettings Balanced => new()
        {
            EnableBatching = true,
            MaxBatchSize = 5,
            BatchTimeout = TimeSpan.FromSeconds(30),
            EnableBackgroundRotation = true,
            Priority = KeyRotationPriority.Normal,
            MaxRotationTime = TimeSpan.FromSeconds(10)
        };
    }

    /// <summary>
    /// Compliance settings for regulatory requirements.
    /// </summary>
    public class KeyRotationComplianceSettings
    {
        /// <summary>
        /// Whether to maintain audit logs of all key rotations.
        /// </summary>
        public bool EnableAuditLogging { get; set; } = false;

        /// <summary>
        /// Whether to require rotation confirmation from multiple parties.
        /// </summary>
        public bool RequireMultiPartyConfirmation { get; set; } = false;

        /// <summary>
        /// Minimum number of parties required for confirmation.
        /// </summary>
        public int MinConfirmationParties { get; set; } = 2;

        /// <summary>
        /// Whether to enforce strict rotation timing requirements.
        /// </summary>
        public bool EnforceStrictTiming { get; set; } = false;

        /// <summary>
        /// Compliance standard being followed (e.g., "FIPS-140-2", "Common Criteria").
        /// </summary>
        public string ComplianceStandard { get; set; } = string.Empty;

        /// <summary>
        /// Whether to prevent rotation rollback for compliance.
        /// </summary>
        public bool PreventRollback { get; set; } = true;

        /// <summary>
        /// Validates the compliance settings.
        /// </summary>
        public List<string> Validate()
        {
            var errors = new List<string>();

            if (RequireMultiPartyConfirmation && MinConfirmationParties < 2)
                errors.Add("MinConfirmationParties must be at least 2 when RequireMultiPartyConfirmation is enabled");

            if (MinConfirmationParties > 10)
                errors.Add("MinConfirmationParties should not exceed 10 for practical reasons");

            return errors;
        }

        /// <summary>
        /// Creates a copy of these compliance settings.
        /// </summary>
        public KeyRotationComplianceSettings Clone()
        {
            return new KeyRotationComplianceSettings
            {
                EnableAuditLogging = EnableAuditLogging,
                RequireMultiPartyConfirmation = RequireMultiPartyConfirmation,
                MinConfirmationParties = MinConfirmationParties,
                EnforceStrictTiming = EnforceStrictTiming,
                ComplianceStandard = ComplianceStandard,
                PreventRollback = PreventRollback
            };
        }

        /// <summary>
        /// Strict compliance settings configuration.
        /// </summary>
        public static KeyRotationComplianceSettings StrictCompliance => new()
        {
            EnableAuditLogging = true,
            RequireMultiPartyConfirmation = false, // Typically not needed for automated systems
            MinConfirmationParties = 2,
            EnforceStrictTiming = true,
            ComplianceStandard = "FIPS-140-2",
            PreventRollback = true
        };
    }

    /// <summary>
    /// Custom rotation schedule for predictable rotations.
    /// </summary>
    public class KeyRotationSchedule
    {
        /// <summary>
        /// Specific times of day when rotation should occur.
        /// </summary>
        public List<TimeOnly> ScheduledTimes { get; set; } = new();

        /// <summary>
        /// Days of the week when rotation should occur.
        /// </summary>
        public List<DayOfWeek> ScheduledDays { get; set; } = new();

        /// <summary>
        /// Whether the schedule is enabled.
        /// </summary>
        public bool Enabled { get; set; } = false;

        /// <summary>
        /// Time zone for the schedule.
        /// </summary>
        public string TimeZone { get; set; } = "UTC";

        /// <summary>
        /// Validates the rotation schedule.
        /// </summary>
        public List<string> Validate()
        {
            var errors = new List<string>();

            if (Enabled && ScheduledTimes.Count == 0)
                errors.Add("ScheduledTimes cannot be empty when schedule is enabled");

            if (Enabled && ScheduledDays.Count == 0)
                errors.Add("ScheduledDays cannot be empty when schedule is enabled");

            try
            {
                TimeZoneInfo.FindSystemTimeZoneById(TimeZone);
            }
            catch
            {
                errors.Add($"Invalid TimeZone: {TimeZone}");
            }

            return errors;
        }

        /// <summary>
        /// Creates a copy of this rotation schedule.
        /// </summary>
        public KeyRotationSchedule Clone()
        {
            return new KeyRotationSchedule
            {
                ScheduledTimes = new List<TimeOnly>(ScheduledTimes),
                ScheduledDays = new List<DayOfWeek>(ScheduledDays),
                Enabled = Enabled,
                TimeZone = TimeZone
            };
        }
    }
}