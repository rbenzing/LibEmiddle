namespace LibEmiddle.Domain
{
    /// <summary>
    /// Configuration options for session backup and restore functionality.
    /// Enables secure backup of encrypted session data for disaster recovery.
    /// </summary>
    public class BackupOptions
    {
        /// <summary>
        /// Directory path where backups will be stored.
        /// </summary>
        public string BackupPath { get; set; } = "./backups";

        /// <summary>
        /// Whether to compress backup files to reduce storage space.
        /// </summary>
        public bool CompressBackups { get; set; } = true;

        /// <summary>
        /// How long to retain backup files before automatic cleanup.
        /// </summary>
        public TimeSpan BackupRetention { get; set; } = TimeSpan.FromDays(30);

        /// <summary>
        /// Custom encryption key for backup files.
        /// If null, derives encryption key from identity key.
        /// </summary>
        public byte[]? EncryptionKey { get; set; } = null;

        /// <summary>
        /// Whether to include message history in backups.
        /// When false, only session keys and metadata are backed up.
        /// </summary>
        public bool IncludeMessageHistory { get; set; } = false;

        /// <summary>
        /// Whether to include one-time prekeys in backups.
        /// When false, only long-term keys are backed up.
        /// </summary>
        public bool IncludeOneTimeKeys { get; set; } = false;

        /// <summary>
        /// Interval for automatic backup creation.
        /// Set to TimeSpan.Zero to disable automatic backups.
        /// </summary>
        public TimeSpan AutoBackupInterval { get; set; } = TimeSpan.Zero;

        /// <summary>
        /// Maximum number of backup files to keep.
        /// Older backups are automatically deleted when this limit is exceeded.
        /// </summary>
        public int MaxBackupFiles { get; set; } = 10;

        /// <summary>
        /// Whether to verify backup integrity after creation.
        /// </summary>
        public bool VerifyAfterBackup { get; set; } = true;

        /// <summary>
        /// Custom backup file naming pattern.
        /// Supports {timestamp}, {version}, {device} placeholders.
        /// </summary>
        public string BackupFilePattern { get; set; } = "libemiddle-backup-{timestamp}.enc";

        /// <summary>
        /// Validates the backup configuration.
        /// </summary>
        /// <returns>True if the configuration is valid.</returns>
        public bool IsValid()
        {
            return !string.IsNullOrWhiteSpace(BackupPath) &&
                   BackupRetention > TimeSpan.Zero &&
                   AutoBackupInterval >= TimeSpan.Zero &&
                   MaxBackupFiles > 0 &&
                   !string.IsNullOrWhiteSpace(BackupFilePattern);
        }

        /// <summary>
        /// Returns a configuration optimized for minimal storage usage.
        /// </summary>
        public static BackupOptions MinimalStorage => new()
        {
            CompressBackups = true,
            BackupRetention = TimeSpan.FromDays(7),
            IncludeMessageHistory = false,
            IncludeOneTimeKeys = false,
            MaxBackupFiles = 3,
            VerifyAfterBackup = false
        };

        /// <summary>
        /// Returns a configuration optimized for comprehensive data protection.
        /// </summary>
        public static BackupOptions Comprehensive => new()
        {
            CompressBackups = true,
            BackupRetention = TimeSpan.FromDays(90),
            IncludeMessageHistory = true,
            IncludeOneTimeKeys = true,
            AutoBackupInterval = TimeSpan.FromHours(6),
            MaxBackupFiles = 20,
            VerifyAfterBackup = true
        };

        /// <summary>
        /// Returns a configuration optimized for development and testing.
        /// </summary>
        public static BackupOptions Development => new()
        {
            BackupPath = "./dev-backups",
            CompressBackups = false,
            BackupRetention = TimeSpan.FromDays(1),
            IncludeMessageHistory = true,
            IncludeOneTimeKeys = true,
            MaxBackupFiles = 5,
            VerifyAfterBackup = true
        };
    }
}