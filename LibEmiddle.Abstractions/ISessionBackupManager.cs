using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;

namespace LibEmiddle.Abstractions
{
    /// <summary>
    /// Interface for managing session backup and restore operations (v2.5).
    /// Provides secure backup and recovery of encrypted session data.
    /// </summary>
    public interface ISessionBackupManager : IDisposable
    {
        /// <summary>
        /// Creates a backup of the specified session.
        /// </summary>
        /// <param name="sessionId">ID of the session to backup.</param>
        /// <param name="backupOptions">Backup configuration options. If null, uses default options.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Information about the created backup.</returns>
        Task<BackupInfo> CreateBackupAsync(
            string sessionId,
            BackupOptions? backupOptions = null,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Creates a backup of all sessions.
        /// </summary>
        /// <param name="backupOptions">Backup configuration options. If null, uses default options.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Information about the created backup.</returns>
        Task<BackupInfo> CreateFullBackupAsync(
            BackupOptions? backupOptions = null,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Restores a session from a backup file.
        /// </summary>
        /// <param name="backupFilePath">Path to the backup file.</param>
        /// <param name="encryptionKey">Encryption key for the backup. If null, attempts to derive from identity key.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Information about the restored sessions.</returns>
        Task<RestoreResult> RestoreBackupAsync(
            string backupFilePath,
            byte[]? encryptionKey = null,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Lists available backup files.
        /// </summary>
        /// <param name="backupDirectory">Directory to search for backups. If null, uses default backup path.</param>
        /// <returns>List of available backup files with metadata.</returns>
        Task<IReadOnlyList<BackupInfo>> ListBackupsAsync(string? backupDirectory = null);

        /// <summary>
        /// Verifies the integrity of a backup file.
        /// </summary>
        /// <param name="backupFilePath">Path to the backup file to verify.</param>
        /// <param name="encryptionKey">Encryption key for the backup. If null, attempts to derive from identity key.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Verification result with details.</returns>
        Task<BackupVerificationResult> VerifyBackupAsync(
            string backupFilePath,
            byte[]? encryptionKey = null,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Deletes old backup files based on retention policy.
        /// </summary>
        /// <param name="backupOptions">Backup options containing retention settings.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Number of files deleted.</returns>
        Task<int> CleanupOldBackupsAsync(
            BackupOptions backupOptions,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Estimates the size of a backup for the specified session.
        /// </summary>
        /// <param name="sessionId">ID of the session to estimate backup size for.</param>
        /// <param name="backupOptions">Backup configuration options.</param>
        /// <returns>Estimated backup size in bytes.</returns>
        Task<long> EstimateBackupSizeAsync(string sessionId, BackupOptions backupOptions);

        /// <summary>
        /// Gets statistics about backup operations and storage usage.
        /// </summary>
        /// <returns>Backup statistics.</returns>
        Task<BackupStatistics> GetStatisticsAsync();

        /// <summary>
        /// Event fired when a backup operation completes.
        /// </summary>
        event EventHandler<BackupCompletedEventArgs>? BackupCompleted;

        /// <summary>
        /// Event fired when a restore operation completes.
        /// </summary>
        event EventHandler<RestoreCompletedEventArgs>? RestoreCompleted;

        /// <summary>
        /// Event fired when backup cleanup occurs.
        /// </summary>
        event EventHandler<BackupCleanupEventArgs>? CleanupCompleted;
    }

    /// <summary>
    /// Information about a backup file or operation.
    /// </summary>
    public class BackupInfo
    {
        /// <summary>
        /// Unique identifier for this backup.
        /// </summary>
        public string BackupId { get; set; } = string.Empty;

        /// <summary>
        /// Path to the backup file.
        /// </summary>
        public string FilePath { get; set; } = string.Empty;

        /// <summary>
        /// When the backup was created.
        /// </summary>
        public DateTime CreatedAt { get; set; }

        /// <summary>
        /// Size of the backup file in bytes.
        /// </summary>
        public long FileSize { get; set; }

        /// <summary>
        /// Number of sessions included in the backup.
        /// </summary>
        public int SessionCount { get; set; }

        /// <summary>
        /// Whether the backup includes message history.
        /// </summary>
        public bool IncludesMessageHistory { get; set; }

        /// <summary>
        /// Whether the backup includes one-time keys.
        /// </summary>
        public bool IncludesOneTimeKeys { get; set; }

        /// <summary>
        /// Whether the backup is compressed.
        /// </summary>
        public bool IsCompressed { get; set; }

        /// <summary>
        /// Version of the backup format.
        /// </summary>
        public string FormatVersion { get; set; } = "2.5.0";

        /// <summary>
        /// Checksum for integrity verification.
        /// </summary>
        public string Checksum { get; set; } = string.Empty;

        /// <summary>
        /// Additional metadata about the backup.
        /// </summary>
        public Dictionary<string, string> Metadata { get; set; } = new();
    }

    /// <summary>
    /// Result of a restore operation.
    /// </summary>
    public class RestoreResult
    {
        /// <summary>
        /// Whether the restore operation was successful.
        /// </summary>
        public bool Success { get; set; }

        /// <summary>
        /// Number of sessions successfully restored.
        /// </summary>
        public int RestoredSessionCount { get; set; }

        /// <summary>
        /// List of session IDs that were restored.
        /// </summary>
        public List<string> RestoredSessionIds { get; set; } = new();

        /// <summary>
        /// List of any errors that occurred during restore.
        /// </summary>
        public List<string> Errors { get; set; } = new();

        /// <summary>
        /// Information about the backup that was restored.
        /// </summary>
        public BackupInfo? BackupInfo { get; set; }

        /// <summary>
        /// Duration of the restore operation.
        /// </summary>
        public TimeSpan Duration { get; set; }
    }

    /// <summary>
    /// Result of backup verification.
    /// </summary>
    public class BackupVerificationResult
    {
        /// <summary>
        /// Whether the backup file is valid and can be restored.
        /// </summary>
        public bool IsValid { get; set; }

        /// <summary>
        /// Whether the backup file checksum is correct.
        /// </summary>
        public bool ChecksumValid { get; set; }

        /// <summary>
        /// Whether the backup file can be decrypted.
        /// </summary>
        public bool CanDecrypt { get; set; }

        /// <summary>
        /// Information about the backup file.
        /// </summary>
        public BackupInfo? BackupInfo { get; set; }

        /// <summary>
        /// List of any validation errors found.
        /// </summary>
        public List<string> ValidationErrors { get; set; } = new();

        /// <summary>
        /// Time taken to perform verification.
        /// </summary>
        public TimeSpan VerificationTime { get; set; }
    }

    /// <summary>
    /// Statistics about backup operations and storage.
    /// </summary>
    public class BackupStatistics
    {
        /// <summary>
        /// Total number of backups created.
        /// </summary>
        public long TotalBackupsCreated { get; set; }

        /// <summary>
        /// Total number of successful restore operations.
        /// </summary>
        public long TotalRestoresPerformed { get; set; }

        /// <summary>
        /// Total storage space used by backups in bytes.
        /// </summary>
        public long TotalStorageUsed { get; set; }

        /// <summary>
        /// Number of backup files currently stored.
        /// </summary>
        public int ActiveBackupCount { get; set; }

        /// <summary>
        /// Average backup file size in bytes.
        /// </summary>
        public long AverageBackupSize { get; set; }

        /// <summary>
        /// Date of the last successful backup.
        /// </summary>
        public DateTime? LastBackupDate { get; set; }

        /// <summary>
        /// Date of the last successful restore.
        /// </summary>
        public DateTime? LastRestoreDate { get; set; }

        /// <summary>
        /// Number of backup operations that failed.
        /// </summary>
        public long FailedBackupCount { get; set; }

        /// <summary>
        /// Number of restore operations that failed.
        /// </summary>
        public long FailedRestoreCount { get; set; }
    }

    /// <summary>
    /// Event arguments for backup completion events.
    /// </summary>
    public class BackupCompletedEventArgs : EventArgs
    {
        /// <summary>
        /// Information about the completed backup.
        /// </summary>
        public BackupInfo BackupInfo { get; set; } = new();

        /// <summary>
        /// Whether the backup operation was successful.
        /// </summary>
        public bool Success { get; set; }

        /// <summary>
        /// Any error that occurred during backup.
        /// </summary>
        public Exception? Error { get; set; }

        /// <summary>
        /// Duration of the backup operation.
        /// </summary>
        public TimeSpan Duration { get; set; }
    }

    /// <summary>
    /// Event arguments for restore completion events.
    /// </summary>
    public class RestoreCompletedEventArgs : EventArgs
    {
        /// <summary>
        /// Result of the restore operation.
        /// </summary>
        public RestoreResult Result { get; set; } = new();

        /// <summary>
        /// Path to the backup file that was restored.
        /// </summary>
        public string BackupFilePath { get; set; } = string.Empty;

        /// <summary>
        /// Duration of the restore operation.
        /// </summary>
        public TimeSpan Duration { get; set; }
    }

    /// <summary>
    /// Event arguments for backup cleanup events.
    /// </summary>
    public class BackupCleanupEventArgs : EventArgs
    {
        /// <summary>
        /// Number of backup files that were deleted.
        /// </summary>
        public int FilesDeleted { get; set; }

        /// <summary>
        /// Total storage space freed in bytes.
        /// </summary>
        public long StorageFreed { get; set; }

        /// <summary>
        /// List of backup files that were deleted.
        /// </summary>
        public List<string> DeletedFiles { get; set; } = new();

        /// <summary>
        /// Duration of the cleanup operation.
        /// </summary>
        public TimeSpan Duration { get; set; }
    }
}