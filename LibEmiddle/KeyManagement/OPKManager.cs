using System.Text.Json;
using LibEmiddle.Core;
using LibEmiddle.Domain;

namespace LibEmiddle.KeyManagement
{
    /// <summary>
    /// Tracks consumed one-time prekeys (OPKs) to prevent reuse, and triggers async
    /// replenishment when the available OPK count falls below a configurable threshold.
    /// </summary>
    /// <remarks>
    /// OPKs are identified by their uint ID (not by key material). The consumed ID set
    /// is persisted to disk so it survives process restarts. All public members are
    /// thread-safe.
    /// </remarks>
    public sealed class OPKManager : IDisposable
    {
        // -----------------------------------------------------------------------
        // Constants
        // -----------------------------------------------------------------------

        /// <summary>Number of available OPKs below which replenishment is triggered.</summary>
        public const int ReplenishmentThreshold = 5;

        /// <summary>Number of new OPKs to generate during replenishment.</summary>
        public const int ReplenishmentBatchSize = 10;

        private const string STORAGE_FILE_NAME = "opk_consumed_ids.json";

        // -----------------------------------------------------------------------
        // Fields
        // -----------------------------------------------------------------------

        private readonly string _storageFilePath;
        private readonly object _lock = new object();
        private readonly HashSet<uint> _consumedIds;

        // Replenishment callback — kept as null until set; called on a background task.
        private Func<int, Task>? _replenishCallback;

        // 0 = idle, 1 = in progress. Using int + Interlocked to avoid TOCTOU on the check-and-set.
        private int _replenishmentInProgress;
        private volatile bool _disposed;

        // -----------------------------------------------------------------------
        // Constructor
        // -----------------------------------------------------------------------

        /// <summary>
        /// Initialises the manager, loading the persisted consumed-ID list from disk.
        /// </summary>
        /// <param name="storagePath">
        /// Directory where the consumed-ID file is stored.
        /// Defaults to the application's local data folder under "LibEmiddle/Keys".
        /// </param>
        public OPKManager(string? storagePath = null)
        {
            string basePath = storagePath ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "LibEmiddle",
                "Keys");

            Directory.CreateDirectory(basePath);
            _storageFilePath = Path.Combine(basePath, STORAGE_FILE_NAME);

            _consumedIds = LoadFromDisk();
        }

        // -----------------------------------------------------------------------
        // Public API
        // -----------------------------------------------------------------------

        /// <summary>
        /// Registers a callback that generates and persists new OPKs when replenishment
        /// is needed. The callback receives the requested number of new OPKs to create.
        /// </summary>
        public void SetReplenishmentCallback(Func<int, Task> callback)
        {
            ArgumentNullException.ThrowIfNull(callback);
            _replenishCallback = callback;
        }

        /// <summary>
        /// Returns <c>true</c> if <paramref name="opkId"/> has already been consumed.
        /// </summary>
        public bool IsConsumed(uint opkId)
        {
            ThrowIfDisposed();
            lock (_lock)
            {
                return _consumedIds.Contains(opkId);
            }
        }

        /// <summary>
        /// Atomically checks whether <paramref name="opkId"/> has been consumed and, if not,
        /// marks it consumed in the same lock acquisition. Optionally triggers async replenishment
        /// when the available OPK count drops below <see cref="ReplenishmentThreshold"/>.
        /// </summary>
        /// <param name="opkId">The OPK ID to check and consume.</param>
        /// <param name="allKnownIds">
        /// The complete list of OPK IDs currently in the local key bundle, used to compute
        /// how many OPKs are still available and whether replenishment should be triggered.
        /// Pass <c>null</c> to skip replenishment triggering.
        /// </param>
        /// <returns>
        /// <c>true</c> if the ID was not previously consumed and has now been marked consumed;
        /// <c>false</c> if the ID was already consumed (the caller should reject the handshake).
        /// </returns>
        public bool TryConsume(uint opkId, IReadOnlyList<uint>? allKnownIds = null)
        {
            ThrowIfDisposed();
            bool added;
            int availableCount;
            lock (_lock)
            {
                // HashSet.Add returns false when the element is already present.
                // Both the check and the insertion happen inside one lock acquisition,
                // so two concurrent arrivals with the same OPK ID cannot both succeed.
                added = _consumedIds.Add(opkId);
                availableCount = ComputeAvailableCount(allKnownIds);
            }

            if (added)
            {
                PersistToDisk();
                LoggingManager.LogDebug(nameof(OPKManager),
                    $"OPK {opkId} atomically consumed via TryConsume. Available: {availableCount}");

                // Trigger replenishment outside the lock to avoid holding it during I/O.
                if (allKnownIds != null && availableCount < ReplenishmentThreshold)
                {
                    TriggerReplenishmentAsync();
                }
            }

            return added;
        }

        /// <summary>
        /// Marks <paramref name="opkId"/> as consumed, persists the updated set, and
        /// triggers async replenishment if the number of available OPKs in
        /// <paramref name="allKnownIds"/> has fallen below <see cref="ReplenishmentThreshold"/>.
        /// </summary>
        /// <param name="opkId">The ID of the OPK that was used.</param>
        /// <param name="allKnownIds">
        /// The complete list of OPK IDs currently in the local key bundle.
        /// Used to compute how many OPKs are still available.
        /// </param>
        public void MarkConsumed(uint opkId, IReadOnlyList<uint>? allKnownIds = null)
        {
            ThrowIfDisposed();

            bool changed;
            int availableCount;

            lock (_lock)
            {
                changed = _consumedIds.Add(opkId);
                availableCount = ComputeAvailableCount(allKnownIds);
            }

            if (changed)
            {
                PersistToDisk();
                LoggingManager.LogDebug(nameof(OPKManager), $"OPK {opkId} marked as consumed. Available: {availableCount}");
            }

            // Trigger replenishment outside the lock to avoid holding it during I/O.
            if (availableCount < ReplenishmentThreshold)
            {
                TriggerReplenishmentAsync();
            }
        }

        /// <summary>
        /// Returns the subset of <paramref name="allIds"/> that have not yet been consumed.
        /// </summary>
        public IReadOnlyList<uint> FilterAvailable(IReadOnlyList<uint> allIds)
        {
            ThrowIfDisposed();
            ArgumentNullException.ThrowIfNull(allIds);

            lock (_lock)
            {
                var result = new List<uint>(allIds.Count);
                foreach (uint id in allIds)
                {
                    if (!_consumedIds.Contains(id))
                        result.Add(id);
                }
                return result;
            }
        }

        /// <summary>
        /// Returns the number of OPK IDs in <paramref name="allKnownIds"/> that have
        /// not yet been consumed.
        /// </summary>
        public int GetAvailableCount(IReadOnlyList<uint>? allKnownIds)
        {
            ThrowIfDisposed();
            lock (_lock)
            {
                return ComputeAvailableCount(allKnownIds);
            }
        }

        /// <summary>
        /// Returns the total number of consumed OPK IDs currently tracked.
        /// </summary>
        public int ConsumedCount
        {
            get
            {
                ThrowIfDisposed();
                lock (_lock)
                {
                    return _consumedIds.Count;
                }
            }
        }

        // -----------------------------------------------------------------------
        // Persistence
        // -----------------------------------------------------------------------

        private HashSet<uint> LoadFromDisk()
        {
            try
            {
                if (!File.Exists(_storageFilePath))
                    return new HashSet<uint>();

                string json = File.ReadAllText(_storageFilePath);
                if (string.IsNullOrWhiteSpace(json))
                    return new HashSet<uint>();

                var ids = JsonSerializer.Deserialize<List<uint>>(json);
                if (ids == null)
                    return new HashSet<uint>();

                LoggingManager.LogDebug(nameof(OPKManager), $"Loaded {ids.Count} consumed OPK IDs from disk.");
                return new HashSet<uint>(ids);
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(OPKManager), $"Failed to load consumed OPK IDs from disk: {ex.Message}");
                return new HashSet<uint>();
            }
        }

        private void PersistToDisk()
        {
            try
            {
                List<uint> snapshot;
                lock (_lock)
                {
                    snapshot = new List<uint>(_consumedIds);
                }

                string json = JsonSerializer.Serialize(snapshot);
                // Write atomically via a temp file then replace.
                string tempPath = _storageFilePath + ".tmp";
                File.WriteAllText(tempPath, json);
                File.Move(tempPath, _storageFilePath, overwrite: true);
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(OPKManager), $"Failed to persist consumed OPK IDs: {ex.Message}");
            }
        }

        // -----------------------------------------------------------------------
        // Replenishment
        // -----------------------------------------------------------------------

        private void TriggerReplenishmentAsync()
        {
            if (_replenishCallback == null)
                return;

            // Only one replenishment run at a time. Use CAS so that exactly one thread can
            // transition from 0 (idle) → 1 (in progress). Any concurrent caller that loses
            // the race sees a non-zero return value and exits immediately.
            if (Interlocked.CompareExchange(ref _replenishmentInProgress, 1, 0) != 0)
                return;

            Func<int, Task> callback = _replenishCallback;
            _ = Task.Run(async () =>
            {
                try
                {
                    LoggingManager.LogInformation(nameof(OPKManager),
                        $"Replenishing {ReplenishmentBatchSize} new OPKs (available count below threshold).");
                    await callback(ReplenishmentBatchSize).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    LoggingManager.LogError(nameof(OPKManager), $"OPK replenishment failed: {ex.Message}");
                }
                finally
                {
                    // Reset to idle so the next under-threshold event can trigger replenishment.
                    Interlocked.Exchange(ref _replenishmentInProgress, 0);
                }
            });
        }

        // -----------------------------------------------------------------------
        // Helpers
        // -----------------------------------------------------------------------

        /// <remarks>Must be called while holding <see cref="_lock"/>.</remarks>
        private int ComputeAvailableCount(IReadOnlyList<uint>? allKnownIds)
        {
            if (allKnownIds == null)
                return 0;

            int count = 0;
            foreach (uint id in allKnownIds)
            {
                if (!_consumedIds.Contains(id))
                    count++;
            }
            return count;
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(OPKManager));
        }

        // -----------------------------------------------------------------------
        // IDisposable
        // -----------------------------------------------------------------------

        /// <summary>Disposes the manager (no-op: no unmanaged resources).</summary>
        public void Dispose()
        {
            _disposed = true;
        }
    }
}
