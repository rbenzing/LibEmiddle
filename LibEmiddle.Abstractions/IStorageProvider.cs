namespace LibEmiddle.Abstractions
{
    /// <summary>
    /// Defines an interface for storage providers to persist and retrieve data.
    /// Implementations can store data in various backends such as filesystem, 
    /// secure key stores, databases, or cloud storage.
    /// Enhanced in v2.5 with additional capabilities for advanced storage scenarios.
    /// </summary>
    public interface IStorageProvider
    {
        // --- Existing v2.0 Methods (Maintained for Backward Compatibility) ---

        /// <summary>
        /// Stores data in the storage backend.
        /// </summary>
        /// <param name="key">The unique key to identify the data.</param>
        /// <param name="data">The data to store.</param>
        /// <returns>A task that represents the asynchronous operation.</returns>
        Task StoreAsync(string key, string data);

        /// <summary>
        /// Stores binary data in the storage backend.
        /// </summary>
        /// <param name="key">The unique key to identify the data.</param>
        /// <param name="data">The binary data to store.</param>
        /// <returns>A task that represents the asynchronous operation.</returns>
        Task StoreBinaryAsync(string key, byte[] data);

        /// <summary>
        /// Retrieves data from the storage backend.
        /// </summary>
        /// <param name="key">The unique key to identify the data.</param>
        /// <returns>The stored data, or null if the key doesn't exist.</returns>
        Task<string> RetrieveAsync(string key);

        /// <summary>
        /// Retrieves binary data from the storage backend.
        /// </summary>
        /// <param name="key">The unique key to identify the data.</param>
        /// <returns>The stored binary data, or null if the key doesn't exist.</returns>
        Task<byte[]?> RetrieveBinaryAsync(string key);

        /// <summary>
        /// Deletes data from the storage backend.
        /// </summary>
        /// <param name="key">The unique key to identify the data.</param>
        /// <returns>True if the data was deleted, false if the key doesn't exist.</returns>
        Task<bool> DeleteAsync(string key);

        /// <summary>
        /// Checks if a key exists in the storage backend.
        /// </summary>
        /// <param name="key">The unique key to check.</param>
        /// <returns>True if the key exists, false otherwise.</returns>
        Task<bool> ExistsAsync(string key);

        /// <summary>
        /// Lists all keys in the storage backend that match a prefix.
        /// </summary>
        /// <param name="keyPrefix">The prefix to match keys against.</param>
        /// <returns>A list of keys that match the prefix.</returns>
        Task<List<string>> ListKeysAsync(string keyPrefix);

        /// <summary>
        /// Securely clears all data from the storage backend.
        /// </summary>
        /// <returns>A task that represents the asynchronous operation.</returns>
        Task ClearAllAsync();
    }

    /// <summary>
    /// Enhanced storage provider interface with v2.5 capabilities (optional).
    /// Providers can implement this interface to provide advanced features.
    /// </summary>
    public interface IEnhancedStorageProvider : IStorageProvider
    {
        // --- v2.5 Enhanced Methods ---

        /// <summary>
        /// Stores a strongly-typed object in the storage backend with optional expiration.
        /// </summary>
        /// <typeparam name="T">Type of the object to store.</typeparam>
        /// <param name="key">The unique key to identify the data.</param>
        /// <param name="value">The object to store.</param>
        /// <param name="expiry">Optional expiration time for the value.</param>
        /// <returns>True if the value was stored successfully.</returns>
        Task<bool> SetAsync<T>(string key, T value, TimeSpan? expiry = null) where T : class;

        /// <summary>
        /// Retrieves a strongly-typed object from the storage backend.
        /// </summary>
        /// <typeparam name="T">Type of the object to retrieve.</typeparam>
        /// <param name="key">The unique key to identify the data.</param>
        /// <returns>The stored object, or null if not found.</returns>
        Task<T?> GetAsync<T>(string key) where T : class;

        /// <summary>
        /// Gets all keys matching a pattern with wildcard support.
        /// </summary>
        /// <param name="pattern">Pattern to match (supports wildcards like * and ?).</param>
        /// <returns>Collection of matching keys.</returns>
        Task<IEnumerable<string>> GetKeysAsync(string pattern = "*");

        /// <summary>
        /// Gets metadata about a stored value.
        /// </summary>
        /// <param name="key">The storage key.</param>
        /// <returns>Storage metadata, or null if the key doesn't exist.</returns>
        Task<StorageMetadata?> GetMetadataAsync(string key);

        /// <summary>
        /// Performs batch operations atomically.
        /// </summary>
        /// <param name="operations">Collection of storage operations to perform.</param>
        /// <returns>True if all operations succeeded.</returns>
        Task<bool> BatchAsync(IEnumerable<StorageOperation> operations);

        /// <summary>
        /// Gets storage statistics and usage information.
        /// </summary>
        /// <returns>Storage statistics.</returns>
        Task<StorageStatistics> GetStatisticsAsync();

        /// <summary>
        /// Tests the connectivity and health of the storage provider.
        /// </summary>
        /// <returns>True if the storage provider is healthy and accessible.</returns>
        Task<bool> HealthCheckAsync();

        /// <summary>
        /// Gets the name of this storage provider.
        /// </summary>
        string ProviderName { get; }

        /// <summary>
        /// Gets whether this storage provider supports transactions.
        /// </summary>
        bool SupportsTransactions { get; }

        /// <summary>
        /// Gets whether this storage provider supports expiration.
        /// </summary>
        bool SupportsExpiration { get; }
    }

    /// <summary>
    /// Metadata about a stored value (v2.5).
    /// </summary>
    public class StorageMetadata
    {
        /// <summary>
        /// The storage key.
        /// </summary>
        public string Key { get; set; } = string.Empty;

        /// <summary>
        /// When the value was created.
        /// </summary>
        public DateTime CreatedAt { get; set; }

        /// <summary>
        /// When the value was last modified.
        /// </summary>
        public DateTime ModifiedAt { get; set; }

        /// <summary>
        /// When the value expires, if applicable.
        /// </summary>
        public DateTime? ExpiresAt { get; set; }

        /// <summary>
        /// Size of the stored value in bytes.
        /// </summary>
        public long SizeBytes { get; set; }

        /// <summary>
        /// Type of the stored value.
        /// </summary>
        public string ValueType { get; set; } = string.Empty;

        /// <summary>
        /// Additional metadata properties.
        /// </summary>
        public Dictionary<string, object> Properties { get; set; } = new();

        /// <summary>
        /// Gets whether the stored value has expired.
        /// </summary>
        public bool IsExpired => ExpiresAt.HasValue && ExpiresAt.Value <= DateTime.UtcNow;
    }

    /// <summary>
    /// Represents a storage operation for batch processing (v2.5).
    /// </summary>
    public class StorageOperation
    {
        /// <summary>
        /// The type of storage operation.
        /// </summary>
        public StorageOperationType OperationType { get; set; }

        /// <summary>
        /// The storage key for the operation.
        /// </summary>
        public string Key { get; set; } = string.Empty;

        /// <summary>
        /// The value for set operations.
        /// </summary>
        public object? Value { get; set; }

        /// <summary>
        /// The value type for serialization.
        /// </summary>
        public Type? ValueType { get; set; }

        /// <summary>
        /// Optional expiration time for set operations.
        /// </summary>
        public TimeSpan? Expiry { get; set; }

        /// <summary>
        /// Creates a set operation.
        /// </summary>
        public static StorageOperation Set<T>(string key, T value, TimeSpan? expiry = null) where T : class
        {
            return new StorageOperation
            {
                OperationType = StorageOperationType.Set,
                Key = key,
                Value = value,
                ValueType = typeof(T),
                Expiry = expiry
            };
        }

        /// <summary>
        /// Creates a delete operation.
        /// </summary>
        public static StorageOperation Delete(string key)
        {
            return new StorageOperation
            {
                OperationType = StorageOperationType.Delete,
                Key = key
            };
        }
    }

    /// <summary>
    /// Types of storage operations (v2.5).
    /// </summary>
    public enum StorageOperationType
    {
        Set,
        Delete
    }

    /// <summary>
    /// Statistics about storage usage and performance (v2.5).
    /// </summary>
    public class StorageStatistics
    {
        /// <summary>
        /// Total number of stored items.
        /// </summary>
        public long TotalItems { get; set; }

        /// <summary>
        /// Total storage size in bytes.
        /// </summary>
        public long TotalSizeBytes { get; set; }

        /// <summary>
        /// Number of expired items.
        /// </summary>
        public long ExpiredItems { get; set; }

        /// <summary>
        /// Average size per item in bytes.
        /// </summary>
        public double AverageItemSizeBytes => TotalItems > 0 ? (double)TotalSizeBytes / TotalItems : 0;

        /// <summary>
        /// Provider-specific statistics.
        /// </summary>
        public Dictionary<string, object> ProviderSpecific { get; set; } = new();

        /// <summary>
        /// Last time statistics were updated.
        /// </summary>
        public DateTime LastUpdated { get; set; } = DateTime.UtcNow;
    }
}