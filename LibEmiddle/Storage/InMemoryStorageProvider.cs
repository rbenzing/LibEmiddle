using LibEmiddle.Abstractions;
using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace LibEmiddle.Storage
{
    /// <summary>
    /// In-memory storage provider for testing and development (v2.5).
    /// Provides fast, temporary storage with full v2.5 feature support.
    /// All data is lost when the application restarts.
    /// </summary>
    public class InMemoryStorageProvider : IEnhancedStorageProvider, IDisposable
    {
        private readonly ConcurrentDictionary<string, StoredItem> _storage;
        private readonly JsonSerializerOptions _jsonOptions;
        private readonly Timer _cleanupTimer;
        private bool _disposed = false;

        public string ProviderName => "In-Memory Storage";
        public bool SupportsTransactions => true; // In-memory can support pseudo-transactions
        public bool SupportsExpiration => true;

        public InMemoryStorageProvider()
        {
            _storage = new ConcurrentDictionary<string, StoredItem>();
            _jsonOptions = new JsonSerializerOptions
            {
                WriteIndented = false,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            };

            // Start cleanup timer for expired items (runs every minute)
            _cleanupTimer = new Timer(CleanupExpiredItems, null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));
        }

        #region IStorageProvider Implementation (v2.0 Compatibility)

        public async Task StoreAsync(string key, string data)
        {
            await SetAsync(key, new StringWrapper { Value = data });
        }

        public async Task StoreBinaryAsync(string key, byte[] data)
        {
            await SetAsync(key, new BinaryWrapper { Value = data });
        }

        public async Task<string> RetrieveAsync(string key)
        {
            var wrapper = await GetAsync<StringWrapper>(key);
            return wrapper?.Value ?? string.Empty;
        }

        public async Task<byte[]?> RetrieveBinaryAsync(string key)
        {
            var wrapper = await GetAsync<BinaryWrapper>(key);
            return wrapper?.Value;
        }

        public async Task<bool> DeleteAsync(string key)
        {
            var result = _storage.TryRemove(key, out _);
            return await Task.FromResult(result);
        }

        public async Task<bool> ExistsAsync(string key)
        {
            if (_storage.TryGetValue(key, out var item))
            {
                if (item.Metadata.IsExpired)
                {
                    _storage.TryRemove(key, out _);
                    return await Task.FromResult(false);
                }
                return await Task.FromResult(true);
            }
            return await Task.FromResult(false);
        }

        public async Task<List<string>> ListKeysAsync(string keyPrefix)
        {
            var keys = await GetKeysAsync($"{keyPrefix}*");
            return keys.ToList();
        }

        public async Task ClearAllAsync()
        {
            _storage.Clear();
            await Task.CompletedTask;
        }

        #endregion

        #region IEnhancedStorageProvider Implementation (v2.5)

        public async Task<bool> SetAsync<T>(string key, T value, TimeSpan? expiry = null) where T : class
        {
            try
            {
                var json = JsonSerializer.Serialize(value, _jsonOptions);
                var metadata = new StorageMetadata
                {
                    Key = key,
                    CreatedAt = DateTime.UtcNow,
                    ModifiedAt = DateTime.UtcNow,
                    ExpiresAt = expiry.HasValue ? DateTime.UtcNow.Add(expiry.Value) : null,
                    SizeBytes = System.Text.Encoding.UTF8.GetByteCount(json),
                    ValueType = typeof(T).FullName ?? typeof(T).Name
                };

                var item = new StoredItem
                {
                    Data = json,
                    Metadata = metadata,
                    ValueType = typeof(T)
                };

                _storage.AddOrUpdate(key, item, (k, existing) =>
                {
                    item.Metadata.CreatedAt = existing.Metadata.CreatedAt; // Preserve creation time
                    return item;
                });

                return await Task.FromResult(true);
            }
            catch (Exception)
            {
                return await Task.FromResult(false);
            }
        }

        public async Task<T?> GetAsync<T>(string key) where T : class
        {
            try
            {
                if (_storage.TryGetValue(key, out var item))
                {
                    if (item.Metadata.IsExpired)
                    {
                        _storage.TryRemove(key, out _);
                        return await Task.FromResult<T?>(null);
                    }

                    var result = JsonSerializer.Deserialize<T>(item.Data, _jsonOptions);
                    return await Task.FromResult(result);
                }

                return await Task.FromResult<T?>(null);
            }
            catch (Exception)
            {
                return await Task.FromResult<T?>(null);
            }
        }

        public async Task<IEnumerable<string>> GetKeysAsync(string pattern = "*")
        {
            try
            {
                var validKeys = new List<string>();

                foreach (var kvp in _storage)
                {
                    if (kvp.Value.Metadata.IsExpired)
                    {
                        _storage.TryRemove(kvp.Key, out _);
                        continue;
                    }

                    if (MatchesPattern(kvp.Key, pattern))
                    {
                        validKeys.Add(kvp.Key);
                    }
                }

                return await Task.FromResult<IEnumerable<string>>(validKeys);
            }
            catch (Exception)
            {
                return await Task.FromResult(Enumerable.Empty<string>());
            }
        }

        public async Task<StorageMetadata?> GetMetadataAsync(string key)
        {
            try
            {
                if (_storage.TryGetValue(key, out var item))
                {
                    if (item.Metadata.IsExpired)
                    {
                        _storage.TryRemove(key, out _);
                        return await Task.FromResult<StorageMetadata?>(null);
                    }

                    return await Task.FromResult<StorageMetadata?>(item.Metadata);
                }

                return await Task.FromResult<StorageMetadata?>(null);
            }
            catch (Exception)
            {
                return await Task.FromResult<StorageMetadata?>(null);
            }
        }

        public async Task<bool> BatchAsync(IEnumerable<StorageOperation> operations)
        {
            // For in-memory storage, we can simulate transactions with snapshots
            var snapshot = new Dictionary<string, StoredItem?>();
            var operationsList = operations.ToList();

            try
            {
                // Create snapshot of affected keys
                foreach (var operation in operationsList)
                {
                    _storage.TryGetValue(operation.Key, out var existing);
                    snapshot[operation.Key] = existing; // null if doesn't exist
                }

                // Apply all operations
                foreach (var operation in operationsList)
                {
                    switch (operation.OperationType)
                    {
                        case StorageOperationType.Set:
                            if (operation.Value != null && operation.ValueType != null)
                            {
                                // Use reflection to call the generic SetAsync method
                                var method = typeof(InMemoryStorageProvider)
                                    .GetMethod(nameof(SetAsync))!
                                    .MakeGenericMethod(operation.ValueType);

                                object?[] parameters = { operation.Key, operation.Value, operation.Expiry };
                                var task = (Task<bool>)method.Invoke(this, parameters)!;
                                var success = await task;

                                if (!success)
                                    throw new InvalidOperationException($"Failed to set key: {operation.Key}");
                            }
                            break;

                        case StorageOperationType.Delete:
                            await DeleteAsync(operation.Key);
                            break;
                    }
                }

                return true;
            }
            catch (Exception)
            {
                // Rollback to snapshot
                foreach (var kvp in snapshot)
                {
                    if (kvp.Value == null)
                    {
                        _storage.TryRemove(kvp.Key, out _);
                    }
                    else
                    {
                        _storage.AddOrUpdate(kvp.Key, kvp.Value, (k, v) => kvp.Value);
                    }
                }

                return false;
            }
        }

        public async Task<StorageStatistics> GetStatisticsAsync()
        {
            try
            {
                var totalItems = 0L;
                var totalSize = 0L;
                var expiredItems = 0L;

                foreach (var item in _storage.Values)
                {
                    totalItems++;
                    totalSize += item.Metadata.SizeBytes;

                    if (item.Metadata.IsExpired)
                        expiredItems++;
                }

                var result = new StorageStatistics
                {
                    TotalItems = totalItems,
                    TotalSizeBytes = totalSize,
                    ExpiredItems = expiredItems,
                    ProviderSpecific = new Dictionary<string, object>
                    {
                        ["MemoryUsageBytes"] = GC.GetTotalMemory(false),
                        ["ConcurrentDictionarySize"] = _storage.Count
                    }
                };
                return await Task.FromResult(result);
            }
            catch (Exception)
            {
                return await Task.FromResult(new StorageStatistics());
            }
        }

        public async Task<bool> HealthCheckAsync()
        {
            try
            {
                // Test basic read/write operations
                var testKey = "__health_check__";
                var testValue = new StringWrapper { Value = "health_check_test" };

                await SetAsync(testKey, testValue, TimeSpan.FromSeconds(10));
                var retrieved = await GetAsync<StringWrapper>(testKey);
                await DeleteAsync(testKey);

                return retrieved?.Value == testValue.Value;
            }
            catch (Exception)
            {
                return false;
            }
        }

        #endregion

        #region Private Methods

        private bool MatchesPattern(string value, string pattern)
        {
            if (pattern == "*") return true;

            // Convert glob pattern to regex
            var regexPattern = "^" + Regex.Escape(pattern).Replace(@"\*", ".*").Replace(@"\?", ".") + "$";
            return Regex.IsMatch(value, regexPattern, RegexOptions.IgnoreCase);
        }

        private void CleanupExpiredItems(object? state)
        {
            try
            {
                var expiredKeys = _storage
                    .Where(kvp => kvp.Value.Metadata.IsExpired)
                    .Select(kvp => kvp.Key)
                    .ToList();

                foreach (var key in expiredKeys)
                {
                    _storage.TryRemove(key, out _);
                }
            }
            catch
            {
                // Ignore cleanup errors
            }
        }

        #endregion

        #region Helper Classes

        private class StoredItem
        {
            public string Data { get; set; } = string.Empty;
            public StorageMetadata Metadata { get; set; } = new();
            public Type ValueType { get; set; } = typeof(object);
        }

        private class StringWrapper
        {
            public string Value { get; set; } = string.Empty;
        }

        private class BinaryWrapper
        {
            public byte[] Value { get; set; } = Array.Empty<byte>();
        }

        #endregion

        public void Dispose()
        {
            if (!_disposed)
            {
                _cleanupTimer?.Dispose();
                _storage.Clear();
                _disposed = true;
            }
        }
    }
}