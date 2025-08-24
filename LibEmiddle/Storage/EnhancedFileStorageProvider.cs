using LibEmiddle.Abstractions;
using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace LibEmiddle.Storage
{
    /// <summary>
    /// Enhanced file system storage provider with v2.5 capabilities.
    /// Extends the basic file storage with metadata, expiration, and batch operations.
    /// </summary>
    public class EnhancedFileStorageProvider : IEnhancedStorageProvider, IDisposable
    {
        private readonly string _basePath;
        private readonly JsonSerializerOptions _jsonOptions;
        private readonly ConcurrentDictionary<string, StorageMetadata> _metadataCache;
        private readonly Timer _cleanupTimer;
        private bool _disposed = false;

        public string ProviderName => "Enhanced File Storage";
        public bool SupportsTransactions => false; // File system doesn't support true transactions
        public bool SupportsExpiration => true;

        public EnhancedFileStorageProvider(string basePath)
        {
            _basePath = basePath ?? throw new ArgumentNullException(nameof(basePath));
            _jsonOptions = new JsonSerializerOptions
            {
                WriteIndented = false,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            };
            _metadataCache = new ConcurrentDictionary<string, StorageMetadata>();

            // Ensure base directory exists
            Directory.CreateDirectory(_basePath);

            // Start cleanup timer for expired items (runs every 5 minutes)
            _cleanupTimer = new Timer(CleanupExpiredItems, null, TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(5));

            // Load existing metadata
            LoadMetadataCache();
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
            try
            {
                var filePath = GetFilePath(key);
                var metadataPath = GetMetadataPath(key);

                var fileDeleted = false;
                var metadataDeleted = false;

                if (File.Exists(filePath))
                {
                    File.Delete(filePath);
                    fileDeleted = true;
                }

                if (File.Exists(metadataPath))
                {
                    File.Delete(metadataPath);
                    metadataDeleted = true;
                }

                _metadataCache.TryRemove(key, out _);

                return await Task.FromResult(fileDeleted || metadataDeleted);
            }
            catch (Exception)
            {
                return await Task.FromResult(false);
            }
        }

        public async Task<bool> ExistsAsync(string key)
        {
            if (_metadataCache.TryGetValue(key, out var metadata))
            {
                if (metadata.IsExpired)
                {
                    await DeleteAsync(key);
                    return false;
                }
                return true;
            }

            return File.Exists(GetFilePath(key));
        }

        public async Task<List<string>> ListKeysAsync(string keyPrefix)
        {
            var keys = await GetKeysAsync($"{keyPrefix}*");
            return keys.ToList();
        }

        public async Task ClearAllAsync()
        {
            try
            {
                if (Directory.Exists(_basePath))
                {
                    Directory.Delete(_basePath, true);
                    Directory.CreateDirectory(_basePath);
                }
                
                _metadataCache.Clear();
                await Task.CompletedTask;
            }
            catch (Exception)
            {
                // Ignore errors during cleanup
                await Task.CompletedTask;
            }
        }

        #endregion

        #region IEnhancedStorageProvider Implementation (v2.5)

        public async Task<bool> SetAsync<T>(string key, T value, TimeSpan? expiry = null) where T : class
        {
            try
            {
                var filePath = GetFilePath(key);
                var metadataPath = GetMetadataPath(key);

                // Ensure directory exists
                Directory.CreateDirectory(Path.GetDirectoryName(filePath)!);

                // Serialize and store the value
                var json = JsonSerializer.Serialize(value, _jsonOptions);
                await File.WriteAllTextAsync(filePath, json);

                // Create and store metadata
                var metadata = new StorageMetadata
                {
                    Key = key,
                    CreatedAt = DateTime.UtcNow,
                    ModifiedAt = DateTime.UtcNow,
                    ExpiresAt = expiry.HasValue ? DateTime.UtcNow.Add(expiry.Value) : null,
                    SizeBytes = System.Text.Encoding.UTF8.GetByteCount(json),
                    ValueType = typeof(T).FullName ?? typeof(T).Name
                };

                var metadataJson = JsonSerializer.Serialize(metadata, _jsonOptions);
                await File.WriteAllTextAsync(metadataPath, metadataJson);

                // Update cache
                _metadataCache.AddOrUpdate(key, metadata, (k, old) => metadata);

                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        public async Task<T?> GetAsync<T>(string key) where T : class
        {
            try
            {
                // Check if expired
                if (_metadataCache.TryGetValue(key, out var metadata) && metadata.IsExpired)
                {
                    await DeleteAsync(key);
                    return null;
                }

                var filePath = GetFilePath(key);
                if (!File.Exists(filePath))
                    return null;

                var json = await File.ReadAllTextAsync(filePath);
                return JsonSerializer.Deserialize<T>(json, _jsonOptions);
            }
            catch (Exception)
            {
                return null;
            }
        }

        public async Task<IEnumerable<string>> GetKeysAsync(string pattern = "*")
        {
            try
            {
                var dataDir = Path.Combine(_basePath, "data");
                if (!Directory.Exists(dataDir))
                    return Enumerable.Empty<string>();

                var files = Directory.GetFiles(dataDir, "*.json", SearchOption.AllDirectories);
                var keys = files.Select(f => Path.GetFileNameWithoutExtension(f))
                              .Where(key => MatchesPattern(key, pattern))
                              .ToList();

                // Filter out expired keys
                var validKeys = new List<string>();
                foreach (var key in keys)
                {
                    if (await ExistsAsync(key))
                    {
                        validKeys.Add(key);
                    }
                }

                return validKeys;
            }
            catch (Exception)
            {
                return Enumerable.Empty<string>();
            }
        }

        public async Task<StorageMetadata?> GetMetadataAsync(string key)
        {
            try
            {
                if (_metadataCache.TryGetValue(key, out var cached))
                {
                    return cached.IsExpired ? null : cached;
                }

                var metadataPath = GetMetadataPath(key);
                if (!File.Exists(metadataPath))
                    return null;

                var json = await File.ReadAllTextAsync(metadataPath);
                var metadata = JsonSerializer.Deserialize<StorageMetadata>(json, _jsonOptions);

                if (metadata != null)
                {
                    _metadataCache.TryAdd(key, metadata);
                    return metadata.IsExpired ? null : metadata;
                }

                return null;
            }
            catch (Exception)
            {
                return null;
            }
        }

        public async Task<bool> BatchAsync(IEnumerable<StorageOperation> operations)
        {
            // File system doesn't support true transactions, so we simulate it
            var completedOperations = new List<(string key, string? backupPath)>();

            try
            {
                foreach (var operation in operations)
                {
                    switch (operation.OperationType)
                    {
                        case StorageOperationType.Set:
                            if (operation.Value != null && operation.ValueType != null)
                            {
                                // Backup existing file if it exists
                                var filePath = GetFilePath(operation.Key);
                                string? backupPath = null;
                                
                                if (File.Exists(filePath))
                                {
                                    backupPath = filePath + ".backup";
                                    File.Copy(filePath, backupPath, true);
                                }

                                // Perform the set operation using reflection
                                var method = typeof(EnhancedFileStorageProvider)
                                    .GetMethod(nameof(SetAsync))!
                                    .MakeGenericMethod(operation.ValueType);

                                object?[] parameters = { operation.Key, operation.Value, operation.Expiry };
                                var task = (Task<bool>)method.Invoke(this, parameters)!;
                                var success = await task;

                                if (!success)
                                    throw new InvalidOperationException($"Failed to set key: {operation.Key}");

                                completedOperations.Add((operation.Key, backupPath));
                            }
                            break;

                        case StorageOperationType.Delete:
                            var deleteSuccess = await DeleteAsync(operation.Key);
                            // Don't fail the batch if delete fails (key might not exist)
                            completedOperations.Add((operation.Key, null));
                            break;
                    }
                }

                // If we get here, all operations succeeded
                // Clean up backup files
                foreach (var (_, backupPath) in completedOperations.Where(op => op.backupPath != null))
                {
                    try
                    {
                        File.Delete(backupPath!);
                    }
                    catch
                    {
                        // Ignore backup cleanup errors
                    }
                }

                return true;
            }
            catch (Exception)
            {
                // Rollback completed operations
                foreach (var (key, backupPath) in completedOperations)
                {
                    try
                    {
                        if (backupPath != null && File.Exists(backupPath))
                        {
                            // Restore from backup
                            var filePath = GetFilePath(key);
                            File.Copy(backupPath, filePath, true);
                            File.Delete(backupPath);
                        }
                        else
                        {
                            // Delete the key that was set
                            await DeleteAsync(key);
                        }
                    }
                    catch
                    {
                        // Ignore rollback errors
                    }
                }

                return false;
            }
        }

        public async Task<StorageStatistics> GetStatisticsAsync()
        {
            try
            {
                var keys = await GetKeysAsync();
                var totalItems = keys.Count();
                var totalSize = 0L;
                var expiredItems = 0L;

                foreach (var key in keys)
                {
                    var metadata = await GetMetadataAsync(key);
                    if (metadata != null)
                    {
                        totalSize += metadata.SizeBytes;
                        if (metadata.IsExpired)
                            expiredItems++;
                    }
                }

                return new StorageStatistics
                {
                    TotalItems = totalItems,
                    TotalSizeBytes = totalSize,
                    ExpiredItems = expiredItems,
                    ProviderSpecific = new Dictionary<string, object>
                    {
                        ["BasePath"] = _basePath,
                        ["MetadataCacheSize"] = _metadataCache.Count
                    }
                };
            }
            catch (Exception)
            {
                return new StorageStatistics();
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

        private string GetFilePath(string key)
        {
            var safeKey = string.Join("_", key.Split(Path.GetInvalidFileNameChars()));
            return Path.Combine(_basePath, "data", $"{safeKey}.json");
        }

        private string GetMetadataPath(string key)
        {
            var safeKey = string.Join("_", key.Split(Path.GetInvalidFileNameChars()));
            return Path.Combine(_basePath, "metadata", $"{safeKey}.meta.json");
        }

        private bool MatchesPattern(string value, string pattern)
        {
            if (pattern == "*") return true;
            
            // Convert glob pattern to regex
            var regexPattern = "^" + Regex.Escape(pattern).Replace(@"\*", ".*").Replace(@"\?", ".") + "$";
            return Regex.IsMatch(value, regexPattern, RegexOptions.IgnoreCase);
        }

        private void LoadMetadataCache()
        {
            try
            {
                var metadataDir = Path.Combine(_basePath, "metadata");
                if (!Directory.Exists(metadataDir))
                    return;

                var metadataFiles = Directory.GetFiles(metadataDir, "*.meta.json");
                
                foreach (var file in metadataFiles)
                {
                    try
                    {
                        var json = File.ReadAllText(file);
                        var metadata = JsonSerializer.Deserialize<StorageMetadata>(json, _jsonOptions);
                        
                        if (metadata != null && !metadata.IsExpired)
                        {
                            _metadataCache.TryAdd(metadata.Key, metadata);
                        }
                    }
                    catch
                    {
                        // Ignore individual metadata file errors
                    }
                }
            }
            catch
            {
                // Ignore metadata loading errors
            }
        }

        private void CleanupExpiredItems(object? state)
        {
            try
            {
                var expiredKeys = _metadataCache
                    .Where(kvp => kvp.Value.IsExpired)
                    .Select(kvp => kvp.Key)
                    .ToList();

                foreach (var key in expiredKeys)
                {
                    DeleteAsync(key).Wait();
                }
            }
            catch
            {
                // Ignore cleanup errors
            }
        }

        #endregion

        #region Helper Classes

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
                _disposed = true;
            }
        }
    }
}