using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using LibEmiddle.Storage;
using LibEmiddle.Abstractions;
using LibEmiddle.Domain;

namespace LibEmiddle.Tests.Unit
{
    [TestClass]
    public class StorageProviderTests
    {
        private InMemoryStorageProvider _inMemoryProvider = null!;
        private EnhancedFileStorageProvider _fileProvider = null!;
        private string _testStoragePath = null!;

        [TestInitialize]
        public void Setup()
        {
            // Setup InMemoryStorageProvider
            _inMemoryProvider = new InMemoryStorageProvider();

            // Setup EnhancedFileStorageProvider with temp directory
            _testStoragePath = Path.Combine(Path.GetTempPath(), "LibEmiddleTests", Guid.NewGuid().ToString());
            Directory.CreateDirectory(_testStoragePath);
            _fileProvider = new EnhancedFileStorageProvider(_testStoragePath);
        }

        [TestCleanup]
        public void Cleanup()
        {
            _inMemoryProvider?.Dispose();
            _fileProvider?.Dispose();

            if (Directory.Exists(_testStoragePath))
            {
                try
                {
                    Directory.Delete(_testStoragePath, true);
                }
                catch
                {
                    // Ignore cleanup errors
                }
            }
        }

        #region InMemoryStorageProvider Tests

        [TestMethod]
        public void InMemoryProvider_Constructor_ShouldInitializeCorrectly()
        {
            // Arrange & Act
            var provider = new InMemoryStorageProvider();

            // Assert
            Assert.AreEqual("In-Memory Storage", provider.ProviderName);
            Assert.IsTrue(provider.SupportsTransactions);
            Assert.IsTrue(provider.SupportsExpiration);
        }

        [TestMethod]
        public async Task InMemoryProvider_StoreAsync_ValidData_ShouldReturnSuccess()
        {
            // Arrange
            var key = "test-key";
            var data = "test-data";

            // Act
            await _inMemoryProvider.StoreAsync(key, data);
            var retrieved = await _inMemoryProvider.RetrieveAsync(key);

            // Assert
            Assert.AreEqual(data, retrieved);
        }

        [TestMethod]
        public async Task InMemoryProvider_RetrieveAsync_NonExistentKey_ShouldReturnEmpty()
        {
            // Arrange
            var key = "non-existent-key";

            // Act
            var result = await _inMemoryProvider.RetrieveAsync(key);

            // Assert
            Assert.AreEqual(string.Empty, result);
        }

        [TestMethod]
        public async Task InMemoryProvider_StoreBinaryAsync_ValidData_ShouldReturnSuccess()
        {
            // Arrange
            var key = "test-binary-key";
            var data = new byte[] { 1, 2, 3, 4, 5 };

            // Act
            await _inMemoryProvider.StoreBinaryAsync(key, data);
            var retrieved = await _inMemoryProvider.RetrieveBinaryAsync(key);

            // Assert
            Assert.IsNotNull(retrieved);
            CollectionAssert.AreEqual(data, retrieved);
        }

        [TestMethod]
        public async Task InMemoryProvider_RetrieveBinaryAsync_NonExistentKey_ShouldReturnNull()
        {
            // Arrange
            var key = "non-existent-binary-key";

            // Act
            var result = await _inMemoryProvider.RetrieveBinaryAsync(key);

            // Assert
            Assert.IsNull(result);
        }

        [TestMethod]
        public async Task InMemoryProvider_DeleteAsync_ExistingKey_ShouldReturnTrue()
        {
            // Arrange
            var key = "test-key";
            var data = "test-data";
            await _inMemoryProvider.StoreAsync(key, data);

            // Act
            var result = await _inMemoryProvider.DeleteAsync(key);

            // Assert
            Assert.IsTrue(result);
            var retrieved = await _inMemoryProvider.RetrieveAsync(key);
            Assert.AreEqual(string.Empty, retrieved);
        }

        [TestMethod]
        public async Task InMemoryProvider_DeleteAsync_NonExistentKey_ShouldReturnFalse()
        {
            // Arrange
            var key = "non-existent-key";

            // Act
            var result = await _inMemoryProvider.DeleteAsync(key);

            // Assert
            Assert.IsFalse(result);
        }

        [TestMethod]
        public async Task InMemoryProvider_ExistsAsync_ExistingKey_ShouldReturnTrue()
        {
            // Arrange
            var key = "test-key";
            var data = "test-data";
            await _inMemoryProvider.StoreAsync(key, data);

            // Act
            var result = await _inMemoryProvider.ExistsAsync(key);

            // Assert
            Assert.IsTrue(result);
        }

        [TestMethod]
        public async Task InMemoryProvider_ExistsAsync_NonExistentKey_ShouldReturnFalse()
        {
            // Arrange
            var key = "non-existent-key";

            // Act
            var result = await _inMemoryProvider.ExistsAsync(key);

            // Assert
            Assert.IsFalse(result);
        }

        [TestMethod]
        public async Task InMemoryProvider_SetAsync_WithExpiry_ShouldExpireCorrectly()
        {
            // Arrange
            var key = "expiry-key";
            var value = new TestObject { Value = "test" };
            var expiry = TimeSpan.FromMilliseconds(100);

            // Act
            var success = await _inMemoryProvider.SetAsync(key, value, expiry);
            Assert.IsTrue(success);

            // Wait for expiration
            await Task.Delay(150);

            var result = await _inMemoryProvider.GetAsync<TestObject>(key);

            // Assert
            Assert.IsNull(result);
        }

        [TestMethod]
        public async Task InMemoryProvider_GetAsync_ValidKey_ShouldReturnObject()
        {
            // Arrange
            var key = "object-key";
            var value = new TestObject { Value = "test-value" };

            // Act
            await _inMemoryProvider.SetAsync(key, value);
            var result = await _inMemoryProvider.GetAsync<TestObject>(key);

            // Assert
            Assert.IsNotNull(result);
            Assert.AreEqual(value.Value, result.Value);
        }

        [TestMethod]
        public async Task InMemoryProvider_GetKeysAsync_WithPattern_ShouldFilterCorrectly()
        {
            // Arrange
            await _inMemoryProvider.SetAsync("user:123", new TestObject { Value = "user1" });
            await _inMemoryProvider.SetAsync("user:456", new TestObject { Value = "user2" });
            await _inMemoryProvider.SetAsync("session:abc", new TestObject { Value = "session1" });

            // Act
            var userKeys = await _inMemoryProvider.GetKeysAsync("user:*");
            var allKeys = await _inMemoryProvider.GetKeysAsync("*");

            // Assert
            Assert.AreEqual(2, userKeys.Count());
            Assert.IsTrue(userKeys.All(k => k.StartsWith("user:")));
            Assert.AreEqual(3, allKeys.Count());
        }

        [TestMethod]
        public async Task InMemoryProvider_GetStatisticsAsync_ShouldReturnCorrectStats()
        {
            // Arrange
            await _inMemoryProvider.SetAsync("key1", new TestObject { Value = "value1" });
            await _inMemoryProvider.SetAsync("key2", new TestObject { Value = "value2" });

            // Act
            var stats = await _inMemoryProvider.GetStatisticsAsync();

            // Assert
            Assert.AreEqual(2, stats.TotalItems);
            Assert.IsTrue(stats.TotalSizeBytes > 0);
            Assert.IsTrue(stats.ProviderSpecific.ContainsKey("MemoryUsageBytes"));
            Assert.IsTrue(stats.ProviderSpecific.ContainsKey("ConcurrentDictionarySize"));
        }

        [TestMethod]
        public async Task InMemoryProvider_HealthCheckAsync_ShouldReturnTrue()
        {
            // Act
            var isHealthy = await _inMemoryProvider.HealthCheckAsync();

            // Assert
            Assert.IsTrue(isHealthy);
        }

        [TestMethod]
        public async Task InMemoryProvider_BatchAsync_MultipleOperations_ShouldExecuteAtomically()
        {
            // Arrange
            var operations = new List<StorageOperation>
            {
                new StorageOperation
                {
                    OperationType = StorageOperationType.Set,
                    Key = "batch-key1",
                    Value = new TestObject { Value = "batch-value1" },
                    ValueType = typeof(TestObject)
                },
                new StorageOperation
                {
                    OperationType = StorageOperationType.Set,
                    Key = "batch-key2",
                    Value = new TestObject { Value = "batch-value2" },
                    ValueType = typeof(TestObject)
                }
            };

            // Act
            var success = await _inMemoryProvider.BatchAsync(operations);

            // Assert
            Assert.IsTrue(success);
            var value1 = await _inMemoryProvider.GetAsync<TestObject>("batch-key1");
            var value2 = await _inMemoryProvider.GetAsync<TestObject>("batch-key2");
            Assert.IsNotNull(value1);
            Assert.IsNotNull(value2);
            Assert.AreEqual("batch-value1", value1.Value);
            Assert.AreEqual("batch-value2", value2.Value);
        }

        [TestMethod]
        public async Task InMemoryProvider_ListKeysAsync_ShouldReturnCorrectKeys()
        {
            // Arrange
            await _inMemoryProvider.StoreAsync("prefix:key1", "value1");
            await _inMemoryProvider.StoreAsync("prefix:key2", "value2");
            await _inMemoryProvider.StoreAsync("other:key3", "value3");

            // Act
            var keys = await _inMemoryProvider.ListKeysAsync("prefix:");

            // Assert
            Assert.AreEqual(2, keys.Count);
            Assert.IsTrue(keys.All(k => k.StartsWith("prefix:")));
        }

        [TestMethod]
        public async Task InMemoryProvider_ClearAllAsync_ShouldRemoveAllData()
        {
            // Arrange
            await _inMemoryProvider.StoreAsync("key1", "value1");
            await _inMemoryProvider.StoreAsync("key2", "value2");

            // Act
            await _inMemoryProvider.ClearAllAsync();

            // Assert
            var exists1 = await _inMemoryProvider.ExistsAsync("key1");
            var exists2 = await _inMemoryProvider.ExistsAsync("key2");
            Assert.IsFalse(exists1);
            Assert.IsFalse(exists2);
        }

        [TestMethod]
        public async Task InMemoryProvider_GetMetadataAsync_ShouldReturnCorrectMetadata()
        {
            // Arrange
            var key = "metadata-key";
            var value = new TestObject { Value = "test" };
            await _inMemoryProvider.SetAsync(key, value);

            // Act
            var metadata = await _inMemoryProvider.GetMetadataAsync(key);

            // Assert
            Assert.IsNotNull(metadata);
            Assert.AreEqual(key, metadata.Key);
            Assert.IsTrue(metadata.SizeBytes > 0);
            Assert.IsTrue(metadata.CreatedAt <= DateTime.UtcNow);
            Assert.IsTrue(metadata.ModifiedAt <= DateTime.UtcNow);
        }

        #endregion

        #region EnhancedFileStorageProvider Tests

        [TestMethod]
        public void FileProvider_Constructor_InvalidPath_ShouldThrowException()
        {
            // Arrange
            var invalidPath = "invalid<>path|?*";

            // Act & Assert
            Assert.ThrowsException<DirectoryNotFoundException>(() =>
            {
                new EnhancedFileStorageProvider(invalidPath);
            });
        }

        [TestMethod]
        public async Task FileProvider_StoreAsync_ValidData_ShouldCreateFile()
        {
            // Arrange
            var key = "file-test-key";
            var data = "file-test-data";

            // Act
            await _fileProvider.StoreAsync(key, data);
            var retrieved = await _fileProvider.RetrieveAsync(key);

            // Assert
            Assert.AreEqual(data, retrieved);
        }

        [TestMethod]
        public async Task FileProvider_DeleteAsync_ExistingKey_ShouldRemoveFiles()
        {
            // Arrange
            var key = "delete-test-key";
            var data = "delete-test-data";
            await _fileProvider.StoreAsync(key, data);

            // Act
            var result = await _fileProvider.DeleteAsync(key);

            // Assert
            Assert.IsTrue(result);
            var retrieved = await _fileProvider.RetrieveAsync(key);
            Assert.AreEqual(string.Empty, retrieved);
        }

        [TestMethod]
        public async Task FileProvider_SetAsync_ShouldPersistToDisk()
        {
            // Arrange
            var key = "persist-key";
            var value = new TestObject { Value = "persist-value" };

            // Act
            var success = await _fileProvider.SetAsync(key, value);

            // Assert
            Assert.IsTrue(success);
            
            // Create new provider instance to test persistence
            using var newProvider = new EnhancedFileStorageProvider(_testStoragePath);
            var retrieved = await newProvider.GetAsync<TestObject>(key);
            Assert.IsNotNull(retrieved);
            Assert.AreEqual(value.Value, retrieved.Value);
        }

        [TestMethod]
        public async Task FileProvider_GetAsync_NonExistentKey_ShouldReturnNull()
        {
            // Arrange
            var key = "non-existent-file-key";

            // Act
            var result = await _fileProvider.GetAsync<TestObject>(key);

            // Assert
            Assert.IsNull(result);
        }

        [TestMethod]
        public async Task FileProvider_HealthCheckAsync_ShouldValidateFileSystemAccess()
        {
            // Act
            var isHealthy = await _fileProvider.HealthCheckAsync();

            // Assert
            Assert.IsTrue(isHealthy);
        }

        [TestMethod]
        public async Task FileProvider_ClearAllAsync_ShouldRemoveAllFiles()
        {
            // Arrange
            await _fileProvider.StoreAsync("clear-key1", "clear-value1");
            await _fileProvider.StoreAsync("clear-key2", "clear-value2");

            // Act
            await _fileProvider.ClearAllAsync();

            // Assert
            var exists1 = await _fileProvider.ExistsAsync("clear-key1");
            var exists2 = await _fileProvider.ExistsAsync("clear-key2");
            Assert.IsFalse(exists1);
            Assert.IsFalse(exists2);
        }

        [TestMethod]
        public async Task FileProvider_BatchAsync_ShouldCreateBackupsAndRollbackOnFailure()
        {
            // Arrange - Set up initial data
            var key = "batch-test-key";
            var initialValue = new TestObject { Value = "initial" };
            await _fileProvider.SetAsync(key, initialValue);

            // Create operations with one that will fail
            var operations = new List<StorageOperation>
            {
                new StorageOperation
                {
                    OperationType = StorageOperationType.Set,
                    Key = key,
                    Value = new TestObject { Value = "updated" },
                    ValueType = typeof(TestObject)
                },
                new StorageOperation
                {
                    OperationType = StorageOperationType.Set,
                    Key = "batch-key2",
                    Value = null, // This should cause failure
                    ValueType = typeof(TestObject)
                }
            };

            // Act
            var success = await _fileProvider.BatchAsync(operations);

            // Assert - Batch should fail and rollback
            Assert.IsFalse(success);
            
            // Original value should be preserved
            var retrievedValue = await _fileProvider.GetAsync<TestObject>(key);
            Assert.IsNotNull(retrievedValue);
            Assert.AreEqual("initial", retrievedValue.Value);
        }

        [TestMethod]
        public async Task FileProvider_GetStatisticsAsync_ShouldReturnFileSystemStats()
        {
            // Arrange
            await _fileProvider.SetAsync("stats-key1", new TestObject { Value = "value1" });
            await _fileProvider.SetAsync("stats-key2", new TestObject { Value = "value2" });

            // Act
            var stats = await _fileProvider.GetStatisticsAsync();

            // Assert
            Assert.AreEqual(2, stats.TotalItems);
            Assert.IsTrue(stats.TotalSizeBytes > 0);
            Assert.IsTrue(stats.ProviderSpecific.ContainsKey("StoragePath"));
            Assert.IsTrue(stats.ProviderSpecific.ContainsKey("CacheHitRate"));
        }

        #endregion

        #region Test Helper Classes

        private class TestObject
        {
            public string Value { get; set; } = string.Empty;
        }

        #endregion
    }
}