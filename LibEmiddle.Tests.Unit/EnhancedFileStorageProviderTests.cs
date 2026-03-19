using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using LibEmiddle.Storage;
using LibEmiddle.Abstractions;

namespace LibEmiddle.Tests.Unit
{
    [TestClass]
    public class EnhancedFileStorageProviderTests
    {
        private string _testBasePath;
        private EnhancedFileStorageProvider _provider;

        [TestInitialize]
        public void Setup()
        {
            _testBasePath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            _provider = new EnhancedFileStorageProvider(_testBasePath);
        }

        [TestCleanup]
        public void Teardown()
        {
            _provider?.Dispose();

            try
            {
                if (Directory.Exists(_testBasePath))
                    Directory.Delete(_testBasePath, true);
            }
            catch
            {
                // Ignore cleanup errors
            }
        }

        // Helper class for round-trip tests — must be public so System.Text.Json can serialize it
        public class TestPayload
        {
            public string Name { get; set; }
            public int Value { get; set; }
        }

        [TestMethod]
        public async Task StoreAndLoad_RoundTrip_ReturnsOriginalValue()
        {
            // Arrange
            var key = "roundtrip-key";
            var payload = new TestPayload { Name = "hello", Value = 42 };

            // Act
            var stored = await _provider.SetAsync(key, payload);
            var retrieved = await _provider.GetAsync<TestPayload>(key);

            // Assert
            Assert.IsTrue(stored, "SetAsync should return true on success");
            Assert.IsNotNull(retrieved, "GetAsync should return a non-null value after storing");
            Assert.AreEqual(payload.Name, retrieved.Name, "Name should survive round-trip");
            Assert.AreEqual(payload.Value, retrieved.Value, "Value should survive round-trip");
        }

        [TestMethod]
        public async Task Load_NonExistentKey_ReturnsNull()
        {
            // Arrange
            var key = "does-not-exist-" + Guid.NewGuid();

            // Act
            var result = await _provider.GetAsync<TestPayload>(key);

            // Assert
            Assert.IsNull(result, "GetAsync for unknown key should return null");
        }

        [TestMethod]
        public async Task Delete_ExistingKey_RemovesIt()
        {
            // Arrange
            var key = "delete-me";
            var payload = new TestPayload { Name = "to be deleted", Value = 1 };
            await _provider.SetAsync(key, payload);

            // Act
            var deleted = await _provider.DeleteAsync(key);
            var afterDelete = await _provider.GetAsync<TestPayload>(key);

            // Assert
            Assert.IsTrue(deleted, "DeleteAsync should return true when key existed");
            Assert.IsNull(afterDelete, "GetAsync after delete should return null");
        }

        [TestMethod]
        public async Task Delete_NonExistentKey_ReturnsFalse()
        {
            // Arrange
            var key = "never-stored-" + Guid.NewGuid();

            // Act
            var result = await _provider.DeleteAsync(key);

            // Assert
            Assert.IsFalse(result, "DeleteAsync on a non-existent key should return false");
        }

        [TestMethod]
        public async Task Store_SameKeyTwice_OverwritesValue()
        {
            // Arrange
            var key = "overwrite-key";
            var first = new TestPayload { Name = "first", Value = 1 };
            var second = new TestPayload { Name = "second", Value = 2 };

            // Act
            await _provider.SetAsync(key, first);
            await _provider.SetAsync(key, second);
            var retrieved = await _provider.GetAsync<TestPayload>(key);

            // Assert
            Assert.IsNotNull(retrieved, "GetAsync should return a value after overwrite");
            Assert.AreEqual(second.Name, retrieved.Name, "Name should reflect the second write");
            Assert.AreEqual(second.Value, retrieved.Value, "Value should reflect the second write");
        }

        [TestMethod]
        public async Task ConcurrentStore_MultipleKeys_DoesNotCorruptData()
        {
            // Arrange
            const int taskCount = 20;
            var tasks = new List<Task>();
            var keys = new List<string>();

            for (int i = 0; i < taskCount; i++)
            {
                var index = i;
                var key = $"concurrent-key-{index}";
                keys.Add(key);
                tasks.Add(Task.Run(async () =>
                {
                    var payload = new TestPayload { Name = $"name-{index}", Value = index };
                    await _provider.SetAsync(key, payload);
                }));
            }

            // Act
            await Task.WhenAll(tasks);

            // Assert - every key should be retrievable with intact data
            for (int i = 0; i < taskCount; i++)
            {
                var result = await _provider.GetAsync<TestPayload>(keys[i]);
                Assert.IsNotNull(result, $"Key {keys[i]} should exist after concurrent writes");
                Assert.AreEqual(i, result.Value, $"Value for key {keys[i]} should not be corrupted");
            }
        }

        [TestMethod]
        public void Dispose_CalledMultipleTimes_DoesNotThrow()
        {
            // Arrange - create a separate provider so we control its lifetime
            var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            var localProvider = new EnhancedFileStorageProvider(path);

            try
            {
                // Act & Assert - should not throw on repeated disposal
                localProvider.Dispose();
                localProvider.Dispose();
                localProvider.Dispose();
            }
            finally
            {
                try { Directory.Delete(path, true); } catch { }
            }
        }

        [TestMethod]
        public async Task Load_CorruptedFile_ReturnsNullNotException()
        {
            // Arrange - store a value then corrupt the underlying file
            var key = "corrupt-key";
            var payload = new TestPayload { Name = "valid", Value = 99 };
            await _provider.SetAsync(key, payload);

            // Overwrite the data file with garbage bytes
            var safeKey = string.Join("_", key.Split(Path.GetInvalidFileNameChars()));
            var dataFile = Path.Combine(_testBasePath, "data", $"{safeKey}.json");
            File.WriteAllText(dataFile, "{ this is not valid json !!!!");

            // Act
            TestPayload result = null;
            Exception caughtException = null;
            try
            {
                result = await _provider.GetAsync<TestPayload>(key);
            }
            catch (Exception ex)
            {
                caughtException = ex;
            }

            // Assert
            Assert.IsNull(caughtException, "GetAsync should not propagate an exception for a corrupted file");
            Assert.IsNull(result, "GetAsync should return null when the file is corrupted");
        }

        [TestMethod]
        public async Task ExistsAsync_AfterStore_ReturnsTrue()
        {
            // Arrange
            var key = "exists-check";
            var payload = new TestPayload { Name = "exists", Value = 7 };

            // Act
            await _provider.SetAsync(key, payload);
            var exists = await _provider.ExistsAsync(key);

            // Assert
            Assert.IsTrue(exists, "ExistsAsync should return true for a stored key");
        }

        [TestMethod]
        public async Task ExistsAsync_AfterDelete_ReturnsFalse()
        {
            // Arrange
            var key = "exists-then-deleted";
            var payload = new TestPayload { Name = "temp", Value = 0 };
            await _provider.SetAsync(key, payload);
            await _provider.DeleteAsync(key);

            // Act
            var exists = await _provider.ExistsAsync(key);

            // Assert
            Assert.IsFalse(exists, "ExistsAsync should return false after the key is deleted");
        }

        [TestMethod]
        public async Task StoreAsync_StringRoundTrip_ReturnsOriginalString()
        {
            // Arrange - exercise IStorageProvider compatibility surface
            var key = "string-compat-key";
            var value = "Hello, LibEmiddle!";

            // Act
            await _provider.StoreAsync(key, value);
            var retrieved = await _provider.RetrieveAsync(key);

            // Assert
            Assert.AreEqual(value, retrieved, "String round-trip via StoreAsync/RetrieveAsync should preserve value");
        }

        [TestMethod]
        public async Task StoreBinaryAsync_BinaryRoundTrip_ReturnsOriginalBytes()
        {
            // Arrange
            var key = "binary-compat-key";
            var bytes = new byte[] { 0x01, 0x02, 0x03, 0xFF, 0xFE };

            // Act
            await _provider.StoreBinaryAsync(key, bytes);
            var retrieved = await _provider.RetrieveBinaryAsync(key);

            // Assert
            Assert.IsNotNull(retrieved, "Binary round-trip should return non-null");
            CollectionAssert.AreEqual(bytes, retrieved, "Binary data should survive round-trip unchanged");
        }
    }
}
