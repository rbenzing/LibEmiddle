using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IO;
using System.Security.Cryptography;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.KeyManagement;
using System;
using System.Threading.Tasks;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestPlatform.ObjectModel.DataCollection;

namespace LibEmiddle.Tests.Unit
{
    [TestClass]
    public class KeyManagementTests
    {
        private CryptoProvider _cryptoProvider;
        private KeyManager _keyManager;

        [TestInitialize]
        public void Setup()
        {
            _cryptoProvider = new CryptoProvider();
            _keyManager = new KeyManager(_cryptoProvider);
        }



        [TestMethod]
        public void StoreAndLoadKeyFromFile_WithoutPassword_ShouldReturnOriginalKey()
        {
            // Arrange
            KeyPair _identityKeyPair = Sodium.GenerateX25519KeyPair();
            var publicKey = _identityKeyPair.PublicKey;

            string sessionId = new Guid().ToString();

            try
            { 
                // Act
                bool success = _keyManager.StoreKeyAsync(sessionId, publicKey).GetAwaiter().GetResult();
                byte[] loadedKey = _keyManager.RetrieveKeyAsync(sessionId).GetAwaiter().GetResult();

                // Assert
                Assert.IsTrue(success, "stored the key successfully");
                CollectionAssert.AreEqual(publicKey, loadedKey);
            }
            finally
            {
                // Cleanup
                _keyManager.DeleteKeyAsync(sessionId).GetAwaiter().GetResult();
            }
        }

        [TestMethod]
        public void StoreAndLoadKeyFromFile_WithPassword_ShouldReturnOriginalKey()
        {
            // Arrange
            KeyPair _identityKeyPair = Sodium.GenerateX25519KeyPair();
            var publicKey = _identityKeyPair.PublicKey;
            string filePath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
            string password = "TestP@ssw0rd";
            string sessionId = new Guid().ToString();

            try
            {
                // Act
                bool success = _keyManager.StoreKeyAsync(sessionId, publicKey, password).GetAwaiter().GetResult();
                byte[] loadedKey = _keyManager.RetrieveKeyAsync(sessionId, password).GetAwaiter().GetResult();

                // Assert
                Assert.IsTrue(success, "stored the key successfully");
                CollectionAssert.AreEqual(publicKey, loadedKey);
            }
            finally
            {
                // Cleanup
                _keyManager.DeleteKeyAsync(sessionId, password).GetAwaiter().GetResult();
            }
        }



        [TestMethod]
        public void ValidateX25519PublicKey_WithValidKey_ShouldReturnTrue()
        {
            // Arrange
            KeyPair _identityKeyPair = Sodium.GenerateX25519KeyPair();
            var publicKey = _identityKeyPair.PublicKey;

            // Act
            bool isValid = _cryptoProvider.ValidateX25519PublicKey(publicKey);

            // Assert
            Assert.IsTrue(isValid, "A properly generated X25519 public key should be valid");
        }

        [TestMethod]
        public void ValidateX25519PublicKey_WithAllZeros_ShouldReturnFalse()
        {
            // Arrange
            byte[] allZeroKey = new byte[Constants.X25519_KEY_SIZE]; // All zeros

            // Act
            bool isValid = _cryptoProvider.ValidateX25519PublicKey(allZeroKey);

            // Assert
            Assert.IsFalse(isValid, "An all-zero key should be invalid");
        }

        [TestMethod]
        public void ValidateX25519PublicKey_WithWrongLength_ShouldReturnFalse()
        {
            // Arrange
            byte[] shortKey = new byte[Constants.X25519_KEY_SIZE - 1]; // Too short
            byte[] longKey = new byte[Constants.X25519_KEY_SIZE + 1]; // Too long

            // Act
            bool shortKeyValid = _cryptoProvider.ValidateX25519PublicKey(shortKey);
            bool longKeyValid = _cryptoProvider.ValidateX25519PublicKey(longKey);

            // Assert
            Assert.IsFalse(shortKeyValid, "A key that's too short should be invalid");
            Assert.IsFalse(longKeyValid, "A key that's too long should be invalid");
        }

        [TestMethod]
        public void DeriveX25519PrivateKeyFromEd25519_ShouldProduceValidKey()
        {
            // Arrange
            KeyPair _identityKeyPair = Sodium.GenerateEd25519KeyPair();

            // Act
            byte[] x25519PrivateKey = _cryptoProvider.ConvertEd25519PrivateKeyToX25519(_identityKeyPair.PrivateKey);

            // Assert
            Assert.IsNotNull(x25519PrivateKey);
            Assert.AreEqual(Constants.X25519_KEY_SIZE, x25519PrivateKey.Length, "Derived X25519 key should be the correct length");
        }

        #region Security Vulnerability Tests

        /// <summary>
        /// Tests that cached keys are properly secured and return copies
        /// </summary>
        [TestMethod]
        public async Task KeyCache_ShouldReturnSecureCopies()
        {
            // Arrange
            string keyId = "test-cache-key";
            byte[] originalKey = _cryptoProvider.GenerateRandomBytes(32);

            // Store the key
            await _keyManager.StoreKeyAsync(keyId, originalKey);

            // Retrieve it multiple times to test caching
            byte[] cachedKey1 = await _keyManager.RetrieveKeyAsync(keyId);
            byte[] cachedKey2 = await _keyManager.RetrieveKeyAsync(keyId);

            Assert.IsNotNull(cachedKey1);
            Assert.IsNotNull(cachedKey2);

            // Verify they are equal in content but different objects
            Assert.IsTrue(SecureMemory.SecureCompare(cachedKey1, cachedKey2));
            Assert.IsFalse(ReferenceEquals(cachedKey1, cachedKey2),
                "Cached keys should return copies, not the same reference");

            // Modify one copy and verify the other is unaffected
            cachedKey1[0] ^= 0xFF;
            Assert.IsFalse(SecureMemory.SecureCompare(cachedKey1, cachedKey2),
                "Modifying one copy should not affect the other");

            // Cleanup
            await _keyManager.DeleteKeyAsync(keyId);
        }

        /// <summary>
        /// Tests that key deletion properly clears cached keys
        /// </summary>
        [TestMethod]
        public async Task KeyDeletion_ShouldClearCachedKeys()
        {
            // Arrange
            string keyId = "test-delete-cache-key";
            byte[] originalKey = _cryptoProvider.GenerateRandomBytes(32);

            // Store and cache the key
            await _keyManager.StoreKeyAsync(keyId, originalKey);
            byte[] cachedKey = await _keyManager.RetrieveKeyAsync(keyId);
            Assert.IsNotNull(cachedKey);

            // Delete the key
            bool deleted = await _keyManager.DeleteKeyAsync(keyId);
            Assert.IsTrue(deleted);

            // Verify key is no longer retrievable
            byte[] retrievedAfterDelete = await _keyManager.RetrieveKeyAsync(keyId);
            Assert.IsNull(retrievedAfterDelete, "Key should not be retrievable after deletion");
        }

        /// <summary>
        /// Tests that concurrent access to cached keys is thread-safe
        /// </summary>
        [TestMethod]
        public async Task KeyCache_ShouldBeThreadSafe()
        {
            // Arrange
            string keyId = "test-concurrent-key";
            byte[] originalKey = _cryptoProvider.GenerateRandomBytes(32);
            await _keyManager.StoreKeyAsync(keyId, originalKey);

            // Act - Concurrent access
            var tasks = new List<Task<byte[]>>();
            for (int i = 0; i < 10; i++)
            {
                tasks.Add(Task.Run(async () => await _keyManager.RetrieveKeyAsync(keyId)));
            }

            byte[][] results = await Task.WhenAll(tasks);

            // Assert - All results should be valid and equal
            foreach (var result in results)
            {
                Assert.IsNotNull(result);
                Assert.IsTrue(SecureMemory.SecureCompare(originalKey, result));
            }

            // Cleanup
            await _keyManager.DeleteKeyAsync(keyId);
        }

        #endregion
    }
}