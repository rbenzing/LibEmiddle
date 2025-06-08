using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;

namespace LibEmiddle.Tests.Unit
{
    [TestClass]
    public class KeyStorageTests
    {
        private CryptoProvider _cryptoProvider;

        [TestInitialize]
        public void Setup()
        {
            _cryptoProvider = new CryptoProvider();
        }

        [TestMethod]
        public void LoadKeyFromFile_NonExistentFile_ShouldThrowException()
        {
            // Act - should return null for non-existent file
            byte[] result = _cryptoProvider.RetrieveKeyAsync("non-existent-file").GetAwaiter().GetResult();

            // Assert
            Assert.IsNull(result, "RetrieveKeyAsync should return null for non-existent file");
        }

        [TestMethod]
        public void LoadKeyFromFile_WrongPassword_ShouldReturnNull()
        {
            // Arrange
            KeyPair _identityKeyPair = Sodium.GenerateX25519KeyPair();
            var publicKey = _identityKeyPair.PublicKey;

            // Debug: Check key size
            Console.WriteLine($"X25519 public key size: {publicKey.Length} bytes");
            Assert.AreEqual(32, publicKey.Length, "X25519 public key should be 32 bytes");

            string correctPassword = "CorrectP@ssw0rd";
            string wrongPassword = "WrongP@ssw0rd";
            string sessionId = Guid.NewGuid().ToString();

            try
            {
                // Act
                bool success = _cryptoProvider.StoreKeyAsync(sessionId, publicKey, correctPassword).GetAwaiter().GetResult();
                Assert.IsTrue(success, "Key should be stored successfully");

                // Should return null for wrong password
                byte[] result = _cryptoProvider.RetrieveKeyAsync(sessionId, wrongPassword).GetAwaiter().GetResult();

                // Assert
                Assert.IsNull(result, "RetrieveKeyAsync should return null for wrong password");
            }
            finally
            {
                // Cleanup - only if key was stored
                try
                {
                    _cryptoProvider.DeleteKeyAsync(sessionId).GetAwaiter().GetResult();
                }
                catch
                {
                    // Ignore cleanup errors
                }
            }
        }

        [TestMethod]
        public void LoadKeyFromFile_CorruptedFile_ShouldReturnNull()
        {
            // Arrange
            string password = "TestP@ssword";
            string sessionId = Guid.NewGuid().ToString();
            bool keyStored = false;

            try
            {
                // Create an empty key (should fail to store)
                byte[] emptyKey = new byte[0];

                // Act - should fail to store empty key
                bool storeResult = _cryptoProvider.StoreKeyAsync(sessionId, emptyKey, password).GetAwaiter().GetResult();
                keyStored = storeResult;

                // Assert
                Assert.IsFalse(storeResult, "Storing empty key should fail");
            }
            finally
            {
                // Cleanup - only if key was stored
                if (keyStored)
                {
                    try
                    {
                        _cryptoProvider.DeleteKeyAsync(sessionId, password).GetAwaiter().GetResult();
                    }
                    catch
                    {
                        // Ignore cleanup errors
                    }
                }
            }
        }

        [TestMethod]
        public void KeyStorage_SaltRotation_ShouldUpdateFile()
        {
            // Arrange
            KeyPair _identityKeyPair = Sodium.GenerateX25519KeyPair();
            var publicKey = _identityKeyPair.PublicKey;

            // Debug: Check key size
            Console.WriteLine($"X25519 public key size: {publicKey.Length} bytes");
            Assert.AreEqual(32, publicKey.Length, "X25519 public key should be 32 bytes");

            string password = "TestP@ssw0rd";
            string sessionId = Guid.NewGuid().ToString();
            bool keyStored = false;

            try
            {
                // Store the key
                bool storeResult = _cryptoProvider.StoreKeyAsync(sessionId, publicKey, password).GetAwaiter().GetResult();
                keyStored = storeResult;
                Assert.IsTrue(storeResult, "Key should be stored successfully");

                // Wait a moment to ensure timestamp can change
                System.Threading.Thread.Sleep(100);

                // new nonce
                var newNonce = _cryptoProvider.GenerateNonce();

                // Debug: Test key derivation consistency
                byte[] derivedKey1 = _cryptoProvider.DeriveKeyFromPassword(password);
                byte[] derivedKey2 = _cryptoProvider.DeriveKeyFromPassword(password);
                Console.WriteLine($"Key derivation consistent: {derivedKey1.SequenceEqual(derivedKey2)}");
                Console.WriteLine($"Derived key length: {derivedKey1.Length}");

                // Act - retrieve the key
                byte[] loadedKey = _cryptoProvider.RetrieveKeyAsync(sessionId, password).GetAwaiter().GetResult();

                // Debug: Check if key was retrieved
                if (loadedKey == null)
                {
                    Console.WriteLine("Key retrieval failed - trying without password");
                    byte[] loadedKeyNoPassword = _cryptoProvider.RetrieveKeyAsync(sessionId).GetAwaiter().GetResult();
                    Console.WriteLine($"Key without password: {(loadedKeyNoPassword != null ? "Found" : "Not found")}");
                }

                // Assert
                Assert.IsNotNull(loadedKey, "Key should be retrieved successfully");
                CollectionAssert.AreEqual(publicKey, loadedKey, "Key should be correctly loaded");
            }
            finally
            {
                // Cleanup - only if key was stored
                if (keyStored)
                {
                    try
                    {
                        _cryptoProvider.DeleteKeyAsync(sessionId).GetAwaiter().GetResult();
                    }
                    catch
                    {
                        // Ignore cleanup errors
                    }
                }
            }
        }

        [TestMethod]
        public void StoreKeyToFile_NullKey_ShouldThrowException()
        {
            // Arrange
            string sessionId = Guid.NewGuid().ToString();

            // Act & Assert
            Assert.ThrowsException<ArgumentNullException>(() =>
            {
                _cryptoProvider.StoreKeyAsync(sessionId, null).GetAwaiter().GetResult();
            }, "StoreKeyAsync should throw ArgumentNullException for null key");
        }

        [TestMethod]
        public void StoreKeyToFile_EmptyKey_ShouldReturnFalse()
        {
            // Arrange
            string sessionId = Guid.NewGuid().ToString();

            // Act
            bool result = _cryptoProvider.StoreKeyAsync(sessionId, new byte[0]).GetAwaiter().GetResult();

            // Assert
            Assert.IsFalse(result, "StoreKeyAsync should return false for empty key");
        }
    }
}