using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IO;
using System.Security.Cryptography;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.KeyManagement;
using System;
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
        public void GenerateSignatureKeyPair_ShouldReturnValidKeyPair()
        {
            // Act
            KeyPair _identityKeyPair = Sodium.GenerateEd25519KeyPair();

            // Assert
            Assert.IsNotNull(_identityKeyPair.PublicKey);
            Assert.IsNotNull(_identityKeyPair.PrivateKey);
            Assert.AreEqual(32, _identityKeyPair.PublicKey.Length); // Ed25519 public key is 32 bytes
            Assert.AreEqual(64, _identityKeyPair.PrivateKey.Length); // Ed25519 private key is 64 bytes
        }

        [TestMethod]
        public void GenerateKeyExchangeKeyPair_ShouldReturnValidKeyPair()
        {
            // Act
            KeyPair _identityKeyPair = Sodium.GenerateX25519KeyPair();

            // Assert
            Assert.IsNotNull(_identityKeyPair.PublicKey);
            Assert.IsNotNull(_identityKeyPair.PrivateKey);
            Assert.AreEqual(32, _identityKeyPair.PublicKey.Length); // X25519 public key is 32 bytes
            Assert.AreEqual(32, _identityKeyPair.PrivateKey.Length); // X25519 private key is 32 bytes
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
        [ExpectedException(typeof(FileNotFoundException))]
        public void LoadKeyFromFile_WithNonExistentFile_ShouldThrowException()
        {
            // Act - should throw FileNotFoundException
            _keyManager.RetrieveKeyAsync("non-existent-file").GetAwaiter().GetResult();
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void LoadKeyFromFile_WithWrongPassword_ShouldThrowException()
        {
            // Arrange
            KeyPair _identityKeyPair = Sodium.GenerateX25519KeyPair();
            var publicKey = _identityKeyPair.PublicKey;
            string filePath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
            string password = "CorrectP@ssw0rd";
            string wrongPassword = "WrongP@ssw0rd";
            string sessionId = new Guid().ToString();

            try
            {
                // Act
                _keyManager.StoreKeyAsync(sessionId, publicKey, password).GetAwaiter().GetResult();

                // Should throw CryptographicException
                _keyManager.RetrieveKeyAsync(sessionId, wrongPassword).GetAwaiter().GetResult();
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
    }
}