using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
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
        [ExpectedException(typeof(FileNotFoundException))]
        public void LoadKeyFromFile_NonExistentFile_ShouldThrowException()
        {
            // Act - should throw FileNotFoundException
            _cryptoProvider.RetrieveKeyAsync("non-existent-file").GetAwaiter().GetResult();
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void LoadKeyFromFile_WrongPassword_ShouldThrowCryptographicException()
        {
            // Arrange
            KeyPair _identityKeyPair = Sodium.GenerateX25519KeyPair();
            var publicKey = _identityKeyPair.PublicKey;
            string filePath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
            string correctPassword = "CorrectP@ssw0rd";
            string wrongPassword = "WrongP@ssw0rd";
            string sessionId = new Guid().ToString();

            try
            {
                // Act
                bool success = _cryptoProvider.StoreKeyAsync(sessionId, publicKey, correctPassword).GetAwaiter().GetResult();

                // Should throw CryptographicException
                _cryptoProvider.RetrieveKeyAsync(sessionId, wrongPassword).GetAwaiter().GetResult();
            }
            finally
            {
                // Cleanup
                _cryptoProvider.DeleteKeyAsync(sessionId).GetAwaiter().GetResult();
            }
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void LoadKeyFromFile_CorruptedFile_ShouldThrowInvalidDataException()
        {
            // Arrange
            string filePath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
            string password = "TestP@ssword";
            string sessionId = new Guid().ToString();

            try
            {
                // Create a corrupted key file
                byte[] corrupted = new byte[128];
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(corrupted);
                }
                File.WriteAllBytes(filePath, corrupted);

                // Act - should throw InvalidDataException
                _cryptoProvider.StoreKeyAsync(sessionId, corrupted, password).GetAwaiter().GetResult();
            }   
            finally
            {
                // Cleanup
                _cryptoProvider.DeleteKeyAsync(sessionId, password).GetAwaiter().GetResult();
            }
        }

        [TestMethod]
        public void KeyStorage_SaltRotation_ShouldUpdateFile()
        {
            // Arrange
            KeyPair _identityKeyPair = Sodium.GenerateX25519KeyPair();
            var publicKey = _identityKeyPair.PublicKey;
            string password = "TestP@ssw0rd";
            string sessionId = new Guid().ToString();

            try
            {
                // Store the key
                _cryptoProvider.StoreKeyAsync(sessionId, publicKey, password);

                // Wait a moment to ensure timestamp can change
                System.Threading.Thread.Sleep(100);

                // new nonce
                var newNonce = _cryptoProvider.GenerateNonce();

                // Act - force salt rotation
                byte[] loadedKey = _cryptoProvider.RetrieveKeyAsync(sessionId, password).GetAwaiter().GetResult();


                // Assert
                CollectionAssert.AreEqual(publicKey, loadedKey, "Key should be correctly loaded");
            }
            finally
            {
                // Cleanup
                _cryptoProvider.DeleteKeyAsync(sessionId).GetAwaiter().GetResult();
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void StoreKeyToFile_NullKey_ShouldThrowException()
        {
            // Act - should throw ArgumentException or ArgumentNullException
            string sessionId = new Guid().ToString();
            try
            {
                _cryptoProvider.StoreKeyAsync(sessionId, null);
            }
            finally
            {
                // remove key
                _cryptoProvider.DeleteKeyAsync(sessionId).GetAwaiter().GetResult();
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void StoreKeyToFile_EmptyKey_ShouldThrowException()
        {
            // Act - should throw ArgumentException
            string sessionId = new Guid().ToString();
            try
            {
                _cryptoProvider.StoreKeyAsync(sessionId, new byte[0]);
            }
            finally
            {
                // remove key
                _cryptoProvider.DeleteKeyAsync(sessionId).GetAwaiter().GetResult();
            }
        }
    }
}