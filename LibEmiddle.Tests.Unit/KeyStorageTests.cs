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
            _cryptoProvider.LoadKeyFromFile("non-existent-file.key");
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

            try
            {
                // Act
                _cryptoProvider.StoreKeyToFile(publicKey, filePath, correctPassword);

                // Should throw CryptographicException
                _cryptoProvider.LoadKeyFromFile(filePath, wrongPassword);
            }
            finally
            {
                // Cleanup
                if (File.Exists(filePath))
                {
                    File.Delete(filePath);
                }
            }
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void LoadKeyFromFile_CorruptedFile_ShouldThrowInvalidDataException()
        {
            // Arrange
            string filePath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
            string password = "TestP@ssword";

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
                _cryptoProvider.LoadKeyFromFile(filePath, password);
            }   
            finally
            {
                // Cleanup
                if (File.Exists(filePath))
                {
                    File.Delete(filePath);
                }
            }
        }

        [TestMethod]
        public void KeyStorage_SaltRotation_ShouldUpdateFile()
        {
            // Arrange
            KeyPair _identityKeyPair = Sodium.GenerateX25519KeyPair();
            var publicKey = _identityKeyPair.PublicKey;
            string filePath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
            string password = "TestP@ssw0rd";
            bool forceRotation = true;

            try
            {
                // Store the key
                _cryptoProvider.StoreKeyToFile(publicKey, filePath, password);

                // Get file info before rotation
                FileInfo fileInfoBefore = new FileInfo(filePath);
                DateTime lastModifiedBefore = fileInfoBefore.LastWriteTime;

                // Wait a moment to ensure timestamp can change
                System.Threading.Thread.Sleep(100);

                // Act - force salt rotation
                byte[] loadedKey = _cryptoProvider.LoadKeyFromFile(filePath, password, forceRotation);

                // Get file info after rotation
                FileInfo fileInfoAfter = new FileInfo(filePath);
                DateTime lastModifiedAfter = fileInfoAfter.LastWriteTime;

                // Assert
                CollectionAssert.AreEqual(publicKey, loadedKey, "Key should be correctly loaded");
                Assert.AreNotEqual(lastModifiedBefore, lastModifiedAfter,
                    "File should be modified when salt rotation occurs");
            }
            finally
            {
                // Cleanup
                if (File.Exists(filePath))
                {
                    File.Delete(filePath);
                }
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void StoreKeyToFile_NullKey_ShouldThrowException()
        {
            // Act - should throw ArgumentException or ArgumentNullException
            string filePath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
            try
            {
                _cryptoProvider.StoreKeyToFile(null, filePath);
            }
            finally
            {
                if (File.Exists(filePath))
                {
                    File.Delete(filePath);
                }
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void StoreKeyToFile_EmptyKey_ShouldThrowException()
        {
            // Act - should throw ArgumentException
            string filePath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
            try
            {
                _cryptoProvider.StoreKeyToFile(new byte[0], filePath);
            }
            finally
            {
                if (File.Exists(filePath))
                {
                    File.Delete(filePath);
                }
            }
        }
    }
}