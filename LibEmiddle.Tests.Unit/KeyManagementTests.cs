using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IO;
using System.Security.Cryptography;
using LibEmiddle.API;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;

namespace LibEmiddle.Tests.Unit
{
    [TestClass]
    public class KeyManagementTests
    {
        [TestMethod]
        public void GenerateSignatureKeyPair_ShouldReturnValidKeyPair()
        {
            // Act
            var (publicKey, privateKey) = LibEmiddleClient.GenerateSignatureKeyPair();

            // Assert
            Assert.IsNotNull(publicKey);
            Assert.IsNotNull(privateKey);
            Assert.AreEqual(32, publicKey.Length); // Ed25519 public key is 32 bytes
            Assert.AreEqual(64, privateKey.Length); // Ed25519 private key is 64 bytes
        }

        [TestMethod]
        public void GenerateKeyExchangeKeyPair_ShouldReturnValidKeyPair()
        {
            // Act
            var (publicKey, privateKey) = LibEmiddleClient.GenerateKeyExchangeKeyPair();

            // Assert
            Assert.IsNotNull(publicKey);
            Assert.IsNotNull(privateKey);
            Assert.AreEqual(32, publicKey.Length); // X25519 public key is 32 bytes
            Assert.AreEqual(32, privateKey.Length); // X25519 private key is 32 bytes
        }

        [TestMethod]
        public void ExportImportKeyToBase64_ShouldReturnOriginalKey()
        {
            // Arrange
            var (publicKey, _) = LibEmiddleClient.GenerateKeyExchangeKeyPair();

            // Act
            string base64Key = KeyPair.ExportKeyToBase64(publicKey);
            byte[] importedKey = KeyPair.ImportKeyFromBase64(base64Key);

            // Assert
            CollectionAssert.AreEqual(publicKey, importedKey);
        }

        [TestMethod]
        public void StoreAndLoadKeyFromFile_WithoutPassword_ShouldReturnOriginalKey()
        {
            // Arrange
            var (publicKey, _) = LibEmiddleClient.GenerateKeyExchangeKeyPair();
            string filePath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());

            try
            {
                // Act
                LibEmiddleClient.StoreKeyToFile(publicKey, filePath);
                byte[] loadedKey = LibEmiddleClient.LoadKeyFromFile(filePath);

                // Assert
                CollectionAssert.AreEqual(publicKey, loadedKey);
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
        public void StoreAndLoadKeyFromFile_WithPassword_ShouldReturnOriginalKey()
        {
            // Arrange
            var (publicKey, _) = LibEmiddleClient.GenerateKeyExchangeKeyPair();
            string filePath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
            string password = "TestP@ssw0rd";

            try
            {
                // Act
                LibEmiddleClient.StoreKeyToFile(publicKey, filePath, password);
                byte[] loadedKey = LibEmiddleClient.LoadKeyFromFile(filePath, password);

                // Assert
                CollectionAssert.AreEqual(publicKey, loadedKey);
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
        [ExpectedException(typeof(FileNotFoundException))]
        public void LoadKeyFromFile_WithNonExistentFile_ShouldThrowException()
        {
            // Act - should throw FileNotFoundException
            LibEmiddleClient.LoadKeyFromFile("non-existent-file.key");
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void LoadKeyFromFile_WithWrongPassword_ShouldThrowException()
        {
            // Arrange
            var (publicKey, _) = LibEmiddleClient.GenerateKeyExchangeKeyPair();
            string filePath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
            string password = "CorrectP@ssw0rd";
            string wrongPassword = "WrongP@ssw0rd";

            try
            {
                // Act
                LibEmiddleClient.StoreKeyToFile(publicKey, filePath, password);

                // Should throw CryptographicException
                LibEmiddleClient.LoadKeyFromFile(filePath, wrongPassword);
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
        public void ValidateX25519PublicKey_WithValidKey_ShouldReturnTrue()
        {
            // Arrange
            var (publicKey, _) = LibEmiddleClient.GenerateKeyExchangeKeyPair();

            // Act
            bool isValid = KeyValidation.ValidateX25519PublicKey(publicKey);

            // Assert
            Assert.IsTrue(isValid, "A properly generated X25519 public key should be valid");
        }

        [TestMethod]
        public void ValidateX25519PublicKey_WithAllZeros_ShouldReturnFalse()
        {
            // Arrange
            byte[] allZeroKey = new byte[Constants.X25519_KEY_SIZE]; // All zeros

            // Act
            bool isValid = KeyValidation.ValidateX25519PublicKey(allZeroKey);

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
            bool shortKeyValid = KeyValidation.ValidateX25519PublicKey(shortKey);
            bool longKeyValid = KeyValidation.ValidateX25519PublicKey(longKey);

            // Assert
            Assert.IsFalse(shortKeyValid, "A key that's too short should be invalid");
            Assert.IsFalse(longKeyValid, "A key that's too long should be invalid");
        }

        [TestMethod]
        public void DeriveX25519PrivateKeyFromEd25519_ShouldProduceValidKey()
        {
            // Arrange
            var (_, ed25519PrivateKey) = LibEmiddleClient.GenerateSignatureKeyPair();

            // Act
            byte[] x25519PrivateKey = KeyConversion.DeriveX25519PrivateKeyFromEd25519(ed25519PrivateKey);

            // Assert
            Assert.IsNotNull(x25519PrivateKey);
            Assert.AreEqual(Constants.X25519_KEY_SIZE, x25519PrivateKey.Length, "Derived X25519 key should be the correct length");
        }
    }
}