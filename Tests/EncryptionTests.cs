using System;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;
using E2EELibrary;
using E2EELibrary.Encryption;
using E2EELibrary.Models;
using E2EELibrary.Core;

namespace E2EELibraryTests
{
    [TestClass]
    public class EncryptionTests
    {
        [TestMethod]
        public void GenerateNonce_ShouldReturnUniqueValues()
        {
            // Act
            byte[] nonce1 = NonceGenerator.GenerateNonce();
            byte[] nonce2 = NonceGenerator.GenerateNonce();
            byte[] nonce3 = NonceGenerator.GenerateNonce();

            // Assert
            Assert.IsFalse(AreByteArraysEqual(nonce1, nonce2));
            Assert.IsFalse(AreByteArraysEqual(nonce2, nonce3));
            Assert.IsFalse(AreByteArraysEqual(nonce1, nonce3));
        }

        [TestMethod]
        public void AESEncryptDecrypt_ShouldReturnOriginalData()
        {
            // Arrange
            byte[] plaintext = Encoding.UTF8.GetBytes("This is a test message for encryption and decryption");
            byte[] key = new byte[32]; // 256-bit key
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(key);
            }
            byte[] nonce = NonceGenerator.GenerateNonce();

            // Act
            byte[] ciphertext = AES.AESEncrypt(plaintext, key, nonce);
            byte[] decrypted = AES.AESDecrypt(ciphertext, key, nonce);

            // Assert
            CollectionAssert.AreEqual(plaintext, decrypted);
        }

        [TestMethod]
        public void EncryptDecryptMessage_ShouldReturnOriginalMessage()
        {
            // Arrange
            string message = "Hello world! This is a secure message.";
            byte[] key = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(key);
            }

            // Act
            var encryptedMessage = E2EEClient.EncryptMessage(message, key);
            string decryptedMessage = E2EEClient.DecryptMessage(encryptedMessage, key);

            // Assert
            Assert.AreEqual(message, decryptedMessage);
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void AESDecrypt_WithWrongKey_ShouldThrowException()
        {
            // Arrange
            byte[] plaintext = Encoding.UTF8.GetBytes("This is a test message");
            byte[] correctKey = new byte[32]; // Using 32 bytes for AES-256
            byte[] wrongKey = new byte[32];

            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(correctKey);
                rng.GetBytes(wrongKey);
            }

            byte[] nonce = NonceGenerator.GenerateNonce();

            // Act
            byte[] ciphertext = AES.AESEncrypt(plaintext, correctKey, nonce);

            // Should throw an exception
            byte[] decrypted = AES.AESDecrypt(ciphertext, wrongKey, nonce);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void AESEncrypt_WithNullKey_ShouldThrowException()
        {
            // Arrange
            byte[] plaintext = Encoding.UTF8.GetBytes("Test message");
            byte[] nonce = NonceGenerator.GenerateNonce();

            // Act & Assert - Should throw ArgumentNullException
            AES.AESEncrypt(plaintext, null, nonce);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void EncryptMessage_WithNullKey_ShouldThrowException()
        {
            // Act & Assert - Should throw ArgumentNullException
            E2EEClient.EncryptMessage("Test message", null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EncryptMessage_WithEmptyMessage_ShouldThrowException()
        {
            // Arrange
            byte[] key = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(key);
            }

            // Act & Assert - Should throw ArgumentException
            E2EEClient.EncryptMessage("", key);
        }

        [TestMethod]
        public void MessageCorruption_ShouldDetectTampering()
        {
            // Arrange
            string message = "This message should be protected from tampering";
            byte[] key = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(key);
            }

            // Encrypt the message
            var encryptedMessage = E2EEClient.EncryptMessage(message, key);

            // Make a copy for tampering
            var tamperedMessage = new EncryptedMessage
            {
                Ciphertext = new byte[encryptedMessage.Ciphertext.Length],
                Nonce = encryptedMessage.Nonce
            };
            Buffer.BlockCopy(encryptedMessage.Ciphertext, 0, tamperedMessage.Ciphertext, 0, encryptedMessage.Ciphertext.Length);

            // Tamper with the ciphertext (flip a bit in the middle)
            int middlePosition = tamperedMessage.Ciphertext.Length / 2;
            tamperedMessage.Ciphertext[middlePosition] ^= 1; // Flip one bit

            // Act & Assert
            Assert.ThrowsException<System.Security.Cryptography.CryptographicException>(() =>
            {
                E2EEClient.DecryptMessage(tamperedMessage, key);
            }, "Tampered message should fail authentication");

            // Original message should still decrypt correctly
            string decryptedOriginal = E2EEClient.DecryptMessage(encryptedMessage, key);
            Assert.AreEqual(message, decryptedOriginal);
        }

        [TestMethod]
        public void ExtremeMessageSizes_ShouldEncryptAndDecryptCorrectly()
        {
            // Arrange
            byte[] key = new byte[32];
            RandomNumberGenerator.Fill(key);

            // Test with very small message
            string tinyMessage = "Hi";

            // Test with a large message (100 KB of text)
            StringBuilder largeMessageBuilder = new StringBuilder(100 * 1024);
            for (int i = 0; i < 1024 * 10; i++) // Generate ~100KB of text
            {
                largeMessageBuilder.Append("This is a test message for encryption with large content. ");
            }
            string largeMessage = largeMessageBuilder.ToString();

            // Act & Assert - Tiny message
            var tinyEncrypted = E2EEClient.EncryptMessage(tinyMessage, key);
            string tinyDecrypted = E2EEClient.DecryptMessage(tinyEncrypted, key);
            Assert.AreEqual(tinyMessage, tinyDecrypted);

            // Act & Assert - Large message
            var largeEncrypted = E2EEClient.EncryptMessage(largeMessage, key);
            string largeDecrypted = E2EEClient.DecryptMessage(largeEncrypted, key);
            Assert.AreEqual(largeMessage, largeDecrypted);
        }

        [TestMethod]
        public void InvalidUTF8Input_ShouldBeHandledGracefully()
        {
            // Arrange
            byte[] key = new byte[32];
            RandomNumberGenerator.Fill(key);

            // Create invalid UTF-8 sequence
            byte[] invalidUtf8 = new byte[] { 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0xC0, 0xC1, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF };
            byte[] nonce = NonceGenerator.GenerateNonce();

            try
            {
                // Attempt to encrypt the invalid UTF-8
                byte[] ciphertext = AES.AESEncrypt(invalidUtf8, key, nonce);
                byte[] decrypted = AES.AESDecrypt(ciphertext, key, nonce);

                // Convert back to string should fail or result in replacement characters
                string result = Encoding.UTF8.GetString(decrypted);

                // The decryption should work at the byte level even with invalid UTF-8
                CollectionAssert.AreEqual(invalidUtf8, decrypted, "Bytes should decrypt correctly even with invalid UTF-8");
            }
            catch (FormatException)
            {
                // This is acceptable - if the library explicitly checks for valid UTF-8
                Assert.IsTrue(true, "Caught expected FormatException for invalid UTF-8");
            }
        }

        // Helper method for byte array comparison
        private bool AreByteArraysEqual(byte[] a, byte[] b)
        {
            return SecureMemory.SecureCompare(a, b);
        }
    }
}