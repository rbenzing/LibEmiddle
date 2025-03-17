using System;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;
using System.Collections.Generic;
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
            Assert.IsFalse(TestsHelpers.AreByteArraysEqual(nonce1, nonce2));
            Assert.IsFalse(TestsHelpers.AreByteArraysEqual(nonce2, nonce3));
            Assert.IsFalse(TestsHelpers.AreByteArraysEqual(nonce1, nonce3));
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

        [TestMethod]
        public void AESEncryptDecrypt_WithAuthTag_ShouldHandleCorrectly()
        {
            // Arrange
            byte[] plaintext = Encoding.UTF8.GetBytes("Test message with authentication tag");
            byte[] key = new byte[32]; // 256-bit key
            RandomNumberGenerator.Fill(key);
            byte[] nonce = NonceGenerator.GenerateNonce();

            // Act
            byte[] ciphertextWithTag = AES.AESEncrypt(plaintext, key, nonce);
            byte[] decrypted = AES.AESDecrypt(ciphertextWithTag, key, nonce);

            // Assert
            Assert.IsTrue(ciphertextWithTag.Length > plaintext.Length,
                "Ciphertext with tag should be longer than plaintext");
            CollectionAssert.AreEqual(plaintext, decrypted, "Decrypted data should match original");
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void AESDecrypt_TamperedTag_ShouldThrowException()
        {
            // Arrange
            byte[] plaintext = Encoding.UTF8.GetBytes("Message with authentication tag");
            byte[] key = new byte[32];
            RandomNumberGenerator.Fill(key);
            byte[] nonce = NonceGenerator.GenerateNonce();

            // Encrypt the message
            byte[] ciphertextWithTag = AES.AESEncrypt(plaintext, key, nonce);

            // Tamper with the authentication tag (last 16 bytes)
            int tagStart = ciphertextWithTag.Length - Constants.AUTH_TAG_SIZE;
            ciphertextWithTag[tagStart] ^= 1; // Flip one bit in the tag

            // Act & Assert - Should throw CryptographicException
            AES.AESDecrypt(ciphertextWithTag, key, nonce);
        }

        [TestMethod]
        public void AESEncrypt_LargeData_ShouldHandleEfficiently()
        {
            // Arrange
            int dataSize = 10 * 1024 * 1024; // 10 MB
            byte[] largeData = new byte[dataSize];
            RandomNumberGenerator.Fill(largeData);

            byte[] key = new byte[32];
            RandomNumberGenerator.Fill(key);
            byte[] nonce = NonceGenerator.GenerateNonce();

            // Act - Measure time for encryption and decryption
            System.Diagnostics.Stopwatch stopwatch = new System.Diagnostics.Stopwatch();

            stopwatch.Start();
            byte[] ciphertext = AES.AESEncrypt(largeData, key, nonce);
            stopwatch.Stop();
            long encryptTime = stopwatch.ElapsedMilliseconds;

            stopwatch.Restart();
            byte[] decrypted = AES.AESDecrypt(ciphertext, key, nonce);
            stopwatch.Stop();
            long decryptTime = stopwatch.ElapsedMilliseconds;

            // Assert
            CollectionAssert.AreEqual(largeData, decrypted, "Decrypted data should match original");

            // Performance depends on the machine, but we can have a reasonable expectation
            Console.WriteLine($"Encryption time for 10MB: {encryptTime}ms");
            Console.WriteLine($"Decryption time for 10MB: {decryptTime}ms");

            // The actual times will vary by environment, so use loose constraints
            Assert.IsTrue(encryptTime < 5000, "Encryption should complete within 5 seconds");
            Assert.IsTrue(decryptTime < 5000, "Decryption should complete within 5 seconds");
        }

        [TestMethod]
        public void AESEncryptDecrypt_ZeroFilledData_ShouldWorkCorrectly()
        {
            // Arrange - All zeros data
            byte[] zeroData = new byte[1024]; // 1KB of zeros

            byte[] key = new byte[32];
            RandomNumberGenerator.Fill(key);
            byte[] nonce = NonceGenerator.GenerateNonce();

            // Act
            byte[] ciphertext = AES.AESEncrypt(zeroData, key, nonce);
            byte[] decrypted = AES.AESDecrypt(ciphertext, key, nonce);

            // Assert
            CollectionAssert.AreEqual(zeroData, decrypted, "Decrypted zero data should match original");

            // Verify ciphertext is not all zeros (encryption actually happened)
            bool allZeros = true;
            for (int i = 0; i < ciphertext.Length; i++)
            {
                if (ciphertext[i] != 0)
                {
                    allZeros = false;
                    break;
                }
            }
            Assert.IsFalse(allZeros, "Ciphertext should not be all zeros");
        }
    }

    [TestClass]
    public class NonceGeneratorTests
    {
        [TestMethod]
        public void GenerateNonce_ShouldProduceCorrectLength()
        {
            // Act
            byte[] nonce = NonceGenerator.GenerateNonce();

            // Assert
            Assert.IsNotNull(nonce, "Nonce should not be null");
            Assert.AreEqual(Constants.NONCE_SIZE, nonce.Length,
                $"Nonce should be {Constants.NONCE_SIZE} bytes");
        }

        [TestMethod]
        public void GenerateNonce_ShouldProduceUniqueValues()
        {
            // Arrange
            int nonceCount = 10000;
            HashSet<string> nonceSet = new HashSet<string>();

            // Act
            for (int i = 0; i < nonceCount; i++)
            {
                byte[] nonce = NonceGenerator.GenerateNonce();
                string nonceStr = Convert.ToBase64String(nonce);
                nonceSet.Add(nonceStr);
            }

            // Assert
            Assert.AreEqual(nonceCount, nonceSet.Count,
                "All generated nonces should be unique");
        }

        [TestMethod]
        public void GenerateNonce_MultiThreaded_ShouldProduceUniqueValues()
        {
            // Arrange
            int threadsCount = 10;
            int noncesPerThread = 1000;
            var allNonces = new System.Collections.Concurrent.ConcurrentBag<byte[]>();

            // Act - Generate nonces from multiple threads
            var tasks = new List<System.Threading.Tasks.Task>();
            for (int t = 0; t < threadsCount; t++)
            {
                var task = System.Threading.Tasks.Task.Run(() => {
                    for (int i = 0; i < noncesPerThread; i++)
                    {
                        byte[] nonce = NonceGenerator.GenerateNonce();
                        allNonces.Add(nonce);
                    }
                });
                tasks.Add(task);
            }

            // Wait for all tasks to complete
            System.Threading.Tasks.Task.WaitAll(tasks.ToArray());

            // Convert to array and check for duplicates
            byte[][] nonceArray = allNonces.ToArray();

            // Assert - Check all nonces are unique
            for (int i = 0; i < nonceArray.Length; i++)
            {
                for (int j = i + 1; j < nonceArray.Length; j++)
                {
                    bool areEqual = true;
                    for (int k = 0; k < nonceArray[i].Length; k++)
                    {
                        if (nonceArray[i][k] != nonceArray[j][k])
                        {
                            areEqual = false;
                            break;
                        }
                    }
                    Assert.IsFalse(areEqual, $"Nonces at positions {i} and {j} should not be equal");
                }
            }
        }

        [TestMethod]
        public void NonceGenerator_RandomnessQuality()
        {
            // Arrange
            int nonceCount = 1000;
            byte[][] nonces = new byte[nonceCount][];

            // Act - Generate many nonces
            for (int i = 0; i < nonceCount; i++)
            {
                nonces[i] = NonceGenerator.GenerateNonce();
            }

            // Count byte frequencies to test randomness
            int[][] byteFrequencies = new int[Constants.NONCE_SIZE][];
            for (int i = 0; i < Constants.NONCE_SIZE; i++)
            {
                byteFrequencies[i] = new int[256];
            }

            // Count occurrences of each byte value at each position
            for (int i = 0; i < nonceCount; i++)
            {
                for (int j = 0; j < Constants.NONCE_SIZE; j++)
                {
                    byteFrequencies[j][nonces[i][j]]++;
                }
            }

            // Assert - Chi-squared test for uniformity
            // For truly random data, each byte value should appear approximately nonceCount/256 times
            double expectedFrequency = (double)nonceCount / 256;

            // Check if the frequency distribution is uniform within reasonable bounds
            for (int pos = 0; pos < Constants.NONCE_SIZE; pos++)
            {
                double chiSquared = 0;
                for (int value = 0; value < 256; value++)
                {
                    chiSquared += Math.Pow(byteFrequencies[pos][value] - expectedFrequency, 2) / expectedFrequency;
                }

                // For 255 degrees of freedom (256-1), chi-squared should be below ~330 for p=0.001
                // This means there's a 99.9% chance that truly random data would pass this test
                Assert.IsTrue(chiSquared < 330,
                    $"Nonce byte distribution at position {pos} fails randomness test (chi-squared = {chiSquared})");
            }
        }
    }
}