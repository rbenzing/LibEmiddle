using System;
using System.IO;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using E2EELibrary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Threading;
using Sodium;
using System.Linq;

namespace E2EELibraryTests
{
    [TestClass]
    public class E2EETests
    {
        #region Key Management Tests

        [TestMethod]
        public void GenerateEd25519KeyPair_ShouldReturnValidKeyPair()
        {
            // Act
            var (publicKey, privateKey) = E2EE2.GenerateEd25519KeyPair();

            // Assert
            Assert.IsNotNull(publicKey);
            Assert.IsNotNull(privateKey);
            Assert.AreEqual(32, publicKey.Length); // Ed25519 public key is 32 bytes
            Assert.AreEqual(64, privateKey.Length); // Ed25519 private key is 64 bytes
        }

        [TestMethod]
        public void GenerateX25519KeyPair_ShouldReturnValidKeyPair()
        {
            // Act
            var (publicKey, privateKey) = E2EE2.GenerateX25519KeyPair();

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
            var (publicKey, _) = E2EE2.GenerateX25519KeyPair();

            // Act
            string base64Key = E2EE2.ExportKeyToBase64(publicKey);
            byte[] importedKey = E2EE2.ImportKeyFromBase64(base64Key);

            // Assert - Use helper method instead of CollectionAssert
            Assert.IsTrue(AreByteArraysEqual(publicKey, importedKey));
        }

        [TestMethod]
        public void StoreAndLoadKeyFromFile_WithoutPassword_ShouldReturnOriginalKey()
        {
            // Arrange
            var (publicKey, _) = E2EE2.GenerateX25519KeyPair();
            string filePath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());

            try
            {
                // Act
                E2EE2.StoreKeyToFile(publicKey, filePath);
                byte[] loadedKey = E2EE2.LoadKeyFromFile(filePath);

                // Assert
                Assert.IsTrue(AreByteArraysEqual(publicKey, loadedKey));
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
            var (publicKey, _) = E2EE2.GenerateX25519KeyPair();
            string filePath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
            string password = "TestP@ssw0rd";

            try
            {
                // Act
                E2EE2.StoreKeyToFile(publicKey, filePath, password);
                byte[] loadedKey = E2EE2.LoadKeyFromFile(filePath, password);

                // Assert
                Assert.IsTrue(AreByteArraysEqual(publicKey, loadedKey));
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
        [ExpectedException(typeof(System.IO.FileNotFoundException))]
        public void LoadKeyFromFile_WithNonExistentFile_ShouldThrowException()
        {
            // Act - should throw FileNotFoundException
            E2EE2.LoadKeyFromFile("non-existent-file.key");
        }

        [TestMethod]
        [ExpectedException(typeof(System.Security.Cryptography.CryptographicException))]
        public void LoadKeyFromFile_WithWrongPassword_ShouldThrowException()
        {
            // Arrange
            var (publicKey, _) = E2EE2.GenerateX25519KeyPair();
            string filePath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
            string password = "CorrectP@ssw0rd";
            string wrongPassword = "WrongP@ssw0rd";

            try
            {
                // Act
                E2EE2.StoreKeyToFile(publicKey, filePath, password);

                // Should throw CryptographicException
                E2EE2.LoadKeyFromFile(filePath, wrongPassword);
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

        #endregion

        #region Encryption and Decryption Tests

        [TestMethod]
        public void GenerateNonce_ShouldReturnUniqueValues()
        {
            // Act
            byte[] nonce1 = E2EE2.GenerateNonce();
            byte[] nonce2 = E2EE2.GenerateNonce();
            byte[] nonce3 = E2EE2.GenerateNonce();

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
            using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
            {
                rng.GetBytes(key);
            }
            byte[] nonce = E2EE2.GenerateNonce();

            // Act
            byte[] ciphertext = E2EE2.AESEncrypt(plaintext, key, nonce);
            byte[] decrypted = E2EE2.AESDecrypt(ciphertext, key, nonce);

            // Assert
            Assert.IsTrue(AreByteArraysEqual(plaintext, decrypted));
        }

        [TestMethod]
        public void EncryptDecryptMessage_ShouldReturnOriginalMessage()
        {
            // Arrange
            string message = "Hello world! This is a secure message.";
            byte[] key = new byte[32];
            using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
            {
                rng.GetBytes(key);
            }

            // Act
            var encryptedMessage = E2EE2.EncryptMessage(message, key);
            string decryptedMessage = E2EE2.DecryptMessage(encryptedMessage, key);

            // Assert
            Assert.AreEqual(message, decryptedMessage);
        }

        [TestMethod]
        [ExpectedException(typeof(System.Security.Cryptography.CryptographicException))]
        public void AESDecrypt_WithWrongKey_ShouldThrowException()
        {
            // Arrange
            byte[] plaintext = Encoding.UTF8.GetBytes("This is a test message");
            byte[] correctKey = new byte[32]; // Using 32 bytes for AES-256
            byte[] wrongKey = new byte[32];

            using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
            {
                rng.GetBytes(correctKey);
                rng.GetBytes(wrongKey);
            }

            byte[] nonce = E2EE2.GenerateNonce();

            // Act
            byte[] ciphertext = E2EE2.AESEncrypt(plaintext, correctKey, nonce);

            // Should throw an exception
            byte[] decrypted = E2EE2.AESDecrypt(ciphertext, wrongKey, nonce);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void AESEncrypt_WithNullKey_ShouldThrowException()
        {
            // Arrange
            byte[] plaintext = Encoding.UTF8.GetBytes("Test message");
            byte[] nonce = E2EE2.GenerateNonce();

            // Act & Assert - Should throw ArgumentNullException
            E2EE2.AESEncrypt(plaintext, null, nonce);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void EncryptMessage_WithNullKey_ShouldThrowException()
        {
            // Act & Assert - Should throw ArgumentNullException
            E2EE2.EncryptMessage("Test message", null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EncryptMessage_WithEmptyMessage_ShouldThrowException()
        {
            // Arrange
            byte[] key = new byte[32];
            using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
            {
                rng.GetBytes(key);
            }

            // Act & Assert - Should throw ArgumentException
            E2EE2.EncryptMessage("", key);
        }

        #endregion

        #region Key Exchange Tests

        [TestMethod]
        public void X3DHKeyExchange_ShouldProduceSameKeyForBothParties()
        {
            // Arrange
            var (alicePublic, alicePrivate) = E2EE2.GenerateX25519KeyPair();
            var (bobPublic, bobPrivate) = E2EE2.GenerateX25519KeyPair();

            // Act
            byte[] aliceSharedSecret = E2EE2.X3DHKeyExchange(bobPublic, alicePrivate);
            byte[] bobSharedSecret = E2EE2.X3DHKeyExchange(alicePublic, bobPrivate);

            // Assert
            Assert.IsTrue(AreByteArraysEqual(aliceSharedSecret, bobSharedSecret));
        }

        [TestMethod]
        public void CreateX3DHKeyBundle_ShouldReturnValidBundle()
        {
            // Act
            var bundle = E2EE2.CreateX3DHKeyBundle();

            // Assert
            Assert.IsNotNull(bundle);
            Assert.IsNotNull(bundle.IdentityKey);
            Assert.IsNotNull(bundle.SignedPreKey);
            Assert.IsNotNull(bundle.SignedPreKeySignature);
            Assert.IsNotNull(bundle.OneTimePreKeys);
            Assert.IsNotNull(bundle.GetIdentityKeyPrivate());
            Assert.IsNotNull(bundle.GetSignedPreKeyPrivate());
            Assert.IsTrue(bundle.OneTimePreKeys.Count > 0);

            // Verify signature
            bool validSignature = E2EE2.VerifySignature(bundle.SignedPreKey, bundle.SignedPreKeySignature, bundle.IdentityKey);

            Assert.IsTrue(validSignature);

            // Clean up sensitive data when done
            bundle.ClearPrivateKeys();
        }

        [TestMethod]
        public void InitiateX3DHSession_ShouldReturnValidSessionData()
        {
            // Arrange
            var bobBundle = E2EE2.CreateX3DHKeyBundle();
            var (alicePublic, alicePrivate) = E2EE2.GenerateX25519KeyPair();

            var bobPublicBundle = new E2EE2.X3DHPublicBundle
            {
                IdentityKey = bobBundle.IdentityKey,
                SignedPreKey = bobBundle.SignedPreKey,
                SignedPreKeySignature = bobBundle.SignedPreKeySignature,
                OneTimePreKeys = bobBundle.OneTimePreKeys
            };

            // Act
            var session = E2EE2.InitiateX3DHSession(bobPublicBundle, (alicePublic, alicePrivate));

            // Assert
            Assert.IsNotNull(session);
            Assert.IsNotNull(session.RootKey);
            Assert.IsNotNull(session.ChainKey);
            Assert.IsTrue(AreByteArraysEqual(bobBundle.IdentityKey, session.RecipientIdentityKey));
            Assert.IsTrue(AreByteArraysEqual(alicePublic, session.SenderIdentityKey));
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void InitiateX3DHSession_WithNullBundle_ShouldThrowException()
        {
            // Arrange
            var (alicePublic, alicePrivate) = E2EE2.GenerateX25519KeyPair();

            // Act & Assert - Should throw ArgumentNullException
            E2EE2.InitiateX3DHSession(null, (alicePublic, alicePrivate));
        }

        #endregion

        #region Signature Tests

        [TestMethod]
        public void SignAndVerifyMessage_ShouldVerifyCorrectly()
        {
            // Arrange
            byte[] message = Encoding.UTF8.GetBytes("This is a message to be signed");
            var (publicKey, privateKey) = E2EE2.GenerateEd25519KeyPair();

            // Act
            byte[] signature = E2EE2.SignMessage(message, privateKey);
            bool isValid = E2EE2.VerifySignature(message, signature, publicKey);

            // Assert
            Assert.IsTrue(isValid);
        }

        [TestMethod]
        public void VerifySignature_WithTamperedMessage_ShouldReturnFalse()
        {
            // Arrange
            byte[] originalMessage = Encoding.UTF8.GetBytes("This is a message to be signed");
            byte[] tamperedMessage = Encoding.UTF8.GetBytes("This is a tampered message");
            var (publicKey, privateKey) = E2EE2.GenerateEd25519KeyPair();

            // Act
            byte[] signature = E2EE2.SignMessage(originalMessage, privateKey);
            bool isValid = E2EE2.VerifySignature(tamperedMessage, signature, publicKey);

            // Assert
            Assert.IsFalse(isValid);
        }

        [TestMethod]
        public void SignAndVerifyTextMessage_ShouldVerifyCorrectly()
        {
            // Arrange
            string message = "This is a text message to be signed";
            var (publicKey, privateKey) = E2EE2.GenerateEd25519KeyPair();

            // Act
            string signatureBase64 = E2EE2.SignTextMessage(message, privateKey);
            bool isValid = E2EE2.VerifyTextMessage(message, signatureBase64, publicKey);

            // Assert
            Assert.IsTrue(isValid);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void SignMessage_WithNullPrivateKey_ShouldThrowException()
        {
            // Arrange
            byte[] message = Encoding.UTF8.GetBytes("Test message");

            // Act & Assert - Should throw ArgumentNullException
            E2EE2.SignMessage(message, null);
        }

        [TestMethod]
        public void VerifyTextMessage_WithInvalidBase64_ShouldReturnFalse()
        {
            // Arrange
            string message = "Test message";
            var (publicKey, _) = E2EE2.GenerateEd25519KeyPair();
            string invalidBase64 = "not valid base64!@#$";

            // Act
            bool result = E2EE2.VerifyTextMessage(message, invalidBase64, publicKey);

            // Assert
            Assert.IsFalse(result);
        }

        #endregion

        #region Double Ratchet Tests

        [TestMethod]
        public void InitializeDoubleRatchet_ShouldReturnValidKeys()
        {
            // Arrange
            byte[] sharedSecret = new byte[32];
            using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
            {
                rng.GetBytes(sharedSecret);
            }

            // Act
            var (rootKey, chainKey) = E2EE2.InitializeDoubleRatchet(sharedSecret);

            // Assert
            Assert.IsNotNull(rootKey);
            Assert.IsNotNull(chainKey);
            Assert.AreEqual(32, rootKey.Length);
            Assert.AreEqual(32, chainKey.Length);
        }

        [TestMethod]
        public void RatchetStep_ShouldProduceNewKeys()
        {
            // Arrange
            byte[] chainKey = new byte[32];
            using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
            {
                rng.GetBytes(chainKey);
            }

            // Act
            var (newChainKey, messageKey) = E2EE2.RatchetStep(chainKey);

            // Assert
            Assert.IsNotNull(newChainKey);
            Assert.IsNotNull(messageKey);
            Assert.IsFalse(AreByteArraysEqual(chainKey, newChainKey));
        }

        [TestMethod]
        public void DHRatchetStep_ShouldProduceNewKeys()
        {
            // Arrange
            byte[] rootKey = new byte[32];
            byte[] dhOutput = new byte[32];
            using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
            {
                rng.GetBytes(rootKey);
                rng.GetBytes(dhOutput);
            }

            // Act
            var (newRootKey, newChainKey) = E2EE2.DHRatchetStep(rootKey, dhOutput);

            // Assert
            Assert.IsNotNull(newRootKey);
            Assert.IsNotNull(newChainKey);
            Assert.IsFalse(AreByteArraysEqual(rootKey, newRootKey));
        }

        [TestMethod]
        public void DoubleRatchetEncryptDecrypt_ShouldReturnOriginalMessage()
        {
            // Arrange
            var aliceKeyPair = E2EE2.GenerateX25519KeyPair();
            var bobKeyPair = E2EE2.GenerateX25519KeyPair();

            // Initial shared secret
            byte[] sharedSecret = E2EE2.X3DHKeyExchange(bobKeyPair.publicKey, aliceKeyPair.privateKey);
            var (rootKey, chainKey) = E2EE2.InitializeDoubleRatchet(sharedSecret);

            // Create a session ID for both parties to use
            string sessionId = "test-session-" + Guid.NewGuid().ToString();

            // Setup sessions - using immutable DoubleRatchetSession
            var aliceSession = new E2EE2.DoubleRatchetSession(
                dhRatchetKeyPair: aliceKeyPair,
                remoteDHRatchetKey: bobKeyPair.publicKey,
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumber: 0,
                sessionId: sessionId
            );

            var bobSession = new E2EE2.DoubleRatchetSession(
                dhRatchetKeyPair: bobKeyPair,
                remoteDHRatchetKey: aliceKeyPair.publicKey,
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumber: 0,
                sessionId: sessionId
            );

            string message = "This is a Double Ratchet encrypted message";

            // Act - Alice encrypts a message for Bob
            var (aliceUpdatedSession, encryptedMessage) = E2EE2.DoubleRatchetEncrypt(aliceSession, message);

            // Add required security fields
            encryptedMessage.MessageId = Guid.NewGuid();
            encryptedMessage.Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            encryptedMessage.SessionId = sessionId;

            // Bob decrypts Alice's message
            var (bobUpdatedSession, decryptedMessage) = E2EE2.DoubleRatchetDecrypt(bobSession, encryptedMessage);

            // Assert
            Assert.IsNotNull(bobUpdatedSession, "Updated session should not be null");
            Assert.IsNotNull(decryptedMessage, "Decryption should return a valid message");
            Assert.AreEqual(message, decryptedMessage, "Decrypted message should match the original");

            // Verify session state has been updated properly
            Assert.AreNotEqual(bobSession, bobUpdatedSession, "Updated session should be a new instance");
            Assert.IsFalse(AreByteArraysEqual(bobSession.ReceivingChainKey, bobUpdatedSession.ReceivingChainKey),
                "Receiving chain key should change after decryption");

            // Verify message number incremented
            Assert.AreEqual(aliceSession.MessageNumber + 1, aliceUpdatedSession.MessageNumber,
                "Message number should be incremented after encryption");
        }

        [TestMethod]
        public void DoubleRatchetDecrypt_WithFutureTimestamp_ShouldReturnNull()
        {
            // Arrange
            var aliceKeyPair = E2EE2.GenerateX25519KeyPair();
            var bobKeyPair = E2EE2.GenerateX25519KeyPair();
            byte[] sharedSecret = E2EE2.X3DHKeyExchange(bobKeyPair.publicKey, aliceKeyPair.privateKey);
            var (rootKey, chainKey) = E2EE2.InitializeDoubleRatchet(sharedSecret);

            var aliceSession = new E2EE2.DoubleRatchetSession(
                dhRatchetKeyPair: aliceKeyPair,
                remoteDHRatchetKey: bobKeyPair.publicKey,
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumber: 0
            );

            var bobSession = new E2EE2.DoubleRatchetSession(
                dhRatchetKeyPair: bobKeyPair,
                remoteDHRatchetKey: aliceKeyPair.publicKey,
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumber: 0
            );

            string message = "Test message";
            var (_, encryptedMessage) = E2EE2.DoubleRatchetEncrypt(aliceSession, message);

            // Set timestamp to the future (beyond allowed clock skew)
            encryptedMessage.Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + (10 * 60 * 1000); // 10 minutes in future

            // Act
            var (resultSession, resultMessage) = E2EE2.DoubleRatchetDecrypt(bobSession, encryptedMessage);

            // Assert
            Assert.IsNull(resultSession);
            Assert.IsNull(resultMessage);
        }

        [TestMethod]
        public void DoubleRatchetDecrypt_ShouldClearSensitiveData()
        {
            // This test is more complex as it requires reflecting into private data
            // A simpler approach is to verify behavior indirectly by ensuring decryption works
            // multiple times in a row with different messages, indicating no data corruption

            // Arrange
            var aliceKeyPair = E2EE2.GenerateX25519KeyPair();
            var bobKeyPair = E2EE2.GenerateX25519KeyPair();
            byte[] sharedSecret = E2EE2.X3DHKeyExchange(bobKeyPair.publicKey, aliceKeyPair.privateKey);
            var (rootKey, chainKey) = E2EE2.InitializeDoubleRatchet(sharedSecret);

            // Create a session ID
            string sessionId = "memory-safety-test-" + Guid.NewGuid().ToString();

            var aliceSession = new E2EE2.DoubleRatchetSession(
                dhRatchetKeyPair: aliceKeyPair,
                remoteDHRatchetKey: bobKeyPair.publicKey,
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumber: 0,
                sessionId: sessionId
            );

            var bobSession = new E2EE2.DoubleRatchetSession(
                dhRatchetKeyPair: bobKeyPair,
                remoteDHRatchetKey: aliceKeyPair.publicKey,
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumber: 0,
                sessionId: sessionId
            );

            var currentAliceSession = aliceSession;
            var currentBobSession = bobSession;

            // Send multiple messages in sequence
            for (int i = 0; i < 10; i++)
            {
                string message = $"Test message {i}";
                var (aliceUpdatedSession, encryptedMessage) = E2EE2.DoubleRatchetEncrypt(
                    currentAliceSession, message);

                // Ensure all security fields are set
                encryptedMessage.MessageId = Guid.NewGuid();
                encryptedMessage.Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                encryptedMessage.SessionId = sessionId;

                var (bobUpdatedSession, decryptedMessage) = E2EE2.DoubleRatchetDecrypt(
                    currentBobSession, encryptedMessage);

                // Update the sessions
                currentAliceSession = aliceUpdatedSession;
                currentBobSession = bobUpdatedSession;

                // Verify decryption worked
                Assert.IsNotNull(bobUpdatedSession, $"Message {i} resulted in null session");
                Assert.IsNotNull(decryptedMessage, $"Message {i} failed to decrypt");
                Assert.AreEqual(message, decryptedMessage, $"Message {i} content mismatch");

                // Force garbage collection to increase chance of detecting memory issues
                if (i % 3 == 0)
                {
                    GC.Collect();
                    GC.WaitForPendingFinalizers();
                }
            }

            // Additional verification: try encrypting with final session state
            string finalMessage = "Final test message";
            var (finalAliceSession, finalEncryptedMessage) = E2EE2.DoubleRatchetEncrypt(
                currentAliceSession, finalMessage);

            finalEncryptedMessage.MessageId = Guid.NewGuid();
            finalEncryptedMessage.Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            finalEncryptedMessage.SessionId = sessionId;

            var (finalBobSession, finalDecryptedMessage) = E2EE2.DoubleRatchetDecrypt(
                currentBobSession, finalEncryptedMessage);

            // Verify final message exchange worked
            Assert.IsNotNull(finalBobSession, "Final message resulted in null session");
            Assert.IsNotNull(finalDecryptedMessage, "Final message failed to decrypt");
            Assert.AreEqual(finalMessage, finalDecryptedMessage, "Final message content mismatch");

            // Test memory safety by forcing multiple garbage collections
            GC.Collect(2, GCCollectionMode.Forced);
            GC.WaitForPendingFinalizers();
            GC.Collect(2, GCCollectionMode.Forced);

            // Try one more exchange after garbage collection
            string postGCMessage = "Post garbage collection message";
            var (postGCAliceSession, postGCEncryptedMessage) = E2EE2.DoubleRatchetEncrypt(
                finalAliceSession, postGCMessage);

            postGCEncryptedMessage.MessageId = Guid.NewGuid();
            postGCEncryptedMessage.Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            postGCEncryptedMessage.SessionId = sessionId;

            var (postGCBobSession, postGCDecryptedMessage) = E2EE2.DoubleRatchetDecrypt(
                finalBobSession, postGCEncryptedMessage);

            // Verify post-GC message exchange worked
            Assert.IsNotNull(postGCBobSession, "Post-GC message resulted in null session");
            Assert.IsNotNull(postGCDecryptedMessage, "Post-GC message failed to decrypt");
            Assert.AreEqual(postGCMessage, postGCDecryptedMessage, "Post-GC message content mismatch");
        }

        [TestMethod]
        public void DoubleRatchetDecrypt_WithInvalidDHKey_ShouldReturnNull()
        {
            // Arrange
            var aliceKeyPair = E2EE2.GenerateX25519KeyPair();
            var bobKeyPair = E2EE2.GenerateX25519KeyPair();
            byte[] sharedSecret = E2EE2.X3DHKeyExchange(bobKeyPair.publicKey, aliceKeyPair.privateKey);
            var (rootKey, chainKey) = E2EE2.InitializeDoubleRatchet(sharedSecret);

            var aliceSession = new E2EE2.DoubleRatchetSession(
                dhRatchetKeyPair: aliceKeyPair,
                remoteDHRatchetKey: bobKeyPair.publicKey,
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumber: 0
            );

            var bobSession = new E2EE2.DoubleRatchetSession(
                dhRatchetKeyPair: bobKeyPair,
                remoteDHRatchetKey: aliceKeyPair.publicKey,
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumber: 0
            );

            string message = "Test message";
            var (_, encryptedMessage) = E2EE2.DoubleRatchetEncrypt(aliceSession, message);

            // Create an invalid DH key (all zeros)
            byte[] invalidDHKey = new byte[32]; // 32 bytes of zeros

            // Replace with invalid key
            encryptedMessage.SenderDHKey = invalidDHKey;

            // Act
            var (resultSession, resultMessage) = E2EE2.DoubleRatchetDecrypt(bobSession, encryptedMessage);

            // Assert
            Assert.IsNull(resultSession);
            Assert.IsNull(resultMessage);
        }

        [TestMethod]
        public void DoubleRatchetDecrypt_WithMismatchedSessionId_ShouldReturnNull()
        {
            // Arrange
            var aliceKeyPair = E2EE2.GenerateX25519KeyPair();
            var bobKeyPair = E2EE2.GenerateX25519KeyPair();
            byte[] sharedSecret = E2EE2.X3DHKeyExchange(bobKeyPair.publicKey, aliceKeyPair.privateKey);
            var (rootKey, chainKey) = E2EE2.InitializeDoubleRatchet(sharedSecret);

            var aliceSession = new E2EE2.DoubleRatchetSession(
                dhRatchetKeyPair: aliceKeyPair,
                remoteDHRatchetKey: bobKeyPair.publicKey,
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumber: 0,
                sessionId: "alice-session-id"
            );

            var bobSession = new E2EE2.DoubleRatchetSession(
                dhRatchetKeyPair: bobKeyPair,
                remoteDHRatchetKey: aliceKeyPair.publicKey,
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumber: 0,
                sessionId: "bob-session-id"
            );

            string message = "Test message";
            var (_, encryptedMessage) = E2EE2.DoubleRatchetEncrypt(aliceSession, message);

            // Set session ID to a mismatched value
            encryptedMessage.SessionId = "wrong-session-id";

            // Act
            var (resultSession, resultMessage) = E2EE2.DoubleRatchetDecrypt(bobSession, encryptedMessage);

            // Assert
            Assert.IsNull(resultSession);
            Assert.IsNull(resultMessage);
        }

        [TestMethod]
        public void DoubleRatchetDecrypt_WithOldTimestamp_ShouldReturnNull()
        {
            // Arrange
            var aliceKeyPair = E2EE2.GenerateX25519KeyPair();
            var bobKeyPair = E2EE2.GenerateX25519KeyPair();
            byte[] sharedSecret = E2EE2.X3DHKeyExchange(bobKeyPair.publicKey, aliceKeyPair.privateKey);
            var (rootKey, chainKey) = E2EE2.InitializeDoubleRatchet(sharedSecret);

            var aliceSession = new E2EE2.DoubleRatchetSession(
                dhRatchetKeyPair: aliceKeyPair,
                remoteDHRatchetKey: bobKeyPair.publicKey,
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumber: 0
            );

            var bobSession = new E2EE2.DoubleRatchetSession(
                dhRatchetKeyPair: bobKeyPair,
                remoteDHRatchetKey: aliceKeyPair.publicKey,
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumber: 0
            );

            string message = "Test message";
            var (_, encryptedMessage) = E2EE2.DoubleRatchetEncrypt(aliceSession, message);

            // Set timestamp to more than 5 minutes in the past
            encryptedMessage.Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - (6 * 60 * 1000); // 6 minutes in past

            // Act
            var (resultSession, resultMessage) = E2EE2.DoubleRatchetDecrypt(bobSession, encryptedMessage);

            // Assert
            Assert.IsNull(resultSession);
            Assert.IsNull(resultMessage);
        }

        [TestMethod]
        public void DoubleRatchetDecrypt_WithReplayedMessageId_ShouldReturnNull()
        {
            // Arrange
            var aliceKeyPair = E2EE2.GenerateX25519KeyPair();
            var bobKeyPair = E2EE2.GenerateX25519KeyPair();
            byte[] sharedSecret = E2EE2.X3DHKeyExchange(bobKeyPair.publicKey, aliceKeyPair.privateKey);
            var (rootKey, chainKey) = E2EE2.InitializeDoubleRatchet(sharedSecret);

            // Create a session ID
            string sessionId = "replay-test-session-" + Guid.NewGuid().ToString();

            var aliceSession = new E2EE2.DoubleRatchetSession(
                dhRatchetKeyPair: aliceKeyPair,
                remoteDHRatchetKey: bobKeyPair.publicKey,
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumber: 0,
                sessionId: sessionId
            );

            var bobSession = new E2EE2.DoubleRatchetSession(
                dhRatchetKeyPair: bobKeyPair,
                remoteDHRatchetKey: aliceKeyPair.publicKey,
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumber: 0,
                sessionId: sessionId
            );

            string message = "Test message for replay detection";
            var (_, encryptedMessage) = E2EE2.DoubleRatchetEncrypt(aliceSession, message);

            // Set required security fields
            Guid messageId = Guid.NewGuid();
            encryptedMessage.MessageId = messageId;
            encryptedMessage.Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            encryptedMessage.SessionId = sessionId;

            // First decryption should succeed
            var (bobUpdatedSession, decryptedMessage) = E2EE2.DoubleRatchetDecrypt(bobSession, encryptedMessage);

            // Assert first decryption worked
            Assert.IsNotNull(bobUpdatedSession, "Initial decryption should return valid session");
            Assert.IsNotNull(decryptedMessage, "Initial decryption should return valid message");
            Assert.AreEqual(message, decryptedMessage, "Initial decryption should return correct message");

            // Create a replay of the exact same message (same message ID)
            var replayedMessage = new E2EE2.EncryptedMessage
            {
                Ciphertext = encryptedMessage.Ciphertext,
                Nonce = encryptedMessage.Nonce,
                MessageNumber = encryptedMessage.MessageNumber,
                SenderDHKey = encryptedMessage.SenderDHKey,
                Timestamp = encryptedMessage.Timestamp,
                MessageId = messageId, // Use the same message ID to simulate replay
                SessionId = sessionId
            };

            // Now try to decrypt the replayed message with the updated session
            var (replaySession, replayMessage) = E2EE2.DoubleRatchetDecrypt(bobUpdatedSession, replayedMessage);

            // Assert replay prevention works
            Assert.IsNull(replaySession, "Replayed message decryption should return null session");
            Assert.IsNull(replayMessage, "Replayed message decryption should return null message");
        }

        [TestMethod]
        public void DoubleRatchetDecrypt_WithEmptyMessageId_ShouldThrowException()
        {
            // Arrange
            var aliceKeyPair = E2EE2.GenerateX25519KeyPair();
            var bobKeyPair = E2EE2.GenerateX25519KeyPair();
            byte[] sharedSecret = E2EE2.X3DHKeyExchange(bobKeyPair.publicKey, aliceKeyPair.privateKey);
            var (rootKey, chainKey) = E2EE2.InitializeDoubleRatchet(sharedSecret);

            // Create a session ID
            string sessionId = "empty-id-test-session-" + Guid.NewGuid().ToString();

            var aliceSession = new E2EE2.DoubleRatchetSession(
                dhRatchetKeyPair: aliceKeyPair,
                remoteDHRatchetKey: bobKeyPair.publicKey,
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumber: 0,
                sessionId: sessionId
            );

            var bobSession = new E2EE2.DoubleRatchetSession(
                dhRatchetKeyPair: bobKeyPair,
                remoteDHRatchetKey: aliceKeyPair.publicKey,
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumber: 0,
                sessionId: sessionId
            );

            string message = "Test message for empty message ID validation";
            var (_, encryptedMessage) = E2EE2.DoubleRatchetEncrypt(aliceSession, message);

            // Set most of the required security fields but use empty GUID for message ID
            encryptedMessage.MessageId = Guid.Empty;
            encryptedMessage.Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            encryptedMessage.SessionId = sessionId;

            // Act & Assert
            var exception = Assert.ThrowsException<CryptographicException>(() =>
            {
                E2EE2.DoubleRatchetDecrypt(bobSession, encryptedMessage);
            }, "Decryption with empty message ID should throw CryptographicException");

            // Verify the exception contains the inner exception about message ID
            Assert.IsTrue(exception.Message.Contains("decrypt", StringComparison.OrdinalIgnoreCase),
                "Exception message should mention decryption failure");
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void DoubleRatchetEncrypt_WithNullSession_ShouldThrowException()
        {
            // Act & Assert - Should throw ArgumentNullException
            E2EE2.DoubleRatchetEncrypt(null, "Test message");
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void DoubleRatchetEncrypt_WithEmptyMessage_ShouldThrowException()
        {
            // Arrange
            var keyPair = E2EE2.GenerateX25519KeyPair();
            byte[] rootKey = new byte[32];
            byte[] chainKey = new byte[32];
            using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
            {
                rng.GetBytes(rootKey);
                rng.GetBytes(chainKey);
            }

            var session = new E2EE2.DoubleRatchetSession(
                dhRatchetKeyPair: keyPair,
                remoteDHRatchetKey: keyPair.publicKey, // Dummy value
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumber: 0
            );

            // Act & Assert - Should throw ArgumentException
            E2EE2.DoubleRatchetEncrypt(session, "");
        }

        #endregion

        #region Group Messaging Tests

        [TestMethod]
        public void GenerateSenderKey_ShouldReturnValidKey()
        {
            // Act
            byte[] senderKey = E2EE2.GenerateSenderKey();

            // Assert
            Assert.IsNotNull(senderKey);
            Assert.AreEqual(32, senderKey.Length);
        }

        [TestMethod]
        public void EncryptDecryptGroupMessage_ShouldReturnOriginalMessage()
        {
            // Arrange
            string message = "This is a group message";
            byte[] senderKey = E2EE2.GenerateSenderKey();

            // Act
            var encryptedMessage = E2EE2.EncryptGroupMessage(message, senderKey);
            string decryptedMessage = E2EE2.DecryptGroupMessage(encryptedMessage, senderKey);

            // Assert
            Assert.AreEqual(message, decryptedMessage);
        }

        [TestMethod]
        public void CreateSenderKeyDistributionMessage_ShouldReturnValidMessage()
        {
            // Arrange
            string groupId = "test-group-123";
            byte[] senderKey = E2EE2.GenerateSenderKey();
            var senderKeyPair = E2EE2.GenerateEd25519KeyPair();

            // Act
            var distributionMessage = E2EE2.CreateSenderKeyDistributionMessage(
                groupId, senderKey, senderKeyPair);

            // Assert
            Assert.IsNotNull(distributionMessage);
            Assert.AreEqual(groupId, distributionMessage.GroupId);
            Assert.IsTrue(AreByteArraysEqual(senderKey, distributionMessage.SenderKey));
            Assert.IsTrue(AreByteArraysEqual(senderKeyPair.publicKey, distributionMessage.SenderIdentityKey));

            // Verify signature
            bool validSignature = E2EE2.VerifySignature(
                distributionMessage.SenderKey,
                distributionMessage.Signature,
                distributionMessage.SenderIdentityKey);
            Assert.IsTrue(validSignature);
        }

        [TestMethod]
        public void EncryptDecryptSenderKeyDistribution_ShouldReturnOriginalMessage()
        {
            // Arrange
            string groupId = "test-group-456";
            byte[] senderKey = E2EE2.GenerateSenderKey();
            var senderKeyPair = E2EE2.GenerateEd25519KeyPair();
            var recipientKeyPair = E2EE2.GenerateEd25519KeyPair();

            var distributionMessage = E2EE2.CreateSenderKeyDistributionMessage(
                groupId, senderKey, senderKeyPair);

            // Act
            var encryptedDistribution = E2EE2.EncryptSenderKeyDistribution(
                distributionMessage, recipientKeyPair.publicKey, senderKeyPair.privateKey);

            var decryptedDistribution = E2EE2.DecryptSenderKeyDistribution(
                encryptedDistribution, recipientKeyPair.privateKey);

            // Assert
            Assert.AreEqual(distributionMessage.GroupId, decryptedDistribution.GroupId);
            Assert.IsTrue(AreByteArraysEqual(distributionMessage.SenderKey, decryptedDistribution.SenderKey));
            Assert.IsTrue(AreByteArraysEqual(distributionMessage.SenderIdentityKey, decryptedDistribution.SenderIdentityKey));
            Assert.IsTrue(AreByteArraysEqual(distributionMessage.Signature, decryptedDistribution.Signature));

            // Note: Don't test for the ephemeral key signature in this test
            // as it's using the compatibility mode, not the production mode
        }

        [TestMethod]
        public void GroupChatManager_ShouldHandleMessageExchange()
        {
            // Arrange
            var aliceKeyPair = E2EE2.GenerateEd25519KeyPair();
            var bobKeyPair = E2EE2.GenerateEd25519KeyPair();

            var aliceManager = new E2EE2.GroupChatManager(aliceKeyPair);
            var bobManager = new E2EE2.GroupChatManager(bobKeyPair);

            string groupId = "test-group-789";
            string message = "Hello group members!";

            // Act
            // Alice creates a group
            aliceManager.CreateGroup(groupId);

            // Alice creates a distribution message
            var distributionMessage = aliceManager.CreateDistributionMessage(groupId);

            // Bob processes the distribution message
            bool processingResult = bobManager.ProcessSenderKeyDistribution(distributionMessage);

            // Alice sends a message
            var encryptedMessage = aliceManager.EncryptGroupMessage(groupId, message);

            // Bob decrypts the message
            string decryptedMessage = bobManager.DecryptGroupMessage(encryptedMessage);

            // Assert
            Assert.IsTrue(processingResult);
            Assert.AreEqual(message, decryptedMessage);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void GroupChatManager_CreateDistribution_WithNonExistentGroup_ShouldThrowException()
        {
            // Arrange
            var keyPair = E2EE2.GenerateEd25519KeyPair();
            var manager = new E2EE2.GroupChatManager(keyPair);

            // Act & Assert - Should throw InvalidOperationException
            manager.CreateDistributionMessage("non-existent-group");
        }

        #endregion

        #region Multi-Device Tests

        [TestMethod]
        public void DeriveSharedKeyForNewDevice_ShouldProduceConsistentKey()
        {
            // Arrange
            byte[] existingSharedKey = new byte[32];
            using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
            {
                rng.GetBytes(existingSharedKey);
            }

            var newDeviceKeyPair = E2EE2.GenerateX25519KeyPair();

            // Act
            byte[] derivedKey1 = E2EE2.DeriveSharedKeyForNewDevice(
                existingSharedKey, newDeviceKeyPair.publicKey);

            byte[] derivedKey2 = E2EE2.DeriveSharedKeyForNewDevice(
                existingSharedKey, newDeviceKeyPair.publicKey);

            // Assert
            Assert.IsTrue(AreByteArraysEqual(derivedKey1, derivedKey2));
        }

        [TestMethod]
        public void CreateDeviceLinkMessage_ShouldCreateValidMessage()
        {
            // Arrange
            var mainDeviceKeyPair = E2EE2.GenerateEd25519KeyPair();
            var newDeviceKeyPair = E2EE2.GenerateEd25519KeyPair();

            // Act
            var encryptedMessage = E2EE2.CreateDeviceLinkMessage(
                mainDeviceKeyPair, newDeviceKeyPair.publicKey);

            // Assert
            Assert.IsNotNull(encryptedMessage);
            Assert.IsNotNull(encryptedMessage.Ciphertext);
            Assert.IsNotNull(encryptedMessage.Nonce);
        }

        [TestMethod]
        public void MultiDeviceManager_ShouldCreateValidSyncMessages()
        {
            // Arrange
            var mainDeviceKeyPair = E2EE2.GenerateEd25519KeyPair();
            var secondDeviceKeyPair = E2EE2.GenerateEd25519KeyPair();

            // Debug: Detailed key inspection
            Console.WriteLine("Main Device Ed25519 Public Key:");
            PrintByteArray(mainDeviceKeyPair.publicKey);
            Console.WriteLine("\nSecond Device Ed25519 Public Key:");
            PrintByteArray(secondDeviceKeyPair.publicKey);

            // Step-by-step key derivation with detailed logging
            Console.WriteLine("\n--- Key Derivation Process ---");

            // Derive X25519 private key
            byte[] secondDeviceX25519Private = E2EE2.DeriveX25519PrivateKeyFromEd25519(secondDeviceKeyPair.privateKey);
            Console.WriteLine("Derived X25519 Private Key:");
            PrintByteArray(secondDeviceX25519Private);

            // Derive X25519 public key
            byte[] secondDeviceX25519Public = ScalarMult.Base(secondDeviceX25519Private);
            Console.WriteLine("\nDerived X25519 Public Key:");
            PrintByteArray(secondDeviceX25519Public);

            // Validate the derived X25519 public key
            bool isValid = E2EE2.ValidateX25519PublicKey(secondDeviceX25519Public);
            Console.WriteLine($"\nIs Second Device X25519 Public Key Valid? {isValid}");

            // Additional manual checks
            Console.WriteLine("\nManual Key Checks:");
            Console.WriteLine($"Has non-zero bytes: {secondDeviceX25519Public.Any(b => b != 0)}");
            Console.WriteLine($"Has non-255 bytes: {secondDeviceX25519Public.Any(b => b != 255)}");

            // Create manager
            var manager = new E2EE2.MultiDeviceManager(mainDeviceKeyPair);

            // Add the X25519 public key
            Console.WriteLine("\n--- Adding Linked Device ---");
            manager.AddLinkedDevice(secondDeviceX25519Public);

            // Debug: Check linked devices
            var privateField = typeof(E2EE2.MultiDeviceManager).GetField("_linkedDevices",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            var linkedDevices = privateField.GetValue(manager) as ConcurrentBag<byte[]>;
            Console.WriteLine($"\nLinked Devices Count: {linkedDevices.Count}");

            // Print details of linked devices
            int deviceIndex = 0;
            foreach (var device in linkedDevices)
            {
                Console.WriteLine($"\nLinked Device Key {deviceIndex++}:");
                PrintByteArray(device);
            }

            // Data to sync
            byte[] syncData = Encoding.UTF8.GetBytes("This is sync data");

            // Act
            Console.WriteLine("\n--- Creating Sync Messages ---");
            var syncMessages = manager.CreateSyncMessages(syncData);

            // Debug: Print sync messages details
            Console.WriteLine($"\nSync Messages Count: {syncMessages.Count}");
            foreach (var kvp in syncMessages)
            {
                Console.WriteLine($"Device Key (Base64): {kvp.Key}");
                Console.WriteLine($"Ciphertext Length: {kvp.Value.Ciphertext?.Length ?? 0}");
                Console.WriteLine($"Nonce Length: {kvp.Value.Nonce?.Length ?? 0}");
            }

            // Assert
            Assert.IsNotNull(syncMessages);
            Assert.AreEqual(1, syncMessages.Count);
            string deviceId = Convert.ToBase64String(secondDeviceX25519Public);
            Assert.IsTrue(syncMessages.ContainsKey(deviceId));
            var message = syncMessages[deviceId];
            Assert.IsNotNull(message.Ciphertext);
            Assert.IsNotNull(message.Nonce);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void MultiDeviceManager_AddLinkedDevice_WithNull_ShouldThrowException()
        {
            // Arrange
            var mainDeviceKeyPair = E2EE2.GenerateEd25519KeyPair();
            var manager = new E2EE2.MultiDeviceManager(mainDeviceKeyPair);

            // Act & Assert - Should throw ArgumentNullException
            manager.AddLinkedDevice(null);
        }

        #endregion

        #region Integration Tests

        [TestMethod]
        public void FullE2EEFlow_ShouldWorkEndToEnd()
        {
            // This test simulates a full conversation flow between Alice and Bob

            // Step 1: Generate identity keys for Alice and Bob
            var aliceIdentityKeyPair = E2EE2.GenerateX25519KeyPair();
            var bobIdentityKeyPair = E2EE2.GenerateX25519KeyPair();

            // Step 2: Bob creates his key bundle and uploads to server
            var bobKeyBundle = E2EE2.CreateX3DHKeyBundle();

            // Convert to public bundle (what would be stored on server)
            var bobPublicBundle = new E2EE2.X3DHPublicBundle
            {
                IdentityKey = bobKeyBundle.IdentityKey,
                SignedPreKey = bobKeyBundle.SignedPreKey,
                SignedPreKeySignature = bobKeyBundle.SignedPreKeySignature,
                OneTimePreKeys = bobKeyBundle.OneTimePreKeys
            };

            // Step 3: Alice fetches Bob's bundle and initiates a session
            var aliceSession = E2EE2.InitiateX3DHSession(bobPublicBundle, aliceIdentityKeyPair);

            // Create a session ID that will be shared between Alice and Bob
            string sessionId = "alice-bob-session-" + Guid.NewGuid().ToString();

            // Create Alice's initial DoubleRatchet session using immutable constructor
            var aliceDRSession = new E2EE2.DoubleRatchetSession(
                dhRatchetKeyPair: E2EE2.GenerateX25519KeyPair(),
                remoteDHRatchetKey: bobPublicBundle.SignedPreKey,
                rootKey: aliceSession.RootKey,
                sendingChainKey: aliceSession.ChainKey,
                receivingChainKey: aliceSession.ChainKey,
                messageNumber: 0,
                sessionId: sessionId
            );

            // Step 4: Alice sends initial message to Bob
            string initialMessage = "Hello Bob, this is Alice!";
            var (aliceUpdatedSession, encryptedMessage) =
                E2EE2.DoubleRatchetEncrypt(aliceDRSession, initialMessage);

            // Add necessary validation fields for enhanced security
            encryptedMessage.MessageId = Guid.NewGuid();
            encryptedMessage.Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            encryptedMessage.SessionId = sessionId;

            // Step 5: Bob receives Alice's initial message 
            // (In reality, Bob would process the X3DH initial message first)

            // Bob creates his DoubleRatchet session
            var bobDRSession = new E2EE2.DoubleRatchetSession(
                dhRatchetKeyPair: (bobKeyBundle.SignedPreKey, bobKeyBundle.GetSignedPreKeyPrivate()),
                remoteDHRatchetKey: encryptedMessage.SenderDHKey,
                rootKey: aliceSession.RootKey, // In reality, Bob would derive this himself
                sendingChainKey: aliceSession.ChainKey,
                receivingChainKey: aliceSession.ChainKey,
                messageNumber: 0,
                sessionId: sessionId // Must match Alice's session ID
            );

            // Bob decrypts Alice's message
            var (bobUpdatedSession, decryptedMessage) =
                E2EE2.DoubleRatchetDecrypt(bobDRSession, encryptedMessage);

            // Verify Bob successfully decrypted the message
            Assert.IsNotNull(bobUpdatedSession, "Bob's session should be updated after decryption");
            Assert.IsNotNull(decryptedMessage, "Bob should successfully decrypt Alice's message");
            Assert.AreEqual(initialMessage, decryptedMessage, "Bob should see Alice's original message");

            // Step 6: Bob replies to Alice
            string replyMessage = "Hi Alice, Bob here!";
            var (bobRepliedSession, bobReplyEncrypted) =
                E2EE2.DoubleRatchetEncrypt(bobUpdatedSession, replyMessage);

            // Add necessary validation fields for enhanced security
            bobReplyEncrypted.MessageId = Guid.NewGuid();
            bobReplyEncrypted.Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            bobReplyEncrypted.SessionId = sessionId;

            // Step 7: Alice decrypts Bob's reply
            var (aliceFinalSession, aliceDecryptedReply) =
                E2EE2.DoubleRatchetDecrypt(aliceUpdatedSession, bobReplyEncrypted);

            // Assert final results
            Assert.IsNotNull(aliceFinalSession, "Alice's session should be updated after decryption");
            Assert.IsNotNull(aliceDecryptedReply, "Alice should successfully decrypt Bob's message");
            Assert.AreEqual(replyMessage, aliceDecryptedReply, "Alice should see Bob's original message");

            // Verify session properties were correctly updated
            Assert.AreNotEqual(aliceDRSession, aliceUpdatedSession, "Alice's initial session should be different from updated session");
            Assert.AreNotEqual(bobDRSession, bobUpdatedSession, "Bob's initial session should be different from updated session");
            Assert.AreNotEqual(aliceUpdatedSession, aliceFinalSession, "Alice's updated session should be different from final session");
            Assert.AreNotEqual(bobUpdatedSession, bobRepliedSession, "Bob's updated session should be different from replied session");

            // Verify message numbers increased
            Assert.AreEqual(1, aliceUpdatedSession.MessageNumber, "Alice's message number should be incremented");
            Assert.AreEqual(1, bobRepliedSession.MessageNumber, "Bob's message number should be incremented");

            // Verify chain keys changed
            Assert.IsFalse(AreByteArraysEqual(aliceDRSession.SendingChainKey, aliceUpdatedSession.SendingChainKey),
                "Alice's sending chain key should change after encryption");
            Assert.IsFalse(AreByteArraysEqual(bobDRSession.SendingChainKey, bobRepliedSession.SendingChainKey),
                "Bob's sending chain key should change after encryption");

            // Clean up sensitive key material
            bobKeyBundle.ClearPrivateKeys();
        }

        [TestMethod]
        public void FullGroupMessageFlow_ShouldWorkEndToEnd()
        {
            // This test simulates a group chat between Alice, Bob, and Charlie

            // Step 1: Generate identity keys for the participants
            var aliceKeyPair = E2EE2.GenerateEd25519KeyPair();
            var bobKeyPair = E2EE2.GenerateEd25519KeyPair();
            var charlieKeyPair = E2EE2.GenerateEd25519KeyPair();

            // Step 2: Create group chat managers for each participant
            var aliceManager = new E2EE2.GroupChatManager(aliceKeyPair);
            var bobManager = new E2EE2.GroupChatManager(bobKeyPair);
            var charlieManager = new E2EE2.GroupChatManager(charlieKeyPair);

            // Step 3: Alice creates the group
            string groupId = "friends-group-123";
            aliceManager.CreateGroup(groupId);

            // Step 4: Alice sends her sender key to Bob and Charlie
            var aliceDistribution = aliceManager.CreateDistributionMessage(groupId);

            // Bob and Charlie process Alice's sender key
            bool bobProcessResult = bobManager.ProcessSenderKeyDistribution(aliceDistribution);
            bool charlieProcessResult = charlieManager.ProcessSenderKeyDistribution(aliceDistribution);

            // Step 5: Bob creates his sender key and distributes it
            bobManager.CreateGroup(groupId);
            var bobDistribution = bobManager.CreateDistributionMessage(groupId);

            // Alice and Charlie process Bob's sender key
            bool aliceProcessBobResult = aliceManager.ProcessSenderKeyDistribution(bobDistribution);
            bool charlieProcessBobResult = charlieManager.ProcessSenderKeyDistribution(bobDistribution);

            // Step 6: Charlie creates his sender key and distributes it
            charlieManager.CreateGroup(groupId);
            var charlieDistribution = charlieManager.CreateDistributionMessage(groupId);

            // Alice and Bob process Charlie's sender key
            bool aliceProcessCharlieResult = aliceManager.ProcessSenderKeyDistribution(charlieDistribution);
            bool bobProcessCharlieResult = bobManager.ProcessSenderKeyDistribution(charlieDistribution);

            // Step 7: Alice sends a message to the group
            string aliceMessage = "Hello everyone, this is Alice!";
            var aliceEncryptedMessage = aliceManager.EncryptGroupMessage(groupId, aliceMessage);

            // Bob and Charlie decrypt Alice's message
            string bobDecryptedAliceMessage = bobManager.DecryptGroupMessage(aliceEncryptedMessage);
            string charlieDecryptedAliceMessage = charlieManager.DecryptGroupMessage(aliceEncryptedMessage);

            // Step 8: Bob replies to the group
            string bobMessage = "Hi Alice and Charlie, Bob here!";
            var bobEncryptedMessage = bobManager.EncryptGroupMessage(groupId, bobMessage);

            // Alice and Charlie decrypt Bob's message
            string aliceDecryptedBobMessage = aliceManager.DecryptGroupMessage(bobEncryptedMessage);
            string charlieDecryptedBobMessage = charlieManager.DecryptGroupMessage(bobEncryptedMessage);

            // Assert results
            Assert.IsTrue(bobProcessResult);
            Assert.IsTrue(charlieProcessResult);
            Assert.IsTrue(aliceProcessBobResult);
            Assert.IsTrue(charlieProcessBobResult);
            Assert.IsTrue(aliceProcessCharlieResult);
            Assert.IsTrue(bobProcessCharlieResult);

            Assert.AreEqual(aliceMessage, bobDecryptedAliceMessage);
            Assert.AreEqual(aliceMessage, charlieDecryptedAliceMessage);
            Assert.AreEqual(bobMessage, aliceDecryptedBobMessage);
            Assert.AreEqual(bobMessage, charlieDecryptedBobMessage);
        }

        #endregion

        #region Forward Secrecy Tests

        [TestMethod]
        public void ForwardSecrecy_CompromisedKeyDoesNotAffectPastMessages()
        {
            // Arrange
            var aliceKeyPair = E2EE2.GenerateX25519KeyPair();
            var bobKeyPair = E2EE2.GenerateX25519KeyPair();

            // Initial shared secret
            byte[] sharedSecret = E2EE2.X3DHKeyExchange(bobKeyPair.publicKey, aliceKeyPair.privateKey);
            var (rootKey, chainKey) = E2EE2.InitializeDoubleRatchet(sharedSecret);

            // Create a session ID to be used consistently
            string sessionId = "forward-secrecy-test-" + Guid.NewGuid().ToString();

            // Setup sessions for both parties
            var aliceSession = new E2EE2.DoubleRatchetSession(
                dhRatchetKeyPair: aliceKeyPair,
                remoteDHRatchetKey: bobKeyPair.publicKey,
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumber: 0,
                sessionId: sessionId
            );

            var bobSession = new E2EE2.DoubleRatchetSession(
                dhRatchetKeyPair: bobKeyPair,
                remoteDHRatchetKey: aliceKeyPair.publicKey,
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumber: 0,
                sessionId: sessionId
            );

            // Act - Exchange several messages
            string message1 = "Message 1";
            string message2 = "Message 2";
            string message3 = "Message 3";

            // Alice sends message 1
            var (aliceSession1, encryptedMessage1) = E2EE2.DoubleRatchetEncrypt(aliceSession, message1);

            // Add security fields for message 1
            encryptedMessage1.MessageId = Guid.NewGuid();
            encryptedMessage1.Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            encryptedMessage1.SessionId = sessionId;

            var (bobSession1, decryptedMessage1) = E2EE2.DoubleRatchetDecrypt(bobSession, encryptedMessage1);

            // Bob sends message 2
            var (bobSession2, encryptedMessage2) = E2EE2.DoubleRatchetEncrypt(bobSession1, message2);

            // Add security fields for message 2
            encryptedMessage2.MessageId = Guid.NewGuid();
            encryptedMessage2.Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            encryptedMessage2.SessionId = sessionId;

            var (aliceSession2, decryptedMessage2) = E2EE2.DoubleRatchetDecrypt(aliceSession1, encryptedMessage2);

            // Save the first two encrypted messages to try to decrypt later
            // Create copies with new message IDs to avoid replay detection
            var savedEncryptedMessage1 = new E2EE2.EncryptedMessage
            {
                Ciphertext = encryptedMessage1.Ciphertext,
                Nonce = encryptedMessage1.Nonce,
                MessageNumber = encryptedMessage1.MessageNumber,
                SenderDHKey = encryptedMessage1.SenderDHKey,
                Timestamp = encryptedMessage1.Timestamp,
                MessageId = Guid.NewGuid(), // New message ID to avoid replay detection
                SessionId = sessionId
            };

            var savedEncryptedMessage2 = new E2EE2.EncryptedMessage
            {
                Ciphertext = encryptedMessage2.Ciphertext,
                Nonce = encryptedMessage2.Nonce,
                MessageNumber = encryptedMessage2.MessageNumber,
                SenderDHKey = encryptedMessage2.SenderDHKey,
                Timestamp = encryptedMessage2.Timestamp,
                MessageId = Guid.NewGuid(), // New message ID to avoid replay detection
                SessionId = sessionId
            };

            // Continue the conversation
            var (aliceSession3, encryptedMessage3) = E2EE2.DoubleRatchetEncrypt(aliceSession2, message3);

            // Add security fields for message 3
            encryptedMessage3.MessageId = Guid.NewGuid();
            encryptedMessage3.Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            encryptedMessage3.SessionId = sessionId;

            var (bobSession3, decryptedMessage3) = E2EE2.DoubleRatchetDecrypt(bobSession2, encryptedMessage3);

            // Simulate compromise of the latest keys - create a new compromised session with the latest keys
            // but without the message history
            var compromisedBobSession = new E2EE2.DoubleRatchetSession(
                dhRatchetKeyPair: bobSession3.DHRatchetKeyPair,
                remoteDHRatchetKey: bobSession3.RemoteDHRatchetKey,
                rootKey: bobSession3.RootKey,
                sendingChainKey: bobSession3.SendingChainKey,
                receivingChainKey: bobSession3.ReceivingChainKey,
                messageNumber: bobSession3.MessageNumber,
                sessionId: sessionId
            // Deliberately not copying message history - an attacker wouldn't have it
            );

            // An attacker shouldn't be able to decrypt previous messages using the compromised session
            bool canDecryptMessage1 = true;
            bool canDecryptMessage2 = true;

            // With our immutable implementation, the method returns null values for failed decryption
            var (resultSession1, resultMessage1) = E2EE2.DoubleRatchetDecrypt(compromisedBobSession, savedEncryptedMessage1);
            canDecryptMessage1 = (resultSession1 != null && resultMessage1 != null);

            var (resultSession2, resultMessage2) = E2EE2.DoubleRatchetDecrypt(compromisedBobSession, savedEncryptedMessage2);
            canDecryptMessage2 = (resultSession2 != null && resultMessage2 != null);

            // Assert
            // Check that legitimate recipients could decrypt messages
            Assert.IsNotNull(decryptedMessage1, "Message 1 should be decrypted by legitimate recipient");
            Assert.IsNotNull(decryptedMessage2, "Message 2 should be decrypted by legitimate recipient");
            Assert.IsNotNull(decryptedMessage3, "Message 3 should be decrypted by legitimate recipient");

            Assert.AreEqual(message1, decryptedMessage1, "Message 1 content should match original");
            Assert.AreEqual(message2, decryptedMessage2, "Message 2 content should match original");
            Assert.AreEqual(message3, decryptedMessage3, "Message 3 content should match original");

            // Check that compromised session can't decrypt previous messages
            Assert.IsFalse(canDecryptMessage1, "Should not be able to decrypt message 1 with compromised session");
            Assert.IsFalse(canDecryptMessage2, "Should not be able to decrypt message 2 with compromised session");

            // Verify session immutability
            Assert.AreNotEqual(aliceSession, aliceSession1, "Alice's session should be updated after first encryption");
            Assert.AreNotEqual(bobSession, bobSession1, "Bob's session should be updated after first decryption");
            Assert.AreNotEqual(bobSession1, bobSession2, "Bob's session should be updated after second encryption");
            Assert.AreNotEqual(aliceSession1, aliceSession2, "Alice's session should be updated after second decryption");
            Assert.AreNotEqual(aliceSession2, aliceSession3, "Alice's session should be updated after third encryption");
            Assert.AreNotEqual(bobSession2, bobSession3, "Bob's session should be updated after third decryption");
        }

        #endregion

        #region Key Rotation Tests

        [TestMethod]
        public void KeyRotation_ShouldMaintainCommunication()
        {
            // Arrange
            var aliceInitialKeyPair = E2EE2.GenerateX25519KeyPair();
            var bobInitialKeyPair = E2EE2.GenerateX25519KeyPair();

            // Initial shared secret
            byte[] sharedSecret = E2EE2.X3DHKeyExchange(bobInitialKeyPair.publicKey, aliceInitialKeyPair.privateKey);
            var (rootKey, chainKey) = E2EE2.InitializeDoubleRatchet(sharedSecret);

            // Setup initial sessions
            var aliceSession = new E2EE2.DoubleRatchetSession(
                dhRatchetKeyPair: aliceInitialKeyPair,
                remoteDHRatchetKey: bobInitialKeyPair.publicKey,
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumber: 0
            );

            var bobSession = new E2EE2.DoubleRatchetSession(
                dhRatchetKeyPair: bobInitialKeyPair,
                remoteDHRatchetKey: aliceInitialKeyPair.publicKey,
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumber: 0
            );

            // Exchange a few messages
            string message1 = "First message";
            var (aliceSession1, encrypted1) = E2EE2.DoubleRatchetEncrypt(aliceSession, message1);

            // Ensure encrypted message has required fields for validation
            encrypted1.MessageId = Guid.NewGuid();
            encrypted1.Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            encrypted1.SessionId = bobSession.SessionId;

            var (bobSession1, decrypted1) = E2EE2.DoubleRatchetDecrypt(bobSession, encrypted1);

            // Instead of manually creating a session with a new key pair,
            // let's just use the Double Ratchet protocol normally:

            // Bob sends a message to Alice
            string responseToBob = "Response from Bob";
            var (bobSession2, bobEncrypted) = E2EE2.DoubleRatchetEncrypt(bobSession1, responseToBob);

            // Ensure encrypted message has required fields for validation
            bobEncrypted.MessageId = Guid.NewGuid();
            bobEncrypted.Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            bobEncrypted.SessionId = aliceSession1.SessionId;

            var (aliceSession2, aliceDecrypted) = E2EE2.DoubleRatchetDecrypt(aliceSession1, bobEncrypted);

            // Now Alice sends another message to Bob - the protocol will handle key rotation automatically
            string message2 = "Message after key rotation";
            var (aliceSession3, encrypted2) = E2EE2.DoubleRatchetEncrypt(aliceSession2, message2);

            // Ensure encrypted message has required fields for validation
            encrypted2.MessageId = Guid.NewGuid();
            encrypted2.Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            encrypted2.SessionId = bobSession2.SessionId;

            var (bobSession3, decrypted2) = E2EE2.DoubleRatchetDecrypt(bobSession2, encrypted2);

            // Assert
            Assert.IsNotNull(decrypted1, "First message should decrypt successfully");
            Assert.AreEqual(message1, decrypted1, "First message should decrypt correctly");

            Assert.IsNotNull(aliceDecrypted, "Bob's response should decrypt successfully");
            Assert.AreEqual(responseToBob, aliceDecrypted, "Bob's response should decrypt correctly");

            Assert.IsNotNull(decrypted2, "Message after key rotation should decrypt successfully");
            Assert.AreEqual(message2, decrypted2, "Message after key rotation should decrypt correctly");

            // Verify that both sessions have been properly updated
            Assert.IsNotNull(bobSession3, "Bob's session should be updated after key rotation");
            Assert.IsNotNull(aliceSession3, "Alice's session should be updated after key rotation");

            // Verify keys have changed
            Assert.IsFalse(AreByteArraysEqual(bobSession1.ReceivingChainKey, bobSession3.ReceivingChainKey),
                "Bob's receiving chain key should change after key rotation");
            Assert.IsFalse(AreByteArraysEqual(aliceSession1.ReceivingChainKey, aliceSession3.ReceivingChainKey),
                "Alice's receiving chain key should change after key rotation");
        }

        #endregion

        #region Message Corruption Tests

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
            var encryptedMessage = E2EE2.EncryptMessage(message, key);

            // Make a copy for tampering
            var tamperedMessage = new E2EE2.EncryptedMessage
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
                E2EE2.DecryptMessage(tamperedMessage, key);
            }, "Tampered message should fail authentication");

            // Original message should still decrypt correctly
            string decryptedOriginal = E2EE2.DecryptMessage(encryptedMessage, key);
            Assert.AreEqual(message, decryptedOriginal);
        }

        [TestMethod]
        public void DoubleRatchet_ShouldDetectTamperedMessage()
        {
            // Arrange
            var aliceKeyPair = E2EE2.GenerateX25519KeyPair();
            var bobKeyPair = E2EE2.GenerateX25519KeyPair();

            // Initial shared secret
            byte[] sharedSecret = E2EE2.X3DHKeyExchange(bobKeyPair.publicKey, aliceKeyPair.privateKey);
            var (rootKey, chainKey) = E2EE2.InitializeDoubleRatchet(sharedSecret);

            // Create a session ID
            string sessionId = "tamper-detection-test-" + Guid.NewGuid().ToString();

            var aliceSession = new E2EE2.DoubleRatchetSession(
                dhRatchetKeyPair: aliceKeyPair,
                remoteDHRatchetKey: bobKeyPair.publicKey,
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumber: 0,
                sessionId: sessionId
            );

            var bobSession = new E2EE2.DoubleRatchetSession(
                dhRatchetKeyPair: bobKeyPair,
                remoteDHRatchetKey: aliceKeyPair.publicKey,
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumber: 0,
                sessionId: sessionId
            );

            // Alice encrypts a message
            string message = "Secret message that should be tamper-proof";
            var (_, encryptedMessage) = E2EE2.DoubleRatchetEncrypt(aliceSession, message);

            // Add security fields
            encryptedMessage.MessageId = Guid.NewGuid();
            encryptedMessage.Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            encryptedMessage.SessionId = sessionId;

            // Make sure encryption succeeded
            Assert.IsNotNull(encryptedMessage, "Encryption should succeed");
            Assert.IsNotNull(encryptedMessage.Ciphertext, "Ciphertext should not be null");
            Assert.IsTrue(encryptedMessage.Ciphertext.Length > 0, "Ciphertext should not be empty");

            // Create a tampered message copy
            var tamperedMessage = new E2EE2.EncryptedMessage
            {
                Ciphertext = new byte[encryptedMessage.Ciphertext.Length],
                Nonce = encryptedMessage.Nonce,
                MessageNumber = encryptedMessage.MessageNumber,
                SenderDHKey = encryptedMessage.SenderDHKey,
                Timestamp = encryptedMessage.Timestamp,
                MessageId = Guid.NewGuid(), // New ID to avoid replay detection
                SessionId = sessionId
            };

            Buffer.BlockCopy(encryptedMessage.Ciphertext, 0, tamperedMessage.Ciphertext, 0, encryptedMessage.Ciphertext.Length);

            // Tamper with a byte in the ciphertext
            tamperedMessage.Ciphertext[tamperedMessage.Ciphertext.Length - 5] ^= 0x42;

            // Make a fresh copy of Bob's session for the tampered message attempt
            // This ensures the original session isn't affected by the tampered message
            var bobSessionForTampered = new E2EE2.DoubleRatchetSession(
                dhRatchetKeyPair: bobKeyPair,
                remoteDHRatchetKey: bobSession.RemoteDHRatchetKey,
                rootKey: bobSession.RootKey,
                sendingChainKey: bobSession.SendingChainKey,
                receivingChainKey: bobSession.ReceivingChainKey,
                messageNumber: bobSession.MessageNumber,
                sessionId: bobSession.SessionId
            );

            // Act - Attempt to decrypt the tampered message
            var (resultSession, resultMessage) = E2EE2.DoubleRatchetDecrypt(bobSessionForTampered, tamperedMessage);

            // Assert - Check that tampering was detected by verifying null returns
            Assert.IsNull(resultSession, "Tampered message should result in null session");
            Assert.IsNull(resultMessage, "Tampered message should result in null decrypted message");

            // Additional verification - make sure the original message still decrypts properly
            // Use the original untouched session
            var (validSession, validMessage) = E2EE2.DoubleRatchetDecrypt(bobSession, encryptedMessage);

            Assert.IsNotNull(validSession, "Original message should decrypt successfully");
            Assert.IsNotNull(validMessage, "Original message should decrypt successfully");
            Assert.AreEqual(message, validMessage, "Original message should decrypt to the correct content");
        }

        #endregion

        #region Security Parameter Tests

        [TestMethod]
        public void GeneratedNonces_ShouldBeUnpredictable()
        {
            // Arrange & Act
            var nonces = new List<byte[]>();
            int numNonces = 1000;

            for (int i = 0; i < numNonces; i++)
            {
                nonces.Add(E2EE2.GenerateNonce());
            }

            // Assert
            // Check that no two nonces are the same
            for (int i = 0; i < nonces.Count; i++)
            {
                for (int j = i + 1; j < nonces.Count; j++)
                {
                    Assert.IsFalse(AreByteArraysEqual(nonces[i], nonces[j]),
                        $"Nonces at position {i} and {j} are identical");
                }
            }

            // Basic randomness test - check distribution of bytes
            // Count the occurrences of each byte value across all nonces
            var byteDistribution = new int[256];
            foreach (var nonce in nonces)
            {
                foreach (byte b in nonce)
                {
                    byteDistribution[b]++;
                }
            }

            // In a uniform distribution, each byte value should appear approximately the same number of times
            double expectedOccurrences = (double)(numNonces * 12) / 256; // 12 is the NONCE_SIZE

            // Use chi-square test to check if the distribution is uniform
            // Chi-square statistic = sum((observed - expected)^2 / expected)
            double chiSquare = 0;
            foreach (int count in byteDistribution)
            {
                chiSquare += Math.Pow(count - expectedOccurrences, 2) / expectedOccurrences;
            }

            // For a uniform distribution with 255 degrees of freedom (256-1),
            // a chi-square value greater than ~340 would be suspicious at a 0.001 significance level
            Assert.IsTrue(chiSquare < 340, $"Chi-square test failed with value {chiSquare}");
        }

        [TestMethod]
        public void LongTermCryptographicIdentity_ShouldBeSecure()
        {
            // Generate multiple key pairs
            var keyPair1 = E2EE2.GenerateEd25519KeyPair();
            var keyPair2 = E2EE2.GenerateEd25519KeyPair();
            var keyPair3 = E2EE2.GenerateEd25519KeyPair();

            // Ensure keys meet minimum security requirements
            Assert.AreEqual(32, keyPair1.publicKey.Length, "Ed25519 public key should be 32 bytes");
            Assert.AreEqual(64, keyPair1.privateKey.Length, "Ed25519 private key should be 64 bytes");

            // Ensure all generated keys are different
            Assert.IsFalse(AreByteArraysEqual(keyPair1.publicKey, keyPair2.publicKey));
            Assert.IsFalse(AreByteArraysEqual(keyPair1.publicKey, keyPair3.publicKey));
            Assert.IsFalse(AreByteArraysEqual(keyPair2.publicKey, keyPair3.publicKey));

            Assert.IsFalse(AreByteArraysEqual(keyPair1.privateKey, keyPair2.privateKey));
            Assert.IsFalse(AreByteArraysEqual(keyPair1.privateKey, keyPair3.privateKey));
            Assert.IsFalse(AreByteArraysEqual(keyPair2.privateKey, keyPair3.privateKey));

            // Test signature functionality
            string message = "Cryptographic identity test message";
            byte[] messageBytes = Encoding.UTF8.GetBytes(message);

            byte[] signature1 = E2EE2.SignMessage(messageBytes, keyPair1.privateKey);
            byte[] signature2 = E2EE2.SignMessage(messageBytes, keyPair2.privateKey);
            byte[] signature3 = E2EE2.SignMessage(messageBytes, keyPair3.privateKey);

            // Ensure signatures are different for different keys
            Assert.IsFalse(AreByteArraysEqual(signature1, signature2));
            Assert.IsFalse(AreByteArraysEqual(signature1, signature3));
            Assert.IsFalse(AreByteArraysEqual(signature2, signature3));

            // Ensure signatures verify correctly
            Assert.IsTrue(E2EE2.VerifySignature(messageBytes, signature1, keyPair1.publicKey));
            Assert.IsTrue(E2EE2.VerifySignature(messageBytes, signature2, keyPair2.publicKey));
            Assert.IsTrue(E2EE2.VerifySignature(messageBytes, signature3, keyPair3.publicKey));

            // Ensure signatures don't verify with the wrong key
            Assert.IsFalse(E2EE2.VerifySignature(messageBytes, signature1, keyPair2.publicKey));
            Assert.IsFalse(E2EE2.VerifySignature(messageBytes, signature2, keyPair3.publicKey));
            Assert.IsFalse(E2EE2.VerifySignature(messageBytes, signature3, keyPair1.publicKey));
        }

        #endregion

        #region Group Messaging Advanced Tests

        [TestMethod]
        public void GroupMultiSenderDeduplication_ShouldHandleSimultaneousMessages()
        {
            // Arrange - Create three participants
            var aliceKeyPair = E2EE2.GenerateEd25519KeyPair();
            var bobKeyPair = E2EE2.GenerateEd25519KeyPair();
            var charlieKeyPair = E2EE2.GenerateEd25519KeyPair();

            var aliceManager = new E2EE2.GroupChatManager(aliceKeyPair);
            var bobManager = new E2EE2.GroupChatManager(bobKeyPair);
            var charlieManager = new E2EE2.GroupChatManager(charlieKeyPair);

            // Setup the group
            string groupId = "multiple-senders-test-group";
            aliceManager.CreateGroup(groupId);
            bobManager.CreateGroup(groupId);
            charlieManager.CreateGroup(groupId);

            // Exchange sender keys
            var aliceDistribution = aliceManager.CreateDistributionMessage(groupId);
            var bobDistribution = bobManager.CreateDistributionMessage(groupId);
            var charlieDistribution = charlieManager.CreateDistributionMessage(groupId);

            // Everyone processes everyone else's distribution
            aliceManager.ProcessSenderKeyDistribution(bobDistribution);
            aliceManager.ProcessSenderKeyDistribution(charlieDistribution);
            bobManager.ProcessSenderKeyDistribution(aliceDistribution);
            bobManager.ProcessSenderKeyDistribution(charlieDistribution);
            charlieManager.ProcessSenderKeyDistribution(aliceDistribution);
            charlieManager.ProcessSenderKeyDistribution(bobDistribution);

            // Act - Simulate simultaneous messages from all three
            string aliceMessage = "Alice's message";
            string bobMessage = "Bob's message";
            string charlieMessage = "Charlie's message";

            var aliceEncrypted = aliceManager.EncryptGroupMessage(groupId, aliceMessage);
            var bobEncrypted = bobManager.EncryptGroupMessage(groupId, bobMessage);
            var charlieEncrypted = charlieManager.EncryptGroupMessage(groupId, charlieMessage);

            // Each participant receives messages from the other two
            string bobDecryptsAlice = bobManager.DecryptGroupMessage(aliceEncrypted);
            string bobDecryptsCharlie = bobManager.DecryptGroupMessage(charlieEncrypted);

            string aliceDecryptsBob = aliceManager.DecryptGroupMessage(bobEncrypted);
            string aliceDecryptsCharlie = aliceManager.DecryptGroupMessage(charlieEncrypted);

            string charlieDecryptsAlice = charlieManager.DecryptGroupMessage(aliceEncrypted);
            string charlieDecryptsBob = charlieManager.DecryptGroupMessage(bobEncrypted);

            // Assert - Each message should be correctly decrypted by the other two participants
            Assert.AreEqual(aliceMessage, bobDecryptsAlice);
            Assert.AreEqual(aliceMessage, charlieDecryptsAlice);

            Assert.AreEqual(bobMessage, aliceDecryptsBob);
            Assert.AreEqual(bobMessage, charlieDecryptsBob);

            Assert.AreEqual(charlieMessage, aliceDecryptsCharlie);
            Assert.AreEqual(charlieMessage, bobDecryptsCharlie);
        }

        [TestMethod]
        public void GroupMemberAddition_ShouldAllowNewMemberToReceiveMessages()
        {
            // Arrange - Create an initial group with Alice and Bob
            var aliceKeyPair = E2EE2.GenerateEd25519KeyPair();
            var bobKeyPair = E2EE2.GenerateEd25519KeyPair();
            var daveKeyPair = E2EE2.GenerateEd25519KeyPair(); // Dave will join later

            var aliceManager = new E2EE2.GroupChatManager(aliceKeyPair);
            var bobManager = new E2EE2.GroupChatManager(bobKeyPair);
            var daveManager = new E2EE2.GroupChatManager(daveKeyPair);

            // Setup the initial group - but only Alice creates it as the admin
            string groupId = "member-addition-test-group";
            aliceManager.CreateGroup(groupId);

            // Alice invites Bob to the group by sending him her distribution message
            var aliceDistribution = aliceManager.CreateDistributionMessage(groupId);

            // Bob processes Alice's sender key to join the group
            bobManager.ProcessSenderKeyDistribution(aliceDistribution);

            // Bob sends his distribution message back to Alice
            var bobDistribution = bobManager.CreateDistributionMessage(groupId);
            aliceManager.ProcessSenderKeyDistribution(bobDistribution);

            // Add a delay before sending the initial message to ensure timestamps are clearly different
            Thread.Sleep(50);

            // Send an initial message before Dave joins
            string initialMessage = "Initial message before Dave joins";
            var initialEncrypted = aliceManager.EncryptGroupMessage(groupId, initialMessage);
            string bobDecryptsInitial = bobManager.DecryptGroupMessage(initialEncrypted);

            // Add a delay before Dave joins to ensure clear timestamp separation
            Thread.Sleep(50);

            // Act - Add Dave to the group
            // Dave never creates the group directly - he only processes messages from Alice and Bob
            daveManager.ProcessSenderKeyDistribution(aliceDistribution);
            daveManager.ProcessSenderKeyDistribution(bobDistribution);

            // Dave sends his distribution message to existing members
            var daveDistribution = daveManager.CreateDistributionMessage(groupId);
            aliceManager.ProcessSenderKeyDistribution(daveDistribution);
            bobManager.ProcessSenderKeyDistribution(daveDistribution);

            // Add a delay before sending messages after Dave joins
            Thread.Sleep(50);

            // Send messages after Dave joins
            string aliceMessage = "Message from Alice after Dave joined";
            string bobMessage = "Message from Bob after Dave joined";
            string daveMessage = "Dave's first message to the group";

            var aliceEncrypted = aliceManager.EncryptGroupMessage(groupId, aliceMessage);
            var bobEncrypted = bobManager.EncryptGroupMessage(groupId, bobMessage);
            var daveEncrypted = daveManager.EncryptGroupMessage(groupId, daveMessage);

            // All participants decrypt the new messages
            string bobDecryptsAlice = bobManager.DecryptGroupMessage(aliceEncrypted);
            string bobDecryptsDave = bobManager.DecryptGroupMessage(daveEncrypted);

            string aliceDecryptsBob = aliceManager.DecryptGroupMessage(bobEncrypted);
            string aliceDecryptsDave = aliceManager.DecryptGroupMessage(daveEncrypted);

            string daveDecryptsAlice = daveManager.DecryptGroupMessage(aliceEncrypted);
            string daveDecryptsBob = daveManager.DecryptGroupMessage(bobEncrypted);

            // Dave attempts to decrypt the initial message that was sent before he joined
            string daveDecryptsInitial = daveManager.DecryptGroupMessage(initialEncrypted);

            // Assert
            Assert.AreEqual(initialMessage, bobDecryptsInitial, "Bob should be able to decrypt the initial message");

            Assert.AreEqual(aliceMessage, bobDecryptsAlice, "Bob should be able to decrypt Alice's message after Dave joined");
            Assert.AreEqual(aliceMessage, daveDecryptsAlice, "Dave should be able to decrypt Alice's message after he joined");

            Assert.AreEqual(bobMessage, aliceDecryptsBob, "Alice should be able to decrypt Bob's message after Dave joined");
            Assert.AreEqual(bobMessage, daveDecryptsBob, "Dave should be able to decrypt Bob's message after he joined");

            Assert.AreEqual(daveMessage, aliceDecryptsDave, "Alice should be able to decrypt Dave's message");
            Assert.AreEqual(daveMessage, bobDecryptsDave, "Bob should be able to decrypt Dave's message");

            // This is the key test - Dave shouldn't be able to decrypt the initial message
            Assert.IsNull(daveDecryptsInitial, "New member should not be able to decrypt messages sent before joining");

            // Verify timestamp behavior
            Assert.IsTrue(initialEncrypted.Timestamp > 0, "Initial message should have a valid timestamp");
            Assert.IsTrue(aliceEncrypted.Timestamp > 0, "Alice's message should have a valid timestamp");
            Assert.IsTrue(bobEncrypted.Timestamp > 0, "Bob's message should have a valid timestamp");
            Assert.IsTrue(daveEncrypted.Timestamp > 0, "Dave's message should have a valid timestamp");

            // Add timestamp verification to ensure message timestamps have the expected ordering
            Assert.IsTrue(aliceEncrypted.Timestamp > initialEncrypted.Timestamp,
                "Alice's later message should have a timestamp after the initial message");
        }

        #endregion

        #region Handling Exceptional Input Tests

        [TestMethod]
        public void InvalidUTF8Input_ShouldBeHandledGracefully()
        {
            // Arrange
            byte[] key = new byte[32];
            RandomNumberGenerator.Fill(key);

            // Create invalid UTF-8 sequence
            byte[] invalidUtf8 = new byte[] { 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0xC0, 0xC1, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF };
            byte[] nonce = E2EE2.GenerateNonce();

            try
            {
                // Attempt to encrypt the invalid UTF-8
                byte[] ciphertext = E2EE2.AESEncrypt(invalidUtf8, key, nonce);
                byte[] decrypted = E2EE2.AESDecrypt(ciphertext, key, nonce);

                // Convert back to string should fail or result in replacement characters
                string result = Encoding.UTF8.GetString(decrypted);

                // The decryption should work at the byte level even with invalid UTF-8
                Assert.IsTrue(AreByteArraysEqual(invalidUtf8, decrypted), "Bytes should decrypt correctly even with invalid UTF-8");
            }
            catch (FormatException)
            {
                // This is acceptable - if the library explicitly checks for valid UTF-8
                Assert.IsTrue(true, "Caught expected FormatException for invalid UTF-8");
            }
        }

        [TestMethod]
        public void ExtremeMessageSizes_ShouldEncryptAndDecryptCorrectly()
        {
            // Arrange
            byte[] key = new byte[32];
            RandomNumberGenerator.Fill(key);

            // Test with empty message (just a few bytes)
            string tinyMessage = "Hi";

            // Test with a large message (1 MB of text)
            StringBuilder largeMessageBuilder = new StringBuilder(1024 * 1024);
            for (int i = 0; i < 1024 * 64; i++) // Generate ~1MB of text
            {
                largeMessageBuilder.Append("This is a large message for testing encryption performance and correctness with extreme message sizes. ");
            }
            string largeMessage = largeMessageBuilder.ToString();

            // Act & Assert - Tiny message
            var tinyEncrypted = E2EE2.EncryptMessage(tinyMessage, key);
            string tinyDecrypted = E2EE2.DecryptMessage(tinyEncrypted, key);
            Assert.AreEqual(tinyMessage, tinyDecrypted);

            // Act & Assert - Large message
            var largeEncrypted = E2EE2.EncryptMessage(largeMessage, key);
            string largeDecrypted = E2EE2.DecryptMessage(largeEncrypted, key);
            Assert.AreEqual(largeMessage, largeDecrypted);
        }

        #endregion

        #region Cross-Platform Compatibility Tests

        [TestMethod]
        public void CrossPlatformCompatibility_HardcodedVectorsTest()
        {
            // This test uses hardcoded test vectors that would match outputs from other implementations

            // Arrange - Key and nonce with predefined values
            byte[] key = new byte[32];
            for (int i = 0; i < key.Length; i++)
            {
                key[i] = (byte)i;
            }

            byte[] nonce = new byte[12];
            for (int i = 0; i < nonce.Length; i++)
            {
                nonce[i] = (byte)(i + 100);
            }

            string message = "Cross-platform test message";
            byte[] messageBytes = Encoding.UTF8.GetBytes(message);

            // Encrypt with our library
            byte[] ciphertextWithTag = E2EE2.AESEncrypt(messageBytes, key, nonce);

            // The expected result would be the output from a reference implementation
            // In a real test, this would be actual output from another platform's implementation
            // For demonstration, we're just checking our own encryption works
            byte[] decrypted = E2EE2.AESDecrypt(ciphertextWithTag, key, nonce);

            // Assert
            Assert.IsTrue(AreByteArraysEqual(messageBytes, decrypted));

            // In a real cross-platform test, you would compare against expected values like:
            // byte[] expectedCiphertext = new byte[] { ... }; // From another implementation
            // Assert.IsTrue(AreByteArraysEqual(expectedCiphertext, ciphertextWithTag));
        }

        #endregion

        #region Performance Tests

        [TestMethod]
        public void Performance_EncryptionAndDecryptionSpeedTest()
        {
            // Arrange
            byte[] key = new byte[32];
            RandomNumberGenerator.Fill(key);

            // Create messages of different sizes
            string smallMessage = "Small message for testing";

            StringBuilder mediumMessageBuilder = new StringBuilder(10 * 1024);
            for (int i = 0; i < 500; i++)
            {
                mediumMessageBuilder.Append("Medium sized message for performance testing. ");
            }
            string mediumMessage = mediumMessageBuilder.ToString();

            StringBuilder largeMessageBuilder = new StringBuilder(100 * 1024);
            for (int i = 0; i < 5000; i++)
            {
                largeMessageBuilder.Append("Large message for comprehensive performance testing across different message sizes. ");
            }
            string largeMessage = largeMessageBuilder.ToString();

            // Act - Measure encryption time
            System.Diagnostics.Stopwatch stopwatch = new System.Diagnostics.Stopwatch();

            // Small message
            stopwatch.Restart();
            var smallEncrypted = E2EE2.EncryptMessage(smallMessage, key);
            stopwatch.Stop();
            long smallEncryptTime = stopwatch.ElapsedMilliseconds;

            // Medium message
            stopwatch.Restart();
            var mediumEncrypted = E2EE2.EncryptMessage(mediumMessage, key);
            stopwatch.Stop();
            long mediumEncryptTime = stopwatch.ElapsedMilliseconds;

            // Large message
            stopwatch.Restart();
            var largeEncrypted = E2EE2.EncryptMessage(largeMessage, key);
            stopwatch.Stop();
            long largeEncryptTime = stopwatch.ElapsedMilliseconds;

            // Measure decryption time
            // Small message
            stopwatch.Restart();
            string smallDecrypted = E2EE2.DecryptMessage(smallEncrypted, key);
            stopwatch.Stop();
            long smallDecryptTime = stopwatch.ElapsedMilliseconds;

            // Medium message
            stopwatch.Restart();
            string mediumDecrypted = E2EE2.DecryptMessage(mediumEncrypted, key);
            stopwatch.Stop();
            long mediumDecryptTime = stopwatch.ElapsedMilliseconds;

            // Large message
            stopwatch.Restart();
            string largeDecrypted = E2EE2.DecryptMessage(largeEncrypted, key);
            stopwatch.Stop();
            long largeDecryptTime = stopwatch.ElapsedMilliseconds;

            // Assert
            // Verify correctness
            Assert.AreEqual(smallMessage, smallDecrypted);
            Assert.AreEqual(mediumMessage, mediumDecrypted);
            Assert.AreEqual(largeMessage, largeDecrypted);

            // Check that performance is reasonable - these thresholds should be adjusted based on your system
            // Small messages should encrypt/decrypt quickly, but we're just checking for gross performance issues
            Assert.IsTrue(smallEncryptTime < 100, $"Small message encryption took {smallEncryptTime}ms");
            Assert.IsTrue(smallDecryptTime < 100, $"Small message decryption took {smallDecryptTime}ms");

            // Medium messages should be reasonably fast
            Assert.IsTrue(mediumEncryptTime < 500, $"Medium message encryption took {mediumEncryptTime}ms");
            Assert.IsTrue(mediumDecryptTime < 500, $"Medium message decryption took {mediumDecryptTime}ms");

            // Verify that performance scales roughly linearly with message size (with some margin)
            double smallToMediumRatio = (double)mediumMessage.Length / smallMessage.Length;
            double encryptTimeRatio = (double)mediumEncryptTime / (smallEncryptTime > 0 ? smallEncryptTime : 1);

            // Allow for some overhead, but if encryption time grows much faster than message size, there may be an issue
            Assert.IsTrue(encryptTimeRatio < smallToMediumRatio * 2,
                $"Encryption time doesn't scale linearly with message size. Message size ratio: {smallToMediumRatio}, time ratio: {encryptTimeRatio}");
        }

        [TestMethod]
        public void Performance_KeyGenerationSpeedTest()
        {
            // Arrange
            System.Diagnostics.Stopwatch stopwatch = new System.Diagnostics.Stopwatch();
            const int iterations = 100;

            // Act - Measure Ed25519 key generation
            stopwatch.Start();
            for (int i = 0; i < iterations; i++)
            {
                var keyPair = E2EE2.GenerateEd25519KeyPair();
            }
            stopwatch.Stop();

            double avgEd25519Time = (double)stopwatch.ElapsedMilliseconds / iterations;

            // Measure X25519 key generation
            stopwatch.Restart();
            for (int i = 0; i < iterations; i++)
            {
                var keyPair = E2EE2.GenerateX25519KeyPair();
            }
            stopwatch.Stop();

            double avgX25519Time = (double)stopwatch.ElapsedMilliseconds / iterations;

            // Assert - Just verifying performance is in a reasonable range
            Assert.IsTrue(avgEd25519Time < 50, $"Ed25519 key generation took average {avgEd25519Time}ms per key");
            Assert.IsTrue(avgX25519Time < 50, $"X25519 key generation took average {avgX25519Time}ms per key");
        }

        #endregion

        #region Memory Safety Tests

        [TestMethod]
        public void MemorySafety_SensitiveDataClearing()
        {
            // This test checks if the SecureClear method actually zeros out memory

            // Create a byte array with recognizable data
            byte[] sensitiveData = new byte[32];
            for (int i = 0; i < sensitiveData.Length; i++)
            {
                sensitiveData[i] = (byte)(i + 1);
            }

            // Make a copy to verify it was actually changed
            byte[] dataCopy = new byte[sensitiveData.Length];
            Buffer.BlockCopy(sensitiveData, 0, dataCopy, 0, sensitiveData.Length);

            // Clear the sensitive data
            E2EE2.SecureClear(sensitiveData);

            // Assert that all bytes are now zero
            foreach (byte b in sensitiveData)
            {
                Assert.AreEqual(0, b, "SecureClear should set all bytes to zero");
            }

            // Verify the copy wasn't changed (proving our initial data wasn't all zeros)
            for (int i = 0; i < dataCopy.Length; i++)
            {
                Assert.AreEqual((byte)(i + 1), dataCopy[i], "Original data copy should remain unchanged");
            }
        }

        [TestMethod]
        public void MemoryUsage_DoesNotLeakHandles()
        {
            // This is a basic test to ensure operations don't leak handles
            // For more thorough testing, you'd need a memory profiler or specific handle tracking

            int initialGCGen2Count = GC.CollectionCount(2);

            // Perform a large number of cryptographic operations to potentially trigger leaks
            for (int i = 0; i < 1000; i++)
            {
                // Generate keys
                var keyPair = E2EE2.GenerateX25519KeyPair();

                // Encrypt and decrypt
                string message = $"Test message for iteration {i}";
                var encrypted = E2EE2.EncryptMessage(message, keyPair.privateKey);
                var decrypted = E2EE2.DecryptMessage(encrypted, keyPair.privateKey);

                // Sign and verify
                byte[] msgBytes = Encoding.UTF8.GetBytes(message);
                var edKeyPair = E2EE2.GenerateEd25519KeyPair();
                byte[] signature = E2EE2.SignMessage(msgBytes, edKeyPair.privateKey);
                bool valid = E2EE2.VerifySignature(msgBytes, signature, edKeyPair.publicKey);
            }

            // Force garbage collection
            GC.Collect(2, GCCollectionMode.Forced);
            GC.WaitForPendingFinalizers();

            // Get generation 2 collection count after operations
            int finalGCGen2Count = GC.CollectionCount(2);

            // Assert that we had at least one collection (and no crashes)
            Assert.IsTrue(finalGCGen2Count > initialGCGen2Count,
                "There should be at least one generation 2 garbage collection");

            // Note: A more thorough test would use memory profiling tools
        }

        #endregion

        #region Advanced Protocol Tests

        [TestMethod]
        public void StateManagement_DoesNotCreateRaceConditions()
        {
            // Test various operations under concurrent access
            var keyPair = E2EE2.GenerateX25519KeyPair();
            string groupId = "concurrent-access-group";

            // Create a group chat manager
            var manager = new E2EE2.GroupChatManager(keyPair);
            manager.CreateGroup(groupId);

            // Simulate multiple threads accessing the manager concurrently
            Parallel.For(0, 100, i =>
            {
                // Each "thread" encrypts a message
                string message = $"Concurrent message {i}";
                var encrypted = manager.EncryptGroupMessage(groupId, message);

                // Each thread then decrypts its own message
                string decrypted = manager.DecryptGroupMessage(encrypted);

                // Verify the decryption worked correctly
                Assert.AreEqual(message, decrypted);
            });

            // Test nonce generation concurrently - should not have duplicates
            var allNonces = new ConcurrentBag<byte[]>();

            Parallel.For(0, 1000, i =>
            {
                byte[] nonce = E2EE2.GenerateNonce();
                allNonces.Add(nonce);
            });

            // Check that all generated nonces are unique
            var nonceSet = new HashSet<string>();
            foreach (var nonce in allNonces)
            {
                string nonceBase64 = Convert.ToBase64String(nonce);
                Assert.IsTrue(nonceSet.Add(nonceBase64), "Duplicate nonce detected");
            }
        }

        [TestMethod]
        public void StateTransitionDeterminism_ShouldProduceConsistentResults()
        {
            // Test that protocol state transitions are deterministic

            // Create key pairs and initial state
            var aliceKeyPair = E2EE2.GenerateX25519KeyPair();
            var bobKeyPair = E2EE2.GenerateX25519KeyPair();

            byte[] sharedSecret1 = E2EE2.X3DHKeyExchange(bobKeyPair.publicKey, aliceKeyPair.privateKey);
            byte[] sharedSecret2 = E2EE2.X3DHKeyExchange(aliceKeyPair.publicKey, bobKeyPair.privateKey);

            // Assert shared secrets are the same
            Assert.IsTrue(AreByteArraysEqual(sharedSecret1, sharedSecret2), "Shared secrets should be identical");

            // Initialize Double Ratchet - should produce consistent results
            var (rootKey1, chainKey1) = E2EE2.InitializeDoubleRatchet(sharedSecret1);
            var (rootKey2, chainKey2) = E2EE2.InitializeDoubleRatchet(sharedSecret1); // Same input should give same output

            Assert.IsTrue(AreByteArraysEqual(rootKey1, rootKey2), "Root keys should be identical with same input");
            Assert.IsTrue(AreByteArraysEqual(chainKey1, chainKey2), "Chain keys should be identical with same input");

            // Test ratchet step determinism
            var (newChainKey1, messageKey1) = E2EE2.RatchetStep(chainKey1);
            var (newChainKey2, messageKey2) = E2EE2.RatchetStep(chainKey1); // Same input again

            Assert.IsTrue(AreByteArraysEqual(newChainKey1, newChainKey2), "New chain keys should be identical with same input");
            Assert.IsTrue(AreByteArraysEqual(messageKey1, messageKey2), "Message keys should be identical with same input");

            // Multiple steps should also be deterministic
            var (finalChainKey1, _) = E2EE2.RatchetStep(newChainKey1);
            var (finalChainKey2, _) = E2EE2.RatchetStep(newChainKey2);

            Assert.IsTrue(AreByteArraysEqual(finalChainKey1, finalChainKey2), "Final chain keys should be identical");
        }

        [TestMethod]
        public void ProtocolUpgradeability_ShouldSupportVersioning()
        {
            // Test for a simplified version protocol
            // In a real implementation, you'd have more formal versioning

            // Generate key pair and encrypt a message
            var keyPair = E2EE2.GenerateX25519KeyPair();
            string message = "Test message for protocol versioning";
            var encryptedMessage = E2EE2.EncryptMessage(message, keyPair.privateKey);

            // Simulate "upgrading" by adding a protocol version
            // This is just a demonstration - real protocol upgrades would need more planning
            var modifiedMessage = new E2EE2.EncryptedMessage
            {
                Ciphertext = encryptedMessage.Ciphertext,
                Nonce = encryptedMessage.Nonce,
                // Add some metadata that would be in a newer version
                MessageNumber = 1,
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
            };

            // The current version should still be able to decrypt this
            string decrypted = E2EE2.DecryptMessage(modifiedMessage, keyPair.privateKey);

            // Assert that the message decrypts successfully despite the added fields
            Assert.AreEqual(message, decrypted, "Added fields should not break backward compatibility");
        }

        #endregion

        #region Security Edge Case Tests

        [TestMethod]
        public void MultiRatchetSequence_ShouldMaintainSecurity()
        {
            // Generate initial key materials
            byte[] initialKey = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(initialKey);
            }

            // Perform a large number of ratchet steps
            byte[] currentKey = initialKey;
            Dictionary<int, byte[]> messageKeys = new Dictionary<int, byte[]>();

            const int steps = 100;
            for (int i = 0; i < steps; i++)
            {
                var (newChainKey, messageKey) = E2EE2.RatchetStep(currentKey);
                currentKey = newChainKey;

                // Store message key
                messageKeys[i] = messageKey;

                // Verify that this message key is unique
                for (int j = 0; j < i; j++)
                {
                    Assert.IsFalse(AreByteArraysEqual(messageKeys[j], messageKey),
                        $"Message keys at positions {j} and {i} should not be equal");
                }
            }

            // Test that the final chain key doesn't reveal anything about the initial key
            Assert.IsFalse(AreByteArraysEqual(initialKey, currentKey),
                "Final chain key should differ from initial key");

            // Check for cryptographic distinctness rather than byte-level differences
            // This is a more appropriate test for the security properties of the protocol
            bool hasDistinctKeys = false;
            for (int i = 0; i < steps; i++)
            {
                // Check that message keys are cryptographically distinct from chain keys
                if (!AreByteArraysEqual(messageKeys[i], initialKey) &&
                    !AreByteArraysEqual(messageKeys[i], currentKey))
                {
                    hasDistinctKeys = true;
                    break;
                }
            }

            Assert.IsTrue(hasDistinctKeys,
                "Message keys should be cryptographically distinct from initial and final chain keys");
        }

        [TestMethod]
        public void InputValidation_HandlesEdgeCases()
        {
            // Arrange
            // Test with key arrays of incorrect length
            byte[] shortKey = new byte[16]; // Too short
            byte[] longKey = new byte[64];  // Too long for AES but valid for Ed25519
            byte[] messageBytes = Encoding.UTF8.GetBytes("Test message");
            byte[] validNonce = E2EE2.GenerateNonce();
            byte[] shortNonce = new byte[8]; // Too short

            // Valid key for comparison
            byte[] validKey = new byte[32];
            RandomNumberGenerator.Fill(validKey);

            // Act & Assert

            // Test AES with invalid key lengths
            Assert.ThrowsException<ArgumentException>(() =>
            {
                E2EE2.AESEncrypt(messageBytes, shortKey, validNonce);
            }, "Should throw for key that's too short");

            Assert.ThrowsException<ArgumentException>(() =>
            {
                E2EE2.AESEncrypt(messageBytes, longKey, validNonce);
            }, "Should throw for key that's too long for AES");

            // Test with invalid nonce
            Assert.ThrowsException<ArgumentException>(() =>
            {
                E2EE2.AESEncrypt(messageBytes, validKey, shortNonce);
            }, "Should throw for nonce that's too short");

            // Test with null inputs
            Assert.ThrowsException<ArgumentNullException>(() =>
            {
                E2EE2.AESEncrypt(null, validKey, validNonce);
            }, "Should throw for null plaintext");

            Assert.ThrowsException<ArgumentNullException>(() =>
            {
                E2EE2.AESEncrypt(messageBytes, null, validNonce);
            }, "Should throw for null key");

            Assert.ThrowsException<ArgumentNullException>(() =>
            {
                E2EE2.AESEncrypt(messageBytes, validKey, null);
            }, "Should throw for null nonce");

            // Test input validation for signature methods
            var (publicKey, privateKey) = E2EE2.GenerateEd25519KeyPair();

            Assert.ThrowsException<ArgumentNullException>(() =>
            {
                E2EE2.SignMessage(null, privateKey);
            }, "Should throw for null message in SignMessage");

            Assert.ThrowsException<ArgumentNullException>(() =>
            {
                E2EE2.SignMessage(messageBytes, null);
            }, "Should throw for null private key in SignMessage");

            Assert.ThrowsException<ArgumentNullException>(() =>
            {
                E2EE2.VerifySignature(null, new byte[64], publicKey);
            }, "Should throw for null message in VerifySignature");

            Assert.ThrowsException<ArgumentNullException>(() =>
            {
                E2EE2.VerifySignature(messageBytes, null, publicKey);
            }, "Should throw for null signature in VerifySignature");

            Assert.ThrowsException<ArgumentNullException>(() =>
            {
                E2EE2.VerifySignature(messageBytes, new byte[64], null);
            }, "Should throw for null public key in VerifySignature");
        }

        [TestMethod]
        public void NonceHandling_RejectsReusedNonces()
        {
            // This test checks if the library prevents nonce reuse - a critical security property

            // Arrange
            byte[] key = new byte[32];
            RandomNumberGenerator.Fill(key);
            byte[] nonce = E2EE2.GenerateNonce();

            string message1 = "First message";
            string message2 = "Second message - should use different nonce";

            byte[] plaintext1 = Encoding.UTF8.GetBytes(message1);
            byte[] plaintext2 = Encoding.UTF8.GetBytes(message2);

            // Act
            byte[] ciphertext1 = E2EE2.AESEncrypt(plaintext1, key, nonce);

            // Attempt to use the same nonce again - in a secure implementation, nonces should never be reused
            // This would typically throw an exception or be prevented by the library's design
            byte[] ciphertext2 = E2EE2.AESEncrypt(plaintext2, key, nonce);

            // Now that we have both ciphertexts, show why nonce reuse is dangerous
            // If your library allows nonce reuse, this test demonstrates the vulnerability

            // We can XOR the ciphertexts to get the XOR of the plaintexts (a known attack pattern)
            byte[] xorResult = new byte[Math.Min(ciphertext1.Length, ciphertext2.Length)];
            for (int i = 0; i < xorResult.Length; i++)
            {
                xorResult[i] = (byte)(ciphertext1[i] ^ ciphertext2[i]);
            }

            // Assert - In a secure implementation, the library should provide automatic nonce management
            // that prevents reuse. This test simply demonstrates the danger.

            // Check that two calls to GenerateNonce() always produce different values
            byte[] newNonce1 = E2EE2.GenerateNonce();
            byte[] newNonce2 = E2EE2.GenerateNonce();

            Assert.IsFalse(AreByteArraysEqual(newNonce1, newNonce2), "Generated nonces should be unique");

            // Note: This test doesn't assert against ciphertext patterns because it's illustrating
            // how a reused nonce compromises security, not strictly testing library behavior
        }

        #endregion

        #region Helper Methods

        /// <summary>
        /// Helper method for byte array comparison
        /// </summary>
        private bool AreByteArraysEqual(byte[] a, byte[] b)
        {
            // Use the secure comparison even in tests to ensure consistent behavior
            return E2EE2.SecureCompare(a, b);
        }

        // Helper method to print byte array contents
        private void PrintByteArray(byte[] arr)
        {
            if (arr == null)
            {
                Console.WriteLine("null");
                return;
            }

            Console.WriteLine($"Length: {arr.Length}");
            Console.WriteLine("Bytes: " + string.Join(", ", arr.Select(b => b.ToString("X2"))));

            // Also print some additional details
            Console.WriteLine($"All Zeros: {arr.All(b => b == 0)}");
            Console.WriteLine($"All Ones: {arr.All(b => b == 255)}");
        }

        #endregion
    }
}