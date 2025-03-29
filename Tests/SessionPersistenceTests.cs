using System;
using System.Text;
using System.IO;
using System.Text.Json;
using System.Collections.Generic;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using E2EELibrary.KeyExchange;
using E2EELibrary.Models;
using E2EELibrary.KeyManagement;
using E2EELibrary.Core;

namespace E2EELibraryTests
{
    [TestClass]
    public class SessionPersistenceTests
    {
        // Helper to create a test session
        private DoubleRatchetSession CreateTestSession()
        {
            // Generate key pairs for Alice and Bob
            var aliceKeyPair = KeyGenerator.GenerateX25519KeyPair();
            var bobKeyPair = KeyGenerator.GenerateX25519KeyPair();

            // Create initial shared secret
            byte[] sharedSecret = X3DHExchange.X3DHKeyExchange(bobKeyPair.publicKey, aliceKeyPair.privateKey);
            var (rootKey, chainKey) = DoubleRatchetExchange.InitializeDoubleRatchet(sharedSecret);

            // Create session ID
            string sessionId = "test-session-" + Guid.NewGuid().ToString();

            // Create a test session
            return new DoubleRatchetSession(
                dhRatchetKeyPair: aliceKeyPair,
                remoteDHRatchetKey: bobKeyPair.publicKey,
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumber: 5, // Use non-zero to verify persistence
                sessionId: sessionId,
                recentlyProcessedIds: new[] { Guid.NewGuid(), Guid.NewGuid() },
                processedMessageNumbers: new[] { 1, 2, 3 }
            );
        }

        [TestMethod]
        public void SerializeDeserializeSession_WithoutEncryption_ShouldPreserveData()
        {
            // Arrange
            var originalSession = CreateTestSession();

            // Act
            byte[] serialized = SessionPersistence.SerializeSession(originalSession);
            var deserializedSession = SessionPersistence.DeserializeSession(serialized);

            // Assert
            Assert.IsNotNull(deserializedSession);
            Assert.AreEqual(originalSession.SessionId, deserializedSession.SessionId);
            Assert.AreEqual(originalSession.MessageNumber, deserializedSession.MessageNumber);

            // Compare key materials
            Assert.IsTrue(SecureMemory.SecureCompare(
                originalSession.DHRatchetKeyPair.publicKey,
                deserializedSession.DHRatchetKeyPair.publicKey));

            Assert.IsTrue(SecureMemory.SecureCompare(
                originalSession.DHRatchetKeyPair.privateKey,
                deserializedSession.DHRatchetKeyPair.privateKey));

            Assert.IsTrue(SecureMemory.SecureCompare(
                originalSession.RemoteDHRatchetKey,
                deserializedSession.RemoteDHRatchetKey));

            Assert.IsTrue(SecureMemory.SecureCompare(
                originalSession.RootKey,
                deserializedSession.RootKey));

            Assert.IsTrue(SecureMemory.SecureCompare(
                originalSession.SendingChainKey,
                deserializedSession.SendingChainKey));

            Assert.IsTrue(SecureMemory.SecureCompare(
                originalSession.ReceivingChainKey,
                deserializedSession.ReceivingChainKey));

            // Check for message IDs preservation
            Assert.AreEqual(originalSession.RecentlyProcessedIds.Count, deserializedSession.RecentlyProcessedIds.Count);

            foreach (Guid id in originalSession.RecentlyProcessedIds)
            {
                Assert.IsTrue(deserializedSession.HasProcessedMessageId(id), $"Message ID {id} should be present");
            }

            // Check for message numbers preservation
            Assert.AreEqual(originalSession.ProcessedMessageNumbers.Count, deserializedSession.ProcessedMessageNumbers.Count);

            foreach (int num in originalSession.ProcessedMessageNumbers)
            {
                Assert.IsTrue(deserializedSession.HasProcessedMessageNumber(num), $"Message number {num} should be present");
            }
        }

        [TestMethod]
        public void SerializeDeserializeSession_WithEncryption_ShouldPreserveData()
        {
            // Arrange
            var originalSession = CreateTestSession();
            byte[] encryptionKey = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(encryptionKey);
            }

            // Act
            byte[] serialized = SessionPersistence.SerializeSession(originalSession, encryptionKey);
            var deserializedSession = SessionPersistence.DeserializeSession(serialized, encryptionKey);

            // Assert
            Assert.IsNotNull(deserializedSession);
            Assert.AreEqual(originalSession.SessionId, deserializedSession.SessionId);
            Assert.AreEqual(originalSession.MessageNumber, deserializedSession.MessageNumber);

            // Compare key materials
            Assert.IsTrue(SecureMemory.SecureCompare(
                originalSession.DHRatchetKeyPair.publicKey,
                deserializedSession.DHRatchetKeyPair.publicKey));
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void DeserializeSession_WithWrongKey_ShouldThrowException()
        {
            // Arrange
            var originalSession = CreateTestSession();
            byte[] correctKey = new byte[32];
            byte[] wrongKey = new byte[32];

            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(correctKey);
                rng.GetBytes(wrongKey);
            }

            // Make sure keys are different
            wrongKey[0] = (byte)(correctKey[0] ^ 0xFF);

            // Act & Assert
            byte[] serialized = SessionPersistence.SerializeSession(originalSession, correctKey);
            // This should throw CryptographicException
            SessionPersistence.DeserializeSession(serialized, wrongKey);
        }

        [TestMethod]
        [ExpectedException(typeof(FormatException))]
        public void DeserializeSession_WithCorruptedData_ShouldThrowException()
        {
            // Arrange
            var originalSession = CreateTestSession();
            byte[] serialized = SessionPersistence.SerializeSession(originalSession);

            // Corrupt the data (change bytes in the middle)
            int middle = serialized.Length / 2;
            serialized[middle] ^= 0xFF;
            serialized[middle + 1] ^= 0xFF;

            // Act & Assert - Should throw FormatException or InvalidDataException
            SessionPersistence.DeserializeSession(serialized);
        }

        [TestMethod]
        public void SaveLoadSessionToFile_WithoutEncryption_ShouldWorkCorrectly()
        {
            // Arrange
            var originalSession = CreateTestSession();
            string filePath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());

            try
            {
                // Act
                SessionPersistence.SaveSessionToFile(originalSession, filePath);
                var loadedSession = SessionPersistence.LoadSessionFromFile(filePath);

                // Assert
                Assert.IsNotNull(loadedSession);
                Assert.AreEqual(originalSession.SessionId, loadedSession.SessionId);
                Assert.AreEqual(originalSession.MessageNumber, loadedSession.MessageNumber);
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
        public void SaveLoadSessionToFile_WithEncryption_ShouldWorkCorrectly()
        {
            // Arrange
            var originalSession = CreateTestSession();
            string filePath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
            byte[] encryptionKey = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(encryptionKey);
            }

            try
            {
                // Act
                SessionPersistence.SaveSessionToFile(originalSession, filePath, encryptionKey);
                var loadedSession = SessionPersistence.LoadSessionFromFile(filePath, encryptionKey);

                // Assert
                Assert.IsNotNull(loadedSession);
                Assert.AreEqual(originalSession.SessionId, loadedSession.SessionId);
                Assert.AreEqual(originalSession.MessageNumber, loadedSession.MessageNumber);
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
        public void LoadSessionFromFile_NonexistentFile_ShouldThrowException()
        {
            // Act & Assert
            SessionPersistence.LoadSessionFromFile("non-existent-file-that-should-not-exist.bin");
        }

        [TestMethod]
        public void SerializeLargeSession_ShouldHandleEfficientlyAndSuccessfully()
        {
            // Arrange
            var originalSession = CreateTestSession();

            // Create a session with many processed message IDs to simulate a long-running session
            var manyIds = new List<Guid>();
            for (int i = 0; i < 1000; i++)
            {
                manyIds.Add(Guid.NewGuid());
            }

            var largeSession = originalSession;
            foreach (var id in manyIds)
            {
                largeSession = largeSession.WithProcessedMessageId(id);
            }

            // Act
            byte[] serialized = SessionPersistence.SerializeSession(largeSession);
            var deserializedSession = SessionPersistence.DeserializeSession(serialized);

            // Assert
            Assert.IsNotNull(deserializedSession);
            Assert.AreEqual(Constants.MAX_TRACKED_MESSAGE_IDS, deserializedSession.RecentlyProcessedIds.Count,
                "Should limit the number of tracked IDs to the maximum defined in Constants");

            // The most recent IDs should be preserved (due to queue-like behavior)
            foreach (var id in manyIds.GetRange(manyIds.Count - Constants.MAX_TRACKED_MESSAGE_IDS, Constants.MAX_TRACKED_MESSAGE_IDS))
            {
                Assert.IsTrue(deserializedSession.HasProcessedMessageId(id),
                    $"Recent message ID {id} should be preserved");
            }
        }

        [TestMethod]
        public void DeserializeWithValidSessionFormat_ShouldWorkCorrectly()
        {
            // Arrange
            var originalSession = CreateTestSession();

            // Manually build the JSON to simulate a specific format
            var sessionData = new
            {
                DHRatchetPublicKey = Convert.ToBase64String(originalSession.DHRatchetKeyPair.publicKey),
                DHRatchetPrivateKey = Convert.ToBase64String(originalSession.DHRatchetKeyPair.privateKey),
                RemoteDHRatchetKey = Convert.ToBase64String(originalSession.RemoteDHRatchetKey),
                RootKey = Convert.ToBase64String(originalSession.RootKey),
                SendingChainKey = Convert.ToBase64String(originalSession.SendingChainKey),
                ReceivingChainKey = Convert.ToBase64String(originalSession.ReceivingChainKey),
                MessageNumber = originalSession.MessageNumber,
                SessionId = originalSession.SessionId,
                ProcessedMessageIds = new[] { Guid.NewGuid(), Guid.NewGuid() }
            };

            string json = JsonSerializer.Serialize(sessionData);
            byte[] serializedData = Encoding.UTF8.GetBytes(json);

            // Act
            var deserializedSession = SessionPersistence.DeserializeSession(serializedData);

            // Assert
            Assert.IsNotNull(deserializedSession);
            Assert.AreEqual(originalSession.SessionId, deserializedSession.SessionId);
            Assert.AreEqual(originalSession.MessageNumber, deserializedSession.MessageNumber);
        }
    }
}