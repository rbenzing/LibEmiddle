using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Text;
using System.IO;
using System.Text.Json;
using System.Collections.Generic;
using System.Security.Cryptography;
using LibEmiddle.KeyExchange;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.Abstractions;

namespace LibEmiddle.Tests.Unit
{
    [TestClass]
    public class SessionPersistenceTests
    {
        private CryptoProvider _cryptoProvider;

        [TestInitialize]
        public void Setup()
        {
            _cryptoProvider = new CryptoProvider();
        }

        // Helper to create a test session
        private DoubleRatchetSession CreateTestSession()
        {
            // Generate key pairs for Alice and Bob
            var aliceKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.X25519);
            var bobKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.X25519);

            // Create initial shared secret
            byte[] sharedSecret = X3DHExchange.PerformX25519DH(bobKeyPair.PublicKey, aliceKeyPair.PrivateKey);
            var (rootKey, chainKey) = _cryptoProvider.DerriveDoubleRatchet(sharedSecret);

            // Create session ID
            string sessionId = "test-session-" + Guid.NewGuid().ToString();

            // Create a test session
            return new DoubleRatchetSession(
                dhRatchetKeyPair: aliceKeyPair,
                remoteDHRatchetKey: bobKeyPair.PublicKey,
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumberReceiving: 5, // Use non-zero to verify persistence
                messageNumberSending: 3, // Use non-zero to verify persistence
                sessionId: sessionId,
                recentlyProcessedIds: [Guid.NewGuid(), Guid.NewGuid()]
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
            Assert.AreEqual(originalSession.MessageNumberReceiving, deserializedSession.MessageNumberReceiving);
            Assert.AreEqual(originalSession.MessageNumberSending, deserializedSession.MessageNumberSending);

            // Compare key materials
            Assert.IsTrue(SecureMemory.SecureCompare(
                originalSession.DHRatchetKeyPair.PublicKey,
                deserializedSession.DHRatchetKeyPair.PublicKey));

            Assert.IsTrue(SecureMemory.SecureCompare(
                originalSession.DHRatchetKeyPair.PrivateKey,
                deserializedSession.DHRatchetKeyPair.PrivateKey));

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
            Assert.AreEqual(originalSession.MessageNumberReceiving, deserializedSession.MessageNumberReceiving);

            // Compare key materials
            Assert.IsTrue(SecureMemory.SecureCompare(
                originalSession.DHRatchetKeyPair.PublicKey,
                deserializedSession.DHRatchetKeyPair.PublicKey));
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
        [ExpectedException(typeof(InvalidDataException))]
        public void DeserializeSession_WithCorruptedData_ShouldThrowException()
        {
            // Arrange
            var originalSession = CreateTestSession();
            byte[] serializedBytes = SessionPersistence.SerializeSession(originalSession);
            string serializedJson = System.Text.Encoding.UTF8.GetString(serializedBytes);

            // Locate the "DHRatchetPublicKey" field in the JSON
            string keyIdentifier = "\"DHRatchetPublicKey\":\"";
            int keyStart = serializedJson.IndexOf(keyIdentifier);
            if (keyStart < 0)
                Assert.Fail("Serialized JSON does not contain DHRatchetPublicKey field.");
            keyStart += keyIdentifier.Length;
            int keyEnd = serializedJson.IndexOf("\"", keyStart);
            if (keyEnd < 0)
                Assert.Fail("Invalid JSON format for DHRatchetPublicKey.");

            // Replace the original Base64-encoded key with an invalid string
            string corruptedKeyValue = "!!!!!!"; // Characters '!' are not in the Base64 alphabet.
            string corruptedJson = serializedJson.Substring(0, keyStart)
                                   + corruptedKeyValue
                                   + serializedJson.Substring(keyEnd);
            byte[] corruptedBytes = System.Text.Encoding.UTF8.GetBytes(corruptedJson);

            // Act & Assert - This should now throw an InvalidDataException.
            SessionPersistence.DeserializeSession(corruptedBytes);
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
                Assert.AreEqual(originalSession.MessageNumberReceiving, loadedSession.MessageNumberReceiving);
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
                Assert.AreEqual(originalSession.MessageNumberReceiving, loadedSession.MessageNumberReceiving);
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
                DHRatchetPublicKey = Convert.ToBase64String(originalSession.DHRatchetKeyPair.PublicKey),
                DHRatchetPrivateKey = Convert.ToBase64String(originalSession.DHRatchetKeyPair.PrivateKey),
                RemoteDHRatchetKey = Convert.ToBase64String(originalSession.RemoteDHRatchetKey),
                RootKey = Convert.ToBase64String(originalSession.RootKey),
                SendingChainKey = Convert.ToBase64String(originalSession.SendingChainKey),
                ReceivingChainKey = Convert.ToBase64String(originalSession.ReceivingChainKey),
                originalSession.MessageNumberReceiving,
                originalSession.MessageNumberSending,
                originalSession.SessionId,
                ProcessedMessageIds = new[] { Guid.NewGuid(), Guid.NewGuid() }
            };

            string json = JsonSerializer.Serialize(sessionData);
            byte[] serializedData = Encoding.UTF8.GetBytes(json);

            // Act
            var deserializedSession = SessionPersistence.DeserializeSession(serializedData);

            // Assert
            Assert.IsNotNull(deserializedSession);
            Assert.AreEqual(originalSession.SessionId, deserializedSession.SessionId);
            Assert.AreEqual(originalSession.MessageNumberReceiving, deserializedSession.MessageNumberReceiving);
            Assert.AreEqual(originalSession.MessageNumberSending, deserializedSession.MessageNumberSending);
        }
    }
}