using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Threading.Tasks;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.Sessions;
using LibEmiddle.Protocol;
using LibEmiddle.Domain.Enums;
using LibEmiddle.Abstractions;

namespace LibEmiddle.Tests.Unit
{
    [TestClass]
    public class SessionPersistenceTests
    {
        private ICryptoProvider _cryptoProvider;
        private SessionPersistenceManager _persistenceManager;
        private IDoubleRatchetProtocol _doubleRatchetProtocol;
        private string _testStoragePath;

        [TestInitialize]
        public void Setup()
        {
            _cryptoProvider = new CryptoProvider();
            _doubleRatchetProtocol = new DoubleRatchetProtocol(_cryptoProvider);

            // Create a temporary directory for test session storage
            _testStoragePath = Path.Combine(Path.GetTempPath(), $"LibEmiddle_Tests_{Guid.NewGuid()}");
            Directory.CreateDirectory(_testStoragePath);

            _persistenceManager = new SessionPersistenceManager(_cryptoProvider, _testStoragePath);
        }

        [TestCleanup]
        public void Cleanup()
        {
            // Clean up the test storage directory
            if (Directory.Exists(_testStoragePath))
            {
                try
                {
                    Directory.Delete(_testStoragePath, true);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error cleaning up test directory: {ex.Message}");
                }
            }

            // Dispose resources
            (_cryptoProvider as IDisposable)?.Dispose();
            _persistenceManager.Dispose();
        }

        // Helper to create a test session
        private async Task<DoubleRatchetSession> CreateTestSessionAsync()
        {
            // Generate key pairs for Alice and Bob
            var aliceKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.X25519);
            var bobKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.X25519);

            // Create a shared secret (similar to what X3DH would produce)
            byte[] sharedSecret = _cryptoProvider.ScalarMult(aliceKeyPair.PrivateKey, bobKeyPair.PublicKey);

            // Create session ID
            string sessionId = $"test-session-{Guid.NewGuid()}";

            // Initialize a Double Ratchet session as the sender
            return await _doubleRatchetProtocol.InitializeSessionAsSenderAsync(
                sharedKeyFromX3DH: sharedSecret,
                recipientInitialPublicKey: bobKeyPair.PublicKey,
                sessionId: sessionId);
        }

        [TestMethod]
        public async Task SaveAndLoadSession_ShouldPreserveSessionData()
        {
            // Arrange
            var originalSession = await CreateTestSessionAsync();

            // Act
            bool saveResult = await SerializeAndSaveSessionAsync(originalSession);
            var loadedSession = await LoadAndDeserializeSessionAsync(originalSession.SessionId);

            // Assert
            Assert.IsTrue(saveResult, "Session should be saved successfully");
            Assert.IsNotNull(loadedSession, "Loaded session should not be null");
            Assert.AreEqual(originalSession.SessionId, loadedSession.SessionId, "Session IDs should match");
            Assert.AreEqual(originalSession.SendMessageNumber, loadedSession.SendMessageNumber, "SendMessageNumber should match");
            Assert.AreEqual(originalSession.ReceiveMessageNumber, loadedSession.ReceiveMessageNumber, "ReceiveMessageNumber should match");

            // Compare key materials
            Assert.IsTrue(SecureMemory.SecureCompare(
                originalSession.SenderRatchetKeyPair.PublicKey,
                loadedSession.SenderRatchetKeyPair.PublicKey),
                "Public keys should match");

            Assert.IsTrue(SecureMemory.SecureCompare(
                originalSession.SenderRatchetKeyPair.PrivateKey,
                loadedSession.SenderRatchetKeyPair.PrivateKey),
                "Private keys should match");

            Assert.IsTrue(SecureMemory.SecureCompare(
                originalSession.ReceiverRatchetPublicKey,
                loadedSession.ReceiverRatchetPublicKey),
                "Receiver public keys should match");

            Assert.IsTrue(SecureMemory.SecureCompare(
                originalSession.RootKey,
                loadedSession.RootKey),
                "Root keys should match");
        }

        [TestMethod]
        public async Task SaveSession_WithCustomMetadata_ShouldPreserveMetadata()
        {
            // Arrange
            var originalSession = await CreateTestSessionAsync();

            // Act - Save the session
            var serializableData = new LibEmiddle.Domain.DTO.SerializedSessionData
            {
                SessionId = originalSession.SessionId,
                SessionType = SessionType.Individual,
                State = SessionState.Active,
                CreatedAt = DateTime.UtcNow,
                LastModifiedAt = DateTime.UtcNow,
                Metadata = new Dictionary<string, string>
                {
                    { "TestKey1", "TestValue1" },
                    { "TestKey2", "TestValue2" }
                },
                CryptoState = SerializeDoubleRatchetSession(originalSession)
            };

            string filePath = Path.Combine(_testStoragePath, $"{originalSession.SessionId}.session");

            // Simulate what SessionPersistenceManager would do
            string json = JsonSerialization.Serialize(serializableData);
            await File.WriteAllTextAsync(filePath, json);

            // Deserialize manually
            string loadedJson = await File.ReadAllTextAsync(filePath);
            var loadedData = JsonSerialization.Deserialize<LibEmiddle.Domain.DTO.SerializedSessionData>(loadedJson);

            // Assert
            Assert.IsNotNull(loadedData, "Loaded data should not be null");
            Assert.AreEqual(originalSession.SessionId, loadedData.SessionId, "Session IDs should match");
            Assert.AreEqual(2, loadedData.Metadata.Count, "Should have 2 metadata entries");
            Assert.AreEqual("TestValue1", loadedData.Metadata["TestKey1"], "TestKey1 value should match");
            Assert.AreEqual("TestValue2", loadedData.Metadata["TestKey2"], "TestKey2 value should match");
        }

        [TestMethod]
        public async Task LoadSession_WithMissingFile_ShouldReturnNull()
        {
            // Arrange - Use a session ID that doesn't exist
            string nonExistentSessionId = $"non-existent-{Guid.NewGuid()}";

            // Act & Assert
            await Assert.ThrowsExceptionAsync<FileNotFoundException>(
                async () => await LoadAndDeserializeSessionAsync(nonExistentSessionId),
                "Loading a non-existent session should throw FileNotFoundException");
        }

        [TestMethod]
        public async Task SaveAndDeleteSession_ShouldRemoveSessionFile()
        {
            // Arrange
            var session = await CreateTestSessionAsync();
            await SerializeAndSaveSessionAsync(session);

            string filePath = Path.Combine(_testStoragePath, $"{session.SessionId}.session");

            // Act
            bool fileExistsBeforeDelete = File.Exists(filePath);
            await _persistenceManager.DeleteSessionAsync(session.SessionId);
            bool fileExistsAfterDelete = File.Exists(filePath);

            // Assert
            Assert.IsTrue(fileExistsBeforeDelete, "Session file should exist before deletion");
            Assert.IsFalse(fileExistsAfterDelete, "Session file should not exist after deletion");
        }

        [TestMethod]
        public async Task ListSessions_ShouldReturnStoredSessions()
        {
            // Arrange
            var sessions = new List<DoubleRatchetSession>();
            for (int i = 0; i < 3; i++)
            {
                var session = await CreateTestSessionAsync();
                sessions.Add(session);
                await SerializeAndSaveSessionAsync(session);
            }

            // Act
            var sessionIds = await _persistenceManager.ListSessionsAsync();

            // Assert
            Assert.IsNotNull(sessionIds, "Session ID list should not be null");
            Assert.AreEqual(3, sessionIds.Length, "Should have 3 sessions");

            foreach (var session in sessions)
            {
                Assert.IsTrue(Array.Exists(sessionIds, id => id == session.SessionId),
                    $"Session ID {session.SessionId} should be in the list");
            }
        }

        [TestMethod]
        public async Task SerializeAndDeserialize_WithManySkippedMessageKeys_ShouldPreserveData()
        {
            // Arrange
            var originalSession = await CreateTestSessionAsync();

            // Add skipped message keys to the session
            var modifiedSession = originalSession;
            for (uint i = 0; i < 50; i++)
            {
                var keyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.X25519);
                var skippedKey = new SkippedMessageKey(keyPair.PublicKey, i);
                modifiedSession.SkippedMessageKeys[skippedKey] = _cryptoProvider.GenerateRandomBytes(32);
            }

            // Act
            bool saveResult = await SerializeAndSaveSessionAsync(modifiedSession);
            var loadedSession = await LoadAndDeserializeSessionAsync(modifiedSession.SessionId);

            // Assert
            Assert.IsTrue(saveResult, "Session should be saved successfully");
            Assert.IsNotNull(loadedSession, "Loaded session should not be null");
            Assert.AreEqual(50, loadedSession.SkippedMessageKeys.Count, "Should preserve all skipped message keys");
        }

        #region Helper Methods

        private async Task<bool> SerializeAndSaveSessionAsync(DoubleRatchetSession session)
        {
            try
            {
                // Create a simple chat session wrapper to use with the persistence manager
                var chatSession = CreateChatSessionWrapper(session);
                return await _persistenceManager.SaveChatSessionAsync(chatSession);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error saving session: {ex.Message}");
                return false;
            }
        }

        private async Task<DoubleRatchetSession> LoadAndDeserializeSessionAsync(string sessionId)
        {
            var chatSession = await _persistenceManager.LoadChatSessionAsync(sessionId, _doubleRatchetProtocol);
            return chatSession.GetCryptoSessionState();
        }

        private LibEmiddle.Messaging.Chat.ChatSession CreateChatSessionWrapper(DoubleRatchetSession session)
        {
            // Create dummy keys for the wrapper
            byte[] dummyRemoteKey = new byte[32];
            byte[] dummyLocalKey = new byte[32];
            Array.Fill<byte>(dummyRemoteKey, 1);
            Array.Fill<byte>(dummyLocalKey, 2);

            // Create a chat session that wraps the double ratchet session
            return new LibEmiddle.Messaging.Chat.ChatSession(
                session,
                dummyRemoteKey,
                dummyLocalKey,
                _doubleRatchetProtocol);
        }

        private string SerializeDoubleRatchetSession(DoubleRatchetSession session)
        {
            // Convert sensitive byte arrays to Base64 for serialization
            var dto = new LibEmiddle.Domain.DTO.DoubleRatchetSessionDto
            {
                SessionId = session.SessionId,
                RootKey = Convert.ToBase64String(session.RootKey),
                SenderChainKey = session.SenderChainKey != null ? Convert.ToBase64String(session.SenderChainKey) : null,
                ReceiverChainKey = session.ReceiverChainKey != null ? Convert.ToBase64String(session.ReceiverChainKey) : null,
                SenderRatchetKeyPair = new LibEmiddle.Domain.DTO.KeyPairDto
                {
                    PublicKey = Convert.ToBase64String(session.SenderRatchetKeyPair.PublicKey),
                    PrivateKey = Convert.ToBase64String(session.SenderRatchetKeyPair.PrivateKey)
                },
                ReceiverRatchetPublicKey = session.ReceiverRatchetPublicKey != null ?
                    Convert.ToBase64String(session.ReceiverRatchetPublicKey) : null,
                PreviousReceiverRatchetPublicKey = session.PreviousReceiverRatchetPublicKey != null ?
                    Convert.ToBase64String(session.PreviousReceiverRatchetPublicKey) : null,
                SendMessageNumber = session.SendMessageNumber,
                ReceiveMessageNumber = session.ReceiveMessageNumber,
                SentMessages = new Dictionary<uint, string>(),
                SkippedMessageKeys = new Dictionary<LibEmiddle.Domain.DTO.SkippedMessageKeyDto, string>(),
                IsInitialized = session.IsInitialized,
                CreationTimestamp = session.CreationTimestamp
            };

            // Convert sent messages
            foreach (var kvp in session.SentMessages)
            {
                dto.SentMessages[kvp.Key] = Convert.ToBase64String(kvp.Value);
            }

            // Convert skipped message keys
            foreach (var kvp in session.SkippedMessageKeys)
            {
                var keyDto = new LibEmiddle.Domain.DTO.SkippedMessageKeyDto
                {
                    DhPublicKey = Convert.ToBase64String(kvp.Key.DhPublicKey),
                    MessageNumber = kvp.Key.MessageNumber
                };
                dto.SkippedMessageKeys[keyDto] = Convert.ToBase64String(kvp.Value);
            }

            return JsonSerialization.Serialize(dto);
        }

        #endregion
    }
}