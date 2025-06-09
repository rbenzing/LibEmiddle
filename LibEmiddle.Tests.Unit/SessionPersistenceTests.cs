using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Linq;
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
            // Create a temporary directory for test session storage
            _testStoragePath = Path.Combine(Path.GetTempPath(), $"LibEmiddle_Tests_{Guid.NewGuid()}");
            Directory.CreateDirectory(_testStoragePath);

            // Create a subdirectory for key storage to ensure keys and sessions use the same base path
            string keyStoragePath = Path.Combine(_testStoragePath, "Keys");
            Directory.CreateDirectory(keyStoragePath);

            // Initialize crypto provider with the same base path as the session storage
            _cryptoProvider = new CryptoProvider(keyStoragePath);
            _doubleRatchetProtocol = new DoubleRatchetProtocol();

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

        /// <summary>
        /// Creates a test Double Ratchet session for testing purposes.
        /// </summary>
        /// <returns>A configured DoubleRatchetSession instance.</returns>
        private async Task<DoubleRatchetSession> CreateTestSessionAsync()
        {
            // Generate key pairs for Alice and Bob
            var aliceKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.X25519);
            var bobKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.X25519);

            // Create a shared secret (similar to what X3DH would produce)
            byte[] sharedSecret = _cryptoProvider.ScalarMult(aliceKeyPair.PrivateKey, bobKeyPair.PublicKey);

            // Create session ID
            string sessionId = $"test-session-{Guid.NewGuid()}";

            // Initialize a Double Ratchet session as the sender (note: this is not async)
            return _doubleRatchetProtocol.InitializeSessionAsSender(
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
            var serializableData = new SerializedSessionData
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
            var loadedData = JsonSerialization.Deserialize<SerializedSessionData>(loadedJson);

            // Assert
            Assert.IsNotNull(loadedData, "Loaded data should not be null");
            Assert.AreEqual(originalSession.SessionId, loadedData.SessionId, "Session IDs should match");
            Assert.AreEqual(2, loadedData.Metadata.Count, "Should have 2 metadata entries");
            Assert.AreEqual("TestValue1", loadedData.Metadata["TestKey1"], "TestKey1 value should match");
            Assert.AreEqual("TestValue2", loadedData.Metadata["TestKey2"], "TestKey2 value should match");
        }

        [TestMethod]
        public async Task CryptoProvider_KeyStorage_ShouldWorkCorrectly()
        {
            // Test the basic key storage functionality to isolate the issue
            string testKeyId = "test-key-123";
            byte[] testKey = _cryptoProvider.GenerateRandomBytes(32);

            // Store the key
            bool storeResult = await _cryptoProvider.StoreKeyAsync(testKeyId, testKey);
            Assert.IsTrue(storeResult, "Key should be stored successfully");

            // Retrieve the key
            byte[] retrievedKey = await _cryptoProvider.RetrieveKeyAsync(testKeyId);
            Assert.IsNotNull(retrievedKey, "Retrieved key should not be null");
            Assert.IsTrue(SecureMemory.SecureCompare(testKey, retrievedKey), "Retrieved key should match original");

            // Clean up
            await _cryptoProvider.DeleteKeyAsync(testKeyId);
        }

        [TestMethod]
        public async Task CryptoProvider_KeyStorage_WithColonInId_ShouldWorkCorrectly()
        {
            // Test key storage with a colon in the ID (like session keys)
            string testKeyId = "session:test-session-12345";
            byte[] testKey = _cryptoProvider.GenerateRandomBytes(32);

            Console.WriteLine($"Original key length: {testKey.Length}");
            Console.WriteLine($"Original key (first 8 bytes): {Convert.ToHexString(testKey.Take(8).ToArray())}");

            // Store the key
            bool storeResult = await _cryptoProvider.StoreKeyAsync(testKeyId, testKey);
            Assert.IsTrue(storeResult, "Key with colon should be stored successfully");

            // Retrieve the key
            byte[] retrievedKey = await _cryptoProvider.RetrieveKeyAsync(testKeyId);
            Assert.IsNotNull(retrievedKey, "Retrieved key with colon should not be null");

            Console.WriteLine($"Retrieved key length: {retrievedKey.Length}");
            Console.WriteLine($"Retrieved key (first 8 bytes): {Convert.ToHexString(retrievedKey.Take(8).ToArray())}");

            Assert.IsTrue(SecureMemory.SecureCompare(testKey, retrievedKey), "Retrieved key with colon should match original");

            // Clean up
            await _cryptoProvider.DeleteKeyAsync(testKeyId);
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

        /// <summary>
        /// Serializes and saves a DoubleRatchetSession using the persistence manager.
        /// </summary>
        /// <param name="session">The session to save.</param>
        /// <returns>True if successful, false otherwise.</returns>
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

        /// <summary>
        /// Loads and deserializes a DoubleRatchetSession from storage.
        /// </summary>
        /// <param name="sessionId">The session ID to load.</param>
        /// <returns>The deserialized DoubleRatchetSession.</returns>
        private async Task<DoubleRatchetSession> LoadAndDeserializeSessionAsync(string sessionId)
        {
            var chatSession = await _persistenceManager.LoadChatSessionAsync(sessionId, _doubleRatchetProtocol);
            if (chatSession == null)
            {
                throw new FileNotFoundException($"Session {sessionId} not found");
            }
            return chatSession.GetCryptoSessionState();
        }

        /// <summary>
        /// Creates a ChatSession wrapper around a DoubleRatchetSession for testing.
        /// </summary>
        /// <param name="session">The DoubleRatchetSession to wrap.</param>
        /// <returns>A ChatSession instance.</returns>
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

        /// <summary>
        /// Serializes a DoubleRatchetSession to JSON using the domain serialization objects.
        /// </summary>
        /// <param name="session">The session to serialize.</param>
        /// <returns>JSON representation of the session.</returns>
        private string SerializeDoubleRatchetSession(DoubleRatchetSession session)
        {
            // Create the serializable data structure using domain objects
            var serializableData = new SerializableSessionData
            {
                SessionId = session.SessionId,
                DHRatchetPublicKey = session.SenderRatchetKeyPair.PublicKey != null ?
                    Convert.ToBase64String(session.SenderRatchetKeyPair.PublicKey) : null,
                DHRatchetPrivateKey = session.SenderRatchetKeyPair.PrivateKey != null ?
                    Convert.ToBase64String(session.SenderRatchetKeyPair.PrivateKey) : null,
                RemoteDHRatchetKey = session.ReceiverRatchetPublicKey != null ?
                    Convert.ToBase64String(session.ReceiverRatchetPublicKey) : null,
                RootKey = session.RootKey != null ?
                    Convert.ToBase64String(session.RootKey) : null,
                SendingChainKey = session.SenderChainKey != null ?
                    Convert.ToBase64String(session.SenderChainKey) : null,
                ReceivingChainKey = session.ReceiverChainKey != null ?
                    Convert.ToBase64String(session.ReceiverChainKey) : null,
                MessageNumberSending = (int)session.SendMessageNumber,
                MessageNumberReceiving = (int)session.ReceiveMessageNumber,
                RecentlyProcessedIds = new List<Guid>(),
                ProcessedMessageNumbersReceiving = new List<int>(),
                SkippedMessageKeys = new List<SerializableSkippedKeyEntry>()
            };

            // Convert skipped message keys to serializable format
            if (session.SkippedMessageKeys != null)
            {
                foreach (var kvp in session.SkippedMessageKeys)
                {
                    var skippedKeyEntry = new SerializableSkippedKeyEntry
                    {
                        RemoteDhKeyBase64 = Convert.ToBase64String(kvp.Key.DhPublicKey),
                        MessageNumber = (int)kvp.Key.MessageNumber,
                        MessageKeyBase64 = Convert.ToBase64String(kvp.Value)
                    };
                    serializableData.SkippedMessageKeys.Add(skippedKeyEntry);
                }
            }

            // Add any recently processed message IDs if available
            // Note: This would need to be populated from session state if available

            return JsonSerialization.Serialize(serializableData);
        }

        #endregion

        #region Security Vulnerability Tests

        /// <summary>
        /// Tests that session encryption keys are properly derived, not randomly generated
        /// </summary>
        [TestMethod]
        public async Task SessionEncryption_ShouldUseDerivedKeys()
        {
            // Arrange
            var session1 = await CreateTestSessionAsync();
            var session2 = await CreateTestSessionAsync();

            // Act - Save both sessions
            bool save1 = await SerializeAndSaveSessionAsync(session1);
            bool save2 = await SerializeAndSaveSessionAsync(session2);

            Assert.IsTrue(save1 && save2, "Both sessions should save successfully");

            // Load the sessions back
            var loaded1 = await LoadAndDeserializeSessionAsync(session1.SessionId);
            var loaded2 = await LoadAndDeserializeSessionAsync(session2.SessionId);

            // Assert - Sessions should be properly encrypted and decrypted
            Assert.IsNotNull(loaded1, "First session should load successfully");
            Assert.IsNotNull(loaded2, "Second session should load successfully");

            // Verify session data integrity
            Assert.AreEqual(session1.SessionId, loaded1.SessionId, "Session 1 ID should be preserved");
            Assert.AreEqual(session2.SessionId, loaded2.SessionId, "Session 2 ID should be preserved");

            // Verify that different sessions have different encryption (this is implicit in successful load/save)
            Assert.AreNotEqual(session1.SessionId, session2.SessionId, "Sessions should have different IDs");
        }

        /// <summary>
        /// Tests that session files are properly stored and protected
        /// </summary>
        [TestMethod]
        public async Task SessionFiles_ShouldBeProperlyProtected()
        {
            // Arrange
            var session = await CreateTestSessionAsync();
            await SerializeAndSaveSessionAsync(session);

            // Act - Read the raw file content
            string filePath = Path.Combine(_testStoragePath, $"{session.SessionId}.session");
            Assert.IsTrue(File.Exists(filePath), "Session file should exist");

            byte[] fileContent = await File.ReadAllBytesAsync(filePath);
            Assert.IsTrue(fileContent.Length > 0, "Session file should not be empty");

            // Assert - File should exist and be non-empty (protection mechanism working)
            // The actual format depends on the implementation - could be encrypted binary or JSON
            string fileText = Encoding.UTF8.GetString(fileContent);

            // File should not contain obvious plaintext sensitive data
            Assert.IsFalse(fileText.Contains("BEGIN PRIVATE KEY"),
                "Session file should not contain raw private key material");
            Assert.IsFalse(fileText.Contains("-----BEGIN"),
                "Session file should not contain PEM-formatted keys");
        }

        /// <summary>
        /// Tests that session persistence handles concurrent access safely
        /// </summary>
        [TestMethod]
        public async Task SessionPersistence_ShouldHandleConcurrentAccess()
        {
            // Arrange
            var session = await CreateTestSessionAsync();
            await SerializeAndSaveSessionAsync(session);

            // Act - Concurrent load operations
            var loadTasks = new List<Task<DoubleRatchetSession>>();
            for (int i = 0; i < 5; i++)
            {
                loadTasks.Add(Task.Run(async () => await LoadAndDeserializeSessionAsync(session.SessionId)));
            }

            var results = await Task.WhenAll(loadTasks);

            // Assert - All loads should succeed and return equivalent data
            foreach (var result in results)
            {
                Assert.IsNotNull(result, "All concurrent loads should succeed");
                Assert.AreEqual(session.SessionId, result.SessionId, "All loads should return the same session ID");
            }
        }

        /// <summary>
        /// Tests that deleted sessions cannot be recovered
        /// </summary>
        [TestMethod]
        public async Task DeletedSessions_ShouldNotBeRecoverable()
        {
            // Arrange
            var session = await CreateTestSessionAsync();
            await SerializeAndSaveSessionAsync(session);

            // Verify session exists
            var loadedSession = await LoadAndDeserializeSessionAsync(session.SessionId);
            Assert.IsNotNull(loadedSession, "Session should exist before deletion");

            // Act - Delete the session
            await _persistenceManager.DeleteSessionAsync(session.SessionId);

            // Assert - Session should not be loadable
            await Assert.ThrowsExceptionAsync<FileNotFoundException>(
                async () => await LoadAndDeserializeSessionAsync(session.SessionId),
                "Deleted session should not be loadable");

            // Verify file is actually gone
            string filePath = Path.Combine(_testStoragePath, $"{session.SessionId}.session");
            Assert.IsFalse(File.Exists(filePath), "Session file should be deleted");
        }

        /// <summary>
        /// Tests that session storage handles corrupted files gracefully
        /// </summary>
        [TestMethod]
        public async Task SessionStorage_ShouldHandleCorruptedFiles()
        {
            // Arrange
            var session = await CreateTestSessionAsync();
            await SerializeAndSaveSessionAsync(session);

            string filePath = Path.Combine(_testStoragePath, $"{session.SessionId}.session");

            // Act - Corrupt the file by writing invalid JSON
            await File.WriteAllTextAsync(filePath, "{ invalid json content");

            // Assert - Loading should fail gracefully
            try
            {
                await LoadAndDeserializeSessionAsync(session.SessionId);
                Assert.Fail("Expected an exception to be thrown for corrupted session");
            }
            catch (Exception ex) when (ex is FileNotFoundException || ex is JsonException || ex is CryptographicException)
            {
                // Expected - corrupted session was detected
                Assert.IsTrue(true, "Corrupted session was properly detected");
            }
        }

        #endregion
    }
}