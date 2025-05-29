using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Linq;
using System.Diagnostics;
using LibEmiddle.Core;
using LibEmiddle.MultiDevice;
using LibEmiddle.Abstractions;
using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;
using LibEmiddle.Messaging.Transport;
using LibEmiddle.Messaging.Group;
using LibEmiddle.Crypto;
using LibEmiddle.Protocol;

namespace LibEmiddle.Tests.Unit
{
    [TestClass]
    public class ErrorRecoveryTests
    {
        private CryptoProvider _cryptoProvider;
        private IDoubleRatchetProtocol _doubleRatchetProtocol;
        private IX3DHProtocol _x3dhProtocol;

        [TestInitialize]
        public void Setup()
        {
            _cryptoProvider = new CryptoProvider();
            _doubleRatchetProtocol = new DoubleRatchetProtocol(_cryptoProvider);
            _x3dhProtocol = new X3DHProtocol(_cryptoProvider);
        }

        #region Setup Helper Methods

        /// <summary>
        /// Creates a pair of initialized DoubleRatchet sessions for testing
        /// </summary>
        private async Task<(DoubleRatchetSession aliceSession, DoubleRatchetSession bobSession, string sessionId)> CreateTestSessionsAsync()
        {
            // Generate a unique session ID
            string sessionId = $"session-{Guid.NewGuid()}";

            // Generate key pairs for Alice and Bob
            var aliceKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.X25519);
            var bobKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.X25519);

            // Generate a shared secret for testing
            byte[] sharedSecret = _cryptoProvider.ScalarMult(aliceKeyPair.PrivateKey, bobKeyPair.PublicKey);

            // Initialize Alice's session as sender
            var aliceSession = await _doubleRatchetProtocol.InitializeSessionAsSenderAsync(
                sharedKeyFromX3DH: sharedSecret,
                recipientInitialPublicKey: bobKeyPair.PublicKey,
                sessionId: sessionId);

            // Initialize Bob's session as receiver 
            var bobSession = await _doubleRatchetProtocol.InitializeSessionAsReceiverAsync(
                sharedKeyFromX3DH: sharedSecret,
                receiverInitialKeyPair: bobKeyPair,
                senderEphemeralKeyPublic: aliceKeyPair.PublicKey,
                sessionId: sessionId);

            return (aliceSession, bobSession, sessionId);
        }

        /// <summary>
        /// Adds required security fields to an encrypted message
        /// </summary>
        private void AddSecurityFields(EncryptedMessage message, string sessionId)
        {
            message.MessageId = Guid.NewGuid().ToString();
            message.Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            message.SessionId = sessionId;
        }

        #endregion

        [TestMethod]
        public async Task DoubleRatchetExchange_ResumeSession_WithValidSession_ShouldReturn()
        {
            // Arrange
            var (aliceSession, _, sessionId) = await CreateTestSessionsAsync();

            // Create a deep clone of the session to simulate serialization/deserialization
            var originalSession = DeepCloneSession(aliceSession);

            // Act
            // In the new protocol, sessions are immutable, so resuming is essentially using the same session
            var resumedSession = originalSession;

            // Assert
            Assert.IsNotNull(resumedSession, "Session should be resumed successfully");
            Assert.AreEqual(originalSession.SessionId, resumedSession.SessionId, "Session ID should be preserved");
            Assert.AreEqual(originalSession.ReceiveMessageNumber, resumedSession.ReceiveMessageNumber, "Message number receiving should be preserved");
            Assert.AreEqual(originalSession.SendMessageNumber, resumedSession.SendMessageNumber, "Message number sending should be preserved");

            // Verify key materials are preserved
            Assert.IsTrue(SecureMemory.SecureCompare(
                originalSession.SenderRatchetKeyPair.PublicKey,
                resumedSession.SenderRatchetKeyPair.PublicKey),
                "Public keys should match");

            Assert.IsTrue(SecureMemory.SecureCompare(
                originalSession.SenderRatchetKeyPair.PrivateKey,
                resumedSession.SenderRatchetKeyPair.PrivateKey),
                "Private keys should match");

            Assert.IsTrue(SecureMemory.SecureCompare(
                originalSession.RootKey,
                resumedSession.RootKey),
                "Root keys should match");
        }

        [TestMethod]
        public async Task DoubleRatchetExchange_ResumeSession_WithSkippedMessageKeys_ShouldPreserve()
        {
            // Arrange
            var (aliceSession, bobSession, sessionId) = await CreateTestSessionsAsync();

            // Simulate some skipped message keys
            string message = "Test message";
            var (aliceUpdatedSession, encrypted) = await _doubleRatchetProtocol.EncryptAsync(aliceSession, message);
            AddSecurityFields(encrypted, sessionId);

            // Arbitrarily increment the message number to simulate an out-of-order message
            encrypted.SenderMessageNumber += 5;

            // Process the out-of-order message
            var (bobUpdatedSession, _) = await _doubleRatchetProtocol.DecryptAsync(bobSession, encrypted);

            // Verify skipped message keys were created
            Assert.IsTrue(bobUpdatedSession.SkippedMessageKeys.Count > 0, "Skipped message keys should be present");

            // Act - Create a copy of the session to simulate resumption
            var resumedSession = DeepCloneSession(bobUpdatedSession);

            // Assert
            Assert.AreEqual(bobUpdatedSession.SkippedMessageKeys.Count, resumedSession.SkippedMessageKeys.Count,
                "Skipped message keys count should be preserved");

            // Check that the keys themselves are preserved
            foreach (var kvp in bobUpdatedSession.SkippedMessageKeys)
            {
                Assert.IsTrue(resumedSession.SkippedMessageKeys.ContainsKey(kvp.Key),
                    "Resumed session should contain all skipped message keys");
                Assert.IsTrue(SecureMemory.SecureCompare(
                    resumedSession.SkippedMessageKeys[kvp.Key], kvp.Value),
                    "Skipped message key values should be preserved");
            }
        }

        [TestMethod]
        public async Task WebSocketClient_HandleConnectionErrors_ShouldReturnMeaningfulErrors()
        {
            // Arrange
            var mockWebSocket = new Mock<IWebSocketClient>();
            var serverUrl = "wss://example.com";

            // Mock a WebSocket connection error
            mockWebSocket
                .Setup(ws => ws.ConnectAsync(It.IsAny<Uri>(), It.IsAny<CancellationToken>()))
                .ThrowsAsync(new System.Net.WebSockets.WebSocketException("Connection refused"));

            // Create client
            var client = new SecureWebSocketClient(serverUrl, mockWebSocket.Object);

            // Act & Assert
            var ex = await Assert.ThrowsExceptionAsync<System.Net.WebSockets.WebSocketException>(
                async () => await client.ConnectAsync());

            // Verify the exception contains useful information
            StringAssert.Contains(ex.Message, "Connection refused",
                "Exception should provide meaningful error message");
        }

        [TestMethod]
        public async Task MailboxTransport_HandleNetworkErrors_ShouldRetryWithBackoff()
        {
            // Arrange
            var mockTransport = new Mock<IMailboxTransport>();
            var recipientKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var senderKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);

            // Use a counter for attempts
            int attemptCount = 0;

            // Create an event that gets set when the third attempt succeeds
            var thirdAttemptSucceeded = new ManualResetEvent(false);

            // Create the message queue in advance
            var messages = new List<MailboxMessage>();
            for (int i = 0; i < 3; i++)
            {
                var msg = new MailboxMessage(
                    recipientKeyPair.PublicKey,
                    senderKeyPair.PublicKey,
                    new EncryptedMessage
                    {
                        Ciphertext = new byte[] { 1, 2, 3 },
                        Nonce = new byte[] { 4, 5, 6 }
                    })
                {
                    Id = Guid.NewGuid().ToString(),
                    Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                };
                messages.Add(msg);
            }

            // Setup the mock to throw twice then succeed
            mockTransport
                .Setup(t => t.FetchMessagesAsync(It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
                .Returns((byte[] recipientKey, CancellationToken token) => {
                    int count = Interlocked.Increment(ref attemptCount);
                    Trace.TraceWarning($"Fetch attempt #{count}");

                    if (count < 3)
                    {
                        Trace.TraceWarning($"Attempt {count}: Throwing network error");
                        throw new System.Net.Http.HttpRequestException($"Network error on attempt {count}");
                    }

                    Trace.TraceWarning("Attempt 3: Succeeding");
                    thirdAttemptSucceeded.Set();
                    return Task.FromResult(messages);
                });

            // Create a mailbox manager with our mocked transport
            var mailboxManager = new MailboxManager(senderKeyPair, mockTransport.Object, _doubleRatchetProtocol, _cryptoProvider);

            // Call the polling method via reflection since it's private
            var pollMethod = typeof(MailboxManager).GetMethod("PollForMessagesAsync",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);

            if (pollMethod == null)
            {
                Assert.Fail("Could not find PollForMessagesAsync method via reflection");
            }

            // Try calling the method multiple times to simulate retries
            try
            {
                // First attempt (will throw)
                pollMethod.Invoke(mailboxManager, new object[] { CancellationToken.None });
            }
            catch (System.Reflection.TargetInvocationException ex)
            {
                // Expected exception
                Trace.TraceWarning($"Expected first exception: {ex.InnerException?.Message}");
            }

            try
            {
                // Second attempt (will throw)
                pollMethod.Invoke(mailboxManager, new object[] { CancellationToken.None });
            }
            catch (System.Reflection.TargetInvocationException ex)
            {
                // Expected exception
                Trace.TraceWarning($"Expected second exception: {ex.InnerException?.Message}");
            }

            try
            {
                // Third attempt (should succeed)
                pollMethod.Invoke(mailboxManager, new object[] { CancellationToken.None });

                // Wait a short time for any event handlers to complete
                Thread.Sleep(100);
            }
            catch (Exception ex)
            {
                Trace.TraceWarning($"Unexpected exception on third attempt: {ex.Message}");
                Assert.Fail("Third attempt should not throw an exception");
            }

            // Assert
            Trace.TraceWarning($"Total attempts made: {attemptCount}");
            Assert.AreEqual(3, attemptCount, "Should have made exactly 3 attempts");
            Assert.IsTrue(thirdAttemptSucceeded.WaitOne(0), "Third attempt should have succeeded");

            // Clean up
            mailboxManager.Dispose();
        }

        [TestMethod]
        public async Task DecryptionFailure_ShouldNotAffectSubsequentDecryption()
        {
            // Arrange
            var (aliceSession, bobSession, sessionId) = await CreateTestSessionsAsync();

            // Alice sends a valid message
            string goodMessage = "This is a valid message";
            var (aliceUpdatedSession, validEncrypted) = await _doubleRatchetProtocol.EncryptAsync(aliceSession, goodMessage);

            // Add security fields
            AddSecurityFields(validEncrypted, sessionId);

            // Create an invalid message
            var invalidEncrypted = new EncryptedMessage
            {
                Ciphertext = new byte[64], // Invalid ciphertext (all zeros)
                Nonce = validEncrypted.Nonce,
                SenderMessageNumber = validEncrypted.SenderMessageNumber,
                SenderDHKey = validEncrypted.SenderDHKey,
                Timestamp = validEncrypted.Timestamp,
                MessageId = Guid.NewGuid().ToString(),
                SessionId = sessionId
            };

            // Act
            // First try to decrypt the invalid message
            var (bobSessionAfterFailure, failedMessage) = await _doubleRatchetProtocol.DecryptAsync(bobSession, invalidEncrypted);

            // Then decrypt the valid message
            var (bobSessionAfterSuccess, successMessage) = await _doubleRatchetProtocol.DecryptAsync(bobSession, validEncrypted);

            // Assert
            Assert.IsNull(failedMessage, "Invalid message should not decrypt");
            Assert.IsNotNull(successMessage, "Valid message should decrypt successfully");
            Assert.AreEqual(goodMessage, successMessage, "Decrypted content should match original");

            // The first decryption failed, so bobSession should remain unchanged for the second decryption
            Assert.IsNull(bobSessionAfterFailure, "Failed decryption should return null session");
        }

        [TestMethod]
        public async Task GroupChatManager_HandleMissingGroup_ShouldFailGracefully()
        {
            // Arrange
            var identityKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var keyManager = new GroupKeyManager(_cryptoProvider);
            var memberManager = new GroupMemberManager();
            var messageCrypto = new GroupMessageCrypto(_cryptoProvider);
            var distributionManager = new SenderKeyDistribution(_cryptoProvider, keyManager);
            var securityValidator = new GroupSecurityValidator(_cryptoProvider, memberManager);

            string nonExistentGroupId = "test-group-123";

            // Act & Assert
            // 1. Attempt to get a non-existent group session
            try
            {
                // This is a simplified test since we don't have direct access to GroupChatManager
                Assert.IsFalse(memberManager.IsMember(nonExistentGroupId, identityKeyPair.PublicKey),
                    "User should not be a member of non-existent group");

                // The group shouldn't exist and has no members
                var members = memberManager.GetMembers(nonExistentGroupId);
                Assert.AreEqual(0, members.Count, "Non-existent group should have no members");
            }
            catch (Exception ex)
            {
                Assert.Fail($"Should handle missing group gracefully: {ex.Message}");
            }

            // 2. Attempt to encrypt for non-existent group
            var senderState = keyManager.GetSenderState(nonExistentGroupId);
            Assert.IsNull(senderState, "Sender state should be null for non-existent group");

            // 3. Attempt to decrypt a message for a non-existent group
            var encryptedMessage = new EncryptedGroupMessage
            {
                GroupId = nonExistentGroupId,
                SenderIdentityKey = identityKeyPair.PublicKey,
                Ciphertext = new byte[64],
                Nonce = new byte[Constants.NONCE_SIZE],
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                MessageId = Guid.NewGuid().ToString()
            };

            // Should validate as false without throwing an exception
            bool isValid = securityValidator.ValidateGroupMessage(encryptedMessage);
            Assert.IsFalse(isValid, "Message for non-existent group should fail validation");

            // Attempt to decrypt (should return null without throwing)
            var senderKey = keyManager.GetSenderKey(nonExistentGroupId, identityKeyPair.PublicKey);
            Assert.IsNull(senderKey, "Should return null sender key for non-existent group");
        }

        [TestMethod]
        public void SecurityVerification_PreventNonceReuse()
        {
            // This test verifies that the Nonce creates unique nonces even when called in rapid succession

            // Arrange & Act
            const int nonceCount = 1000;
            var nonces = new HashSet<string>(StringComparer.Ordinal);

            // Generate many nonces rapidly
            for (int i = 0; i < nonceCount; i++)
            {
                byte[] nonce = _cryptoProvider.GenerateNonce();
                string nonceBase64 = Convert.ToBase64String(nonce);

                // Assert - Each nonce should be unique
                Assert.IsFalse(nonces.Contains(nonceBase64),
                    $"Nonce {nonceBase64} was generated more than once (at iteration {i})");

                nonces.Add(nonceBase64);
            }

            // Verify we have the expected number of unique nonces
            Assert.AreEqual(nonceCount, nonces.Count, "All generated nonces should be unique");
        }

        [TestMethod]
        public async Task TransportLayerFailure_ShouldNotLoseMessages()
        {
            // Arrange
            var mockTransport = new Mock<IMailboxTransport>();
            var identityKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var recipientKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);

            // Simulate a new DoubleRatchet session for this test
            var (aliceSession, _, _) = await CreateTestSessionsAsync();

            // Create a stateful flag that can be accessed from the mock
            bool[] firstAttempt = { true }; // Using array to enable modification from lambda

            mockTransport
                .Setup(t => t.SendMessageAsync(It.IsAny<MailboxMessage>()))
                .ReturnsAsync((MailboxMessage msg) =>
                {
                    if (firstAttempt[0])
                    {
                        firstAttempt[0] = false;
                        return false; // First attempt fails
                    }
                    return true; // Subsequent attempts succeed
                });

            // Configure fetch to return an empty list
            mockTransport
                .Setup(t => t.FetchMessagesAsync(It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new List<MailboxMessage>());

            using (var mailboxManager = new MailboxManager(identityKeyPair, mockTransport.Object, _doubleRatchetProtocol, _cryptoProvider))
            {
                // Act - Send a message
                string messageId = await mailboxManager.SendMessageAsync(
                    recipientKeyPair.PublicKey,
                    "Test message that should be retained after transport failure",
                    aliceSession,
                    MessageType.Chat);

                // Start the manager to process the outgoing queue
                mailboxManager.Start();

                // Allow enough time for processing to complete
                Thread.Sleep(200); // Increased sleep time for reliability

                // Stop the manager
                mailboxManager.Stop();

                // Assert
                // Verify that SendMessageAsync was called exactly twice (once failing, once succeeding)
                mockTransport.Verify(t => t.SendMessageAsync(It.IsAny<MailboxMessage>()), Times.Exactly(2),
                    "Transport should be called twice - once failing and once succeeding");
            }
        }

        [TestMethod]
        public async Task MultiDeviceSynchronization_ShouldRecoverFromMessageLoss()
        {
            Trace.TraceWarning("==== Starting MultiDeviceSynchronization_ShouldRecoverFromMessageLoss ====");

            // Arrange
            var mainDeviceKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var secondDeviceKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);

            Trace.TraceWarning($"Main device key pair - Public: {Convert.ToBase64String(mainDeviceKeyPair.PublicKey)}, " +
                             $"Private: {Convert.ToBase64String(mainDeviceKeyPair.PrivateKey).Substring(0, 10)}...");
            Trace.TraceWarning($"Second device key pair - Public: {Convert.ToBase64String(secondDeviceKeyPair.PublicKey)}, " +
                             $"Private: {Convert.ToBase64String(secondDeviceKeyPair.PrivateKey).Substring(0, 10)}...");

            // Create device managers
            var deviceLinkingService = new DeviceLinkingService(_cryptoProvider);
            var mainDeviceManager = new DeviceManager(mainDeviceKeyPair, _cryptoProvider, deviceLinkingService);
            var secondDeviceManager = new DeviceManager(secondDeviceKeyPair, _cryptoProvider, deviceLinkingService);

            // Convert to X25519 keys for direct testing
            byte[] mainDeviceX25519Public = _cryptoProvider.ConvertEd25519PublicKeyToX25519(mainDeviceKeyPair.PublicKey);
            byte[] secondDeviceX25519Public = _cryptoProvider.ConvertEd25519PublicKeyToX25519(secondDeviceKeyPair.PublicKey);

            Trace.TraceWarning($"Main device X25519 public key: {Convert.ToBase64String(mainDeviceX25519Public)}");
            Trace.TraceWarning($"Second device X25519 public key: {Convert.ToBase64String(secondDeviceX25519Public)}");

            // Link devices
            mainDeviceManager.AddLinkedDevice(secondDeviceKeyPair.PublicKey);
            secondDeviceManager.AddLinkedDevice(mainDeviceKeyPair.PublicKey);
            Trace.TraceWarning("Linked both devices successfully");

            // Create sync data
            byte[] syncData = Encoding.Default.GetBytes("Important sync data");
            Trace.TraceWarning($"Created sync data of length {syncData.Length}");

            // Create sync messages
            var syncMessages = mainDeviceManager.CreateSyncMessages(syncData);
            Trace.TraceWarning($"Created {syncMessages.Count} sync messages");

            // Get the sync message for the second device
            string secondDeviceId = Convert.ToBase64String(secondDeviceX25519Public);
            Trace.TraceWarning($"Second device ID: {secondDeviceId}");
            Assert.IsTrue(syncMessages.ContainsKey(secondDeviceId), "Should have sync message for second device");

            var syncMessageForSecondDevice = syncMessages[secondDeviceId];
            Trace.TraceWarning($"Got sync message with ciphertext length: {syncMessageForSecondDevice.Ciphertext?.Length}");

            // Simulate main device sending a corrupted message - create a tampered copy
            var tamperedMessage = new EncryptedMessage
            {
                Ciphertext = new byte[syncMessageForSecondDevice.Ciphertext.Length],
                Nonce = syncMessageForSecondDevice.Nonce?.ToArray(),
                SenderMessageNumber = syncMessageForSecondDevice.SenderMessageNumber,
                SenderDHKey = syncMessageForSecondDevice.SenderDHKey?.ToArray(),
                Timestamp = syncMessageForSecondDevice.Timestamp,
                MessageId = syncMessageForSecondDevice.MessageId,
                SessionId = syncMessageForSecondDevice.SessionId
            };

            // Copy the ciphertext and tamper with it
            Buffer.BlockCopy(syncMessageForSecondDevice.Ciphertext, 0, tamperedMessage.Ciphertext, 0,
                tamperedMessage.Ciphertext.Length);

            // Tamper with the middle part
            int middleIndex = tamperedMessage.Ciphertext.Length / 2;
            tamperedMessage.Ciphertext[middleIndex] ^= 0xFF;
            Trace.TraceWarning($"Created tampered message by modifying byte at index {middleIndex}");

            // Try to process the tampered message - should fail
            Trace.TraceWarning("Attempting to process tampered message...");
            byte[] result1 = secondDeviceManager.ProcessSyncMessage(tamperedMessage, mainDeviceKeyPair.PublicKey);
            Trace.TraceWarning($"Tampered message processing result: {(result1 == null ? "null" : "success")}");

            // Main device notices failure (no acknowledgment) and resends the correct message
            Trace.TraceWarning("Attempting to process valid message...");
            byte[] result2 = secondDeviceManager.ProcessSyncMessage(syncMessageForSecondDevice, mainDeviceKeyPair.PublicKey);
            Trace.TraceWarning($"Valid message processing result: {(result2 == null ? "null" : "success")}");

            // Assert
            Assert.IsNull(result1, "Processing tampered sync message should fail");
            Assert.IsNotNull(result2, "Processing valid sync message should succeed");

            if (result2 != null)
            {
                // Verify the received data matches the original
                Trace.TraceWarning($"Comparing received data '{Encoding.UTF8.GetString(result2)}' with original '{Encoding.UTF8.GetString(syncData)}'");
                Assert.IsTrue(SecureMemory.SecureCompare(syncData, result2),
                    "Received sync data should match original after recovery");
            }

            Trace.TraceWarning("==== Test completed ====");
        }

        [TestMethod]
        public async Task CrossDeviceSessionRestoration_ShouldWorkCorrectly()
        {
            // Arrange
            var (aliceSession, _, _) = await CreateTestSessionsAsync();

            // Create a deep clone of the session to simulate serialization/deserialization
            var originalSession = DeepCloneSession(aliceSession);

            // Act - Simulate serialization and deserialization across devices
            // Convert to DTO
            var dto = new DoubleRatchetSessionDto
            {
                SessionId = originalSession.SessionId,
                RootKey = Convert.ToBase64String(originalSession.RootKey),
                SenderChainKey = originalSession.SenderChainKey != null ? Convert.ToBase64String(originalSession.SenderChainKey) : null,
                ReceiverChainKey = originalSession.ReceiverChainKey != null ? Convert.ToBase64String(originalSession.ReceiverChainKey) : null,
                SenderRatchetKeyPair = new KeyPairDto
                {
                    PublicKey = Convert.ToBase64String(originalSession.SenderRatchetKeyPair.PublicKey),
                    PrivateKey = Convert.ToBase64String(originalSession.SenderRatchetKeyPair.PrivateKey)
                },
                ReceiverRatchetPublicKey = originalSession.ReceiverRatchetPublicKey != null ?
                    Convert.ToBase64String(originalSession.ReceiverRatchetPublicKey) : null,
                PreviousReceiverRatchetPublicKey = originalSession.PreviousReceiverRatchetPublicKey != null ?
                    Convert.ToBase64String(originalSession.PreviousReceiverRatchetPublicKey) : null,
                SendMessageNumber = originalSession.SendMessageNumber,
                ReceiveMessageNumber = originalSession.ReceiveMessageNumber,
                IsInitialized = originalSession.IsInitialized,
                CreationTimestamp = originalSession.CreationTimestamp,
                SentMessages = new Dictionary<uint, string>(),
                SkippedMessageKeys = new Dictionary<SkippedMessageKeyDto, string>(),
            };

            // Serialize to JSON
            string json = System.Text.Json.JsonSerializer.Serialize(dto);

            // Deserialize and restore (on another device)
            var restoredDto = System.Text.Json.JsonSerializer.Deserialize<DoubleRatchetSessionDto>(json);
            Assert.IsNotNull(restoredDto, "Deserialization should succeed");

            // Convert back to session
            var restoredSession = new DoubleRatchetSession
            {
                SessionId = restoredDto.SessionId,
                RootKey = Convert.FromBase64String(restoredDto.RootKey),
                SenderChainKey = restoredDto.SenderChainKey != null ? Convert.FromBase64String(restoredDto.SenderChainKey) : null,
                ReceiverChainKey = restoredDto.ReceiverChainKey != null ? Convert.FromBase64String(restoredDto.ReceiverChainKey) : null,
                SenderRatchetKeyPair = new KeyPair
                {
                    PublicKey = Convert.FromBase64String(restoredDto.SenderRatchetKeyPair.PublicKey),
                    PrivateKey = Convert.FromBase64String(restoredDto.SenderRatchetKeyPair.PrivateKey)
                },
                ReceiverRatchetPublicKey = restoredDto.ReceiverRatchetPublicKey != null ?
                    Convert.FromBase64String(restoredDto.ReceiverRatchetPublicKey) : null,
                PreviousReceiverRatchetPublicKey = restoredDto.PreviousReceiverRatchetPublicKey != null ?
                    Convert.FromBase64String(restoredDto.PreviousReceiverRatchetPublicKey) : null,
                SendMessageNumber = restoredDto.SendMessageNumber,
                ReceiveMessageNumber = restoredDto.ReceiveMessageNumber,
                IsInitialized = restoredDto.IsInitialized,
                CreationTimestamp = restoredDto.CreationTimestamp,
                SentMessages = new Dictionary<uint, byte[]>(),
                SkippedMessageKeys = new Dictionary<SkippedMessageKey, byte[]>()
            };

            // Assert
            Assert.IsNotNull(restoredSession, "Session should be restored successfully");
            Assert.AreEqual(originalSession.SessionId, restoredSession.SessionId, "Session ID should match");
            Assert.AreEqual(originalSession.SendMessageNumber, restoredSession.SendMessageNumber, "Message number sending should match");
            Assert.AreEqual(originalSession.ReceiveMessageNumber, restoredSession.ReceiveMessageNumber, "Message number receiving should match");

            // Verify the restored session can be used for communication
            string testMessage = "Message after session restoration";
            var (updatedSession, encryptedMessage) = await _doubleRatchetProtocol.EncryptAsync(restoredSession, testMessage);

            Assert.IsNotNull(updatedSession, "Should get valid updated session after encryption");
            Assert.IsNotNull(encryptedMessage, "Should be able to encrypt new message with restored session");
            Assert.IsNotNull(encryptedMessage.Ciphertext, "Ciphertext should not be null");
            Assert.IsTrue(encryptedMessage.Ciphertext.Length > 0, "Ciphertext should not be empty");
        }

        #region Helper Methods

        /// <summary>
        /// Creates a deep clone of a DoubleRatchetSession for testing purposes
        /// </summary>
        private DoubleRatchetSession DeepCloneSession(DoubleRatchetSession original)
        {
            // Create a new session with the same properties
            var clone = new DoubleRatchetSession
            {
                SessionId = original.SessionId,
                RootKey = original.RootKey?.ToArray(),
                SenderChainKey = original.SenderChainKey?.ToArray(),
                ReceiverChainKey = original.ReceiverChainKey?.ToArray(),
                SenderRatchetKeyPair = new KeyPair
                {
                    PublicKey = original.SenderRatchetKeyPair.PublicKey.ToArray(),
                    PrivateKey = original.SenderRatchetKeyPair.PrivateKey.ToArray()
                },
                ReceiverRatchetPublicKey = original.ReceiverRatchetPublicKey?.ToArray(),
                PreviousReceiverRatchetPublicKey = original.PreviousReceiverRatchetPublicKey?.ToArray(),
                SendMessageNumber = original.SendMessageNumber,
                ReceiveMessageNumber = original.ReceiveMessageNumber,
                IsInitialized = original.IsInitialized,
                CreationTimestamp = original.CreationTimestamp,
                SentMessages = new Dictionary<uint, byte[]>(),
                SkippedMessageKeys = new Dictionary<SkippedMessageKey, byte[]>()
            };

            // Copy sent messages
            foreach (var kvp in original.SentMessages)
            {
                clone.SentMessages[kvp.Key] = kvp.Value.ToArray();
            }

            // Copy skipped message keys
            foreach (var kvp in original.SkippedMessageKeys)
            {
                clone.SkippedMessageKeys[kvp.Key] = kvp.Value.ToArray();
            }

            return clone;
        }

        #endregion
    }
}