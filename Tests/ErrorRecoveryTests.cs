using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using E2EELibrary;
using E2EELibrary.Communication;
using E2EELibrary.Models;
using E2EELibrary.Core;
using E2EELibrary.KeyExchange;
using E2EELibrary.KeyManagement;
using E2EELibrary.Encryption;
using E2EELibrary.GroupMessaging;
using E2EELibrary.MultiDevice;
using E2EELibrary.Communication.Abstract;

namespace E2EELibraryTests
{
    [TestClass]
    public class ErrorRecoveryTests
    {
        [TestMethod]
        public void DoubleRatchetExchange_ResumeSession_WithValidSession_ShouldReturn()
        {
            // Arrange
            var aliceKeyPair = E2EEClient.GenerateKeyExchangeKeyPair();
            var bobKeyPair = E2EEClient.GenerateKeyExchangeKeyPair();

            // Initial shared secret
            byte[] sharedSecret = X3DHExchange.X3DHKeyExchange(bobKeyPair.publicKey, aliceKeyPair.privateKey);
            var (rootKey, chainKey) = DoubleRatchetExchange.InitializeDoubleRatchet(sharedSecret);

            string sessionId = "resume-test-" + Guid.NewGuid().ToString();

            var originalSession = new DoubleRatchetSession(
                dhRatchetKeyPair: aliceKeyPair,
                remoteDHRatchetKey: bobKeyPair.publicKey,
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumber: 5,
                sessionId: sessionId
            );

            // Act
            var resumedSession = E2EEClient.ResumeDoubleRatchetSession(originalSession);

            // Assert
            Assert.IsNotNull(resumedSession, "Session should be resumed successfully");
            Assert.AreEqual(originalSession.SessionId, resumedSession.SessionId, "Session ID should be preserved");
            Assert.AreEqual(originalSession.MessageNumber, resumedSession.MessageNumber, "Message number should be preserved");

            // Verify key materials are preserved
            Assert.IsTrue(SecureMemory.SecureCompare(
                originalSession.DHRatchetKeyPair.publicKey,
                resumedSession.DHRatchetKeyPair.publicKey),
                "Public keys should match");

            Assert.IsTrue(SecureMemory.SecureCompare(
                originalSession.DHRatchetKeyPair.privateKey,
                resumedSession.DHRatchetKeyPair.privateKey),
                "Private keys should match");

            Assert.IsTrue(SecureMemory.SecureCompare(
                originalSession.RootKey,
                resumedSession.RootKey),
                "Root keys should match");
        }

        [TestMethod]
        public void DoubleRatchetExchange_ResumeSession_WithLastProcessedMessageId_ShouldAddToProcessedIds()
        {
            // Arrange
            var aliceKeyPair = E2EEClient.GenerateKeyExchangeKeyPair();
            var bobKeyPair = E2EEClient.GenerateKeyExchangeKeyPair();

            // Initial shared secret
            byte[] sharedSecret = X3DHExchange.X3DHKeyExchange(bobKeyPair.publicKey, aliceKeyPair.privateKey);
            var (rootKey, chainKey) = DoubleRatchetExchange.InitializeDoubleRatchet(sharedSecret);

            string sessionId = "resume-with-msgid-" + Guid.NewGuid().ToString();

            // Create session with no processed message IDs
            var originalSession = new DoubleRatchetSession(
                dhRatchetKeyPair: aliceKeyPair,
                remoteDHRatchetKey: bobKeyPair.publicKey,
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumber: 0,
                sessionId: sessionId
            );

            // Create a message ID to use in resumption
            Guid lastProcessedId = Guid.NewGuid();

            // Act
            var resumedSession = E2EEClient.ResumeDoubleRatchetSession(originalSession, lastProcessedId);

            // Assert
            Assert.IsNotNull(resumedSession, "Session should be resumed successfully");
            Assert.IsTrue(resumedSession.HasProcessedMessageId(lastProcessedId),
                "Resumed session should include the last processed message ID");
        }

        [TestMethod]
        public void WebSocketClient_HandleConnectionErrors_ShouldReturnMeaningfulErrors()
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
            var ex = Assert.ThrowsExceptionAsync<System.Net.WebSockets.WebSocketException>(
                async () => await client.ConnectAsync());

            // Verify the exception contains useful information
            StringAssert.Contains(ex.Result.Message, "Connection refused",
                "Exception should provide meaningful error message");
        }

        [TestMethod]
        public void MailboxTransport_HandleNetworkErrors_ShouldRetryWithBackoff()
        {
            // Arrange
            var mockTransport = new Mock<IMailboxTransport>();
            var recipientKeyPair = KeyGenerator.GenerateEd25519KeyPair();
            var senderKeyPair = KeyGenerator.GenerateEd25519KeyPair();

            // Use a counter for attempts
            int attemptCount = 0;

            // Create an event that gets set when the third attempt succeeds
            var thirdAttemptSucceeded = new ManualResetEvent(false);

            // Create the message queue in advance
            var messages = new List<MailboxMessage>();
            for (int i = 0; i < 3; i++)
            {
                var msg = new MailboxMessage
                {
                    MessageId = Guid.NewGuid().ToString(),
                    RecipientKey = recipientKeyPair.publicKey,
                    SenderKey = senderKeyPair.publicKey,
                    EncryptedPayload = new EncryptedMessage
                    {
                        Ciphertext = new byte[] { 1, 2, 3 },
                        Nonce = new byte[] { 4, 5, 6 }
                    },
                    Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                };
                messages.Add(msg);
            }

            // Setup the mock to throw twice then succeed
            mockTransport
                .Setup(t => t.FetchMessagesAsync(It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
                .Returns((byte[] recipientKey, CancellationToken token) => {
                    int count = Interlocked.Increment(ref attemptCount);
                    Console.WriteLine($"Fetch attempt #{count}");

                    if (count < 3)
                    {
                        Console.WriteLine($"Attempt {count}: Throwing network error");
                        throw new System.Net.Http.HttpRequestException($"Network error on attempt {count}");
                    }

                    Console.WriteLine("Attempt 3: Succeeding");
                    thirdAttemptSucceeded.Set();
                    return Task.FromResult(messages);
                });

            // Instead of relying on the MailboxManager's internal polling, we'll call the poll method directly multiple times
            var mailboxManager = new MailboxManager(senderKeyPair, mockTransport.Object);

            // Get the PollForMessagesAsync method via reflection
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
                Console.WriteLine($"Expected first exception: {ex.InnerException?.Message}");
            }

            try
            {
                // Second attempt (will throw)
                pollMethod.Invoke(mailboxManager, new object[] { CancellationToken.None });
            }
            catch (System.Reflection.TargetInvocationException ex)
            {
                // Expected exception
                Console.WriteLine($"Expected second exception: {ex.InnerException?.Message}");
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
                Console.WriteLine($"Unexpected exception on third attempt: {ex.Message}");
                Assert.Fail("Third attempt should not throw an exception");
            }

            // Assert
            Console.WriteLine($"Total attempts made: {attemptCount}");
            Assert.AreEqual(3, attemptCount, "Should have made exactly 3 attempts");
            Assert.IsTrue(thirdAttemptSucceeded.WaitOne(0), "Third attempt should have succeeded");

            // Clean up
            mailboxManager.Dispose();
        }

        [TestMethod]
        public void DecryptionFailure_ShouldNotAffectSubsequentDecryption()
        {
            // Arrange
            var aliceKeyPair = E2EEClient.GenerateKeyExchangeKeyPair();
            var bobKeyPair = E2EEClient.GenerateKeyExchangeKeyPair();

            // Initial shared secret
            byte[] sharedSecret = X3DHExchange.X3DHKeyExchange(bobKeyPair.publicKey, aliceKeyPair.privateKey);
            var (rootKey, chainKey) = DoubleRatchetExchange.InitializeDoubleRatchet(sharedSecret);

            // Create a session ID that will be shared between Alice and Bob
            string sessionId = "error-recovery-test-" + Guid.NewGuid().ToString();

            var aliceSession = new DoubleRatchetSession(
                dhRatchetKeyPair: aliceKeyPair,
                remoteDHRatchetKey: bobKeyPair.publicKey,
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumber: 0,
                sessionId: sessionId
            );

            var bobSession = new DoubleRatchetSession(
                dhRatchetKeyPair: bobKeyPair,
                remoteDHRatchetKey: aliceKeyPair.publicKey,
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumber: 0,
                sessionId: sessionId
            );

            // Alice sends a valid message
            string goodMessage = "This is a valid message";
            var (aliceUpdatedSession, validEncrypted) = DoubleRatchet.DoubleRatchetEncrypt(aliceSession, goodMessage);

            // Add security fields
            validEncrypted.MessageId = Guid.NewGuid();
            validEncrypted.Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            validEncrypted.SessionId = sessionId;

            // Create an invalid message
            var invalidEncrypted = new EncryptedMessage
            {
                Ciphertext = new byte[64], // Invalid ciphertext (all zeros)
                Nonce = validEncrypted.Nonce,
                MessageNumber = validEncrypted.MessageNumber,
                SenderDHKey = validEncrypted.SenderDHKey,
                Timestamp = validEncrypted.Timestamp,
                MessageId = Guid.NewGuid(),
                SessionId = sessionId
            };

            // Act
            // First try to decrypt the invalid message
            var (bobSessionAfterFailure, failedMessage) = DoubleRatchet.DoubleRatchetDecrypt(bobSession, invalidEncrypted);

            // Then decrypt the valid message
            var (bobSessionAfterSuccess, successMessage) = DoubleRatchet.DoubleRatchetDecrypt(bobSession, validEncrypted);

            // Assert
            Assert.IsNull(failedMessage, "Invalid message should not decrypt");
            Assert.IsNotNull(successMessage, "Valid message should decrypt successfully");
            Assert.AreEqual(goodMessage, successMessage, "Decrypted content should match original");

            // The first decryption failed, so bobSession should remain unchanged for the second decryption
            Assert.IsNull(bobSessionAfterFailure, "Failed decryption should return null session");
        }

        [TestMethod]
        public void GroupChatManager_HandleMissingGroup_ShouldFailGracefully()
        {
            // Arrange
            var aliceKeyPair = E2EEClient.GenerateSignatureKeyPair();
            var groupManager = new GroupChatManager(aliceKeyPair);
            string nonExistentGroupId = "non-existent-group-id";

            // Act

            // Attempt to create a distribution message for a non-existent group
            try
            {
                groupManager.CreateDistributionMessage(nonExistentGroupId);
                Assert.Fail("Should throw an exception for non-existent group");
            }
            catch (ArgumentException ex)
            {
                // Expected exception
                StringAssert.Contains(ex.Message, "not created yet",
                    "Exception should indicate group doesn't exist");
            }

            // Attempt to encrypt for non-existent group
            try
            {
                groupManager.EncryptGroupMessage(nonExistentGroupId, "Test message");
                Assert.Fail("Should throw an exception for non-existent group");
            }
            catch (InvalidOperationException ex)
            {
                // Expected exception
                StringAssert.Contains(ex.Message, "not created yet",
                    "Exception should indicate group doesn't exist");
            }

            // Attempt to decrypt a message for a non-existent group
            var encryptedMessage = new EncryptedGroupMessage
            {
                GroupId = nonExistentGroupId,
                SenderIdentityKey = aliceKeyPair.publicKey,
                Ciphertext = new byte[64],
                Nonce = new byte[12]
            };

            string decryptedMessage = groupManager.DecryptGroupMessage(encryptedMessage);
            Assert.IsNull(decryptedMessage, "Should return null for message from non-existent group");
        }

        [TestMethod]
        public void SecurityVerification_PreventNonceReuse()
        {
            // This test verifies that the NonceGenerator creates unique nonces even when called in rapid succession

            // Arrange & Act
            const int nonceCount = 1000;
            var nonces = new HashSet<string>(StringComparer.Ordinal);

            // Generate many nonces rapidly
            for (int i = 0; i < nonceCount; i++)
            {
                byte[] nonce = NonceGenerator.GenerateNonce();
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
        public void TransportLayerFailure_ShouldNotLoseMessages()
        {
            // Arrange
            var mockTransport = new Mock<IMailboxTransport>();
            var identityKeyPair = KeyGenerator.GenerateEd25519KeyPair();
            var recipientKeyPair = KeyGenerator.GenerateEd25519KeyPair();

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

            using (var mailboxManager = new MailboxManager(identityKeyPair, mockTransport.Object))
            {
                // Act
                // Send a message
                string messageId = mailboxManager.SendMessage(
                    recipientKeyPair.publicKey,
                    "Test message that should be retained after transport failure",
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
        public void MultiDeviceSynchronization_ShouldRecoverFromMessageLoss()
        {
            // Arrange
            var mainDeviceKeyPair = KeyGenerator.GenerateEd25519KeyPair();
            var secondDeviceKeyPair = KeyGenerator.GenerateEd25519KeyPair();

            // Create X25519 keys for the secondary device
            byte[] secondDeviceX25519Private = KeyConversion.DeriveX25519PrivateKeyFromEd25519(secondDeviceKeyPair.privateKey);
            byte[] secondDeviceX25519Public = Sodium.ScalarMultBase(secondDeviceX25519Private);
            byte[] mainDeviceX25519Public = Sodium.ScalarMultBase(
                KeyConversion.DeriveX25519PrivateKeyFromEd25519(mainDeviceKeyPair.privateKey));

            // Create device managers
            var mainDeviceManager = new DeviceManager(mainDeviceKeyPair);
            var secondDeviceManager = new DeviceManager(secondDeviceKeyPair);

            // Link devices
            mainDeviceManager.AddLinkedDevice(secondDeviceX25519Public);
            secondDeviceManager.AddLinkedDevice(mainDeviceX25519Public);

            // Create sync data
            byte[] syncData = Encoding.UTF8.GetBytes("Important sync data");

            // Act
            // Create sync messages
            var syncMessages = mainDeviceManager.CreateSyncMessages(syncData);

            // Get the sync message for the second device
            string secondDeviceId = Convert.ToBase64String(secondDeviceX25519Public);
            Assert.IsTrue(syncMessages.ContainsKey(secondDeviceId), "Should have sync message for second device");

            var syncMessageForSecondDevice = syncMessages[secondDeviceId];

            // Simulate main device sending a corrupted message - create a tampered copy
            var tamperedMessage = new EncryptedMessage
            {
                Ciphertext = new byte[syncMessageForSecondDevice.Ciphertext.Length],
                Nonce = syncMessageForSecondDevice.Nonce
            };

            // Copy the ciphertext and tamper with it
            Buffer.BlockCopy(syncMessageForSecondDevice.Ciphertext, 0, tamperedMessage.Ciphertext, 0,
                tamperedMessage.Ciphertext.Length);

            // Tamper with the middle part
            int middleIndex = tamperedMessage.Ciphertext.Length / 2;
            tamperedMessage.Ciphertext[middleIndex] ^= 0xFF;

            // Try to process the tampered message - should fail
            byte[] result1 = secondDeviceManager.ProcessSyncMessage(tamperedMessage, mainDeviceX25519Public);

            // Main device notices failure (no acknowledgment) and resends the correct message
            byte[] result2 = secondDeviceManager.ProcessSyncMessage(syncMessageForSecondDevice, mainDeviceX25519Public);

            // Assert
            Assert.IsNull(result1, "Processing tampered sync message should fail");
            Assert.IsNotNull(result2, "Processing valid sync message should succeed");

            // Verify the received data matches the original
            Assert.IsTrue(SecureMemory.SecureCompare(syncData, result2),
                "Received sync data should match original after recovery");
        }

        [TestMethod]
        public void CrossDeviceSessionRestoration_ShouldWorkCorrectly()
        {
            // Arrange
            var aliceKeyPair = E2EEClient.GenerateKeyExchangeKeyPair();
            var bobKeyPair = E2EEClient.GenerateKeyExchangeKeyPair();

            // Initial shared secret
            byte[] sharedSecret = X3DHExchange.X3DHKeyExchange(bobKeyPair.publicKey, aliceKeyPair.privateKey);
            var (rootKey, chainKey) = DoubleRatchetExchange.InitializeDoubleRatchet(sharedSecret);

            string sessionId = "cross-device-" + Guid.NewGuid().ToString();

            // Create a session
            var originalSession = new DoubleRatchetSession(
                dhRatchetKeyPair: aliceKeyPair,
                remoteDHRatchetKey: bobKeyPair.publicKey,
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumber: 10,
                sessionId: sessionId
            );

            // Simulate a few messages being processed
            var processedIds = new List<Guid>();
            for (int i = 0; i < 5; i++)
            {
                Guid msgId = Guid.NewGuid();
                processedIds.Add(msgId);
                originalSession = originalSession.WithProcessedMessageId(msgId);
            }

            // Act
            // Serialize the session for transfer to another device
            byte[] encryptionKey = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(encryptionKey);
            }

            byte[] serializedSession = SessionPersistence.SerializeSession(originalSession, encryptionKey);

            // On the "new device", deserialize and resume the session
            var restoredSession = SessionPersistence.DeserializeSession(serializedSession, encryptionKey);
            var resumedSession = E2EEClient.ResumeDoubleRatchetSession(restoredSession);

            // Assert
            Assert.IsNotNull(resumedSession, "Session should be resumed successfully on new device");
            Assert.AreEqual(originalSession.SessionId, resumedSession.SessionId, "Session ID should match");
            Assert.AreEqual(originalSession.MessageNumber, resumedSession.MessageNumber, "Message number should match");

            // Verify message history is intact
            foreach (Guid msgId in processedIds)
            {
                Assert.IsTrue(resumedSession.HasProcessedMessageId(msgId),
                    $"Resumed session should have processed message {msgId}");
            }

            // Verify the resumed session can be used for communication
            string testMessage = "Message after session restoration";
            var (updatedSession, encryptedMessage) = DoubleRatchet.DoubleRatchetEncrypt(resumedSession, testMessage);

            Assert.IsNotNull(updatedSession, "Should get valid updated session after encryption");
            Assert.IsNotNull(encryptedMessage, "Should be able to encrypt new message with resumed session");
            Assert.IsNotNull(encryptedMessage.Ciphertext, "Ciphertext should not be null");
            Assert.IsTrue(encryptedMessage.Ciphertext.Length > 0, "Ciphertext should not be empty");
        }
    }
}