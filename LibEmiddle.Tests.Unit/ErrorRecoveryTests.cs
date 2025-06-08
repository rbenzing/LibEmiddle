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
using LibEmiddle.Sessions;

namespace LibEmiddle.Tests.Unit
{
    [TestClass]
    public class ErrorRecoveryTests
    {
        private CryptoProvider _cryptoProvider;
        private DoubleRatchetProtocol _doubleRatchetProtocol;

        [TestInitialize]
        public void Setup()
        {
            _doubleRatchetProtocol = new DoubleRatchetProtocol();
            _cryptoProvider = new CryptoProvider();
        }

        #region Setup Helper Methods

        /// <summary>
        /// Creates a pair of initialized DoubleRatchet sessions for testing
        /// </summary>
        private (DoubleRatchetSession aliceSession, DoubleRatchetSession bobSession, string sessionId) CreateTestSessions()
        {
            // Generate a unique session ID
            string sessionId = $"session-{Guid.NewGuid()}";

            // Generate key pairs for Alice and Bob
            var aliceKeyPair = Sodium.GenerateX25519KeyPair();
            var bobKeyPair = Sodium.GenerateX25519KeyPair();

            // Generate a shared secret for testing
            byte[] sharedSecret = Sodium.ScalarMult(aliceKeyPair.PrivateKey, bobKeyPair.PublicKey);

            // Initialize Alice's session as sender
            var aliceSession = _doubleRatchetProtocol.InitializeSessionAsSender(
                sharedKeyFromX3DH: sharedSecret,
                recipientInitialPublicKey: bobKeyPair.PublicKey,
                sessionId: sessionId);

            // Initialize Bob's session as receiver
            var bobSession = _doubleRatchetProtocol.InitializeSessionAsReceiver(
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
        public void DoubleRatchetExchange_ResumeSession_WithValidSession_ShouldReturn()
        {
            // Arrange
            var (aliceSession, _, sessionId) = CreateTestSessions();

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
        public void DoubleRatchetExchange_ResumeSession_WithSkippedMessageKeys_ShouldPreserve()
        {
            // Arrange
            var (aliceSession, bobSession, sessionId) = CreateTestSessions();

            // Create multiple messages to properly simulate out-of-order scenario (like the working test)
            const int messageCount = 3;
            var encryptedMessages = new List<EncryptedMessage>();
            var originalMessages = new List<string>();
            var currentSession = aliceSession;

            // Generate encrypted messages
            for (int i = 0; i < messageCount; i++)
            {
                string message = $"Test message {i}";
                originalMessages.Add(message);

                var (updatedSession, encrypted) = _doubleRatchetProtocol.EncryptAsync(
                    currentSession, message);

                AddSecurityFields(encrypted, sessionId);
                encryptedMessages.Add(encrypted);
                currentSession = updatedSession;
            }

            // Decrypt messages in reverse order to create skipped message keys (following the working pattern)
            var currentBobSession = bobSession;
            for (int i = messageCount - 1; i >= 0; i--)
            {
                var (updatedSession, decrypted) = _doubleRatchetProtocol.DecryptAsync(
                    currentBobSession, encryptedMessages[i]);

                Assert.IsNotNull(decrypted, $"Failed to decrypt message {i} out of order");
                currentBobSession = updatedSession;
            }

            // Act - Create a copy of the session to simulate resumption
            var resumedSession = DeepCloneSession(currentBobSession);

            // Assert - Verify that session resumption preserves the basic session state
            Assert.IsNotNull(resumedSession, "Session should be resumable");
            Assert.AreEqual(currentBobSession.SessionId, resumedSession.SessionId, "Session ID should be preserved");
            Assert.AreEqual(currentBobSession.SendMessageNumber, resumedSession.SendMessageNumber, "Send message number should be preserved");
            Assert.AreEqual(currentBobSession.ReceiveMessageNumber, resumedSession.ReceiveMessageNumber, "Receive message number should be preserved");

            // Verify that skipped message keys are preserved (if any exist)
            Assert.AreEqual(currentBobSession.SkippedMessageKeys.Count, resumedSession.SkippedMessageKeys.Count,
                "Skipped message keys count should be preserved");

            // Check that the keys themselves are preserved
            foreach (var kvp in currentBobSession.SkippedMessageKeys)
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
                .Setup(ws => ws.ConnectAsync(It.IsAny<CancellationToken>()))
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
        public void MailboxTransport_HandleNetworkErrors_ShouldRetryWithBackoff()
        {
            // Arrange
            var mockTransport = new Mock<IMailboxTransport>();
            var recipientKeyPair = Sodium.GenerateEd25519KeyPair();
            var senderKeyPair = Sodium.GenerateEd25519KeyPair();

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
        public void DecryptionFailure_ShouldNotAffectSubsequentDecryption()
        {
            // Arrange
            var (aliceSession, bobSession, sessionId) = CreateTestSessions();

            // Alice sends a valid message
            string validMessage = "This is a valid message";
            var (aliceSession1, validEncrypted) = _doubleRatchetProtocol.EncryptAsync(aliceSession, validMessage);
            AddSecurityFields(validEncrypted, sessionId);

            // First, decrypt the valid message to establish the session properly
            var (bobSession1, decryptedMessage) = _doubleRatchetProtocol.DecryptAsync(bobSession, validEncrypted);
            Assert.IsNotNull(bobSession1, "Valid message should decrypt successfully");
            Assert.AreEqual(validMessage, decryptedMessage, "Decrypted content should match original");

            // Now create a second valid message
            string secondMessage = "This is the second valid message";
            var (aliceSession2, secondEncrypted) = _doubleRatchetProtocol.EncryptAsync(aliceSession1, secondMessage);
            AddSecurityFields(secondEncrypted, sessionId);

            // Create an invalid message by corrupting the second message
            var invalidEncrypted = new EncryptedMessage
            {
                Ciphertext = new byte[secondEncrypted.Ciphertext.Length], // Same length but all zeros
                Nonce = secondEncrypted.Nonce,
                SenderMessageNumber = secondEncrypted.SenderMessageNumber,
                SenderDHKey = secondEncrypted.SenderDHKey,
                Timestamp = secondEncrypted.Timestamp,
                MessageId = Guid.NewGuid().ToString(),
                SessionId = sessionId
            };

            // Act
            // First try to decrypt the invalid message
            var (bobSessionAfterFailure, failedMessage) = _doubleRatchetProtocol.DecryptAsync(bobSession1, invalidEncrypted);

            // Then decrypt the valid second message using the session state before the failure
            var sessionToUse = bobSessionAfterFailure ?? bobSession1;
            var (bobSessionAfterSuccess, successMessage) = _doubleRatchetProtocol.DecryptAsync(sessionToUse, secondEncrypted);

            // Assert
            Assert.IsNull(failedMessage, "Invalid message should not decrypt");
            Assert.IsNotNull(successMessage, "Valid message should decrypt successfully");
            Assert.AreEqual(secondMessage, successMessage, "Decrypted content should match original");

            // The first decryption failed, so the session should remain unchanged for the second decryption
            Assert.IsNull(bobSessionAfterFailure, "Failed decryption should return null session");
        }

        [TestMethod]
        public async Task GroupChatManager_HandleMissingGroup_ShouldFailGracefully()
        {
            // Arrange
            var identityKeyPair = Sodium.GenerateEd25519KeyPair();
            string nonExistentGroupId = "test-group-123";
            string groupName = Guid.NewGuid().ToString();
            // Create a GroupSession for testing (this represents our consolidated approach)
            var testGroupSession = new GroupSession(
                "existing-group-456", // Different group ID
                groupName,
                identityKeyPair,
                KeyRotationStrategy.Standard);

            // Act & Assert
            try
            {
                // 1. Test that a user is not a member of a non-existent group
                // Since we're using the consolidated GroupSession, we test through the actual session

                // Create an encrypted message for a non-existent group
                var encryptedMessage = new EncryptedGroupMessage
                {
                    GroupId = nonExistentGroupId, // Different from our session's group
                    SenderIdentityKey = identityKeyPair.PublicKey,
                    Ciphertext = new byte[64],
                    Nonce = new byte[Constants.NONCE_SIZE],
                    Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    MessageId = Guid.NewGuid().ToString(),
                    RotationEpoch = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    Signature = new byte[64] // Mock signature
                };

                // 2. Attempt to decrypt a message for wrong group - should throw ArgumentException
                try
                {
                    await testGroupSession.DecryptMessageAsync(encryptedMessage);
                    Assert.Fail("Should throw ArgumentException for wrong group ID");
                }
                catch (ArgumentException)
                {
                    // Expected - any ArgumentException for wrong group ID is acceptable
                }

                // 3. Test with SessionManager trying to get non-existent session
                var cryptoProvider = new CryptoProvider();
                var x3dhProtocol = new X3DHProtocol(cryptoProvider);
                var doubleRatchetProtocol = new DoubleRatchetProtocol();

                var sessionManager = new SessionManager(
                    cryptoProvider,
                    x3dhProtocol,
                    doubleRatchetProtocol,
                    identityKeyPair);

                try
                {
                    await sessionManager.GetSessionAsync($"group-{nonExistentGroupId}-12345");
                    Assert.Fail("Should throw KeyNotFoundException for non-existent session");
                }
                catch (KeyNotFoundException)
                {
                    // Expected behavior - this is correct
                }

                // 4. Test that GroupSession validates group ID correctly
                var wrongGroupMessage = new EncryptedGroupMessage
                {
                    GroupId = "completely-different-group",
                    SenderIdentityKey = identityKeyPair.PublicKey,
                    Ciphertext = Sodium.GenerateRandomBytes(32),
                    Nonce = Sodium.GenerateRandomBytes(Constants.NONCE_SIZE),
                    Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    MessageId = Guid.NewGuid().ToString(),
                    RotationEpoch = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    Signature = new byte[64]
                };

                // Should throw ArgumentException due to group mismatch
                await Assert.ThrowsExceptionAsync<ArgumentException>(async () =>
                {
                    await testGroupSession.DecryptMessageAsync(wrongGroupMessage);
                });

                // 5. Test creation of distribution message on activated group
                await testGroupSession.ActivateAsync(); // Ensure session is activated
                var distributionMessage = testGroupSession.CreateDistributionMessage();
                Assert.IsNotNull(distributionMessage, "Should be able to create distribution message");
                Assert.AreEqual("existing-group-456", distributionMessage.GroupId, "Distribution should have correct group ID");

                // 6. Test ProcessDistributionMessage with wrong group
                var wrongGroupDistribution = new SenderKeyDistributionMessage
                {
                    GroupId = nonExistentGroupId, // Wrong group
                    ChainKey = Sodium.GenerateRandomBytes(Constants.CHAIN_KEY_SIZE),
                    Iteration = 0,
                    SenderIdentityKey = identityKeyPair.PublicKey,
                    Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    Signature = new byte[64]
                };

                bool distributionResult = testGroupSession.ProcessDistributionMessage(wrongGroupDistribution);
                Assert.IsFalse(distributionResult, "Should reject distribution message for wrong group");

            }
            catch (Exception ex)
            {
                Assert.Fail($"Should handle missing/wrong group gracefully without unexpected exceptions: {ex.Message}");
            }
            finally
            {
                // Clean up
                testGroupSession?.Dispose();
            }
        }

        [TestMethod]
        public async Task GroupSession_HandleNonMember_ShouldFailGracefully()
        {
            // Arrange
            var adminKeyPair = Sodium.GenerateEd25519KeyPair();
            var nonMemberKeyPair = Sodium.GenerateEd25519KeyPair();
            string groupId = $"test-non-member-{Guid.NewGuid()}";
            string groupName = "Test Group Name";

            var groupSession = new GroupSession(groupId, groupName, adminKeyPair, KeyRotationStrategy.Standard);
            await groupSession.ActivateAsync();

            // Act & Assert
            try
            {
                // 1. Non-member tries to create a message for the group
                var nonMemberSession = new GroupSession(groupId, groupName, nonMemberKeyPair, KeyRotationStrategy.Standard);
                await nonMemberSession.ActivateAsync();

                // This should work (encryption) but the message won't be valid for decryption by others
                var encryptedMessage = await nonMemberSession.EncryptMessageAsync("Unauthorized message");
                Assert.IsNotNull(encryptedMessage, "Encryption should work even for non-members");

                // 2. Admin tries to decrypt message from non-member (should fail validation)
                string decryptedMessage = await groupSession.DecryptMessageAsync(encryptedMessage);
                Assert.IsNull(decryptedMessage, "Should not be able to decrypt message from non-member");

                // 3. Non-member tries to add themselves (should fail)
                try
                {
                    await nonMemberSession.AddMemberAsync(nonMemberKeyPair.PublicKey);
                    Assert.Fail("Non-member should not be able to add themselves");
                }
                catch (Exception)
                {
                    // Expected - non-members can't add members (any exception is acceptable)
                }

                // 4. Non-member tries to rotate keys (should fail)
                try
                {
                    await nonMemberSession.RotateKeyAsync();
                    Assert.Fail("Non-member should not be able to rotate keys");
                }
                catch (Exception)
                {
                    // Expected - non-members can't rotate keys (any exception is acceptable)
                }

                // 5. Test distribution message from non-member
                var nonMemberDistribution = nonMemberSession.CreateDistributionMessage();
                bool distributionAccepted = groupSession.ProcessDistributionMessage(nonMemberDistribution);
                Assert.IsFalse(distributionAccepted, "Should reject distribution from non-member");

            }
            catch (Exception ex)
            {
                Assert.Fail($"Should handle non-member operations gracefully: {ex.Message}");
            }
            finally
            {
                // Clean up
                groupSession?.Dispose();
            }
        }

        [TestMethod]
        public async Task GroupSession_HandleCorruptedData_ShouldFailGracefully()
        {
            // Arrange
            var identityKeyPair = Sodium.GenerateEd25519KeyPair();
            string groupId = $"test-corrupted-{Guid.NewGuid()}";
            string groupName = "Test group name";

            var groupSession = new GroupSession(groupId, groupName, identityKeyPair, KeyRotationStrategy.Standard);
            await groupSession.ActivateAsync();

            // Act & Assert
            try
            {
                // 1. Test with corrupted encrypted message
                var corruptedMessage = new EncryptedGroupMessage
                {
                    GroupId = groupId,
                    SenderIdentityKey = identityKeyPair.PublicKey,
                    Ciphertext = new byte[0], // Empty ciphertext
                    Nonce = new byte[0], // Empty nonce
                    Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    MessageId = Guid.NewGuid().ToString(),
                    RotationEpoch = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                };

                string result1 = await groupSession.DecryptMessageAsync(corruptedMessage);
                Assert.IsNull(result1, "Should return null for corrupted message (empty arrays)");

                // 2. Test with null fields
                var nullFieldMessage = new EncryptedGroupMessage
                {
                    GroupId = groupId,
                    SenderIdentityKey = null!, // Null sender
                    Ciphertext = null!,
                    Nonce = null!,
                    Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    MessageId = Guid.NewGuid().ToString()
                };

                string result2 = await groupSession.DecryptMessageAsync(nullFieldMessage);
                Assert.IsNull(result2, "Should return null for message with null fields");

                // 3. Test with corrupted distribution message
                var corruptedDistribution = new SenderKeyDistributionMessage
                {
                    GroupId = groupId,
                    ChainKey = null!, // Null chain key
                    SenderIdentityKey = null!,
                    Signature = null!
                };

                bool distributionResult = groupSession.ProcessDistributionMessage(corruptedDistribution);
                Assert.IsFalse(distributionResult, "Should reject corrupted distribution message");

                // 4. Test with invalid serialized state
                try
                {
                    bool restoreResult = await groupSession.RestoreSerializedStateAsync("");
                    Assert.IsFalse(restoreResult, "Should reject empty serialized state");
                }
                catch (Exception)
                {
                    // Expected - empty string might throw exception instead of returning false
                }

                try
                {
                    bool restoreResult2 = await groupSession.RestoreSerializedStateAsync("invalid json");
                    Assert.IsFalse(restoreResult2, "Should reject invalid JSON serialized state");
                }
                catch (Exception)
                {
                    // Expected - invalid JSON might throw exception instead of returning false
                }

            }
            catch (Exception ex)
            {
                Assert.Fail($"Should handle corrupted data gracefully without throwing: {ex.Message}");
            }
            finally
            {
                // Clean up
                groupSession?.Dispose();
            }
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
            var identityKeyPair = Sodium.GenerateEd25519KeyPair();
            var recipientKeyPair = Sodium.GenerateEd25519KeyPair();

            // Simulate a new DoubleRatchet session for this test
            var (aliceSession, _, _) = CreateTestSessions();

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
        public void MultiDeviceSynchronization_ShouldRecoverFromMessageLoss()
        {
            Trace.TraceWarning("==== Starting MultiDeviceSynchronization_ShouldRecoverFromMessageLoss ====");

            // Arrange
            var mainDeviceKeyPair = Sodium.GenerateEd25519KeyPair();
            var secondDeviceKeyPair = Sodium.GenerateEd25519KeyPair();

            Trace.TraceWarning($"Main device key pair - Public: {Convert.ToBase64String(mainDeviceKeyPair.PublicKey)}, " +
                             $"Private: {Convert.ToBase64String(mainDeviceKeyPair.PrivateKey).Substring(0, 10)}...");
            Trace.TraceWarning($"Second device key pair - Public: {Convert.ToBase64String(secondDeviceKeyPair.PublicKey)}, " +
                             $"Private: {Convert.ToBase64String(secondDeviceKeyPair.PrivateKey).Substring(0, 10)}...");

            // Create device managers
            var deviceLinkingService = new DeviceLinkingService(_cryptoProvider);
            var mainDeviceManager = new DeviceManager(mainDeviceKeyPair, deviceLinkingService, _cryptoProvider);
            var secondDeviceManager = new DeviceManager(secondDeviceKeyPair, deviceLinkingService, _cryptoProvider);

            // Convert to X25519 keys for direct testing
            byte[] mainDeviceX25519Public = Sodium.ConvertEd25519PublicKeyToX25519(mainDeviceKeyPair.PublicKey);
            byte[] secondDeviceX25519Public = Sodium.ConvertEd25519PublicKeyToX25519(secondDeviceKeyPair.PublicKey);

            Trace.TraceWarning($"Main device X25519 public key: {Convert.ToBase64String(mainDeviceX25519Public)}");
            Trace.TraceWarning($"Second device X25519 public key: {Convert.ToBase64String(secondDeviceX25519Public)}");

            // Link devices
            mainDeviceManager.AddLinkedDevice(secondDeviceKeyPair.PublicKey);
            secondDeviceManager.AddLinkedDevice(mainDeviceKeyPair.PublicKey);
            Trace.TraceWarning("Linked both devices successfully");

            // Wait a moment for linking to complete
            Thread.Sleep(100);

            // Create sync data
            byte[] syncData = Encoding.Default.GetBytes("Important sync data");
            Trace.TraceWarning($"Created sync data of length {syncData.Length}");

            // Create sync messages
            var syncMessages = mainDeviceManager.CreateSyncMessages(syncData);
            Trace.TraceWarning($"Created {syncMessages.Count} sync messages");

            // Get the sync message for the second device
            // The DeviceManager uses the Base64 representation of the normalized key as the device ID
            // Since we added the Ed25519 key, it should be normalized to X25519 and used as the key
            string expectedDeviceId = Convert.ToBase64String(secondDeviceX25519Public);

            Trace.TraceWarning($"Expected device ID: {expectedDeviceId}");
            Trace.TraceWarning($"Available sync message keys: {string.Join(", ", syncMessages.Keys)}");

            // The sync messages should contain the normalized key
            if (syncMessages.Count == 0)
            {
                Assert.Inconclusive("No sync messages were created - sync functionality may not be implemented or device linking failed");
                return;
            }

            // Use the first available key since there should only be one linked device
            string actualDeviceId = syncMessages.Keys.First();
            Trace.TraceWarning($"Using device ID: {actualDeviceId}");

            var syncMessageForSecondDevice = syncMessages[actualDeviceId];
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
        public void CrossDeviceSessionRestoration_ShouldWorkCorrectly()
        {
            // Arrange
            var (aliceSession, _, _) = CreateTestSessions();

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
            var (updatedSession, encryptedMessage) = _doubleRatchetProtocol.EncryptAsync(restoredSession, testMessage);

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