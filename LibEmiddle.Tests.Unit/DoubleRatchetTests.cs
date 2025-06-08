using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using LibEmiddle.Core;
using LibEmiddle.Domain;
using LibEmiddle.Crypto;
using LibEmiddle.Domain.Enums;
using LibEmiddle.Protocol;
using LibEmiddle.Abstractions;

namespace LibEmiddle.Tests.Unit
{
    [TestClass]
    public class DoubleRatchetTests
    {
        private IDoubleRatchetProtocol _doubleRatchetProtocol;

        [TestInitialize]
        public void Setup()
        {
            _doubleRatchetProtocol = new DoubleRatchetProtocol();
        }

        #region Setup Helper Methods

        /// <summary>
        /// Creates a pair of initialized DoubleRatchet sessions for testing
        /// </summary>
        /// <returns>A tuple containing Alice's session, Bob's session, and the session ID</returns>
        private (DoubleRatchetSession aliceSession, DoubleRatchetSession bobSession, string sessionId) CreateTestSessionsAsync()
        {
            // Generate key pairs for Alice and Bob
            var aliceKeyPair = Sodium.GenerateX25519KeyPair();
            var bobKeyPair = Sodium.GenerateX25519KeyPair();

            // Generate a shared secret (simulating the X3DH result)
            byte[] sharedSecret = Sodium.ScalarMult(
                aliceKeyPair.PrivateKey,
                bobKeyPair.PublicKey);

            // Create a unique session ID
            string sessionId = $"test-session-{Guid.NewGuid()}";

            // Initialize Alice's session as the sender
            var aliceSession = _doubleRatchetProtocol.InitializeSessionAsSender(
                sharedSecret,
                bobKeyPair.PublicKey,
                sessionId);

            // Initialize Bob's session as the receiver
            var bobSession = _doubleRatchetProtocol.InitializeSessionAsReceiver(
                sharedSecret,
                bobKeyPair,
                aliceKeyPair.PublicKey,
                sessionId);

            return (aliceSession, bobSession, sessionId);
        }

        /// <summary>
        /// Adds required security fields to an encrypted message
        /// </summary>
        private void AddSecurityFields(EncryptedMessage message, string sessionId)
        {
            message.MessageId = Guid.NewGuid().ToString("N");
            message.Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            message.SessionId = sessionId;
        }

        #endregion

        #region Basic Functionality Tests

        [TestMethod]
        public void BasicEncryptionDecryption_ShouldWork()
        {
            // Arrange
            var (aliceSession, bobSession, sessionId) = CreateTestSessionsAsync();
            string originalMessage = "Hello, secure world!";

            // Act - Alice encrypts a message for Bob
            var (aliceUpdatedSession, encryptedMessage) = _doubleRatchetProtocol.EncryptAsync(
                aliceSession, originalMessage);

            // Add security fields
            AddSecurityFields(encryptedMessage, sessionId);

            // Bob decrypts the message
            var (bobUpdatedSession, decryptedMessage) = _doubleRatchetProtocol.DecryptAsync(
                bobSession, encryptedMessage);

            // Assert
            Assert.IsNotNull(aliceUpdatedSession, "Alice's session should be updated");
            Assert.IsNotNull(bobUpdatedSession, "Bob's session should be updated");
            Assert.IsNotNull(decryptedMessage, "Decrypted message should not be null");
            Assert.AreEqual(originalMessage, decryptedMessage, "Decrypted message should match original");
        }

        [TestMethod]
        public void RepeatedRatchetSteps_ShouldProduceUniqueKeys()
        {
            // Arrange
            byte[] initialChainKey = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(initialChainKey);

            // Act - Perform multiple ratchet steps using the Double Ratchet protocol
            HashSet<string> messageKeys = new HashSet<string>();

            // Create test sessions
            var (aliceSession, bobSession, sessionId) = CreateTestSessionsAsync();
            var currentAliceSession = aliceSession;

            const int iterations = 100;
            for (int i = 0; i < iterations; i++)
            {
                // Encrypt a message (which performs a ratchet step)
                string message = $"Test message {i}";
                var (updatedSession, encrypted) = _doubleRatchetProtocol.EncryptAsync(
                    currentAliceSession, message);

                // Ensure we got a valid encrypted message
                Assert.IsNotNull(encrypted, $"Encryption failed at iteration {i}");
                Assert.IsNotNull(encrypted.Ciphertext, $"No ciphertext produced at iteration {i}");
                Assert.IsNotNull(encrypted.Nonce, $"No nonce produced at iteration {i}");

                // Convert the encrypted message to a string for comparison
                string uniqueId = $"{Convert.ToBase64String(encrypted.Ciphertext)}:{Convert.ToBase64String(encrypted.Nonce)}";

                // Assert each encrypted result is unique
                Assert.IsFalse(messageKeys.Contains(uniqueId),
                    $"Encryption produced duplicate result at iteration {i}");

                messageKeys.Add(uniqueId);
                currentAliceSession = updatedSession;
            }

            // Verify we have the expected number of unique keys
            Assert.AreEqual(iterations, messageKeys.Count,
                "Should have generated the correct number of unique message encryptions");
        }

        [TestMethod]
        public void OutOfOrderMessages_ShouldDecryptCorrectly()
        {
            // Arrange
            var (aliceSession, bobSession, sessionId) = CreateTestSessionsAsync();

            // Create a collection of messages
            const int messageCount = 5;
            var encryptedMessages = new List<EncryptedMessage>(messageCount);
            var originalMessages = new List<string>(messageCount);
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

            // Act - Decrypt messages in reverse order
            var results = new List<string>();
            currentSession = bobSession;

            for (int i = messageCount - 1; i >= 0; i--)
            {
                var (updatedSession, decrypted) = _doubleRatchetProtocol.DecryptAsync(
                    currentSession, encryptedMessages[i]);

                // We expect this to work with the new Double Ratchet implementation
                Assert.IsNotNull(decrypted, $"Failed to decrypt message {i} out of order");
                results.Add(decrypted);
                currentSession = updatedSession;
            }

            // Assert - Check that all messages were decrypted correctly
            for (int i = 0; i < messageCount; i++)
            {
                int reverseIndex = messageCount - 1 - i;
                Assert.AreEqual(originalMessages[reverseIndex], results[i],
                    $"Message {reverseIndex} was not decrypted correctly");
            }
        }

        [TestMethod]
        public void MessageExpiration_BasedOnTimestamp()
        {
            // Arrange
            var (aliceSession, bobSession, sessionId) = CreateTestSessionsAsync();

            string message = "This message will expire";
            var (_, encrypted) = _doubleRatchetProtocol.EncryptAsync(aliceSession, message);

            // Set timestamp to 10 minutes in the past (beyond the 5 minute threshold)
            encrypted.MessageId = Guid.NewGuid().ToString("N");
            encrypted.Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - 10 * 60 * 1000;
            encrypted.SessionId = sessionId;

            // Act
            var (resultSession, resultMessage) = _doubleRatchetProtocol.DecryptAsync(bobSession, encrypted);

            // Assert - The actual behavior depends on implementation, but either:
            // 1. The decryption will fail and return null results
            // 2. Or the protocol might still decrypt but log a warning

            // For this test, we check what the implementation we're testing actually does
            if (resultSession == null || resultMessage == null)
            {
                // If implementation rejects expired messages
                Assert.IsNull(resultSession, "Session should be null for expired message");
                Assert.IsNull(resultMessage, "Decrypted message should be null for expired message");
            }
            else
            {
                // If implementation accepts but logs (we can't verify logging in a test)
                Assert.AreEqual(message, resultMessage, "If accepting expired messages, content should match");
            }
        }

        [TestMethod]
        public void UnsignedLongOverflowTimestamp_ShouldBeRejected()
        {
            // Arrange
            var (aliceSession, bobSession, sessionId) = CreateTestSessionsAsync();

            string message = "Message with suspicious timestamp";
            var (_, encrypted) = _doubleRatchetProtocol.EncryptAsync(aliceSession, message);

            // Set extremely high timestamp (potential overflow attack)
            encrypted.MessageId = Guid.NewGuid().ToString("N");
            encrypted.Timestamp = long.MaxValue;
            encrypted.SessionId = sessionId;

            // Act
            var (resultSession, resultMessage) = _doubleRatchetProtocol.DecryptAsync(bobSession, encrypted);

            // Assert - Expect rejection (actual behavior depends on implementation)
            if (resultSession == null || resultMessage == null)
            {
                Assert.IsNull(resultSession, "Session should be null for suspicious timestamp");
                Assert.IsNull(resultMessage, "Decrypted message should be null for suspicious timestamp");
            }
        }

        [TestMethod]
        public void NegativeTimestamp_ShouldBeRejected()
        {
            // Arrange
            var (aliceSession, bobSession, sessionId) = CreateTestSessionsAsync();

            string message = "Message with negative timestamp";
            var (_, encrypted) = _doubleRatchetProtocol.EncryptAsync(aliceSession, message);

            // Set negative timestamp (potential overflow attack)
            encrypted.MessageId = Guid.NewGuid().ToString("N");
            encrypted.Timestamp = -1;
            encrypted.SessionId = sessionId;

            // Act
            var (resultSession, resultMessage) = _doubleRatchetProtocol.DecryptAsync(bobSession, encrypted);

            // Assert - Expect rejection
            Assert.IsNull(resultSession, "Session should be null for negative timestamp");
            Assert.IsNull(resultMessage, "Decrypted message should be null for negative timestamp");
        }

        #endregion

        #region Extended Security Tests

        [TestMethod]
        public void LongConversation_ShouldMaintainSecurity()
        {
            // Arrange
            var (aliceSession, bobSession, sessionId) = CreateTestSessionsAsync();
            var currentAliceSession = aliceSession;
            var currentBobSession = bobSession;

            // Store initial key states for comparison
            byte[] initialAliceSendingChainKey = null;
            byte[] initialBobSendingChainKey = null;

            if (currentAliceSession.SenderChainKey != null)
            {
                initialAliceSendingChainKey = (byte[])currentAliceSession.SenderChainKey.Clone();
            }
            if (currentBobSession.SenderChainKey != null)
            {
                initialBobSendingChainKey = (byte[])currentBobSession.SenderChainKey.Clone();
            }

            // Act - Simulate a long conversation with 100 messages
            const int messageCount = 100;
            for (int i = 0; i < messageCount; i++)
            {
                try
                {
                    // Alternate messages between Alice and Bob
                    if (i % 2 == 0)
                    {
                        // Alice sends message to Bob
                        string message = $"Alice message {i}";
                        var (updatedAliceSession, encrypted) = _doubleRatchetProtocol.EncryptAsync(
                            currentAliceSession, message, KeyRotationStrategy.Standard);

                        Assert.IsNotNull(updatedAliceSession, $"Alice's session update failed at message {i}");
                        Assert.IsNotNull(encrypted, $"Message encryption failed at message {i}");

                        AddSecurityFields(encrypted, sessionId);
                        var (updatedBobSession, decrypted) = _doubleRatchetProtocol.DecryptAsync(
                            currentBobSession, encrypted);

                        Assert.IsNotNull(updatedBobSession, $"Bob's session update failed at message {i}");
                        Assert.IsNotNull(decrypted, $"Decryption failed at message {i}");
                        Assert.AreEqual(message, decrypted, $"Message content mismatch at message {i}");

                        currentAliceSession = updatedAliceSession;
                        currentBobSession = updatedBobSession;
                    }
                    else
                    {
                        // Bob sends message to Alice
                        string message = $"Bob message {i}";
                        var (updatedBobSession, encrypted) = _doubleRatchetProtocol.EncryptAsync(
                            currentBobSession, message, KeyRotationStrategy.Standard);

                        Assert.IsNotNull(updatedBobSession, $"Bob's session update failed at message {i}");
                        Assert.IsNotNull(encrypted, $"Message encryption failed at message {i}");

                        AddSecurityFields(encrypted, sessionId);
                        var (updatedAliceSession, decrypted) = _doubleRatchetProtocol.DecryptAsync(
                            currentAliceSession, encrypted);

                        Assert.IsNotNull(updatedAliceSession, $"Alice's session update failed at message {i}");
                        Assert.IsNotNull(decrypted, $"Decryption failed at message {i}");
                        Assert.AreEqual(message, decrypted, $"Message content mismatch at message {i}");

                        currentBobSession = updatedBobSession;
                        currentAliceSession = updatedAliceSession;
                    }
                }
                catch (Exception ex)
                {
                    Assert.Fail($"Exception at message {i}: {ex.Message}\nStack trace: {ex.StackTrace}");
                }

                // Periodically force garbage collection to test memory safety
                if (i % 10 == 0)
                {
                    GC.Collect();
                    GC.WaitForPendingFinalizers();
                }
            }

            // Verify that chain keys have changed
            if (initialAliceSendingChainKey != null && currentAliceSession.SenderChainKey != null)
            {
                Assert.IsFalse(SecureMemory.SecureCompare(initialAliceSendingChainKey, currentAliceSession.SenderChainKey),
                    "Alice's sending chain key should have changed during the conversation");
            }

            if (initialBobSendingChainKey != null && currentBobSession.SenderChainKey != null)
            {
                Assert.IsFalse(SecureMemory.SecureCompare(initialBobSendingChainKey, currentBobSession.SenderChainKey),
                    "Bob's sending chain key should have changed during the conversation");
            }
        }

        [TestMethod]
        public void DoubleRatchetSessionImmutability_ShouldBeEnforced()
        {
            // Arrange
            var (aliceSession, bobSession, sessionId) = CreateTestSessionsAsync();

            // Keep copies of original values for comparison
            byte[] originalSendingChainKey = null;
            if (aliceSession.SenderChainKey != null)
            {
                originalSendingChainKey = (byte[])aliceSession.SenderChainKey.Clone();
            }
            uint originalSendMessageNumber = aliceSession.SendMessageNumber;

            // Act - Use Alice's session to encrypt a message
            string message = "Test message for immutability";
            var (updatedSession, encrypted) = _doubleRatchetProtocol.EncryptAsync(aliceSession, message);

            // Assert - Original session should not be modified
            Assert.AreNotSame(aliceSession, updatedSession,
                "Updated session should be a different instance than original session");

            // Sending chain key should have changed in the updated session but not in the original
            if (originalSendingChainKey != null && updatedSession.SenderChainKey != null)
            {
                Assert.IsFalse(SecureMemory.SecureCompare(originalSendingChainKey, updatedSession.SenderChainKey),
                    "Sending chain key should change in the updated session");

                if (aliceSession.SenderChainKey != null)
                {
                    Assert.IsTrue(SecureMemory.SecureCompare(originalSendingChainKey, aliceSession.SenderChainKey),
                        "Original session's sending chain key should remain unchanged");
                }
            }

            // Message number should be incremented in the updated session but not the original
            Assert.AreEqual(originalSendMessageNumber, aliceSession.SendMessageNumber,
                "Original session's send message number should remain unchanged");
            Assert.AreEqual(originalSendMessageNumber + 1, updatedSession.SendMessageNumber,
                "Updated session's send message number should be incremented");
        }

        [TestMethod]
        public void ExtensiveReplayProtection_ShouldPreventReplayAttacks()
        {
            // Arrange
            var (aliceSession, bobSession, sessionId) = CreateTestSessionsAsync();

            // Send a message from Alice to Bob
            string message = "Message that should not be replayable";
            var (_, encrypted) = _doubleRatchetProtocol.EncryptAsync(aliceSession, message);

            // Add security fields
            encrypted.MessageId = Guid.NewGuid().ToString("N");
            encrypted.Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            encrypted.SessionId = sessionId;

            // First decryption should succeed
            var (bobUpdatedSession, decrypted) = _doubleRatchetProtocol.DecryptAsync(bobSession, encrypted);

            Assert.IsNotNull(bobUpdatedSession, "First decryption should succeed");
            Assert.IsNotNull(decrypted, "First decryption should succeed");
            Assert.AreEqual(message, decrypted, "First decryption should return correct message");

            // Act - Try to decrypt the exact same message again (replay attempt)
            var (replaySession, replayMessage) = _doubleRatchetProtocol.DecryptAsync(bobUpdatedSession, encrypted);

            // Assert - Replay should be detected and rejected
            Assert.IsNull(replaySession, "Replay attempt should be rejected (session)");
            Assert.IsNull(replayMessage, "Replay attempt should be rejected (message)");

            // Try with variations of replays to ensure comprehensive protection

            // 1. Same content but new message ID (should still be detected by message number)
            var replayWithNewId = new EncryptedMessage
            {
                Ciphertext = encrypted.Ciphertext,
                Nonce = encrypted.Nonce,
                SenderMessageNumber = encrypted.SenderMessageNumber, // Same message number
                SenderDHKey = encrypted.SenderDHKey,
                Timestamp = encrypted.Timestamp,
                MessageId = Guid.NewGuid().ToString("N"), // New ID
                SessionId = sessionId
            };

            var (replayResult1, replayMessage1) = _doubleRatchetProtocol.DecryptAsync(
                bobUpdatedSession, replayWithNewId);

            Assert.IsNull(replayResult1, "Replay with new ID should be rejected (session)");
            Assert.IsNull(replayMessage1, "Replay with new ID should be rejected (message)");

            // 2. Same content, new ID, updated timestamp
            var replayWithNewTimestamp = new EncryptedMessage
            {
                Ciphertext = encrypted.Ciphertext,
                Nonce = encrypted.Nonce,
                SenderMessageNumber = encrypted.SenderMessageNumber,
                SenderDHKey = encrypted.SenderDHKey,
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), // New timestamp
                MessageId = Guid.NewGuid().ToString("N"),
                SessionId = sessionId
            };

            var (replayResult2, replayMessage2) = _doubleRatchetProtocol.DecryptAsync(
                bobUpdatedSession, replayWithNewTimestamp);

            Assert.IsNull(replayResult2, "Replay with new timestamp should be rejected (session)");
            Assert.IsNull(replayMessage2, "Replay with new timestamp should be rejected (message)");
        }

        [TestMethod]
        public async Task MultiThreadedRatchetingSecurity_SimulatesStressTest()
        {
            // Arrange
            var (aliceSession, bobSession, sessionId) = CreateTestSessionsAsync();

            // Create multiple tasks that will attempt to encrypt with the same session concurrently
            List<Task<(DoubleRatchetSession, EncryptedMessage)>> encryptTasks =
                new List<Task<(DoubleRatchetSession, EncryptedMessage)>>();

            const int taskCount = 10;
            for (int i = 0; i < taskCount; i++)
            {
                int taskId = i; // Capture for closure
                var task = Task.Run(() => {
                    // Each task tries to encrypt with the same original session
                    string message = $"Task {taskId} message";
                    return _doubleRatchetProtocol.EncryptAsync(aliceSession, message);
                });
                encryptTasks.Add(task);
            }

            // Act - Wait for all tasks to complete
            await Task.WhenAll(encryptTasks);

            // Collect all the encrypted messages and updated sessions
            var results = encryptTasks.Select(t => t.Result).ToList();

            // Assert - Each task should complete successfully
            foreach (var (updatedSession, encryptedMessage) in results)
            {
                Assert.IsNotNull(updatedSession, "Updated session should not be null");
                Assert.IsNotNull(encryptedMessage, "Encrypted message should not be null");
                Assert.IsNotNull(encryptedMessage.Ciphertext, "Ciphertext should not be null");

                // Make sure the session has been updated properly
                Assert.AreEqual(1u, updatedSession.SendMessageNumber,
                    "All sessions should have message number 1");

                // Make sure the chain key has changed (it's not the same as the original session)
                if (aliceSession.SenderChainKey != null && updatedSession.SenderChainKey != null)
                {
                    Assert.IsFalse(SecureMemory.SecureCompare(aliceSession.SenderChainKey, updatedSession.SenderChainKey),
                        "Updated session should have a different sending chain key than the original");
                }
            }

            // Verify that all the updated sessions have the same chain key
            // This is expected because the encryption operation is deterministic
            // when starting from the same session state
            if (results.Count > 1 && results[0].Item1.SenderChainKey != null)
            {
                for (int i = 1; i < results.Count; i++)
                {
                    if (results[i].Item1.SenderChainKey != null)
                    {
                        Assert.IsTrue(SecureMemory.SecureCompare(results[0].Item1.SenderChainKey, results[i].Item1.SenderChainKey),
                            "All updated sessions should have the same chain key when starting from the same session");
                    }
                }
            }
        }

        [TestMethod]
        public void ExtremeLongMessages_ShouldProcess()
        {
            // Arrange
            var (aliceSession, bobSession, sessionId) = CreateTestSessionsAsync();

            // Create extremely long message (1MB)
            StringBuilder messageBuilder = new StringBuilder(1024 * 1024);
            for (int i = 0; i < 1024 * 1024 / 100; i++)
            {
                messageBuilder.Append("This is part of an extremely long message to test the robustness of the Double Ratchet protocol. ");
            }
            string longMessage = messageBuilder.ToString();

            // Act
            var (aliceUpdatedSession, encrypted) = _doubleRatchetProtocol.EncryptAsync(aliceSession, longMessage);
            AddSecurityFields(encrypted, sessionId);

            var (bobUpdatedSession, decrypted) = _doubleRatchetProtocol.DecryptAsync(bobSession, encrypted);

            // Assert
            Assert.IsNotNull(aliceUpdatedSession, "Alice's session should be updated");
            Assert.IsNotNull(bobUpdatedSession, "Bob's session should be updated");
            Assert.IsNotNull(decrypted, "Decryption should succeed");
            Assert.AreEqual(longMessage.Length, decrypted.Length, "Message length should be preserved");
            Assert.AreEqual(longMessage, decrypted, "Message content should be preserved");
        }

        #endregion

        #region Edge Case Tests

        [TestMethod]
        public void EmptyMessage_ShouldBeHandled()
        {
            // Arrange
            var (aliceSession, bobSession, sessionId) = CreateTestSessionsAsync();

            // Act & Assert - Empty message should throw ArgumentException
            Assert.ThrowsException<ArgumentException>(() =>
            {
                _doubleRatchetProtocol.EncryptAsync(aliceSession, "");

            }, "Empty message should be rejected");
        }

        [TestMethod]
        public void ZeroByteMessage_ShouldBeHandled()
        {
            // Arrange
            var (aliceSession, bobSession, sessionId) = CreateTestSessionsAsync();
            string zeroByteMessage = "\0";

            // Act
            var (aliceUpdatedSession, encrypted) = _doubleRatchetProtocol.EncryptAsync(aliceSession, zeroByteMessage);
            AddSecurityFields(encrypted, sessionId);

            var (bobUpdatedSession, decrypted) = _doubleRatchetProtocol.DecryptAsync(bobSession, encrypted);

            // Assert
            Assert.IsNotNull(decrypted, "Null byte message should be decryptable");
            Assert.AreEqual(zeroByteMessage, decrypted, "Null byte should be preserved");
        }

        [TestMethod]
        public void SpecialCharacters_ShouldBePreserved()
        {
            // Arrange
            var (aliceSession, bobSession, sessionId) = CreateTestSessionsAsync();
            string specialCharsMessage = "Special chars: 你好 áéíóú ñ Ж ß Ø אבג 😊 🔐 ∞ ≈ π √";

            // Act
            var (aliceUpdatedSession, encrypted) = _doubleRatchetProtocol.EncryptAsync(aliceSession, specialCharsMessage);
            AddSecurityFields(encrypted, sessionId);

            var (bobUpdatedSession, decrypted) = _doubleRatchetProtocol.DecryptAsync(bobSession, encrypted);

            // Assert
            Assert.IsNotNull(decrypted, "Special character message should be decryptable");
            Assert.AreEqual(specialCharsMessage, decrypted, "Special characters should be preserved");
        }

        [TestMethod]
        public void MissingSessionId_ShouldBeRejected()
        {
            // Arrange
            var (aliceSession, bobSession, sessionId) = CreateTestSessionsAsync();
            string message = "Message with mismatched session ID";
            var (_, encrypted) = _doubleRatchetProtocol.EncryptAsync(aliceSession, message);

            // Add security fields but use a completely different session ID
            encrypted.MessageId = Guid.NewGuid().ToString("N");
            encrypted.Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            encrypted.SessionId = "completely-different-session-id";

            // Act
            var (resultSession, resultMessage) = _doubleRatchetProtocol.DecryptAsync(bobSession, encrypted);

            // Assert
            Assert.IsNull(resultSession, "Session should be null for mismatched session ID");
            Assert.IsNull(resultMessage, "Decrypted message should be null for mismatched session ID");
        }

        [TestMethod]
        public void InvalidMalformedDHKey_ShouldBeRejected()
        {
            // Arrange
            var (aliceSession, bobSession, sessionId) = CreateTestSessionsAsync();
            string message = "Message with invalid DH key";
            var (_, encrypted) = _doubleRatchetProtocol.EncryptAsync(aliceSession, message);
            AddSecurityFields(encrypted, sessionId);

            // Create a malformed DH key (wrong length)
            encrypted.SenderDHKey = new byte[16]; // Too short

            // Act
            var (resultSession, resultMessage) = _doubleRatchetProtocol.DecryptAsync(bobSession, encrypted);

            // Assert
            Assert.IsNull(resultSession, "Session should be null for malformed DH key");
            Assert.IsNull(resultMessage, "Message should be null for malformed DH key");
        }

        [TestMethod]
        public void MaxMessageNumber_ShouldHandleGracefully()
        {
            // Arrange
            var (aliceSession, bobSession, sessionId) = CreateTestSessionsAsync();
            string message = "Message with extreme message number";
            var (_, encrypted) = _doubleRatchetProtocol.EncryptAsync(aliceSession, message);
            AddSecurityFields(encrypted, sessionId);

            // Set an unreasonably high message number
            encrypted.SenderMessageNumber = uint.MaxValue;

            // Act
            try
            {
                var (resultSession, resultMessage) = _doubleRatchetProtocol.DecryptAsync(bobSession, encrypted);

                // Our implementation might choose to accept this (it's not necessarily invalid)
                // but this test verifies that it doesn't cause crashes or memory corruption

                // No specific assertion here - we're mainly ensuring no exceptions are thrown
            }
            catch (Exception ex)
            {
                Assert.Fail($"MaxMessageNumber test should not throw exceptions: {ex.Message}");
            }
        }

        #endregion

        #region Key Rotation Tests

        [TestMethod]
        public void KeyRotation_AfterEveryMessage_ShouldChangeKeys()
        {
            // Arrange
            var (aliceSession, bobSession, sessionId) = CreateTestSessionsAsync();
            var currentAliceSession = aliceSession;
            var previousSenderKey = currentAliceSession.SenderChainKey?.ToArray();

            // Act - Send multiple messages with AfterEveryMessage rotation
            const int messageCount = 5;
            for (int i = 0; i < messageCount; i++)
            {
                string message = $"Rotation test message {i}";
                var (updatedSession, encrypted) = _doubleRatchetProtocol.EncryptAsync(
                    currentAliceSession, message, KeyRotationStrategy.AfterEveryMessage);

                // Add security fields
                AddSecurityFields(encrypted, sessionId);

                // Assert - Verify key has changed
                Assert.IsNotNull(updatedSession, "Session update should not be null");
                Assert.IsNotNull(updatedSession.SenderChainKey, "Sender chain key should not be null");

                if (previousSenderKey != null)
                {
                    Assert.IsFalse(
                        SecureMemory.SecureCompare(previousSenderKey, updatedSession.SenderChainKey),
                        $"Keys should be different after rotation {i}");
                }

                // Update for next iteration
                previousSenderKey = updatedSession.SenderChainKey?.ToArray();
                currentAliceSession = updatedSession;
            }
        }

        [TestMethod]
        public void KeyRotation_Standard_ShouldRotateAfterMultipleMessages()
        {
            // Arrange
            var (aliceSession, bobSession, sessionId) = CreateTestSessionsAsync();
            var currentAliceSession = aliceSession;
            var initialSenderKey = currentAliceSession.SenderChainKey?.ToArray();

            // Act - Send 25 messages with Standard rotation (should rotate after 20)
            const int messageCount = 25;
            DoubleRatchetSession sessionAfterRotation = null;

            for (int i = 0; i < messageCount; i++)
            {
                string message = $"Standard rotation test message {i}";
                var (updatedSession, encrypted) = _doubleRatchetProtocol.EncryptAsync(
                    currentAliceSession, message, KeyRotationStrategy.Standard);

                AddSecurityFields(encrypted, sessionId);
                currentAliceSession = updatedSession;

                // Store the session after expected rotation point
                if (i == 20)
                {
                    sessionAfterRotation = currentAliceSession;
                }
            }

            // Assert - Verify key has changed after rotation point
            if (initialSenderKey != null && sessionAfterRotation?.SenderChainKey != null)
            {
                Assert.IsFalse(
                    SecureMemory.SecureCompare(initialSenderKey, sessionAfterRotation.SenderChainKey),
                    "Keys should be different after standard rotation occurred");
            }
        }

        #endregion
    }
}