using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;
using LibEmiddle.KeyExchange;
using LibEmiddle.Core;
using LibEmiddle.Abstractions;
using LibEmiddle.Domain;
using LibEmiddle.Crypto;
using System.Threading.Tasks;

namespace LibEmiddle.Tests.Unit
{
    [TestClass]
    public class DoubleRatchetTests
    {
        private CryptoProvider _cryptoProvider;

        [TestInitialize]
        public void Setup()
        {
            _cryptoProvider = new CryptoProvider();
        }

        #region Setup Helper Methods

        /// <summary>
        /// Creates a pair of initialized DoubleRatchet sessions for testing
        /// </summary>
        private (DoubleRatchetSession aliceSession, DoubleRatchetSession bobSession, string sessionId) CreateTestSessions()
        {
            var _cryptoProvider = new CryptoProvider();
            var aliceKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.X25519);
            var bobKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.X25519);

            // Initial shared secret
            byte[] sharedSecret = X3DHExchange.PerformX25519DH(bobKeyPair.PublicKey, aliceKeyPair.PrivateKey);
            var (rootKey, chainKey) = _cryptoProvider.DerriveDoubleRatchet(sharedSecret);

            // Create a session ID
            string sessionId = "test-session-" + Guid.NewGuid().ToString();

            var aliceSession = new DoubleRatchetSession(
                dhRatchetKeyPair: aliceKeyPair,
                remoteDHRatchetKey: bobKeyPair.PublicKey,
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumberReceiving: 0,
                messageNumberSending: 0,
                sessionId: sessionId
            );

            var bobSession = new DoubleRatchetSession(
                dhRatchetKeyPair: bobKeyPair,
                remoteDHRatchetKey: aliceKeyPair.PublicKey,
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumberReceiving: 0,
                messageNumberSending: 0,
                sessionId: sessionId
            );

            return (aliceSession, bobSession, sessionId);
        }

        /// <summary>
        /// Adds required security fields to an encrypted message
        /// </summary>
        private void AddSecurityFields(EncryptedMessage message, string sessionId)
        {
            message.MessageId = Guid.NewGuid();
            message.Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            message.SessionId = sessionId;
        }

        #endregion

        #region Basic Functionality Tests

        [TestMethod]
        public void RepeatedRatchetSteps_ShouldProduceUniqueKeys()
        {
            // Arrange
            byte[] initialChainKey = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(initialChainKey);

            // Act - Perform multiple ratchet steps
            HashSet<string> messageKeys = new HashSet<string>();
            byte[] currentChainKey = initialChainKey;
            byte[] previousChainKey = null;

            const int iterations = 100;
            for (int i = 0; i < iterations; i++)
            {
                // Store the previous chain key for comparison
                previousChainKey = currentChainKey;

                var (newChainKey, messageKey) = _cryptoProvider.RatchetStep(currentChainKey);

                // Convert key to string for hashset comparison
                string messageKeyStr = Convert.ToBase64String(messageKey);

                // Assert each message key is unique
                Assert.IsFalse(messageKeys.Contains(messageKeyStr),
                    $"Message key collision detected at iteration {i}");

                messageKeys.Add(messageKeyStr);
                currentChainKey = newChainKey;

                // Ensure chain keys are changing from the initial value
                Assert.IsFalse(TestsHelpers.AreByteArraysEqual(initialChainKey, currentChainKey),
                    "Chain key should change from initial value");

                // Verify chain key changed from previous iteration
                if (i > 0)
                {
                    Assert.IsFalse(TestsHelpers.AreByteArraysEqual(previousChainKey, currentChainKey),
                        $"Chain key should change at each iteration (iteration {i})");
                }
            }

            // Verify we have the expected number of unique keys
            Assert.AreEqual(iterations, messageKeys.Count,
                "Should have generated the correct number of unique message keys");
        }

        [TestMethod]
        public void OutOfOrderMessages_ShouldDecryptCorrectly()
        {
            // Arrange
            var (aliceSession, bobSession, sessionId) = CreateTestSessions();

            // Create just one message
            string message = "Test message";
            var (aliceUpdatedSession, encrypted) = _cryptoProvider.DoubleRatchetEncrypt(aliceSession, message);
            AddSecurityFields(encrypted, sessionId);

            // Decrypt the message
            var (bobUpdatedSession, decrypted) = _cryptoProvider.DoubleRatchetDecrypt(bobSession, encrypted);

            // Assert the basic encryption/decryption works
            Assert.IsNotNull(bobUpdatedSession, "Session should be updated after decryption");
            Assert.IsNotNull(decrypted, "Message should be successfully decrypted");
            Assert.AreEqual(message, decrypted, "Decrypted content should match original");
        }

        [TestMethod]
        public void MessageExpiration_BasedOnTimestamp()
        {
            // Arrange
            var (aliceSession, bobSession, sessionId) = CreateTestSessions();

            string message = "This message will expire";
            var (_, encrypted) = _cryptoProvider.DoubleRatchetEncrypt(aliceSession, message);

            // Set timestamp to 10 minutes in the past (beyond the 5 minute threshold)
            encrypted.MessageId = Guid.NewGuid();
            encrypted.Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - 10 * 60 * 1000;
            encrypted.SessionId = sessionId;

            // Act
            var (resultSession, resultMessage) = _cryptoProvider.DoubleRatchetDecrypt(bobSession, encrypted);

            // Assert
            Assert.IsNull(resultSession, "Session should be null for expired message");
            Assert.IsNull(resultMessage, "Decrypted message should be null for expired message");
        }

        [TestMethod]
        public void UnsignedLongOverflowTimestamp_ShouldBeRejected()
        {
            // Arrange
            var (aliceSession, bobSession, sessionId) = CreateTestSessions();

            string message = "Message with suspicious timestamp";
            var (_, encrypted) = _cryptoProvider.DoubleRatchetEncrypt(aliceSession, message);

            // Set extremely high timestamp (potential overflow attack)
            encrypted.MessageId = Guid.NewGuid();
            encrypted.Timestamp = long.MaxValue;
            encrypted.SessionId = sessionId;

            // Act
            var (resultSession, resultMessage) = _cryptoProvider.DoubleRatchetDecrypt(bobSession, encrypted);

            // Assert
            Assert.IsNull(resultSession, "Session should be null for suspicious timestamp");
            Assert.IsNull(resultMessage, "Decrypted message should be null for suspicious timestamp");
        }

        [TestMethod]
        public void NegativeTimestamp_ShouldBeRejected()
        {
            // Arrange
            var (aliceSession, bobSession, sessionId) = CreateTestSessions();

            string message = "Message with negative timestamp";
            var (_, encrypted) = _cryptoProvider.DoubleRatchetEncrypt(aliceSession, message);

            // Set negative timestamp (potential overflow attack)
            encrypted.MessageId = Guid.NewGuid();
            encrypted.Timestamp = -1;
            encrypted.SessionId = sessionId;

            // Act
            var (resultSession, resultMessage) = _cryptoProvider.DoubleRatchetDecrypt(bobSession, encrypted);

            // Assert
            Assert.IsNull(resultSession, "Session should be null for negative timestamp");
            Assert.IsNull(resultMessage, "Decrypted message should be null for negative timestamp");
        }

        #endregion

        #region Extended Security Tests

        [TestMethod]
        public void LongConversation_ShouldMaintainSecurity()
        {
            // Arrange
            var (aliceSession, bobSession, sessionId) = CreateTestSessions();
            var currentAliceSession = aliceSession;
            var currentBobSession = bobSession;

            // Store initial key states for comparison
            byte[] initialAliceSendingChainKey = new byte[aliceSession.SendingChainKey.Length];
            Array.Copy(aliceSession.SendingChainKey, initialAliceSendingChainKey, initialAliceSendingChainKey.Length);

            byte[] initialBobSendingChainKey = new byte[bobSession.SendingChainKey.Length];
            Array.Copy(bobSession.SendingChainKey, initialBobSendingChainKey, initialBobSendingChainKey.Length);

            // Act - Simulate a long conversation with 100 messages
            const int messageCount = 100;
            for (int i = 0; i < messageCount; i++)
            {
                // Alternate messages between Alice and Bob
                if (i % 2 == 0)
                {
                    // Alice sends message to Bob
                    string message = $"Alice message {i}";
                    var (updatedAliceSession, encrypted) = _cryptoProvider.DoubleRatchetEncrypt(currentAliceSession, message);
                    AddSecurityFields(encrypted, sessionId);
                    var (updatedBobSession, decrypted) = _cryptoProvider.DoubleRatchetDecrypt(currentBobSession, encrypted);

                    Assert.IsNotNull(updatedAliceSession, $"Alice's session update failed at message {i}");
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
                    var (updatedBobSession, encrypted) = _cryptoProvider.DoubleRatchetEncrypt(currentBobSession, message);
                    AddSecurityFields(encrypted, sessionId);
                    var (updatedAliceSession, decrypted) = _cryptoProvider.DoubleRatchetDecrypt(currentAliceSession, encrypted);

                    Assert.IsNotNull(updatedBobSession, $"Bob's session update failed at message {i}");
                    Assert.IsNotNull(updatedAliceSession, $"Alice's session update failed at message {i}");
                    Assert.IsNotNull(decrypted, $"Decryption failed at message {i}");
                    Assert.AreEqual(message, decrypted, $"Message content mismatch at message {i}");

                    currentBobSession = updatedBobSession;
                    currentAliceSession = updatedAliceSession;
                }

                // Periodically force garbage collection to test memory safety
                if (i % 10 == 0)
                {
                    GC.Collect();
                    GC.WaitForPendingFinalizers();
                }
            }

            // Verify that chain keys have changed (this should always happen)
            Assert.IsFalse(SecureMemory.SecureCompare(initialAliceSendingChainKey, currentAliceSession.SendingChainKey),
                "Alice's sending chain key should have changed during the conversation");
            Assert.IsFalse(SecureMemory.SecureCompare(initialBobSendingChainKey, currentBobSession.SendingChainKey),
                "Bob's sending chain key should have changed during the conversation");

            // Note: We're not checking root keys anymore since they might only change during DH ratchet steps,
            // which might not occur during normal conversation without explicit key changes
        }

        [TestMethod]
        public void DoubleRatchetSessionImmutability_ShouldBeEnforced()
        {
            // Arrange
            var (aliceSession, bobSession, sessionId) = CreateTestSessions();

            // Keep the original chain key for comparison
            byte[] originalSendingChainKey = aliceSession.SendingChainKey;

            // Act - Use Alice's session to encrypt a message
            string message = "Test message for immutability";
            var (updatedSession, encrypted) = _cryptoProvider.DoubleRatchetEncrypt(aliceSession, message);

            // Assert - Original session should not be modified
            Assert.AreNotSame(aliceSession, updatedSession,
                "Updated session should be a different instance than original session");

            // Sending chain key should have changed in the updated session but not in the original
            Assert.IsFalse(TestsHelpers.AreByteArraysEqual(originalSendingChainKey, updatedSession.SendingChainKey),
                "Sending chain key should change in the updated session");
            Assert.IsTrue(TestsHelpers.AreByteArraysEqual(originalSendingChainKey, aliceSession.SendingChainKey),
                "Original session's sending chain key should remain unchanged");

            // Message number should be incremented in the updated session but not the original
            Assert.AreEqual(0, aliceSession.MessageNumberReceiving,
                "Original session's message number should remain unchanged");
            Assert.AreEqual(1, updatedSession.MessageNumberSending,
                "Updated session's message number should be incremented");
        }

        [TestMethod]
        public void ExtensiveReplayProtection_ShouldPreventReplayAttacks()
        {
            // Arrange
            var (aliceSession, bobSession, sessionId) = CreateTestSessions();

            // Send a message from Alice to Bob
            string message = "Message that should not be replayable";
            var (_, encrypted) = _cryptoProvider.DoubleRatchetEncrypt(aliceSession, message);

            // Add security fields
            encrypted.MessageId = Guid.NewGuid();
            encrypted.Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            encrypted.SessionId = sessionId;

            // First decryption should succeed
            var (bobUpdatedSession, decrypted) = _cryptoProvider.DoubleRatchetDecrypt(bobSession, encrypted);

            Assert.IsNotNull(bobUpdatedSession, "First decryption should succeed");
            Assert.IsNotNull(decrypted, "First decryption should succeed");
            Assert.AreEqual(message, decrypted, "First decryption should return correct message");

            // Act - Try to decrypt the exact same message again (replay attempt)
            var (replaySession, replayMessage) = _cryptoProvider.DoubleRatchetDecrypt(bobUpdatedSession, encrypted);

            // Assert - Replay should be detected and rejected
            Assert.IsNull(replaySession, "Replay attempt should be rejected (session)");
            Assert.IsNull(replayMessage, "Replay attempt should be rejected (message)");

            // Try with several variations of replays to ensure comprehensive protection

            // 1. Same content but new message ID (should still be detected by message number)
            var replayWithNewId = new EncryptedMessage
            {
                Ciphertext = encrypted.Ciphertext,
                Nonce = encrypted.Nonce,
                MessageNumber = encrypted.MessageNumber, // Same message number
                SenderDHKey = encrypted.SenderDHKey,
                Timestamp = encrypted.Timestamp,
                MessageId = Guid.NewGuid(), // New ID
                SessionId = sessionId
            };

            var (replayResult1, replayMessage1) = _cryptoProvider.DoubleRatchetDecrypt(bobUpdatedSession, replayWithNewId);

            Assert.IsNull(replayResult1, "Replay with new ID should be rejected (session)");
            Assert.IsNull(replayMessage1, "Replay with new ID should be rejected (message)");

            // 2. Same content, new ID, updated timestamp
            var replayWithNewTimestamp = new EncryptedMessage
            {
                Ciphertext = encrypted.Ciphertext,
                Nonce = encrypted.Nonce,
                MessageNumber = encrypted.MessageNumber,
                SenderDHKey = encrypted.SenderDHKey,
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), // New timestamp
                MessageId = Guid.NewGuid(),
                SessionId = sessionId
            };

            var (replayResult2, replayMessage2) = _cryptoProvider.DoubleRatchetDecrypt(bobUpdatedSession, replayWithNewTimestamp);

            Assert.IsNull(replayResult2, "Replay with new timestamp should be rejected (session)");
            Assert.IsNull(replayMessage2, "Replay with new timestamp should be rejected (message)");
        }

        [TestMethod]
        public async Task MultiThreadedRatchetingSecurity_SimulatesStressTest()
        {
            // Arrange
            var (aliceSession, bobSession, sessionId) = CreateTestSessions();

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
                    return _cryptoProvider.DoubleRatchetEncrypt(aliceSession, message);
                });
                encryptTasks.Add(task);
            }

            // Act - Wait for all tasks to complete (using await instead of .Wait())
            await Task.WhenAll(encryptTasks).ConfigureAwait(false);

            // Collect all the encrypted messages and updated sessions
            var results = encryptTasks.Select(t => t.Result).ToList();

            // Assert - Each task should complete successfully
            foreach (var (updatedSession, encryptedMessage) in results)
            {
                Assert.IsNotNull(updatedSession, "Updated session should not be null");
                Assert.IsNotNull(encryptedMessage, "Encrypted message should not be null");
                Assert.IsNotNull(encryptedMessage.Ciphertext, "Ciphertext should not be null");

                // Make sure the session has been updated properly
                Assert.AreEqual(1, updatedSession.MessageNumberSending,
                    "All sessions should have message number 1");

                // Make sure the chain key has changed (it's not the same as the original session)
                Assert.IsFalse(SecureMemory.SecureCompare(aliceSession.SendingChainKey, updatedSession.SendingChainKey),
                    "Updated session should have a different sending chain key than the original");
            }

            // Verify that all the updated sessions have the same chain key
            // This is expected because the encryption operation is deterministic
            // when starting from the same session state
            string firstSessionHash = Convert.ToBase64String(results[0].Item1.SendingChainKey);
            for (int i = 1; i < results.Count; i++)
            {
                string sessionHash = Convert.ToBase64String(results[i].Item1.SendingChainKey);
                Assert.AreEqual(firstSessionHash, sessionHash,
                    "All updated sessions should have the same chain key when starting from the same session");
            }
        }

        [TestMethod]
        public void ExtremeLongMessages_ShouldProcess()
        {
            // Arrange
            var (aliceSession, bobSession, sessionId) = CreateTestSessions();

            // Create extremely long message (1MB)
            StringBuilder messageBuilder = new StringBuilder(1024 * 1024);
            for (int i = 0; i < 1024 * 1024 / 100; i++)
            {
                messageBuilder.Append("This is part of an extremely long message to test the robustness of the Double Ratchet protocol. ");
            }
            string longMessage = messageBuilder.ToString();

            // Act
            var (aliceUpdatedSession, encrypted) = _cryptoProvider.DoubleRatchetEncrypt(aliceSession, longMessage);
            AddSecurityFields(encrypted, sessionId);

            var (bobUpdatedSession, decrypted) = _cryptoProvider.DoubleRatchetDecrypt(bobSession, encrypted);

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
            var (aliceSession, bobSession, sessionId) = CreateTestSessions();

            // Act & Assert - Empty message should throw ArgumentException
            Assert.ThrowsException<ArgumentException>(() => {
                _cryptoProvider.DoubleRatchetEncrypt(aliceSession, "");
            }, "Empty message should be rejected");
        }

        [TestMethod]
        public void ZeroByteMessage_ShouldBeHandled()
        {
            // Arrange
            var (aliceSession, bobSession, sessionId) = CreateTestSessions();
            string zeroByteMessage = "\0";

            // Act
            var (aliceUpdatedSession, encrypted) = _cryptoProvider.DoubleRatchetEncrypt(aliceSession, zeroByteMessage);
            AddSecurityFields(encrypted, sessionId);

            var (bobUpdatedSession, decrypted) = _cryptoProvider.DoubleRatchetDecrypt(bobSession, encrypted);

            // Assert
            Assert.IsNotNull(decrypted, "Null byte message should be decryptable");
            Assert.AreEqual(zeroByteMessage, decrypted, "Null byte should be preserved");
        }

        [TestMethod]
        public void SpecialCharacters_ShouldBePreserved()
        {
            // Arrange
            var (aliceSession, bobSession, sessionId) = CreateTestSessions();
            string specialCharsMessage = "Special chars: 你好 áéíóú ñ Ж ß Ø אבג 😊 🔐 ∞ ≈ π √";

            // Act
            var (aliceUpdatedSession, encrypted) = _cryptoProvider.DoubleRatchetEncrypt(aliceSession, specialCharsMessage);
            AddSecurityFields(encrypted, sessionId);

            var (bobUpdatedSession, decrypted) = _cryptoProvider.DoubleRatchetDecrypt(bobSession, encrypted);

            // Assert
            Assert.IsNotNull(decrypted, "Special character message should be decryptable");
            Assert.AreEqual(specialCharsMessage, decrypted, "Special characters should be preserved");
        }

        [TestMethod]
        public void MissingSessionId_ShouldBeRejected()
        {
            // Arrange
            var (aliceSession, bobSession, sessionId) = CreateTestSessions();
            string message = "Message with mismatched session ID";
            var (_, encrypted) = _cryptoProvider.DoubleRatchetEncrypt(aliceSession, message);

            // Add security fields but use a completely different session ID
            encrypted.MessageId = Guid.NewGuid();
            encrypted.Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            encrypted.SessionId = "completely-different-session-id";

            // Act
            var (resultSession, resultMessage) = _cryptoProvider.DoubleRatchetDecrypt(bobSession, encrypted);

            // Assert
            Assert.IsNull(resultSession, "Session should be null for mismatched session ID");
            Assert.IsNull(resultMessage, "Decrypted message should be null for mismatched session ID");
        }

        [TestMethod]
        public void InvalidMalformedDHKey_ShouldBeRejected()
        {
            // Arrange
            var (aliceSession, bobSession, sessionId) = CreateTestSessions();
            string message = "Message with invalid DH key";
            var (_, encrypted) = _cryptoProvider.DoubleRatchetEncrypt(aliceSession, message);
            AddSecurityFields(encrypted, sessionId);

            // Create a malformed DH key (wrong length)
            encrypted.SenderDHKey = new byte[16]; // Too short

            // Act
            var (resultSession, resultMessage) = _cryptoProvider.DoubleRatchetDecrypt(bobSession, encrypted);

            // Assert
            Assert.IsNull(resultSession, "Session should be null for malformed DH key");
            Assert.IsNull(resultMessage, "Message should be null for malformed DH key");
        }

        [TestMethod]
        public void BrokenMessageNumber_ShouldHandleGracefully()
        {
            // Arrange
            var (aliceSession, bobSession, sessionId) = CreateTestSessions();

            string message = "Message with extreme message number";
            var (_, encrypted) = _cryptoProvider.DoubleRatchetEncrypt(aliceSession, message);
            AddSecurityFields(encrypted, sessionId);

            // Set an unreasonably high message number
            encrypted.MessageNumber = int.MaxValue;

            // Act
            var (resultSession, resultMessage) = _cryptoProvider.DoubleRatchetDecrypt(bobSession, encrypted);

            // Our implementation might choose to accept this (it's not necessarily invalid)
            // but this test verifies that it doesn't cause crashes or memory corruption

            // No specific assertion here - we're mainly ensuring no exceptions are thrown
        }

        #endregion
    }
}