#pragma warning disable CS8632 // Nullable annotation from nullable-enabled assembly reference
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Threading.Tasks;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.Messaging.Chat;
using LibEmiddle.Protocol;
using LibEmiddle.Abstractions;
using LibEmiddle.Sessions;

namespace LibEmiddle.Tests.Unit
{
    /// <summary>
    /// Tests for replay attack protection in ChatSession.DecryptAsync.
    /// Verifies that identical encrypted messages are silently dropped after the first
    /// successful decryption, and that the processed-message-ID tracker is bounded.
    /// </summary>
    [TestClass]
    public class ChatSessionReplayProtectionTests
    {
        private KeyPair _aliceKeyPair;
        private KeyPair _bobKeyPair;

        private CryptoProvider _cryptoProvider;
        private DoubleRatchetProtocol _doubleRatchetProtocol;
        private X3DHProtocol _x3DHProtocol;
        private ProtocolAdapter _protocolAdapter;

        private ChatSession _aliceChatSession;
        private ChatSession _bobChatSession;

        [TestInitialize]
        public async Task Setup()
        {
            _cryptoProvider = new CryptoProvider();
            _doubleRatchetProtocol = new DoubleRatchetProtocol();
            _x3DHProtocol = new X3DHProtocol(_cryptoProvider);
            _protocolAdapter = new ProtocolAdapter(_x3DHProtocol, _doubleRatchetProtocol, _cryptoProvider);

            _aliceKeyPair = Sodium.GenerateEd25519KeyPair();
            _bobKeyPair = Sodium.GenerateEd25519KeyPair();

            string sessionId = Guid.NewGuid().ToString();

            X3DHKeyBundle bobX3DHBundle = await _x3DHProtocol.CreateKeyBundleAsync(_bobKeyPair);
            X3DHPublicBundle bobPublicBundle = bobX3DHBundle.ToPublicBundle();

            var prepareSenderResult = await _protocolAdapter.PrepareSenderSessionAsync(
                bobPublicBundle, _aliceKeyPair, sessionId);

            var aliceDRSession = prepareSenderResult.Item1;
            var initialMessage = prepareSenderResult.Item2;

            var bobDRSession = await _protocolAdapter.PrepareReceiverSessionAsync(
                initialMessage, bobX3DHBundle, sessionId);

            _aliceChatSession = new ChatSession(
                aliceDRSession,
                _bobKeyPair.PublicKey,
                _aliceKeyPair.PublicKey,
                _doubleRatchetProtocol
            );

            _bobChatSession = new ChatSession(
                bobDRSession,
                _aliceKeyPair.PublicKey,
                _bobKeyPair.PublicKey,
                _doubleRatchetProtocol
            );

            _aliceChatSession.SetInitialMessageData(initialMessage);
        }

        [TestCleanup]
        public void Cleanup()
        {
            try { _aliceChatSession?.Dispose(); } catch (ObjectDisposedException) { }
            try { _bobChatSession?.Dispose(); } catch (ObjectDisposedException) { }
            try { _cryptoProvider?.Dispose(); } catch (ObjectDisposedException) { }
        }

        /// <summary>
        /// Encrypting the same plaintext produces a unique MessageId each time.
        /// Replaying the exact same EncryptedMessage object must be rejected.
        /// </summary>
        [TestMethod]
        public async Task DecryptAsync_ReplayedMessage_ReturnsNull()
        {
            // Arrange
            string plaintext = "Hello, Bob!";
            EncryptedMessage encryptedMessage = await _aliceChatSession.EncryptAsync(plaintext);
            Assert.IsNotNull(encryptedMessage, "Encryption should succeed.");

            // First decryption — must succeed
            string firstResult = await _bobChatSession.DecryptAsync(encryptedMessage);
            Assert.IsNotNull(firstResult, "First decryption should succeed.");
            Assert.AreEqual(plaintext, firstResult, "Decrypted content should match original.");

            // Act — replay the same ciphertext object
            string replayResult = await _bobChatSession.DecryptAsync(encryptedMessage);

            // Assert — replay must be silently dropped
            Assert.IsNull(replayResult, "Replayed message should be rejected (returned null).");
        }

        /// <summary>
        /// Ten copies of the same encrypted message should only yield one successful decryption.
        /// </summary>
        [TestMethod]
        public async Task DecryptAsync_TenCopiesOfSameMessage_OnlyFirstAccepted()
        {
            // Arrange
            string plaintext = "Replay stress test";
            EncryptedMessage encryptedMessage = await _aliceChatSession.EncryptAsync(plaintext);
            Assert.IsNotNull(encryptedMessage);

            int successCount = 0;
            int nullCount = 0;

            // Act — attempt to decrypt the same message 10 times
            for (int i = 0; i < 10; i++)
            {
                // Clone the message so each attempt uses a structurally identical object
                // (same MessageId, same ciphertext, same nonce — i.e., a genuine replay).
                EncryptedMessage copy = encryptedMessage.Clone();
                string result = await _bobChatSession.DecryptAsync(copy);

                if (result != null)
                    successCount++;
                else
                    nullCount++;
            }

            // Assert
            Assert.AreEqual(1, successCount, "Exactly one copy should be decrypted successfully.");
            Assert.AreEqual(9, nullCount, "The remaining 9 copies must be silently rejected.");
        }

        /// <summary>
        /// Two different messages sent by Alice should both decrypt successfully — the replay
        /// tracker must not incorrectly block legitimate distinct messages.
        /// </summary>
        [TestMethod]
        public async Task DecryptAsync_TwoDistinctMessages_BothAccepted()
        {
            // Arrange
            EncryptedMessage msg1 = await _aliceChatSession.EncryptAsync("First message");
            EncryptedMessage msg2 = await _aliceChatSession.EncryptAsync("Second message");

            Assert.IsNotNull(msg1);
            Assert.IsNotNull(msg2);
            Assert.AreNotEqual(msg1.MessageId, msg2.MessageId, "Each message should have a unique MessageId.");

            // Act
            string result1 = await _bobChatSession.DecryptAsync(msg1);
            string result2 = await _bobChatSession.DecryptAsync(msg2);

            // Assert
            Assert.IsNotNull(result1, "First distinct message should be accepted.");
            Assert.IsNotNull(result2, "Second distinct message should be accepted.");
            Assert.AreEqual("First message", result1);
            Assert.AreEqual("Second message", result2);
        }

        /// <summary>
        /// After the second distinct message is received, replaying the first (older) message
        /// is still rejected because its ID remains in the tracker.
        /// </summary>
        [TestMethod]
        public async Task DecryptAsync_ReplayOlderMessageAfterNewerArrives_Rejected()
        {
            // Arrange
            EncryptedMessage msg1 = await _aliceChatSession.EncryptAsync("Message A");
            EncryptedMessage msg2 = await _aliceChatSession.EncryptAsync("Message B");

            Assert.IsNotNull(msg1);
            Assert.IsNotNull(msg2);

            // First receive both in order
            string r1 = await _bobChatSession.DecryptAsync(msg1);
            string r2 = await _bobChatSession.DecryptAsync(msg2);
            Assert.IsNotNull(r1);
            Assert.IsNotNull(r2);

            // Act — replay msg1 (older message)
            string replayResult = await _bobChatSession.DecryptAsync(msg1.Clone());

            // Assert
            Assert.IsNull(replayResult, "Replaying an older already-processed message must be rejected.");
        }

        /// <summary>
        /// Verifies that a message with a null/missing MessageId is deduplicated using the
        /// structural fallback key (SessionId + SenderMessageNumber + Nonce).
        /// </summary>
        [TestMethod]
        public async Task DecryptAsync_ReplayedMessageWithNullMessageId_ReturnsNull()
        {
            // Arrange
            EncryptedMessage encryptedMessage = await _aliceChatSession.EncryptAsync("Null-ID replay test");
            Assert.IsNotNull(encryptedMessage);

            // Strip the MessageId to force fallback key path
            encryptedMessage.MessageId = null;

            string firstResult = await _bobChatSession.DecryptAsync(encryptedMessage);
            Assert.IsNotNull(firstResult, "First decryption (null MessageId) should succeed.");

            // Act — replay with same null MessageId (identical structural content)
            EncryptedMessage replay = encryptedMessage.Clone();
            // replay.MessageId is already null after Clone()
            string replayResult = await _bobChatSession.DecryptAsync(replay);

            // Assert
            Assert.IsNull(replayResult, "Structural replay with null MessageId should be rejected.");
        }

        /// <summary>
        /// When throwOnReplay=true, replayed messages throw InvalidOperationException
        /// instead of returning null.
        /// </summary>
        [TestMethod]
        public async Task DecryptAsync_ThrowOnReplay_ThrowsInvalidOperationException()
        {
            // Arrange — create Bob's session with throwOnReplay=true
            var bobThrowSession = new ChatSession(
                _bobChatSession.GetCryptoSessionState(),
                _aliceKeyPair.PublicKey,
                _bobKeyPair.PublicKey,
                _doubleRatchetProtocol,
                throwOnReplay: true
            );

            string plaintext = "ThrowMode test";
            EncryptedMessage encryptedMessage = await _aliceChatSession.EncryptAsync(plaintext);
            Assert.IsNotNull(encryptedMessage);

            // First decryption must succeed
            string firstResult = await bobThrowSession.DecryptAsync(encryptedMessage);
            Assert.IsNotNull(firstResult, "First decryption should succeed.");

            // Act + Assert — replay must throw
            await Assert.ThrowsExceptionAsync<InvalidOperationException>(
                async () => await bobThrowSession.DecryptAsync(encryptedMessage.Clone()),
                "Replayed message in throwOnReplay mode should throw InvalidOperationException."
            );

            bobThrowSession.Dispose();
        }

        /// <summary>
        /// After the 500-entry cap is reached, the oldest evicted message ID is accepted again
        /// (because it is no longer in the tracker).
        /// </summary>
        [TestMethod]
        public async Task DecryptAsync_EvictionAt500Cap_EvictedMessageAcceptedAgain()
        {
            // We need 501 unique encrypted messages from Alice to Bob.
            // Use a fresh pair of sessions so we start from a clean state.
            var aliceFresh = new ChatSession(
                _aliceChatSession.GetCryptoSessionState(),
                _bobKeyPair.PublicKey,
                _aliceKeyPair.PublicKey,
                _doubleRatchetProtocol
            );
            var bobFresh = new ChatSession(
                _bobChatSession.GetCryptoSessionState(),
                _aliceKeyPair.PublicKey,
                _bobKeyPair.PublicKey,
                _doubleRatchetProtocol
            );

            // Encrypt and successfully decrypt 500 unique messages to fill the tracker.
            EncryptedMessage firstMessage = null;
            for (int i = 0; i < 500; i++)
            {
                var msg = await aliceFresh.EncryptAsync($"fill {i}");
                Assert.IsNotNull(msg);
                if (i == 0) firstMessage = msg.Clone(); // save a copy of the first message
                var result = await bobFresh.DecryptAsync(msg);
                Assert.IsNotNull(result, $"Fill message {i} should decrypt successfully.");
            }

            // Replay the FIRST message — still in tracker, should be rejected.
            string replay1 = await bobFresh.DecryptAsync(firstMessage!.Clone());
            Assert.IsNull(replay1, "First message should still be in tracker (not yet evicted).");

            // Add message #501 — this evicts message #0 (FIFO).
            var msg501 = await aliceFresh.EncryptAsync("message 501");
            Assert.IsNotNull(msg501);
            var result501 = await bobFresh.DecryptAsync(msg501);
            Assert.IsNotNull(result501, "Message 501 should decrypt successfully.");

            // Now the first message is evicted; its ID is no longer tracked.
            // However, replaying it still won't decrypt (Double Ratchet state has advanced),
            // but the replay-protection check itself should NOT block it (it's been evicted).
            // We verify the eviction by asserting we do NOT get an InvalidOperationException
            // when using throwOnReplay mode — only a null from crypto failure.
            var bobThrow = new ChatSession(
                bobFresh.GetCryptoSessionState(),
                _aliceKeyPair.PublicKey,
                _bobKeyPair.PublicKey,
                _doubleRatchetProtocol,
                throwOnReplay: true
            );
            // Since the ID is evicted, throwOnReplay should NOT fire — crypto will just fail.
            // The method returns null rather than throwing.
            string evictedReplay = null;
            try
            {
                evictedReplay = await bobThrow.DecryptAsync(firstMessage.Clone());
            }
            catch (InvalidOperationException)
            {
                Assert.Fail("Evicted message should not trigger throwOnReplay — it's no longer in tracker.");
            }
            // Crypto failure produces null (not the same key anymore).
            Assert.IsNull(evictedReplay, "Evicted message ID passes replay check but fails crypto — returns null.");

            aliceFresh.Dispose();
            bobFresh.Dispose();
            bobThrow.Dispose();
        }

        /// <summary>
        /// An empty-string MessageId is deduplicated correctly and does not collide with
        /// other messages that also have empty/null MessageIds.
        /// </summary>
        [TestMethod]
        public async Task DecryptAsync_EmptyStringMessageId_ReplayRejectedNoCrossCollision()
        {
            // Arrange — encrypt two distinct messages and force both to empty-string MessageId
            EncryptedMessage msg1 = await _aliceChatSession.EncryptAsync("msg1 empty id");
            EncryptedMessage msg2 = await _aliceChatSession.EncryptAsync("msg2 empty id");
            Assert.IsNotNull(msg1);
            Assert.IsNotNull(msg2);

            msg1.MessageId = string.Empty;
            msg2.MessageId = string.Empty;

            // First decrypt of msg1 should succeed (structural key differs from msg2)
            string result1 = await _bobChatSession.DecryptAsync(msg1);
            Assert.IsNotNull(result1, "First message with empty MessageId should decrypt successfully.");

            // Replay of msg1 (identical structure) must be rejected
            string replay1 = await _bobChatSession.DecryptAsync(msg1.Clone());
            Assert.IsNull(replay1, "Replay of msg1 (empty MessageId) should be rejected.");

            // msg2 has different structure (different nonce, ciphertext) — must NOT be blocked by msg1's entry
            string result2 = await _bobChatSession.DecryptAsync(msg2);
            Assert.IsNotNull(result2, "Second distinct message with empty MessageId should not be blocked by msg1.");
        }

        /// <summary>
        /// Sanity check: the tracker must not affect normal bidirectional messaging.
        /// Alice and Bob each send and receive several messages without interference.
        /// </summary>
        [TestMethod]
        public async Task DecryptAsync_NormalBidirectionalConversation_AllMessagesAccepted()
        {
            // Arrange + Act
            for (int i = 0; i < 5; i++)
            {
                EncryptedMessage aliceMsg = await _aliceChatSession.EncryptAsync("Alice says " + i);
                Assert.IsNotNull(aliceMsg, "Alice encryption #" + i + " should succeed.");

                string bobReceived = await _bobChatSession.DecryptAsync(aliceMsg);
                Assert.IsNotNull(bobReceived, "Bob decryption #" + i + " should succeed.");
                Assert.AreEqual("Alice says " + i, bobReceived);

                EncryptedMessage bobMsg = await _bobChatSession.EncryptAsync("Bob says " + i);
                Assert.IsNotNull(bobMsg, "Bob encryption #" + i + " should succeed.");

                string aliceReceived = await _aliceChatSession.DecryptAsync(bobMsg);
                Assert.IsNotNull(aliceReceived, "Alice decryption #" + i + " should succeed.");
                Assert.AreEqual("Bob says " + i, aliceReceived);
            }
        }
    }
}
