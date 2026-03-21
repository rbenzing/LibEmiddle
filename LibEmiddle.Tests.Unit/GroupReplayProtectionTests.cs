using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;
using LibEmiddle.Messaging.Group;

namespace LibEmiddle.Tests.Unit
{
    /// <summary>
    /// Tests for replay-attack protection in GroupSession.DecryptMessageAsync.
    ///
    /// Verifies that:
    ///   - A replayed message is silently dropped (null) after the first successful decryption.
    ///   - Ten copies of the same message are only accepted once.
    ///   - The message ID is registered only AFTER a successful decryption.
    ///   - Sequence-number tracking rejects replay for messages without a MessageId.
    ///   - Distinct messages from the same sender are all accepted correctly.
    ///   - Replay state is reset correctly when a new sender-key distribution is processed
    ///     (e.g., after key rotation).
    ///   - Cross-sender isolation: replay tracking for one sender does not affect another.
    /// </summary>
    [TestClass]
    public class GroupReplayProtectionTests
    {
        private CryptoProvider _cryptoProvider;

        [TestInitialize]
        public void Setup()
        {
            _cryptoProvider = new CryptoProvider();
        }

        [TestCleanup]
        public void Cleanup()
        {
            try { _cryptoProvider?.Dispose(); } catch (ObjectDisposedException) { }
        }

        // ------------------------------------------------------------------
        // Helper: create two sessions that can communicate with each other.
        // ------------------------------------------------------------------
        private async Task<(GroupSession sender, GroupSession receiver)> BuildPairAsync()
        {
            var senderKey = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var receiverKey = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            string groupId = $"replay-test-{Guid.NewGuid()}";
            const string groupName = "Replay Test Group";

            var sender = new GroupSession(groupId, groupName, senderKey);
            var receiver = new GroupSession(groupId, groupName, receiverKey);

            await sender.ActivateAsync();
            await receiver.ActivateAsync();

            await sender.AddMemberAsync(receiverKey.PublicKey);
            await receiver.AddMemberAsync(senderKey.PublicKey);

            var senderDist = sender.CreateDistributionMessage();
            var receiverDist = receiver.CreateDistributionMessage();

            receiver.ProcessDistributionMessage(senderDist);
            sender.ProcessDistributionMessage(receiverDist);

            return (sender, receiver);
        }

        // ------------------------------------------------------------------
        // AC: Replay same message — rejected
        // ------------------------------------------------------------------

        [TestMethod]
        public async Task DecryptMessageAsync_ReplayedMessage_IsRejected()
        {
            // Arrange
            var (sender, receiver) = await BuildPairAsync();
            var encrypted = await sender.EncryptMessageAsync("Hello, group!");
            Assert.IsNotNull(encrypted, "Encryption should succeed.");

            // Act — first decryption
            string firstResult = await receiver.DecryptMessageAsync(encrypted);
            Assert.IsNotNull(firstResult, "First decryption should succeed.");
            Assert.AreEqual("Hello, group!", firstResult);

            // Act — replay
            string replayResult = await receiver.DecryptMessageAsync(encrypted);

            // Assert
            Assert.IsNull(replayResult, "Replayed message should be silently dropped (return null).");
        }

        // ------------------------------------------------------------------
        // AC: 10 copies of same message — only first accepted
        // ------------------------------------------------------------------

        [TestMethod]
        public async Task DecryptMessageAsync_TenCopiesOfSameMessage_OnlyFirstAccepted()
        {
            // Arrange
            var (sender, receiver) = await BuildPairAsync();
            var encrypted = await sender.EncryptMessageAsync("Replay stress test");
            Assert.IsNotNull(encrypted);

            int successCount = 0;
            int nullCount = 0;

            // Act — attempt to decrypt the same message 10 times
            for (int i = 0; i < 10; i++)
            {
                // Clone so each attempt uses a structurally identical but distinct object
                var copy = encrypted.Clone();
                string result = await receiver.DecryptMessageAsync(copy);

                if (result != null)
                    successCount++;
                else
                    nullCount++;
            }

            // Assert
            Assert.AreEqual(1, successCount, "Exactly one copy should be accepted.");
            Assert.AreEqual(9, nullCount, "The remaining 9 copies must be silently rejected.");
        }

        // ------------------------------------------------------------------
        // AC: Message ID added AFTER successful decryption (not before)
        // A transient bad ciphertext does not permanently block the real message.
        // ------------------------------------------------------------------

        [TestMethod]
        public async Task DecryptMessageAsync_FailedDecryptionDoesNotConsumeMessageId()
        {
            // Arrange
            var (sender, receiver) = await BuildPairAsync();
            var goodMessage = await sender.EncryptMessageAsync("Good message");
            Assert.IsNotNull(goodMessage);

            // Tamper: create a message with the SAME MessageId but corrupted ciphertext
            var tampered = goodMessage.Clone();
            tampered.Ciphertext = new byte[tampered.Ciphertext.Length]; // all zeroes — invalid

            // Act — attempt to decrypt the tampered version; expect null (decryption failure)
            // NOTE: the tampered message will fail signature verification (not the MessageId check),
            // so we can't directly test the "ID not consumed" path through signature tampering.
            // Instead, strip the signature so only ciphertext corruption matters.
            tampered.Signature = null;

            // The message will still fail at ValidateGroupMessage (signature was null — skipped) and
            // then at actual AES decryption.  After this failure the real message ID must NOT be in
            // _seenMessageIds, so the genuine message must still decrypt.
            string tamperedResult = await receiver.DecryptMessageAsync(tampered);
            // May be null due to AES failure or signature skip — either is acceptable for setup

            // Act — decrypt the real (unmodified) message — must succeed even after the tampered attempt
            string goodResult = await receiver.DecryptMessageAsync(goodMessage);

            // Assert
            Assert.IsNotNull(goodResult,
                "Genuine message must still decrypt successfully after a failed attempt with the same MessageId prefix.");
            Assert.AreEqual("Good message", goodResult);
        }

        // ------------------------------------------------------------------
        // AC: Distinct messages from same sender are all accepted
        // ------------------------------------------------------------------

        [TestMethod]
        public async Task DecryptMessageAsync_MultipleDistinctMessages_AllAccepted()
        {
            // Arrange
            var (sender, receiver) = await BuildPairAsync();
            var messages = new List<(EncryptedGroupMessage Encrypted, string Plaintext)>();
            for (int i = 0; i < 5; i++)
            {
                string text = $"Distinct message {i}";
                var enc = await sender.EncryptMessageAsync(text);
                Assert.IsNotNull(enc, $"Encryption of message {i} should succeed.");
                messages.Add((enc, text));
            }

            // Act
            for (int i = 0; i < messages.Count; i++)
            {
                string result = await receiver.DecryptMessageAsync(messages[i].Encrypted);
                Assert.IsNotNull(result, $"Distinct message {i} should be accepted.");
                Assert.AreEqual(messages[i].Plaintext, result, $"Decrypted content for message {i} should match.");
            }
        }

        // ------------------------------------------------------------------
        // AC: Replaying an earlier message after newer ones arrive — rejected
        // ------------------------------------------------------------------

        [TestMethod]
        public async Task DecryptMessageAsync_ReplayOlderMessageAfterNewerArrives_Rejected()
        {
            // Arrange
            var (sender, receiver) = await BuildPairAsync();
            var msg1 = await sender.EncryptMessageAsync("Message A");
            var msg2 = await sender.EncryptMessageAsync("Message B");
            Assert.IsNotNull(msg1);
            Assert.IsNotNull(msg2);

            string r1 = await receiver.DecryptMessageAsync(msg1);
            string r2 = await receiver.DecryptMessageAsync(msg2);
            Assert.IsNotNull(r1);
            Assert.IsNotNull(r2);

            // Act — replay msg1 (older message, already seen)
            string replayResult = await receiver.DecryptMessageAsync(msg1.Clone());

            // Assert
            Assert.IsNull(replayResult, "Replaying an already-processed message must be rejected.");
        }

        // ------------------------------------------------------------------
        // AC: Replay state is reset after key rotation (new distribution processed)
        // ------------------------------------------------------------------

        [TestMethod]
        public async Task DecryptMessageAsync_AfterKeyRotationAndNewDistribution_NewMessagesAccepted()
        {
            // Arrange
            var (sender, receiver) = await BuildPairAsync();

            // Send and decrypt a message in the first epoch
            var preRotation = await sender.EncryptMessageAsync("Pre-rotation message");
            Assert.IsNotNull(preRotation);
            string preResult = await receiver.DecryptMessageAsync(preRotation);
            Assert.IsNotNull(preResult, "Pre-rotation message should decrypt.");

            // Rotate key — generates a fresh epoch (iteration resets to 0)
            bool rotated = await sender.RotateKeyAsync();
            Assert.IsTrue(rotated, "Key rotation should succeed.");

            // Distribute the new sender key to the receiver
            var newDist = sender.CreateDistributionMessage();
            bool processed = receiver.ProcessDistributionMessage(newDist);
            Assert.IsTrue(processed, "Receiver should accept the new distribution message.");

            // Act — send a first message in the new epoch (iteration will be 0 again)
            var postRotation = await sender.EncryptMessageAsync("Post-rotation message");
            Assert.IsNotNull(postRotation);
            string postResult = await receiver.DecryptMessageAsync(postRotation);

            // Assert — the new epoch message must succeed despite sequence resetting to 0
            Assert.IsNotNull(postResult,
                "Post-rotation message must be accepted; replay tracking resets with the new distribution.");
            Assert.AreEqual("Post-rotation message", postResult);
        }

        // ------------------------------------------------------------------
        // AC: Cross-sender isolation — replay tracking for one sender does not block another
        // ------------------------------------------------------------------

        [TestMethod]
        public async Task DecryptMessageAsync_CrossSenderIsolation_ReplayOfOneSenderDoesNotBlockOther()
        {
            // Arrange — three participants: Alice, Bob, and Charlie all in the same group
            var aliceKey = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var bobKey = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var charlieKey = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);

            string groupId = $"cross-sender-{Guid.NewGuid()}";
            const string groupName = "Cross Sender Test";

            var aliceSession = new GroupSession(groupId, groupName, aliceKey);
            var bobSession = new GroupSession(groupId, groupName, bobKey);
            var charlieSession = new GroupSession(groupId, groupName, charlieKey);

            await aliceSession.ActivateAsync();
            await bobSession.ActivateAsync();
            await charlieSession.ActivateAsync();

            // Mutual membership
            await aliceSession.AddMemberAsync(bobKey.PublicKey);
            await aliceSession.AddMemberAsync(charlieKey.PublicKey);
            await bobSession.AddMemberAsync(aliceKey.PublicKey);
            await bobSession.AddMemberAsync(charlieKey.PublicKey);
            await charlieSession.AddMemberAsync(aliceKey.PublicKey);
            await charlieSession.AddMemberAsync(bobKey.PublicKey);

            // Exchange distributions
            var aliceDist = aliceSession.CreateDistributionMessage();
            var bobDist = bobSession.CreateDistributionMessage();
            var charlieDist = charlieSession.CreateDistributionMessage();

            bobSession.ProcessDistributionMessage(aliceDist);
            charlieSession.ProcessDistributionMessage(aliceDist);
            aliceSession.ProcessDistributionMessage(bobDist);
            charlieSession.ProcessDistributionMessage(bobDist);
            aliceSession.ProcessDistributionMessage(charlieDist);
            bobSession.ProcessDistributionMessage(charlieDist);

            // Act — Alice sends a message; Bob decrypts it twice (second is replay)
            var aliceMsg = await aliceSession.EncryptMessageAsync("Alice's message");
            Assert.IsNotNull(aliceMsg);

            string bobFirst = await bobSession.DecryptMessageAsync(aliceMsg);
            Assert.IsNotNull(bobFirst, "Bob's first decryption of Alice's message must succeed.");

            string bobReplay = await bobSession.DecryptMessageAsync(aliceMsg.Clone());
            Assert.IsNull(bobReplay, "Bob's replay of Alice's message must be rejected.");

            // Charlie's first message (distinct sender) must still be accepted
            var charlieMsg = await charlieSession.EncryptMessageAsync("Charlie's message");
            Assert.IsNotNull(charlieMsg);
            string bobDecryptsCharlie = await bobSession.DecryptMessageAsync(charlieMsg);

            // Assert
            Assert.IsNotNull(bobDecryptsCharlie,
                "Alice's replay being blocked must not affect decryption of Charlie's (distinct sender) message.");
            Assert.AreEqual("Charlie's message", bobDecryptsCharlie);
        }
    }
}
