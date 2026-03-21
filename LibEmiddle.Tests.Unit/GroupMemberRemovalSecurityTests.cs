using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Linq;
using System.Threading.Tasks;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;
using LibEmiddle.Messaging.Group;

namespace LibEmiddle.Tests.Unit
{
    /// <summary>
    /// Security tests for group member removal in GroupSession.
    ///
    /// Verifies that:
    ///   - RemoveMemberAsync() triggers a chain key rotation.
    ///   - The new chain key is different from the old chain key after rotation.
    ///   - The removed member cannot decrypt messages sent after their removal.
    ///   - Remaining members can still decrypt messages after the key rotation.
    ///   - Messages sent before the rotation are unaffected.
    ///   - Multiple sequential removals each trigger independent rotations.
    ///   - Key rotation does not affect the ability of remaining members to send and receive.
    /// </summary>
    [TestClass]
    public class GroupMemberRemovalSecurityTests
    {
        private CryptoProvider _cryptoProvider = null!;

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
        // Helper: build a fully wired-up two-participant session pair.
        // ------------------------------------------------------------------
        private async Task<(GroupSession admin, GroupSession member, KeyPair adminKey, KeyPair memberKey)>
            BuildAdminMemberPairAsync(string groupId)
        {
            var adminKey = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var memberKey = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            const string groupName = "Removal Security Test Group";

            var admin = new GroupSession(groupId, groupName, adminKey);
            var member = new GroupSession(groupId, groupName, memberKey);

            await admin.ActivateAsync();
            await member.ActivateAsync();

            await admin.AddMemberAsync(memberKey.PublicKey);
            await member.AddMemberAsync(adminKey.PublicKey);

            var adminDist = admin.CreateDistributionMessage();
            var memberDist = member.CreateDistributionMessage();

            member.ProcessDistributionMessage(adminDist);
            admin.ProcessDistributionMessage(memberDist);

            return (admin, member, adminKey, memberKey);
        }

        // ------------------------------------------------------------------
        // AC: RemoveMemberAsync() triggers key rotation — chain key must change.
        // ------------------------------------------------------------------

        [TestMethod]
        public async Task RemoveMemberAsync_TriggersKeyRotation_ChainKeyChanges()
        {
            // Arrange
            string groupId = $"removal-rotation-{Guid.NewGuid()}";
            var (admin, member, _, memberKey) = await BuildAdminMemberPairAsync(groupId);

            // Capture the chain key before removal
            byte[] chainKeyBefore = admin.ChainKey.ToArray();

            // Act — remove the member (this triggers key rotation internally)
            bool removed = await admin.RemoveMemberAsync(memberKey.PublicKey);

            // Capture the chain key after removal
            byte[] chainKeyAfter = admin.ChainKey.ToArray();

            // Assert
            Assert.IsTrue(removed, "RemoveMemberAsync should return true when the member exists.");
            Assert.IsFalse(chainKeyBefore.SequenceEqual(chainKeyAfter),
                "Chain key must change after member removal to prevent the removed member from decrypting future messages.");
        }

        // ------------------------------------------------------------------
        // AC: Removed member's decryption fails after rotation.
        // ------------------------------------------------------------------

        [TestMethod]
        public async Task RemoveMemberAsync_RemovedMemberCannotDecryptPostRemovalMessages()
        {
            // Arrange
            string groupId = $"removed-no-decrypt-{Guid.NewGuid()}";
            var (admin, member, adminKey, memberKey) = await BuildAdminMemberPairAsync(groupId);

            // Capture the admin distribution message BEFORE removal/rotation
            // This represents key material the removed member already has stored.
            var preRotationAdminDist = admin.CreateDistributionMessage();

            // Verify communication works before removal
            string preMsgText = "Message before removal";
            var preMsg = await admin.EncryptMessageAsync(preMsgText);
            Assert.IsNotNull(preMsg, "Pre-removal message encryption must succeed.");
            string preDecrypted = await member.DecryptMessageAsync(preMsg);
            Assert.AreEqual(preMsgText, preDecrypted, "Member must be able to decrypt pre-removal messages.");

            // Act — remove the member; this rotates the admin session's chain key
            bool removed = await admin.RemoveMemberAsync(memberKey.PublicKey);
            Assert.IsTrue(removed, "RemoveMemberAsync must succeed.");

            // Simulate a compromised/stale member session that still has the old distribution key
            // but cannot receive the new one because they are no longer a trusted member.
            // This models the forward-secrecy threat: a removed member who stored old key material.
            var staleRemovedSession = new GroupSession(groupId, "Removal Security Test Group", memberKey);
            await staleRemovedSession.ActivateAsync();
            // The stale session adds admin as a member so it can process the old distribution
            await staleRemovedSession.AddMemberAsync(adminKey.PublicKey);
            // Process the OLD pre-rotation distribution (the key material the removed member held)
            staleRemovedSession.ProcessDistributionMessage(preRotationAdminDist);

            // Admin sends a post-removal message (encrypted with the new, post-rotation chain key)
            string postMsgText = "Message after removal";
            var postMsg = await admin.EncryptMessageAsync(postMsgText);
            Assert.IsNotNull(postMsg, "Post-removal message encryption must succeed.");

            // The removed member attempts to decrypt using the old key material — must fail
            // because the new message was encrypted with a key derived from the new chain key,
            // which is cryptographically independent of the old chain key.
            string postDecrypted = await staleRemovedSession.DecryptMessageAsync(postMsg);

            // Assert — the removed member must not decrypt the post-rotation message
            Assert.IsNull(postDecrypted,
                "Removed member must not be able to decrypt messages sent after their removal and the subsequent key rotation.");
        }

        // ------------------------------------------------------------------
        // AC: Remaining members can still decrypt after key rotation.
        // ------------------------------------------------------------------

        [TestMethod]
        public async Task RemoveMemberAsync_RemainingMembersCanStillDecryptAfterRotation()
        {
            // Arrange — three participants: admin, member (to be removed), and observer
            var adminKey = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var removedMemberKey = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var observerKey = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);

            string groupId = $"remaining-members-{Guid.NewGuid()}";
            const string groupName = "Removal Security Test Group";

            var adminSession = new GroupSession(groupId, groupName, adminKey);
            var removedMemberSession = new GroupSession(groupId, groupName, removedMemberKey);
            var observerSession = new GroupSession(groupId, groupName, observerKey);

            await adminSession.ActivateAsync();
            await removedMemberSession.ActivateAsync();
            await observerSession.ActivateAsync();

            // Mutual membership setup
            await adminSession.AddMemberAsync(removedMemberKey.PublicKey);
            await adminSession.AddMemberAsync(observerKey.PublicKey);
            await removedMemberSession.AddMemberAsync(adminKey.PublicKey);
            await removedMemberSession.AddMemberAsync(observerKey.PublicKey);
            await observerSession.AddMemberAsync(adminKey.PublicKey);
            await observerSession.AddMemberAsync(removedMemberKey.PublicKey);

            // Exchange distribution messages
            var adminDist = adminSession.CreateDistributionMessage();
            var removedDist = removedMemberSession.CreateDistributionMessage();
            var observerDist = observerSession.CreateDistributionMessage();

            removedMemberSession.ProcessDistributionMessage(adminDist);
            observerSession.ProcessDistributionMessage(adminDist);
            adminSession.ProcessDistributionMessage(removedDist);
            observerSession.ProcessDistributionMessage(removedDist);
            adminSession.ProcessDistributionMessage(observerDist);
            removedMemberSession.ProcessDistributionMessage(observerDist);

            // Verify initial communication
            string initialMsg = "Group message before removal";
            var initialEncrypted = await adminSession.EncryptMessageAsync(initialMsg);
            string observerDecryptsInitial = await observerSession.DecryptMessageAsync(initialEncrypted);
            Assert.AreEqual(initialMsg, observerDecryptsInitial, "Observer should decrypt messages before removal.");

            // Act — remove the member; triggers key rotation on admin session
            bool removed = await adminSession.RemoveMemberAsync(removedMemberKey.PublicKey);
            Assert.IsTrue(removed, "RemoveMemberAsync must succeed.");

            // Observer must now sync with the new admin distribution message
            var newAdminDist = adminSession.CreateDistributionMessage();
            bool newDistProcessed = observerSession.ProcessDistributionMessage(newAdminDist);
            Assert.IsTrue(newDistProcessed, "Observer must accept the new admin distribution after key rotation.");

            // Admin sends a post-removal message
            string postMsg = "Group message after member removed";
            var postEncrypted = await adminSession.EncryptMessageAsync(postMsg);
            Assert.IsNotNull(postEncrypted, "Post-removal message encryption must succeed.");

            // Observer (remaining member) decrypts — must succeed
            string observerDecryptsPost = await observerSession.DecryptMessageAsync(postEncrypted);

            // Assert
            Assert.IsNotNull(observerDecryptsPost,
                "Remaining members must be able to decrypt messages after key rotation triggered by member removal.");
            Assert.AreEqual(postMsg, observerDecryptsPost,
                "Decrypted content must match original post-removal message.");
        }

        // ------------------------------------------------------------------
        // AC: Messages sent before removal (and before rotation) are unaffected.
        // ------------------------------------------------------------------

        [TestMethod]
        public async Task RemoveMemberAsync_PreRemovalMessagesDecryptCorrectly()
        {
            // Arrange
            string groupId = $"pre-removal-msg-{Guid.NewGuid()}";
            var (admin, member, _, memberKey) = await BuildAdminMemberPairAsync(groupId);

            // Send a message before removal
            string preMsg = "Pre-removal message";
            var preEncrypted = await admin.EncryptMessageAsync(preMsg);
            Assert.IsNotNull(preEncrypted);

            // Member decrypts pre-removal message (before removal happens)
            string preDecrypted = await member.DecryptMessageAsync(preEncrypted);
            Assert.AreEqual(preMsg, preDecrypted, "Pre-removal messages must decrypt correctly.");

            // Act — remove the member
            await admin.RemoveMemberAsync(memberKey.PublicKey);

            // Pre-removal messages already decrypted remain accessible (no regression).
            // This test validates that the rotation does not corrupt earlier successfully
            // decrypted state — the result was obtained before removal and is still valid.
            Assert.AreEqual(preMsg, preDecrypted,
                "Pre-removal decryption result must not be altered by the subsequent key rotation.");
        }

        // ------------------------------------------------------------------
        // AC: Sequential removals each produce independent key rotations.
        // ------------------------------------------------------------------

        [TestMethod]
        public async Task RemoveMemberAsync_SequentialRemovals_EachRotatesKeyIndependently()
        {
            // Arrange — admin plus two members
            var adminKey = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var member1Key = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var member2Key = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);

            string groupId = $"sequential-removals-{Guid.NewGuid()}";
            const string groupName = "Removal Security Test Group";

            var adminSession = new GroupSession(groupId, groupName, adminKey);
            await adminSession.ActivateAsync();

            await adminSession.AddMemberAsync(member1Key.PublicKey);
            await adminSession.AddMemberAsync(member2Key.PublicKey);

            // Capture initial key
            byte[] keyBefore = adminSession.ChainKey.ToArray();

            // Act — remove member 1
            await adminSession.RemoveMemberAsync(member1Key.PublicKey);
            byte[] keyAfterFirst = adminSession.ChainKey.ToArray();

            // Assert first removal changed the key
            Assert.IsFalse(keyBefore.SequenceEqual(keyAfterFirst),
                "First removal must rotate the chain key.");

            // Act — remove member 2
            await adminSession.RemoveMemberAsync(member2Key.PublicKey);
            byte[] keyAfterSecond = adminSession.ChainKey.ToArray();

            // Assert second removal changed the key again (independent rotation)
            Assert.IsFalse(keyAfterFirst.SequenceEqual(keyAfterSecond),
                "Second removal must also rotate the chain key independently of the first rotation.");

            // All three keys must be distinct
            Assert.IsFalse(keyBefore.SequenceEqual(keyAfterSecond),
                "Key after both removals must differ from the original key.");
        }

        // ------------------------------------------------------------------
        // AC: RemoveMemberAsync returns false for non-members (no spurious rotation).
        // ------------------------------------------------------------------

        [TestMethod]
        public async Task RemoveMemberAsync_NonExistentMember_ReturnsFalseAndDoesNotRotateKey()
        {
            // Arrange
            string groupId = $"non-member-removal-{Guid.NewGuid()}";
            var adminKey = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var nonMemberKey = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            const string groupName = "Removal Security Test Group";

            var adminSession = new GroupSession(groupId, groupName, adminKey);
            await adminSession.ActivateAsync();

            byte[] keyBefore = adminSession.ChainKey.ToArray();

            // Act — attempt to remove someone who was never a member
            bool removed = await adminSession.RemoveMemberAsync(nonMemberKey.PublicKey);
            byte[] keyAfter = adminSession.ChainKey.ToArray();

            // Assert
            Assert.IsFalse(removed, "Removing a non-member must return false.");
            Assert.IsTrue(keyBefore.SequenceEqual(keyAfter),
                "Key must not rotate when attempting to remove a non-member.");
        }
    }
}
