using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Messaging.Group;
using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;
using LibEmiddle.Abstractions;

namespace LibEmiddle.Tests.Unit
{
    [TestClass]
    public class GroupMessagingTests
    {
        private CryptoProvider _cryptoProvider;

        [TestInitialize]
        public void Setup()
        {
            _cryptoProvider = new CryptoProvider();
        }

        [TestMethod]
        public async Task AddGroupMember_ShouldAddMemberToAuthorizedList()
        {
            // Arrange
            var adminKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var memberKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            string groupId = $"test-authorization-{Guid.NewGuid()}";
            string groupName = "Test Group Name";

            // Create group using new consolidated GroupSession
            var session = new GroupSession(groupId, groupName, adminKeyPair);
            await session.ActivateAsync();

            // Act
            bool result = await session.AddMemberAsync(memberKeyPair.PublicKey);

            // Assert
            Assert.IsTrue(result);
        }

        [TestMethod]
        public async Task DecryptGroupMessage_ShouldRejectReplayedMessage()
        {
            // Arrange
            var keyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            string groupId = $"test-replay-protection-{Guid.NewGuid()}";
            string groupName = "Test Group Name";

            // Create the group session
            var session = new GroupSession(groupId, groupName, keyPair);
            await session.ActivateAsync();

            // Create and encrypt a message
            string originalMessage = "Hello, secure group!";
            var encryptedMessage = await session.EncryptMessageAsync(originalMessage);

            // Log details to help diagnose the issue
            Trace.TraceWarning($"Group ID: {groupId}");
            Trace.TraceWarning($"Message ID: {encryptedMessage?.MessageId}");
            Trace.TraceWarning($"Sender Identity Key Length: {encryptedMessage?.SenderIdentityKey?.Length ?? 0}");
            Trace.TraceWarning($"Ciphertext Length: {encryptedMessage?.Ciphertext?.Length ?? 0}");
            Trace.TraceWarning($"Nonce Length: {encryptedMessage?.Nonce?.Length ?? 0}");

            Assert.IsNotNull(encryptedMessage, "Message encryption should succeed");

            // Act & Assert - First decryption
            string firstDecryption = await session.DecryptMessageAsync(encryptedMessage);

            if (firstDecryption == null)
            {
                Trace.TraceWarning("First decryption FAILED - returned null");
            }
            else
            {
                Trace.TraceWarning("First decryption SUCCESS");
            }

            Assert.IsNotNull(firstDecryption, "First decryption should succeed");
            Assert.AreEqual(originalMessage, firstDecryption);

            // Act & Assert - Second decryption (simulating replay)
            string secondDecryption = await session.DecryptMessageAsync(encryptedMessage);
            Assert.IsNull(secondDecryption, "Replay attack should be detected and result in null return value");
        }

        [TestMethod]
        public async Task ForwardSecrecy_RemovedMemberCannotDecryptNewMessages()
        {
            // Arrange
            var adminKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var memberKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);

            string groupId = $"test-forward-secrecy-{Guid.NewGuid()}";
            string groupName = "Test Group Name";

            // 1. Admin creates the group
            var adminSession = new GroupSession(groupId, groupName, adminKeyPair);
            await adminSession.ActivateAsync();

            // 2. Member creates their session
            var memberSession = new GroupSession(groupId, groupName, memberKeyPair);
            await memberSession.ActivateAsync();

            // 3. Admin authorizes member
            await adminSession.AddMemberAsync(memberKeyPair.PublicKey);
            await memberSession.AddMemberAsync(adminKeyPair.PublicKey);

            // 4. Exchange distribution messages
            var adminDistribution = adminSession.CreateDistributionMessage();
            var memberDistribution = memberSession.CreateDistributionMessage();

            bool memberProcessResult = memberSession.ProcessDistributionMessage(adminDistribution);
            bool adminProcessResult = adminSession.ProcessDistributionMessage(memberDistribution);

            Assert.IsTrue(memberProcessResult, "Member should be able to process admin's distribution");
            Assert.IsTrue(adminProcessResult, "Admin should be able to process member's distribution");

            // 5. Test communication before revocation
            string message1 = "Message before revocation";
            var encrypted1 = await adminSession.EncryptMessageAsync(message1);
            string decrypted1 = await memberSession.DecryptMessageAsync(encrypted1);

            Assert.IsNotNull(decrypted1);
            Assert.AreEqual(message1, decrypted1);

            // 6. Now revoke member (this triggers key rotation)
            await adminSession.RemoveMemberAsync(memberKeyPair.PublicKey);

            // 7. Create a new member session to simulate restarting the app
            var memberSession2 = new GroupSession(groupId, groupName, memberKeyPair);
            await memberSession2.ActivateAsync();
            await memberSession2.AddMemberAsync(adminKeyPair.PublicKey);

            // Try to process the old distribution (should work)
            memberSession2.ProcessDistributionMessage(adminDistribution);

            // 8. Send a new message after revocation
            string message2 = "Message after revocation";
            var encrypted2 = await adminSession.EncryptMessageAsync(message2);

            // 9. Act - member tries to decrypt post-revocation message
            string decrypted2 = await memberSession2.DecryptMessageAsync(encrypted2);

            // Assert - Should not be able to decrypt after revocation
            Assert.IsNull(decrypted2, "Should not be able to decrypt after revocation due to key rotation");
        }

        [TestMethod]
        public async Task ProcessSenderKeyDistribution_ShouldRejectMessagesFromUntrustedSenders()
        {
            // Arrange
            var adminKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var memberKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var untrustedKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);

            string groupId = $"test-untrusted-rejection-{Guid.NewGuid()}";
            string groupName = "Test Group Name";

            // Create sessions for all participants
            var adminSession = new GroupSession(groupId, groupName, adminKeyPair);
            var memberSession = new GroupSession(groupId, groupName, memberKeyPair);
            var untrustedSession = new GroupSession(groupId, groupName, untrustedKeyPair);

            await adminSession.ActivateAsync();
            await memberSession.ActivateAsync();
            await untrustedSession.ActivateAsync();

            // Add trusted members to each other's groups, but NOT the untrusted user
            await adminSession.AddMemberAsync(memberKeyPair.PublicKey);
            await memberSession.AddMemberAsync(adminKeyPair.PublicKey);
            // Note: untrusted user is NOT added to either session

            // Exchange distribution messages between trusted participants
            var adminDistribution = adminSession.CreateDistributionMessage();
            var memberDistribution = memberSession.CreateDistributionMessage();

            // Process distributions between trusted members
            bool memberProcessResult = memberSession.ProcessDistributionMessage(adminDistribution);
            bool adminProcessResult = adminSession.ProcessDistributionMessage(memberDistribution);

            Assert.IsTrue(memberProcessResult, "Member should be able to process admin's distribution");
            Assert.IsTrue(adminProcessResult, "Admin should be able to process member's distribution");

            // Verify trusted communication works
            string testMessage = "Test message between trusted members";
            var encryptedMessage = await adminSession.EncryptMessageAsync(testMessage);
            string decryptedMessage = await memberSession.DecryptMessageAsync(encryptedMessage);
            Assert.AreEqual(testMessage, decryptedMessage, "Trusted members should be able to communicate");

            // The untrusted user attempts to create a distribution message
            var untrustedDistribution = untrustedSession.CreateDistributionMessage();

            // The member attempts to process the distribution message from the untrusted user
            // This should fail because the untrusted user is not in the member list
            bool distributionAccepted = memberSession.ProcessDistributionMessage(untrustedDistribution);

            // Now test if the member can decrypt a message from the untrusted sender
            string untrustedMessage = "Message from untrusted sender";
            var untrustedEncrypted = await untrustedSession.EncryptMessageAsync(untrustedMessage);

            // This should fail - the message should be rejected due to sender not being a member
            string untrustedDecrypted = await memberSession.DecryptMessageAsync(untrustedEncrypted);

            // Assert
            Assert.IsFalse(distributionAccepted, "Distribution from untrusted sender should be rejected");
            Assert.IsNull(untrustedDecrypted, "Member should not be able to decrypt message from untrusted sender");
        }

        [TestMethod]
        public void GenerateSenderKey_ShouldReturnValidKey()
        {
            // Act
            byte[] senderKey = Sodium.GenerateRandomBytes(Constants.AES_KEY_SIZE);

            // Assert
            Assert.IsNotNull(senderKey);
            Assert.AreEqual(32, senderKey.Length);
        }

        [TestMethod]
        public async Task EncryptDecryptGroupMessage_ShouldReturnOriginalMessage()
        {
            // Arrange
            string message = "This is a group message";
            string groupId = $"test-group-{Guid.NewGuid()}";
            string groupName = "Test Group Name";
            var identityKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);

            // Create group session
            var session = new GroupSession(groupId, groupName, identityKeyPair);
            await session.ActivateAsync();

            // Act
            var encryptedMessage = await session.EncryptMessageAsync(message);
            Assert.IsNotNull(encryptedMessage, "Message encryption should succeed");

            var decryptedMessage = await session.DecryptMessageAsync(encryptedMessage);

            // Assert
            Assert.AreEqual(message, decryptedMessage);
        }

        [TestMethod]
        public async Task CreateDistributionMessage_ShouldReturnValidMessage()
        {
            // Arrange
            string groupId = $"test-group-{Guid.NewGuid()}";
            string groupName = "Test Group Name";
            string message = "This is my test message";
            var senderKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);

            // Create group session
            var session = new GroupSession(groupId, groupName, senderKeyPair);
            await session.ActivateAsync();

            // Act - Create distribution and send a message
            var distributionMessage = session.CreateDistributionMessage();
            var encryptedMessage = await session.EncryptMessageAsync(message);

            // Assert
            Assert.IsNotNull(session);
            Assert.IsNotNull(distributionMessage);
            Assert.IsNotNull(encryptedMessage);
            Assert.AreEqual(groupId, encryptedMessage.GroupId);
        }

        [TestMethod]
        public async Task GroupSession_ShouldHandleMessageExchange()
        {
            // Arrange
            var aliceKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var bobKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);

            string groupId = $"test-group-{Guid.NewGuid()}";
            string groupName = "Test Group Name";
            string message = "Hello group members!";

            // Create group sessions
            var aliceSession = new GroupSession(groupId, groupName, aliceKeyPair);
            var bobSession = new GroupSession(groupId, groupName, bobKeyPair);

            await aliceSession.ActivateAsync();
            await bobSession.ActivateAsync();

            // Act
            // Alice and Bob authorize each other
            await aliceSession.AddMemberAsync(bobKeyPair.PublicKey);
            await bobSession.AddMemberAsync(aliceKeyPair.PublicKey);

            // Exchange distribution messages
            var aliceDistribution = aliceSession.CreateDistributionMessage();
            var bobDistribution = bobSession.CreateDistributionMessage();

            bool bobProcessResult = bobSession.ProcessDistributionMessage(aliceDistribution);
            bool aliceProcessResult = aliceSession.ProcessDistributionMessage(bobDistribution);

            // Alice sends a message
            var encryptedMessage = await aliceSession.EncryptMessageAsync(message);

            // Bob decrypts the message
            string decryptedMessage = await bobSession.DecryptMessageAsync(encryptedMessage);

            // Assert
            Assert.IsTrue(bobProcessResult);
            Assert.IsTrue(aliceProcessResult);
            Assert.AreEqual(message, decryptedMessage);
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidOperationException))]
        public void GroupSession_CreateDistribution_WithoutInitialization_ShouldThrowException()
        {
            // Arrange
            var keyPair = Sodium.GenerateEd25519KeyPair();
            string groupId = "non-existent-group";
            string groupName = "Test Group Name";

            // Create session but don't activate it or initialize keys
            var session = new GroupSession(groupId, groupName, keyPair);

            // Act & Assert - Should throw InvalidOperationException
            session.CreateDistributionMessage(); // This should throw
        }

        [TestMethod]
        public async Task GroupMultiSenderDeduplication_ShouldHandleSimultaneousMessages()
        {
            // Arrange - Create three participants
            var aliceKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var bobKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var charlieKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);

            string groupId = $"test-multiple-senders-{Guid.NewGuid()}";
            string groupName = "Test Group Name";

            var aliceSession = new GroupSession(groupId, groupName, aliceKeyPair);
            var bobSession = new GroupSession(groupId, groupName, bobKeyPair);
            var charlieSession = new GroupSession(groupId, groupName, charlieKeyPair);

            await aliceSession.ActivateAsync();
            await bobSession.ActivateAsync();
            await charlieSession.ActivateAsync();

            // Add members to all sessions
            await aliceSession.AddMemberAsync(bobKeyPair.PublicKey);
            await aliceSession.AddMemberAsync(charlieKeyPair.PublicKey);
            await bobSession.AddMemberAsync(aliceKeyPair.PublicKey);
            await bobSession.AddMemberAsync(charlieKeyPair.PublicKey);
            await charlieSession.AddMemberAsync(aliceKeyPair.PublicKey);
            await charlieSession.AddMemberAsync(bobKeyPair.PublicKey);

            // Exchange sender keys
            var aliceDistribution = aliceSession.CreateDistributionMessage();
            var bobDistribution = bobSession.CreateDistributionMessage();
            var charlieDistribution = charlieSession.CreateDistributionMessage();

            // Everyone processes everyone else's distribution
            aliceSession.ProcessDistributionMessage(bobDistribution);
            aliceSession.ProcessDistributionMessage(charlieDistribution);
            bobSession.ProcessDistributionMessage(aliceDistribution);
            bobSession.ProcessDistributionMessage(charlieDistribution);
            charlieSession.ProcessDistributionMessage(aliceDistribution);
            charlieSession.ProcessDistributionMessage(bobDistribution);

            // Act - Simulate simultaneous messages from all three
            string aliceMessage = "Alice's message";
            string bobMessage = "Bob's message";
            string charlieMessage = "Charlie's message";

            var aliceEncrypted = await aliceSession.EncryptMessageAsync(aliceMessage);
            var bobEncrypted = await bobSession.EncryptMessageAsync(bobMessage);
            var charlieEncrypted = await charlieSession.EncryptMessageAsync(charlieMessage);

            // Each participant receives messages from the other two
            string bobDecryptsAlice = await bobSession.DecryptMessageAsync(aliceEncrypted);
            string bobDecryptsCharlie = await bobSession.DecryptMessageAsync(charlieEncrypted);

            string aliceDecryptsBob = await aliceSession.DecryptMessageAsync(bobEncrypted);
            string aliceDecryptsCharlie = await aliceSession.DecryptMessageAsync(charlieEncrypted);

            string charlieDecryptsAlice = await charlieSession.DecryptMessageAsync(aliceEncrypted);
            string charlieDecryptsBob = await charlieSession.DecryptMessageAsync(bobEncrypted);

            // Assert - Each message should be correctly decrypted by the other two participants
            Assert.AreEqual(aliceMessage, bobDecryptsAlice);
            Assert.AreEqual(aliceMessage, charlieDecryptsAlice);

            Assert.AreEqual(bobMessage, aliceDecryptsBob);
            Assert.AreEqual(bobMessage, charlieDecryptsBob);

            Assert.AreEqual(charlieMessage, aliceDecryptsCharlie);
            Assert.AreEqual(charlieMessage, bobDecryptsCharlie);
        }

        [TestMethod]
        public async Task GroupMemberAddition_ShouldAllowNewMemberToReceiveMessages()
        {
            // Create a unique group ID to prevent test interference
            string groupId = $"member-addition-test-group-{Guid.NewGuid()}";
            string groupName = "Test Group Name";

            // Create test participants
            var aliceKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var bobKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var daveKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);

            // 1. Alice and Bob create group sessions
            var aliceSession = new GroupSession(groupId, groupName, aliceKeyPair);
            var bobSession = new GroupSession(groupId, groupName, bobKeyPair);

            await aliceSession.ActivateAsync();
            await bobSession.ActivateAsync();

            // 2. Alice and Bob add each other to their member lists
            await aliceSession.AddMemberAsync(bobKeyPair.PublicKey);
            await bobSession.AddMemberAsync(aliceKeyPair.PublicKey);

            // 3. Exchange distribution messages
            var aliceDistribution = aliceSession.CreateDistributionMessage();
            var bobDistribution = bobSession.CreateDistributionMessage();

            aliceSession.ProcessDistributionMessage(bobDistribution);
            bobSession.ProcessDistributionMessage(aliceDistribution);

            // 4. Send initial message before Dave joins
            string initialMessage = "Initial message before Dave joins";
            var initialEncrypted = await aliceSession.EncryptMessageAsync(initialMessage);
            string bobDecryptsInitial = await bobSession.DecryptMessageAsync(initialEncrypted);
            Assert.AreEqual(initialMessage, bobDecryptsInitial, "Bob should be able to decrypt the initial message");

            // 5. Dave joins the group
            Thread.Sleep(100); // Ensure timestamp separation for clarity
            var daveSession = new GroupSession(groupId, groupName, daveKeyPair);
            await daveSession.ActivateAsync();

            // 6. Add Dave to member lists
            await aliceSession.AddMemberAsync(daveKeyPair.PublicKey);
            await bobSession.AddMemberAsync(daveKeyPair.PublicKey);
            await daveSession.AddMemberAsync(aliceKeyPair.PublicKey);
            await daveSession.AddMemberAsync(bobKeyPair.PublicKey);

            // 7. Rotate keys after membership changes (happens automatically in RemoveMemberAsync but we need to do it manually for AddMemberAsync)
            await aliceSession.RotateKeyAsync();
            await bobSession.RotateKeyAsync();

            // 8. Create new distribution messages after key rotation
            var aliceDistributionNew = aliceSession.CreateDistributionMessage();
            var bobDistributionNew = bobSession.CreateDistributionMessage();
            var daveDistribution = daveSession.CreateDistributionMessage();

            // 9. Process the new distribution messages
            aliceSession.ProcessDistributionMessage(bobDistributionNew);
            aliceSession.ProcessDistributionMessage(daveDistribution);

            bobSession.ProcessDistributionMessage(aliceDistributionNew);
            bobSession.ProcessDistributionMessage(daveDistribution);

            daveSession.ProcessDistributionMessage(aliceDistributionNew);
            daveSession.ProcessDistributionMessage(bobDistributionNew);

            // 10. Send new messages
            Thread.Sleep(100); // Ensure timestamp separation

            string aliceMessage = "Message from Alice after Dave joined";
            string bobMessage = "Message from Bob after Dave joined";
            string daveMessage = "Dave's first message to the group";

            var aliceEncrypted = await aliceSession.EncryptMessageAsync(aliceMessage);
            var bobEncrypted = await bobSession.EncryptMessageAsync(bobMessage);
            var daveEncrypted = await daveSession.EncryptMessageAsync(daveMessage);

            // 11. Verify everyone can decrypt the new messages
            string bobDecryptsAlice = await bobSession.DecryptMessageAsync(aliceEncrypted);
            string bobDecryptsDave = await bobSession.DecryptMessageAsync(daveEncrypted);
            string aliceDecryptsBob = await aliceSession.DecryptMessageAsync(bobEncrypted);
            string aliceDecryptsDave = await aliceSession.DecryptMessageAsync(daveEncrypted);
            string daveDecryptsAlice = await daveSession.DecryptMessageAsync(aliceEncrypted);
            string daveDecryptsBob = await daveSession.DecryptMessageAsync(bobEncrypted);

            // 12. Dave attempts to decrypt the initial message (should fail for security)
            string daveDecryptsInitial = await daveSession.DecryptMessageAsync(initialEncrypted);

            // 13. Assert results
            Assert.AreEqual(aliceMessage, bobDecryptsAlice, "Bob should be able to decrypt Alice's message");
            Assert.AreEqual(daveMessage, bobDecryptsDave, "Bob should be able to decrypt Dave's message");
            Assert.AreEqual(bobMessage, aliceDecryptsBob, "Alice should be able to decrypt Bob's message");
            Assert.AreEqual(daveMessage, aliceDecryptsDave, "Alice should be able to decrypt Dave's message");
            Assert.AreEqual(aliceMessage, daveDecryptsAlice, "Dave should be able to decrypt Alice's message");
            Assert.AreEqual(bobMessage, daveDecryptsBob, "Dave should be able to decrypt Bob's message");

            // Key security property - Dave can't access old messages
            Assert.IsNull(daveDecryptsInitial, "Dave should not be able to decrypt messages sent before joining");
        }

        [TestMethod]
        public async Task FullGroupMessageFlow_ShouldWorkEndToEnd()
        {
            // This test simulates a group chat between Alice, Bob, and Charlie

            // Step 1: Generate identity keys for the participants
            var aliceKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var bobKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var charlieKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);

            // Step 2: Create group sessions for each participant
            string groupId = $"test-friends-{Guid.NewGuid()}";
            string groupName = "Test Group Name";

            var aliceSession = new GroupSession(groupId, groupName, aliceKeyPair);
            var bobSession = new GroupSession(groupId, groupName, bobKeyPair);
            var charlieSession = new GroupSession(groupId, groupName, charlieKeyPair);

            await aliceSession.ActivateAsync();
            await bobSession.ActivateAsync();
            await charlieSession.ActivateAsync();

            // Step 3: Each participant authorizes all others
            // Alice authorizes Bob and Charlie
            await aliceSession.AddMemberAsync(bobKeyPair.PublicKey);
            await aliceSession.AddMemberAsync(charlieKeyPair.PublicKey);

            // Bob authorizes Alice and Charlie
            await bobSession.AddMemberAsync(aliceKeyPair.PublicKey);
            await bobSession.AddMemberAsync(charlieKeyPair.PublicKey);

            // Charlie authorizes Alice and Bob
            await charlieSession.AddMemberAsync(aliceKeyPair.PublicKey);
            await charlieSession.AddMemberAsync(bobKeyPair.PublicKey);

            // Step 4: Each participant creates their distribution message
            var aliceDistribution = aliceSession.CreateDistributionMessage();
            var bobDistribution = bobSession.CreateDistributionMessage();
            var charlieDistribution = charlieSession.CreateDistributionMessage();

            // Step 5: Everyone processes everyone else's distribution
            // Bob and Charlie process Alice's distribution
            bool bobProcessAliceResult = bobSession.ProcessDistributionMessage(aliceDistribution);
            bool charlieProcessAliceResult = charlieSession.ProcessDistributionMessage(aliceDistribution);

            // Alice and Charlie process Bob's distribution
            bool aliceProcessBobResult = aliceSession.ProcessDistributionMessage(bobDistribution);
            bool charlieProcessBobResult = charlieSession.ProcessDistributionMessage(bobDistribution);

            // Alice and Bob process Charlie's distribution
            bool aliceProcessCharlieResult = aliceSession.ProcessDistributionMessage(charlieDistribution);
            bool bobProcessCharlieResult = bobSession.ProcessDistributionMessage(charlieDistribution);

            // Step 6: Alice sends a message to the group
            string aliceMessage = "Hello everyone, this is Alice!";
            var aliceEncryptedMessage = await aliceSession.EncryptMessageAsync(aliceMessage);

            // Bob and Charlie decrypt Alice's message
            string bobDecryptedAliceMessage = await bobSession.DecryptMessageAsync(aliceEncryptedMessage);
            string charlieDecryptedAliceMessage = await charlieSession.DecryptMessageAsync(aliceEncryptedMessage);

            // Step 7: Bob replies to the group
            string bobMessage = "Hi Alice and Charlie, Bob here!";
            var bobEncryptedMessage = await bobSession.EncryptMessageAsync(bobMessage);

            // Alice and Charlie decrypt Bob's message
            string aliceDecryptedBobMessage = await aliceSession.DecryptMessageAsync(bobEncryptedMessage);
            string charlieDecryptedBobMessage = await charlieSession.DecryptMessageAsync(bobEncryptedMessage);

            // Assert results
            Assert.IsTrue(bobProcessAliceResult);
            Assert.IsTrue(charlieProcessAliceResult);
            Assert.IsTrue(aliceProcessBobResult);
            Assert.IsTrue(charlieProcessBobResult);
            Assert.IsTrue(aliceProcessCharlieResult);
            Assert.IsTrue(bobProcessCharlieResult);

            Assert.AreEqual(aliceMessage, bobDecryptedAliceMessage);
            Assert.AreEqual(aliceMessage, charlieDecryptedAliceMessage);
            Assert.AreEqual(bobMessage, aliceDecryptedBobMessage);
            Assert.AreEqual(bobMessage, charlieDecryptedBobMessage);
        }

        [TestMethod]
        public async Task TerminateSession_ShouldWorkCorrectly()
        {
            // Arrange
            var adminKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var memberKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);

            string groupId = $"test-terminate-{Guid.NewGuid()}";
            string groupName = "Test Group Name";

            // Create group session and add a member
            var session = new GroupSession(groupId, groupName, adminKeyPair);
            await session.ActivateAsync();
            await session.AddMemberAsync(memberKeyPair.PublicKey);

            // Verify session is active
            Assert.AreEqual(SessionState.Active, session.State, "Session should be active");

            // Act
            bool result = await session.TerminateAsync();

            // Assert
            Assert.IsTrue(result, "Terminate operation should return true");
            Assert.AreEqual(SessionState.Terminated, session.State, "Session should be terminated");

            // Verify we can't send messages after termination
            await Assert.ThrowsExceptionAsync<InvalidOperationException>(
                async () => await session.EncryptMessageAsync("This should fail"),
                "Should not be able to encrypt messages after termination");
        }
    }
}