using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Reflection;
using E2EELibrary;
using E2EELibrary.Core;
using E2EELibrary.GroupMessaging;

namespace E2EELibraryTests
{
    [TestClass]
    public class GroupMessagingTests
    {
        [TestMethod]
        public void RotateGroupKey_ShouldGenerateNewKey()
        {
            // Arrange
            var keyPair = E2EEClient.GenerateSignatureKeyPair();
            var groupManager = new GroupChatManager(keyPair);
            string groupId = "test-key-rotation";
            byte[] originalKey = groupManager.CreateGroup(groupId);

            // Act
            byte[] newKey = groupManager.RotateGroupKey(groupId);

            // Get the sender key via reflection
            var groupSessionPersistenceField = typeof(GroupChatManager).GetField("_sessionPersistence",
                BindingFlags.NonPublic | BindingFlags.Instance);
            var sessionPersistence = groupSessionPersistenceField.GetValue(groupManager) as GroupSessionPersistence;

            var session = sessionPersistence.GetGroupSession(groupId);
            byte[] storedKey = session.SenderKey;

            // Assert
            Assert.IsNotNull(newKey);
            Assert.AreEqual(32, newKey.Length);
            Assert.IsFalse(SecureMemory.SecureCompare(originalKey, newKey));
            Assert.IsTrue(SecureMemory.SecureCompare(newKey, storedKey));
        }

        [TestMethod]
        public void AddGroupMember_ShouldAddMemberToAuthorizedList()
        {
            // Arrange
            var adminKeyPair = E2EEClient.GenerateSignatureKeyPair();
            var memberKeyPair = E2EEClient.GenerateSignatureKeyPair();
            var groupManager = new GroupChatManager(adminKeyPair);
            string groupId = "test-authorization";
            groupManager.CreateGroup(groupId);

            // Act
            bool result = groupManager.AddGroupMember(groupId, memberKeyPair.publicKey);

            // Get the member manager via reflection
            var memberManagerField = typeof(GroupChatManager).GetField("_memberManager",
                BindingFlags.NonPublic | BindingFlags.Instance);
            var memberManager = memberManagerField.GetValue(groupManager) as GroupMemberManager;

            bool isMember = memberManager.IsMember(groupId, memberKeyPair.publicKey);

            // Assert
            Assert.IsTrue(result);
            Assert.IsTrue(isMember);
        }

        [TestMethod]
        public void RemoveGroupMember_ShouldRemoveMemberAndRotateKey()
        {
            // Arrange
            var adminKeyPair = E2EEClient.GenerateSignatureKeyPair();
            var memberKeyPair = E2EEClient.GenerateSignatureKeyPair();
            var groupManager = new GroupChatManager(adminKeyPair);
            string groupId = "test-revocation";
            groupManager.CreateGroup(groupId);
            groupManager.AddGroupMember(groupId, memberKeyPair.publicKey);

            // Get the original key
            var sessionPersistenceField = typeof(GroupChatManager).GetField("_sessionPersistence",
                BindingFlags.NonPublic | BindingFlags.Instance);
            var sessionPersistence = sessionPersistenceField.GetValue(groupManager) as GroupSessionPersistence;

            var originalSession = sessionPersistence.GetGroupSession(groupId);
            byte[] originalKey = originalSession.SenderKey;

            // Act
            bool result = groupManager.RemoveGroupMember(groupId, memberKeyPair.publicKey);

            // Get the member manager via reflection
            var memberManagerField = typeof(GroupChatManager).GetField("_memberManager",
                BindingFlags.NonPublic | BindingFlags.Instance);
            var memberManager = memberManagerField.GetValue(groupManager) as GroupMemberManager;

            bool isMember = memberManager.IsMember(groupId, memberKeyPair.publicKey);

            // Get the updated key
            var updatedSession = sessionPersistence.GetGroupSession(groupId);
            byte[] newKey = updatedSession.SenderKey;

            // Assert
            Assert.IsTrue(result);
            Assert.IsFalse(isMember);
            Assert.IsFalse(SecureMemory.SecureCompare(originalKey, newKey)); // Key should have been rotated
        }

        [TestMethod]
        public void DecryptGroupMessage_ShouldRejectReplayedMessage()
        {
            // Arrange
            var keyPair = E2EEClient.GenerateSignatureKeyPair();
            var groupManager = new GroupChatManager(keyPair);
            string groupId = "test-replay-protection";
            byte[] senderKey = groupManager.CreateGroup(groupId);

            // Create and encrypt a message
            string originalMessage = "Hello, secure group!";
            var encryptedMessage = groupManager.EncryptGroupMessage(groupId, originalMessage);

            // Log details to help diagnose the issue
            Console.WriteLine($"Group ID: {groupId}");
            Console.WriteLine($"Message ID: {encryptedMessage.MessageId}");
            Console.WriteLine($"Sender Identity Key Length: {encryptedMessage.SenderIdentityKey?.Length ?? 0}");
            Console.WriteLine($"Ciphertext Length: {encryptedMessage.Ciphertext?.Length ?? 0}");
            Console.WriteLine($"Nonce Length: {encryptedMessage.Nonce?.Length ?? 0}");

            // Act & Assert - First decryption with detailed logging
            string firstDecryption = groupManager.DecryptGroupMessage(encryptedMessage);

            // If firstDecryption is null, log additional details to help diagnose
            if (firstDecryption == null)
            {
                Console.WriteLine("First decryption FAILED - returned null");

                // Try direct decryption via the underlying components to isolate the issue
                var messageCrypto = new GroupMessageCrypto();
                var directDecrypt = messageCrypto.DecryptMessage(encryptedMessage, senderKey);
                Console.WriteLine($"Direct decryption via GroupMessageCrypto: {(directDecrypt != null ? "SUCCESS" : "FAILED")}");
            }
            else
            {
                Console.WriteLine("First decryption SUCCESS");
            }

            Assert.IsNotNull(firstDecryption, "First decryption should succeed");
            Assert.AreEqual(originalMessage, firstDecryption);

            // Act & Assert - Second decryption (simulating replay)
            string secondDecryption = groupManager.DecryptGroupMessage(encryptedMessage);
            Assert.IsNull(secondDecryption, "Replay attack should be detected and result in null return value");
        }

        [TestMethod]
        public void ForwardSecrecy_RemovedMemberCannotDecryptNewMessages()
        {
            // Arrange
            var adminKeyPair = E2EEClient.GenerateSignatureKeyPair();
            var memberKeyPair = E2EEClient.GenerateSignatureKeyPair();
            var adminManager = new GroupChatManager(adminKeyPair);
            var memberManager = new GroupChatManager(memberKeyPair);

            string groupId = "test-forward-secrecy";

            // 1. Admin creates the group and member joins
            adminManager.CreateGroup(groupId);
            memberManager.CreateGroup(groupId);

            // 2. Admin authorizes member and vice versa
            adminManager.AddGroupMember(groupId, memberKeyPair.publicKey);
            memberManager.AddGroupMember(groupId, adminKeyPair.publicKey);

            // Create and exchange distribution messages
            var adminDistribution = adminManager.CreateDistributionMessage(groupId);
            var memberDistribution = memberManager.CreateDistributionMessage(groupId);

            // Process distributions
            bool memberProcessResult = memberManager.ProcessSenderKeyDistribution(adminDistribution);
            Assert.IsTrue(memberProcessResult, "Member should be able to process admin's distribution");

            bool adminProcessResult = adminManager.ProcessSenderKeyDistribution(memberDistribution);
            Assert.IsTrue(adminProcessResult, "Admin should process member's distribution");

            // Test communication before revocation
            string message1 = "Message before revocation";
            var encrypted1 = adminManager.EncryptGroupMessage(groupId, message1);
            string decrypted1 = memberManager.DecryptGroupMessage(encrypted1);

            // Now revoke member
            adminManager.RemoveGroupMember(groupId, memberKeyPair.publicKey);

            // Send a new message after revocation
            string message2 = "Message after revocation";
            var encrypted2 = adminManager.EncryptGroupMessage(groupId, message2);

            // Act - member tries to decrypt post-revocation message
            string decrypted2 = memberManager.DecryptGroupMessage(encrypted2);

            // Assert
            Assert.IsNotNull(decrypted1);
            Assert.AreEqual(message1, decrypted1);
            Assert.IsNull(decrypted2); // Should not be able to decrypt after revocation
        }

        [TestMethod]
        public void ProcessSenderKeyDistribution_ShouldRejectUntrustedSenders()
        {
            // Arrange
            var adminKeyPair = E2EEClient.GenerateSignatureKeyPair();
            var memberKeyPair = E2EEClient.GenerateSignatureKeyPair();
            var untrustedKeyPair = E2EEClient.GenerateSignatureKeyPair();

            var adminManager = new GroupChatManager(adminKeyPair);
            var memberManager = new GroupChatManager(memberKeyPair);
            var untrustedManager = new GroupChatManager(untrustedKeyPair);

            string groupId = "test-untrusted-rejection";
            adminManager.CreateGroup(groupId);
            memberManager.CreateGroup(groupId);
            untrustedManager.CreateGroup(groupId);

            // Add only the trusted member
            adminManager.AddGroupMember(groupId, memberKeyPair.publicKey);
            memberManager.AddGroupMember(groupId, adminKeyPair.publicKey);

            // Exchange distribution messages between admin and trusted member
            var adminDistribution = adminManager.CreateDistributionMessage(groupId);
            var memberDistribution = memberManager.CreateDistributionMessage(groupId);

            adminManager.ProcessSenderKeyDistribution(memberDistribution);
            memberManager.ProcessSenderKeyDistribution(adminDistribution);

            // Now try to process distribution from untrusted sender
            var untrustedDistribution = untrustedManager.CreateDistributionMessage(groupId);

            // Act
            bool result = memberManager.ProcessSenderKeyDistribution(untrustedDistribution);

            // Assert
            Assert.IsFalse(result);
        }

        [TestMethod]
        public void GenerateSenderKey_ShouldReturnValidKey()
        {
            // Act
            byte[] senderKey = E2EEClient.GenerateSenderKey();

            // Assert
            Assert.IsNotNull(senderKey);
            Assert.AreEqual(32, senderKey.Length);
        }

        [TestMethod]
        public void EncryptDecryptGroupMessage_ShouldReturnOriginalMessage()
        {
            // Arrange
            string message = "This is a group message";
            string groupId = "test-group-123";
            byte[] senderKey = E2EEClient.GenerateSenderKey();

            // Create identity key pair for signing
            var identityKeyPair = E2EEClient.GenerateSignatureKeyPair();

            // Create an instance of GroupMessageCrypto
            var messageCrypto = new GroupMessageCrypto();

            // Act
            var encryptedMessage = messageCrypto.EncryptMessage(groupId, message, senderKey, identityKeyPair);
            var decryptedMessage = messageCrypto.DecryptMessage(encryptedMessage, senderKey);

            // Assert
            Assert.AreEqual(message, decryptedMessage);
        }

        [TestMethod]
        public void CreateDistributionMessage_ShouldReturnValidMessage()
        {
            // Arrange
            string groupId = "test-group-123";
            var senderKeyPair = E2EEClient.GenerateSignatureKeyPair();

            // Create an instance of GroupChatManager
            var groupChatManager = new GroupChatManager(senderKeyPair);

            // Create the group
            byte[] senderKey = groupChatManager.CreateGroup(groupId);

            // Act
            var distributionMessage = groupChatManager.CreateDistributionMessage(groupId);

            // Assert
            Assert.IsNotNull(distributionMessage);
            Assert.AreEqual(groupId, distributionMessage.GroupId);

            // Get session persistence manager via reflection
            var sessionPersistenceField = typeof(GroupChatManager).GetField("_sessionPersistence",
                BindingFlags.NonPublic | BindingFlags.Instance);
            var sessionPersistence = sessionPersistenceField.GetValue(groupChatManager) as GroupSessionPersistence;

            var session = sessionPersistence.GetGroupSession(groupId);
            byte[] storedKey = session.SenderKey;

            Assert.IsTrue(SecureMemory.SecureCompare(storedKey, distributionMessage.SenderKey));
            Assert.IsTrue(SecureMemory.SecureCompare(senderKeyPair.publicKey, distributionMessage.SenderIdentityKey));

            // Get the distribution manager via reflection to verify signature
            var distributionManagerField = typeof(GroupChatManager).GetField("_distributionManager",
                BindingFlags.NonPublic | BindingFlags.Instance);
            var distributionManager = distributionManagerField.GetValue(groupChatManager) as SenderKeyDistribution;

            bool isValidDistribution = distributionManager.ValidateDistributionMessage(distributionMessage);
            Assert.IsTrue(isValidDistribution, "Distribution message should be valid");
        }

        [TestMethod]
        public void EncryptDecryptSenderKeyDistribution_ShouldReturnOriginalMessage()
        {
            // Arrange
            string groupId = "test-group-456";
            var senderKeyPair = E2EEClient.GenerateSignatureKeyPair();
            var recipientKeyPair = E2EEClient.GenerateSignatureKeyPair();

            // Create an instance of GroupChatManager
            var groupChatManager = new GroupChatManager(senderKeyPair);

            // Create the group
            groupChatManager.CreateGroup(groupId);

            // Create distribution message
            var distributionMessage = groupChatManager.CreateDistributionMessage(groupId);

            // Act
            var encryptedDistribution = SenderKeyDistribution.EncryptSenderKeyDistribution(
                distributionMessage, recipientKeyPair.publicKey, senderKeyPair.privateKey);
            var decryptedDistribution = SenderKeyDistribution.DecryptSenderKeyDistribution(
                encryptedDistribution, recipientKeyPair.privateKey);

            // Assert
            Assert.AreEqual(distributionMessage.GroupId, decryptedDistribution.GroupId);
            Assert.IsTrue(SecureMemory.SecureCompare(distributionMessage.SenderKey, decryptedDistribution.SenderKey));
            Assert.IsTrue(SecureMemory.SecureCompare(distributionMessage.SenderIdentityKey, decryptedDistribution.SenderIdentityKey));
            Assert.IsTrue(SecureMemory.SecureCompare(distributionMessage.Signature, decryptedDistribution.Signature));
        }

        [TestMethod]
        public void GroupChatManager_ShouldHandleMessageExchange()
        {
            // Arrange
            var aliceKeyPair = E2EEClient.GenerateSignatureKeyPair();
            var bobKeyPair = E2EEClient.GenerateSignatureKeyPair();

            var aliceManager = new GroupChatManager(aliceKeyPair);
            var bobManager = new GroupChatManager(bobKeyPair);

            string groupId = "test-group-789";
            string message = "Hello group members!";

            // Act
            // Alice creates a group
            aliceManager.CreateGroup(groupId);

            // Alice authorizes Bob and Bob authorizes Alice
            aliceManager.AddGroupMember(groupId, bobKeyPair.publicKey);
            bobManager.CreateGroup(groupId);
            bobManager.AddGroupMember(groupId, aliceKeyPair.publicKey);

            // Alice creates a distribution message
            var distributionMessage = aliceManager.CreateDistributionMessage(groupId);

            // Bob processes the distribution message
            bool processingResult = bobManager.ProcessSenderKeyDistribution(distributionMessage);

            // Alice sends a message
            var encryptedMessage = aliceManager.EncryptGroupMessage(groupId, message);

            // Bob decrypts the message
            string decryptedMessage = bobManager.DecryptGroupMessage(encryptedMessage);

            // Assert
            Assert.IsTrue(processingResult);
            Assert.AreEqual(message, decryptedMessage);
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidOperationException))]
        public void GroupChatManager_CreateDistribution_WithNonExistentGroup_ShouldThrowException()
        {
            // Arrange
            var keyPair = E2EEClient.GenerateSignatureKeyPair();
            var manager = new GroupChatManager(keyPair);

            // Act & Assert - Should throw InvalidOperationException
            manager.CreateDistributionMessage("non-existent-group");
        }

        [TestMethod]
        public void GroupMultiSenderDeduplication_ShouldHandleSimultaneousMessages()
        {
            // Arrange - Create three participants
            var aliceKeyPair = E2EEClient.GenerateSignatureKeyPair();
            var bobKeyPair = E2EEClient.GenerateSignatureKeyPair();
            var charlieKeyPair = E2EEClient.GenerateSignatureKeyPair();

            var aliceManager = new GroupChatManager(aliceKeyPair);
            var bobManager = new GroupChatManager(bobKeyPair);
            var charlieManager = new GroupChatManager(charlieKeyPair);

            // Setup the group - Alice is the admin/creator
            string groupId = "multiple-senders-test-group";
            aliceManager.CreateGroup(groupId);
            bobManager.CreateGroup(groupId);
            charlieManager.CreateGroup(groupId);

            // Add members both ways
            // Alice adds Bob and Charlie
            aliceManager.AddGroupMember(groupId, bobKeyPair.publicKey);
            aliceManager.AddGroupMember(groupId, charlieKeyPair.publicKey);

            // Bob adds Alice and Charlie
            bobManager.AddGroupMember(groupId, aliceKeyPair.publicKey);
            bobManager.AddGroupMember(groupId, charlieKeyPair.publicKey);

            // Charlie adds Alice and Bob
            charlieManager.AddGroupMember(groupId, aliceKeyPair.publicKey);
            charlieManager.AddGroupMember(groupId, bobKeyPair.publicKey);

            // Exchange sender keys
            var aliceDistribution = aliceManager.CreateDistributionMessage(groupId);
            var bobDistribution = bobManager.CreateDistributionMessage(groupId);
            var charlieDistribution = charlieManager.CreateDistributionMessage(groupId);

            // Everyone processes everyone else's distribution
            aliceManager.ProcessSenderKeyDistribution(bobDistribution);
            aliceManager.ProcessSenderKeyDistribution(charlieDistribution);
            bobManager.ProcessSenderKeyDistribution(aliceDistribution);
            bobManager.ProcessSenderKeyDistribution(charlieDistribution);
            charlieManager.ProcessSenderKeyDistribution(aliceDistribution);
            charlieManager.ProcessSenderKeyDistribution(bobDistribution);

            // Act - Simulate simultaneous messages from all three
            string aliceMessage = "Alice's message";
            string bobMessage = "Bob's message";
            string charlieMessage = "Charlie's message";

            var aliceEncrypted = aliceManager.EncryptGroupMessage(groupId, aliceMessage);
            var bobEncrypted = bobManager.EncryptGroupMessage(groupId, bobMessage);
            var charlieEncrypted = charlieManager.EncryptGroupMessage(groupId, charlieMessage);

            // Each participant receives messages from the other two
            string bobDecryptsAlice = bobManager.DecryptGroupMessage(aliceEncrypted);
            string bobDecryptsCharlie = bobManager.DecryptGroupMessage(charlieEncrypted);

            string aliceDecryptsBob = aliceManager.DecryptGroupMessage(bobEncrypted);
            string aliceDecryptsCharlie = aliceManager.DecryptGroupMessage(charlieEncrypted);

            string charlieDecryptsAlice = charlieManager.DecryptGroupMessage(aliceEncrypted);
            string charlieDecryptsBob = charlieManager.DecryptGroupMessage(bobEncrypted);

            // Assert - Each message should be correctly decrypted by the other two participants
            Assert.AreEqual(aliceMessage, bobDecryptsAlice);
            Assert.AreEqual(aliceMessage, charlieDecryptsAlice);

            Assert.AreEqual(bobMessage, aliceDecryptsBob);
            Assert.AreEqual(bobMessage, charlieDecryptsBob);

            Assert.AreEqual(charlieMessage, aliceDecryptsCharlie);
            Assert.AreEqual(charlieMessage, bobDecryptsCharlie);
        }

        [TestMethod]
        public void GroupMemberAddition_ShouldAllowNewMemberToReceiveMessages()
        {
            // Create test participants
            var aliceKeyPair = E2EEClient.GenerateSignatureKeyPair();
            var bobKeyPair = E2EEClient.GenerateSignatureKeyPair();
            var daveKeyPair = E2EEClient.GenerateSignatureKeyPair();

            var aliceManager = new GroupChatManager(aliceKeyPair);
            var bobManager = new GroupChatManager(bobKeyPair);
            var daveManager = new GroupChatManager(daveKeyPair);

            // 1. Each member creates their own group
            string groupId = "member-addition-test-group";
            aliceManager.CreateGroup(groupId);
            bobManager.CreateGroup(groupId);

            // 2. Bidirectional authorization between Alice and Bob
            aliceManager.AddGroupMember(groupId, bobKeyPair.publicKey);
            bobManager.AddGroupMember(groupId, aliceKeyPair.publicKey);

            // 3. Exchange distribution messages between Alice and Bob
            var aliceDistribution = aliceManager.CreateDistributionMessage(groupId);
            var bobDistribution = bobManager.CreateDistributionMessage(groupId);

            bool aliceProcessBob = aliceManager.ProcessSenderKeyDistribution(bobDistribution);
            bool bobProcessAlice = bobManager.ProcessSenderKeyDistribution(aliceDistribution);

            Assert.IsTrue(aliceProcessBob, "Alice should successfully process Bob's distribution");
            Assert.IsTrue(bobProcessAlice, "Bob should successfully process Alice's distribution");

            // 4. Send initial message before Dave joins
            string initialMessage = "Initial message before Dave joins";
            var initialEncrypted = aliceManager.EncryptGroupMessage(groupId, initialMessage);
            string bobDecryptsInitial = bobManager.DecryptGroupMessage(initialEncrypted);

            Assert.AreEqual(initialMessage, bobDecryptsInitial, "Bob should be able to decrypt the initial message");

            // 5. Add Dave to the group
            daveManager.CreateGroup(groupId);

            // Bidirectional authorization for Dave with both Alice and Bob
            aliceManager.AddGroupMember(groupId, daveKeyPair.publicKey);
            daveManager.AddGroupMember(groupId, aliceKeyPair.publicKey);

            bobManager.AddGroupMember(groupId, daveKeyPair.publicKey);
            daveManager.AddGroupMember(groupId, bobKeyPair.publicKey);

            // 6. Exchange distribution messages for all members
            var daveDistribution = daveManager.CreateDistributionMessage(groupId);

            // Process Dave's distribution
            bool aliceProcessDave = aliceManager.ProcessSenderKeyDistribution(daveDistribution);
            bool bobProcessDave = bobManager.ProcessSenderKeyDistribution(daveDistribution);

            // Dave processes Alice's and Bob's distributions
            bool daveProcessAlice = daveManager.ProcessSenderKeyDistribution(aliceDistribution);
            bool daveProcessBob = daveManager.ProcessSenderKeyDistribution(bobDistribution);

            Assert.IsTrue(aliceProcessDave, "Alice should successfully process Dave's distribution");
            Assert.IsTrue(bobProcessDave, "Bob should successfully process Dave's distribution");
            Assert.IsTrue(daveProcessAlice, "Dave should successfully process Alice's distribution");
            Assert.IsTrue(daveProcessBob, "Dave should successfully process Bob's distribution");

            // 7. Send new messages after Dave joins
            string aliceMessage = "Message from Alice after Dave joined";
            string bobMessage = "Message from Bob after Dave joined";
            string daveMessage = "Dave's first message to the group";

            var aliceEncrypted = aliceManager.EncryptGroupMessage(groupId, aliceMessage);
            var bobEncrypted = bobManager.EncryptGroupMessage(groupId, bobMessage);
            var daveEncrypted = daveManager.EncryptGroupMessage(groupId, daveMessage);

            // 8. Everyone decrypts new messages
            string bobDecryptsAlice = bobManager.DecryptGroupMessage(aliceEncrypted);
            string bobDecryptsDave = bobManager.DecryptGroupMessage(daveEncrypted);
            string aliceDecryptsBob = aliceManager.DecryptGroupMessage(bobEncrypted);
            string aliceDecryptsDave = aliceManager.DecryptGroupMessage(daveEncrypted);
            string daveDecryptsAlice = daveManager.DecryptGroupMessage(aliceEncrypted);
            string daveDecryptsBob = daveManager.DecryptGroupMessage(bobEncrypted);

            // 9. Dave tries to decrypt the initial message
            string daveDecryptsInitial = daveManager.DecryptGroupMessage(initialEncrypted);

            // 10. Assert results
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
        public void FullGroupMessageFlow_ShouldWorkEndToEnd()
        {
            // This test simulates a group chat between Alice, Bob, and Charlie

            // Step 1: Generate identity keys for the participants
            var aliceKeyPair = E2EEClient.GenerateSignatureKeyPair();
            var bobKeyPair = E2EEClient.GenerateSignatureKeyPair();
            var charlieKeyPair = E2EEClient.GenerateSignatureKeyPair();

            // Step 2: Create group chat managers for each participant
            var aliceManager = new GroupChatManager(aliceKeyPair);
            var bobManager = new GroupChatManager(bobKeyPair);
            var charlieManager = new GroupChatManager(charlieKeyPair);

            // Step 3: Each participant creates the group
            string groupId = "friends-group-123";
            aliceManager.CreateGroup(groupId);
            bobManager.CreateGroup(groupId);
            charlieManager.CreateGroup(groupId);

            // Step 4: Each participant authorizes all others
            // Alice authorizes Bob and Charlie
            aliceManager.AddGroupMember(groupId, bobKeyPair.publicKey);
            aliceManager.AddGroupMember(groupId, charlieKeyPair.publicKey);

            // Bob authorizes Alice and Charlie
            bobManager.AddGroupMember(groupId, aliceKeyPair.publicKey);
            bobManager.AddGroupMember(groupId, charlieKeyPair.publicKey);

            // Charlie authorizes Alice and Bob
            charlieManager.AddGroupMember(groupId, aliceKeyPair.publicKey);
            charlieManager.AddGroupMember(groupId, bobKeyPair.publicKey);

            // Step 5: Each participant creates their distribution message
            var aliceDistribution = aliceManager.CreateDistributionMessage(groupId);
            var bobDistribution = bobManager.CreateDistributionMessage(groupId);
            var charlieDistribution = charlieManager.CreateDistributionMessage(groupId);

            // Step 6: Everyone processes everyone else's distribution
            // Bob and Charlie process Alice's distribution
            bool bobProcessAliceResult = bobManager.ProcessSenderKeyDistribution(aliceDistribution);
            bool charlieProcessAliceResult = charlieManager.ProcessSenderKeyDistribution(aliceDistribution);

            // Alice and Charlie process Bob's distribution
            bool aliceProcessBobResult = aliceManager.ProcessSenderKeyDistribution(bobDistribution);
            bool charlieProcessBobResult = charlieManager.ProcessSenderKeyDistribution(bobDistribution);

            // Alice and Bob process Charlie's distribution
            bool aliceProcessCharlieResult = aliceManager.ProcessSenderKeyDistribution(charlieDistribution);
            bool bobProcessCharlieResult = bobManager.ProcessSenderKeyDistribution(charlieDistribution);

            // Step 7: Alice sends a message to the group
            string aliceMessage = "Hello everyone, this is Alice!";
            var aliceEncryptedMessage = aliceManager.EncryptGroupMessage(groupId, aliceMessage);

            // Bob and Charlie decrypt Alice's message
            string bobDecryptedAliceMessage = bobManager.DecryptGroupMessage(aliceEncryptedMessage);
            string charlieDecryptedAliceMessage = charlieManager.DecryptGroupMessage(aliceEncryptedMessage);

            // Step 8: Bob replies to the group
            string bobMessage = "Hi Alice and Charlie, Bob here!";
            var bobEncryptedMessage = bobManager.EncryptGroupMessage(groupId, bobMessage);

            // Alice and Charlie decrypt Bob's message
            string aliceDecryptedBobMessage = aliceManager.DecryptGroupMessage(bobEncryptedMessage);
            string charlieDecryptedBobMessage = charlieManager.DecryptGroupMessage(bobEncryptedMessage);

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
        public void DeleteGroup_ShouldWorkCorrectly()
        {
            // Arrange
            var adminKeyPair = E2EEClient.GenerateSignatureKeyPair();
            var memberKeyPair = E2EEClient.GenerateSignatureKeyPair();

            var groupManager = new GroupChatManager(adminKeyPair);
            string groupId = "test-delete-group";

            // Create group and add a member
            groupManager.CreateGroup(groupId);
            groupManager.AddGroupMember(groupId, memberKeyPair.publicKey);

            // Verify group exists
            Assert.IsTrue(groupManager.GroupExists(groupId));

            // Act
            bool result = groupManager.DeleteGroup(groupId);

            // Assert
            Assert.IsTrue(result);
            Assert.IsFalse(groupManager.GroupExists(groupId));
        }
    }
}