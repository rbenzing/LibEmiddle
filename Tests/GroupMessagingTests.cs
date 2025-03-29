using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using E2EELibrary;
using E2EELibrary.Core;
using E2EELibrary.Encryption;
using E2EELibrary.GroupMessaging;
using System.Collections.Concurrent;
using System.IO;
using System.Text;

namespace E2EELibraryTests
{
    [TestClass]
    public class GroupMessagingTests
    {
        [TestMethod]
        public void RotateGroupEpoch_ShouldIncrementEpochAndGenerateNewKey()
        {
            // Arrange
            var keyPair = E2EEClient.GenerateSignatureKeyPair();
            var groupManager = new GroupChatManager(keyPair);
            string groupId = "test-epoch-rotation";
            byte[] originalKey = groupManager.CreateGroup(groupId);

            // Act
            int newEpoch = groupManager.RotateGroupEpoch(groupId);

            // Get the new sender key via reflection
            var myGroupSenderKeysField = typeof(GroupChatManager).GetField("_myGroupSenderKeys",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            var groupSenderKeys = (ConcurrentDictionary<string, byte[]>)myGroupSenderKeysField.GetValue(groupManager);
            byte[] newKey = groupSenderKeys[groupId];

            // Assert
            Assert.AreEqual(2, newEpoch); // Should increment from 1 to 2
            Assert.IsFalse(AreByteArraysEqual(originalKey, newKey));
        }

        [TestMethod]
        public void AuthorizeMember_ShouldAddMemberToAuthorizedList()
        {
            // Arrange
            var adminKeyPair = E2EEClient.GenerateSignatureKeyPair();
            var memberKeyPair = E2EEClient.GenerateSignatureKeyPair();
            var groupManager = new GroupChatManager(adminKeyPair);
            string groupId = "test-authorization";
            groupManager.CreateGroup(groupId);

            // Act
            bool result = groupManager.AuthorizeMember(groupId, memberKeyPair.publicKey);

            // Get the authorized members via reflection
            var authorizedMembersField = typeof(GroupChatManager).GetField("_authorizedMembers",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            var allAuthorizedMembers = (ConcurrentDictionary<string, ConcurrentDictionary<string, bool>>)
                authorizedMembersField.GetValue(groupManager);
            var groupMembers = allAuthorizedMembers[groupId];
            string memberIdBase64 = Convert.ToBase64String(memberKeyPair.publicKey);

            // Assert
            Assert.IsTrue(result);
            Assert.IsTrue(groupMembers.ContainsKey(memberIdBase64));
        }

        [TestMethod]
        public void RevokeMember_ShouldRemoveMemberAndRotateEpoch()
        {
            // Arrange
            var adminKeyPair = E2EEClient.GenerateSignatureKeyPair();
            var memberKeyPair = E2EEClient.GenerateSignatureKeyPair();
            var groupManager = new GroupChatManager(adminKeyPair);
            string groupId = "test-revocation";
            groupManager.CreateGroup(groupId);
            groupManager.AuthorizeMember(groupId, memberKeyPair.publicKey);

            // Get the initial epoch
            var epochsField = typeof(GroupChatManager).GetField("_groupEpochs",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            var epochs = (ConcurrentDictionary<string, int>)epochsField.GetValue(groupManager);
            int initialEpoch = epochs[groupId];

            // Act
            bool result = groupManager.RevokeMember(groupId, memberKeyPair.publicKey);

            // Get the authorized members and updated epoch
            var authorizedMembersField = typeof(GroupChatManager).GetField("_authorizedMembers",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            var allAuthorizedMembers = (ConcurrentDictionary<string, ConcurrentDictionary<string, bool>>)
                authorizedMembersField.GetValue(groupManager);
            var groupMembers = allAuthorizedMembers[groupId];
            string memberIdBase64 = Convert.ToBase64String(memberKeyPair.publicKey);
            int newEpoch = epochs[groupId];

            // Assert
            Assert.IsTrue(result);
            Assert.IsFalse(groupMembers.ContainsKey(memberIdBase64));
            Assert.AreEqual(initialEpoch + 1, newEpoch); // Epoch should be incremented
        }

        [TestMethod]
        public void DecryptGroupMessage_ShouldRejectReplayedMessage()
        {
            // Arrange
            var keyPair = E2EEClient.GenerateSignatureKeyPair();
            var groupManager = new GroupChatManager(keyPair);
            string groupId = "test-replay-protection";
            groupManager.CreateGroup(groupId);

            // Create and encrypt a message
            string originalMessage = "Hello, secure group!";
            var encryptedMessage = groupManager.EncryptGroupMessage(groupId, originalMessage);

            // Decrypt the message once - should succeed
            string firstDecryption = groupManager.DecryptGroupMessage(encryptedMessage);

            // Act - attempt to decrypt the same message again (simulating replay)
            string secondDecryption = groupManager.DecryptGroupMessage(encryptedMessage);

            // Assert
            Assert.IsNotNull(firstDecryption);
            Assert.AreEqual(originalMessage, firstDecryption);
            Assert.IsNull(secondDecryption); // Should be null on replay attempt
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

            // 1. Both parties create the group
            adminManager.CreateGroup(groupId);
            memberManager.CreateGroup(groupId);

            // 2. Bi-directional authorization - this is the missing piece
            // Admin authorizes member
            adminManager.AuthorizeMember(groupId, memberKeyPair.publicKey);
            // AND member authorizes admin
            memberManager.AuthorizeMember(groupId, adminKeyPair.publicKey);

            // Create and exchange distribution messages
            var adminDistribution = adminManager.CreateDistributionMessage(groupId);
            var memberDistribution = memberManager.CreateDistributionMessage(groupId);

            // Process distributions - now both should succeed
            bool memberProcessResult = memberManager.ProcessSenderKeyDistribution(adminDistribution);
            Assert.IsTrue(memberProcessResult, "Member should be able to process admin's distribution");

            bool adminProcessResult = adminManager.ProcessSenderKeyDistribution(memberDistribution);
            Assert.IsTrue(adminProcessResult, "Admin should process member's distribution");

            // Test communication before revocation
            string message1 = "Message before revocation";
            var encrypted1 = adminManager.EncryptGroupMessage(groupId, message1);
            string decrypted1 = memberManager.DecryptGroupMessage(encrypted1);

            // Now revoke member
            adminManager.RevokeMember(groupId, memberKeyPair.publicKey);

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
            memberManager.CreateGroup(groupId); // Member needs to create the group too
            untrustedManager.CreateGroup(groupId); // Even untrusted member creates a group (but won't be authorized)

            // Add only the trusted member
            adminManager.AuthorizeMember(groupId, memberKeyPair.publicKey);

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
            byte[] senderKey = E2EEClient.GenerateSenderKey();

            // Act
            var encryptedMessage = GroupMessage.EncryptGroupMessage(message, senderKey);
            string decryptedMessage = GroupMessage.DecryptGroupMessage(encryptedMessage, senderKey);

            // Assert
            Assert.AreEqual(message, decryptedMessage);
        }

        [TestMethod]
        public void CreateSenderKeyDistributionMessage_ShouldReturnValidMessage()
        {
            // Arrange
            string groupId = "test-group-123";
            byte[] senderKey = E2EEClient.GenerateSenderKey();
            var senderKeyPair = E2EEClient.GenerateSignatureKeyPair();

            // Create an instance of GroupChatManager
            var groupChatManager = new GroupChatManager(senderKeyPair);

            // We need to create the group first to initialize it
            groupChatManager.CreateGroup(groupId);

            // Manually set the sender key for testing
            var field = typeof(GroupChatManager).GetField("_myGroupSenderKeys",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            var groupKeys = (ConcurrentDictionary<string, byte[]>)field.GetValue(groupChatManager);
            groupKeys[groupId] = senderKey;

            // Act
            var distributionMessage = groupChatManager.CreateDistributionMessage(groupId);

            // Assert
            Assert.IsNotNull(distributionMessage);
            Assert.AreEqual(groupId, distributionMessage.GroupId);
            Assert.IsTrue(AreByteArraysEqual(senderKey, distributionMessage.SenderKey));
            Assert.IsTrue(AreByteArraysEqual(senderKeyPair.publicKey, distributionMessage.SenderIdentityKey));

            // Extract the current epoch (will be 1 for a new group)
            int epoch = 1;

            // Create the same signing context that's used internally
            byte[] dataToVerify;
            using (var ms = new MemoryStream())
            {
                // Start with the sender key
                ms.Write(distributionMessage.SenderKey, 0, distributionMessage.SenderKey.Length);

                // Add the epoch number
                ms.Write(BitConverter.GetBytes(epoch), 0, 4);

                // Add the group ID
                byte[] groupIdBytes = Encoding.UTF8.GetBytes(groupId);
                ms.Write(groupIdBytes, 0, groupIdBytes.Length);

                dataToVerify = ms.ToArray();
            }

            // Verify signature with the enhanced context
            bool validSignature = E2EEClient.VerifySignature(
                dataToVerify,
                distributionMessage.Signature,
                distributionMessage.SenderIdentityKey);

            Assert.IsTrue(validSignature);
        }

        [TestMethod]
        public void EncryptDecryptSenderKeyDistribution_ShouldReturnOriginalMessage()
        {
            // Arrange
            string groupId = "test-group-456";
            byte[] senderKey = E2EEClient.GenerateSenderKey();
            var senderKeyPair = E2EEClient.GenerateSignatureKeyPair();
            var recipientKeyPair = E2EEClient.GenerateSignatureKeyPair();

            // Create an instance of GroupChatManager
            var groupChatManager = new GroupChatManager(senderKeyPair);

            // Create the group and set the sender key
            groupChatManager.CreateGroup(groupId);

            // Set the sender key directly for testing
            var myGroupSenderKeysField = typeof(GroupChatManager).GetField("_myGroupSenderKeys",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            var groupSenderKeys = (ConcurrentDictionary<string, byte[]>)myGroupSenderKeysField.GetValue(groupChatManager);
            groupSenderKeys[groupId] = senderKey;

            // Create distribution message using the instance method
            var distributionMessage = groupChatManager.CreateDistributionMessage(groupId);

            // Act
            var encryptedDistribution = SenderKeyDistribution.EncryptSenderKeyDistribution(
                distributionMessage, recipientKeyPair.publicKey, senderKeyPair.privateKey);
            var decryptedDistribution = SenderKeyDistribution.DecryptSenderKeyDistribution(
                encryptedDistribution, recipientKeyPair.privateKey);

            // Assert
            Assert.AreEqual(distributionMessage.GroupId, decryptedDistribution.GroupId);
            Assert.IsTrue(AreByteArraysEqual(distributionMessage.SenderKey, decryptedDistribution.SenderKey));
            Assert.IsTrue(AreByteArraysEqual(distributionMessage.SenderIdentityKey, decryptedDistribution.SenderIdentityKey));

            // The signature verification needs to be separate since our enhanced signatures include different context
            // The SenderKeyDistribution encrypt/decrypt code doesn't need to understand our enhanced format,
            // it just needs to correctly transport the message

            // Verify the signature in context-aware manner
            // Extract the epoch from the enhanced message (will be 1 for a new group)
            int epoch = 1;

            // Create the signature verification context
            byte[] dataToVerify;
            using (var ms = new MemoryStream())
            {
                // Start with the sender key
                ms.Write(decryptedDistribution.SenderKey, 0, decryptedDistribution.SenderKey.Length);

                // Add the epoch number
                ms.Write(BitConverter.GetBytes(epoch), 0, 4);

                // Add the group ID
                byte[] groupIdBytes = Encoding.UTF8.GetBytes(groupId);
                ms.Write(groupIdBytes, 0, groupIdBytes.Length);

                dataToVerify = ms.ToArray();
            }

            // Verify signature with context
            bool validSignature = E2EEClient.VerifySignature(
                dataToVerify,
                decryptedDistribution.Signature,
                decryptedDistribution.SenderIdentityKey);

            Assert.IsTrue(validSignature);
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
        [ExpectedException(typeof(ArgumentException))]
        public void GroupChatManager_CreateDistribution_WithNonExistentGroup_ShouldThrowException()
        {
            // Arrange
            var keyPair = E2EEClient.GenerateSignatureKeyPair();
            var manager = new GroupChatManager(keyPair);

            // Act & Assert - Should throw ArgumentException
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

            // Alice authorizes Bob and Charlie 
            aliceManager.AuthorizeMember(groupId, bobKeyPair.publicKey);
            aliceManager.AuthorizeMember(groupId, charlieKeyPair.publicKey);

            // Bob and Charlie join the group
            bobManager.CreateGroup(groupId);
            charlieManager.CreateGroup(groupId);

            // Bob authorizes Alice and Charlie
            bobManager.AuthorizeMember(groupId, aliceKeyPair.publicKey);
            bobManager.AuthorizeMember(groupId, charlieKeyPair.publicKey);

            // Charlie authorizes Alice and Bob
            charlieManager.AuthorizeMember(groupId, aliceKeyPair.publicKey);
            charlieManager.AuthorizeMember(groupId, bobKeyPair.publicKey);

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
            Console.WriteLine("Creating groups for all members");
            string groupId = "member-addition-test-group";
            aliceManager.CreateGroup(groupId);
            bobManager.CreateGroup(groupId);

            // 2. Bidirectional authorization between Alice and Bob
            Console.WriteLine("Setting up bidirectional authorization between Alice and Bob");
            aliceManager.AuthorizeMember(groupId, bobKeyPair.publicKey);
            bobManager.AuthorizeMember(groupId, aliceKeyPair.publicKey);

            // 3. Exchange distribution messages between Alice and Bob
            Console.WriteLine("Exchanging distribution messages between Alice and Bob");
            var aliceDistribution = aliceManager.CreateDistributionMessage(groupId);
            var bobDistribution = bobManager.CreateDistributionMessage(groupId);

            bool aliceProcessBob = aliceManager.ProcessSenderKeyDistribution(bobDistribution);
            bool bobProcessAlice = bobManager.ProcessSenderKeyDistribution(aliceDistribution);

            Assert.IsTrue(aliceProcessBob, "Alice should successfully process Bob's distribution");
            Assert.IsTrue(bobProcessAlice, "Bob should successfully process Alice's distribution");

            // 4. Send initial message before Dave joins
            Console.WriteLine("Sending initial message before Dave joins");
            string initialMessage = "Initial message before Dave joins";
            var initialEncrypted = aliceManager.EncryptGroupMessage(groupId, initialMessage);
            string bobDecryptsInitial = bobManager.DecryptGroupMessage(initialEncrypted);

            Assert.AreEqual(initialMessage, bobDecryptsInitial, "Bob should be able to decrypt the initial message");

            // 5. Add Dave to the group (with proper bidirectional authorization)
            Console.WriteLine("Adding Dave to the group");
            daveManager.CreateGroup(groupId);

            // Bidirectional authorization for Dave with both Alice and Bob
            // Alice <-> Dave
            aliceManager.AuthorizeMember(groupId, daveKeyPair.publicKey);
            daveManager.AuthorizeMember(groupId, aliceKeyPair.publicKey);

            // Bob <-> Dave
            bobManager.AuthorizeMember(groupId, daveKeyPair.publicKey);
            daveManager.AuthorizeMember(groupId, bobKeyPair.publicKey);

            // 6. Exchange distribution messages for all members
            Console.WriteLine("Exchanging distribution messages for all members");
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
            Console.WriteLine("Sending new messages after Dave joins");
            string aliceMessage = "Message from Alice after Dave joined";
            string bobMessage = "Message from Bob after Dave joined";
            string daveMessage = "Dave's first message to the group";

            var aliceEncrypted = aliceManager.EncryptGroupMessage(groupId, aliceMessage);
            var bobEncrypted = bobManager.EncryptGroupMessage(groupId, bobMessage);
            var daveEncrypted = daveManager.EncryptGroupMessage(groupId, daveMessage);

            // 8. Everyone decrypts new messages
            Console.WriteLine("Decrypting new messages");
            string bobDecryptsAlice = bobManager.DecryptGroupMessage(aliceEncrypted);
            string bobDecryptsDave = bobManager.DecryptGroupMessage(daveEncrypted);
            string aliceDecryptsBob = aliceManager.DecryptGroupMessage(bobEncrypted);
            string aliceDecryptsDave = aliceManager.DecryptGroupMessage(daveEncrypted);
            string daveDecryptsAlice = daveManager.DecryptGroupMessage(aliceEncrypted);
            string daveDecryptsBob = daveManager.DecryptGroupMessage(bobEncrypted);

            // 9. Dave tries to decrypt the initial message
            Console.WriteLine("Dave attempts to decrypt the initial message");
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
            aliceManager.AuthorizeMember(groupId, bobKeyPair.publicKey);
            aliceManager.AuthorizeMember(groupId, charlieKeyPair.publicKey);

            // Bob authorizes Alice and Charlie
            bobManager.AuthorizeMember(groupId, aliceKeyPair.publicKey);
            bobManager.AuthorizeMember(groupId, charlieKeyPair.publicKey);

            // Charlie authorizes Alice and Bob
            charlieManager.AuthorizeMember(groupId, aliceKeyPair.publicKey);
            charlieManager.AuthorizeMember(groupId, bobKeyPair.publicKey);

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

        // Helper method for byte array comparison
        private bool AreByteArraysEqual(byte[] a, byte[] b)
        {
            return SecureMemory.SecureCompare(a, b);
        }
    }
}