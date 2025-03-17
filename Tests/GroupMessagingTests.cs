using System;
using System.Threading;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;
using E2EELibrary;
using E2EELibrary.Core;
using E2EELibrary.Models;
using E2EELibrary.KeyManagement;
using E2EELibrary.Encryption;
using E2EELibrary.GroupMessaging;

namespace E2EELibraryTests
{
    [TestClass]
    public class GroupMessagingTests
    {
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

            // Act
            var distributionMessage = GroupChatManager.CreateSenderKeyDistributionMessage(
                groupId, senderKey, senderKeyPair);

            // Assert
            Assert.IsNotNull(distributionMessage);
            Assert.AreEqual(groupId, distributionMessage.GroupId);
            Assert.IsTrue(AreByteArraysEqual(senderKey, distributionMessage.SenderKey));
            Assert.IsTrue(AreByteArraysEqual(senderKeyPair.publicKey, distributionMessage.SenderIdentityKey));

            // Verify signature
            bool validSignature = E2EEClient.VerifySignature(
                distributionMessage.SenderKey,
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

            var distributionMessage = GroupChatManager.CreateSenderKeyDistributionMessage(
                groupId, senderKey, senderKeyPair);

            // Act
            var encryptedDistribution = SenderKeyDistribution.EncryptSenderKeyDistribution(
                distributionMessage, recipientKeyPair.publicKey, senderKeyPair.privateKey);

            var decryptedDistribution = SenderKeyDistribution.DecryptSenderKeyDistribution(
                encryptedDistribution, recipientKeyPair.privateKey);

            // Assert
            Assert.AreEqual(distributionMessage.GroupId, decryptedDistribution.GroupId);
            Assert.IsTrue(AreByteArraysEqual(distributionMessage.SenderKey, decryptedDistribution.SenderKey));
            Assert.IsTrue(AreByteArraysEqual(distributionMessage.SenderIdentityKey, decryptedDistribution.SenderIdentityKey));
            Assert.IsTrue(AreByteArraysEqual(distributionMessage.Signature, decryptedDistribution.Signature));
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

            // Setup the group
            string groupId = "multiple-senders-test-group";
            aliceManager.CreateGroup(groupId);
            bobManager.CreateGroup(groupId);
            charlieManager.CreateGroup(groupId);

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
            // Arrange - Create an initial group with Alice and Bob
            var aliceKeyPair = E2EEClient.GenerateSignatureKeyPair();
            var bobKeyPair = E2EEClient.GenerateSignatureKeyPair();
            var daveKeyPair = E2EEClient.GenerateSignatureKeyPair(); // Dave will join later

            var aliceManager = new GroupChatManager(aliceKeyPair);
            var bobManager = new GroupChatManager(bobKeyPair);
            var daveManager = new GroupChatManager(daveKeyPair);

            // Setup the initial group - but only Alice creates it as the admin
            string groupId = "member-addition-test-group";
            aliceManager.CreateGroup(groupId);

            // Alice invites Bob to the group by sending him her distribution message
            var aliceDistribution = aliceManager.CreateDistributionMessage(groupId);

            // Bob processes Alice's sender key to join the group
            bobManager.ProcessSenderKeyDistribution(aliceDistribution);

            // Bob sends his distribution message back to Alice
            var bobDistribution = bobManager.CreateDistributionMessage(groupId);
            aliceManager.ProcessSenderKeyDistribution(bobDistribution);

            // Add a delay before sending the initial message to ensure timestamps are clearly different
            Thread.Sleep(50);

            // Send an initial message before Dave joins
            string initialMessage = "Initial message before Dave joins";
            var initialEncrypted = aliceManager.EncryptGroupMessage(groupId, initialMessage);
            string bobDecryptsInitial = bobManager.DecryptGroupMessage(initialEncrypted);

            // Add a delay before Dave joins to ensure clear timestamp separation
            Thread.Sleep(50);

            // Act - Add Dave to the group
            // Dave never creates the group directly - he only processes messages from Alice and Bob
            daveManager.ProcessSenderKeyDistribution(aliceDistribution);
            daveManager.ProcessSenderKeyDistribution(bobDistribution);

            // Dave sends his distribution message to existing members
            var daveDistribution = daveManager.CreateDistributionMessage(groupId);
            aliceManager.ProcessSenderKeyDistribution(daveDistribution);
            bobManager.ProcessSenderKeyDistribution(daveDistribution);

            // Add a delay before sending messages after Dave joins
            Thread.Sleep(50);

            // Send messages after Dave joins
            string aliceMessage = "Message from Alice after Dave joined";
            string bobMessage = "Message from Bob after Dave joined";
            string daveMessage = "Dave's first message to the group";

            var aliceEncrypted = aliceManager.EncryptGroupMessage(groupId, aliceMessage);
            var bobEncrypted = bobManager.EncryptGroupMessage(groupId, bobMessage);
            var daveEncrypted = daveManager.EncryptGroupMessage(groupId, daveMessage);

            // All participants decrypt the new messages
            string bobDecryptsAlice = bobManager.DecryptGroupMessage(aliceEncrypted);
            string bobDecryptsDave = bobManager.DecryptGroupMessage(daveEncrypted);

            string aliceDecryptsBob = aliceManager.DecryptGroupMessage(bobEncrypted);
            string aliceDecryptsDave = aliceManager.DecryptGroupMessage(daveEncrypted);

            string daveDecryptsAlice = daveManager.DecryptGroupMessage(aliceEncrypted);
            string daveDecryptsBob = daveManager.DecryptGroupMessage(bobEncrypted);

            // Dave attempts to decrypt the initial message that was sent before he joined
            string daveDecryptsInitial = daveManager.DecryptGroupMessage(initialEncrypted);

            // Assert
            Assert.AreEqual(initialMessage, bobDecryptsInitial, "Bob should be able to decrypt the initial message");

            Assert.AreEqual(aliceMessage, bobDecryptsAlice, "Bob should be able to decrypt Alice's message after Dave joined");
            Assert.AreEqual(aliceMessage, daveDecryptsAlice, "Dave should be able to decrypt Alice's message after he joined");

            Assert.AreEqual(bobMessage, aliceDecryptsBob, "Alice should be able to decrypt Bob's message after Dave joined");
            Assert.AreEqual(bobMessage, daveDecryptsBob, "Dave should be able to decrypt Bob's message after he joined");

            Assert.AreEqual(daveMessage, aliceDecryptsDave, "Alice should be able to decrypt Dave's message");
            Assert.AreEqual(daveMessage, bobDecryptsDave, "Bob should be able to decrypt Dave's message");

            // This is the key test - Dave shouldn't be able to decrypt the initial message
            Assert.IsNull(daveDecryptsInitial, "New member should not be able to decrypt messages sent before joining");

            // Verify timestamp behavior
            Assert.IsTrue(initialEncrypted.Timestamp > 0, "Initial message should have a valid timestamp");
            Assert.IsTrue(aliceEncrypted.Timestamp > 0, "Alice's message should have a valid timestamp");
            Assert.IsTrue(bobEncrypted.Timestamp > 0, "Bob's message should have a valid timestamp");
            Assert.IsTrue(daveEncrypted.Timestamp > 0, "Dave's message should have a valid timestamp");

            // Add timestamp verification to ensure message timestamps have the expected ordering
            Assert.IsTrue(aliceEncrypted.Timestamp > initialEncrypted.Timestamp,
                "Alice's later message should have a timestamp after the initial message");
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

            // Step 3: Alice creates the group
            string groupId = "friends-group-123";
            aliceManager.CreateGroup(groupId);

            // Step 4: Alice sends her sender key to Bob and Charlie
            var aliceDistribution = aliceManager.CreateDistributionMessage(groupId);

            // Bob and Charlie process Alice's sender key
            bool bobProcessResult = bobManager.ProcessSenderKeyDistribution(aliceDistribution);
            bool charlieProcessResult = charlieManager.ProcessSenderKeyDistribution(aliceDistribution);

            // Step 5: Bob creates his sender key and distributes it
            bobManager.CreateGroup(groupId);
            var bobDistribution = bobManager.CreateDistributionMessage(groupId);

            // Alice and Charlie process Bob's sender key
            bool aliceProcessBobResult = aliceManager.ProcessSenderKeyDistribution(bobDistribution);
            bool charlieProcessBobResult = charlieManager.ProcessSenderKeyDistribution(bobDistribution);

            // Step 6: Charlie creates his sender key and distributes it
            charlieManager.CreateGroup(groupId);
            var charlieDistribution = charlieManager.CreateDistributionMessage(groupId);

            // Alice and Bob process Charlie's sender key
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
            Assert.IsTrue(bobProcessResult);
            Assert.IsTrue(charlieProcessResult);
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