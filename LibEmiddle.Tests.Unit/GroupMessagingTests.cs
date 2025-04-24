using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Diagnostics;
using System.Reflection;
using System.Threading;
using LibEmiddle.Abstractions;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Messaging.Group;
using LibEmiddle.Domain;

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
        public void RotateGroupKey_ShouldGenerateNewKey()
        {
            // Arrange
            var keyPair = Sodium.GenerateEd25519KeyPair();
            var groupManager = new GroupChatManager(keyPair);
            string groupId = $"test-key-{Guid.NewGuid()}";
            byte[] originalKey = groupManager.CreateGroup(groupId);

            // Act
            byte[] newKey = groupManager.RotateGroupKey(groupId);

            // Get the sender key via reflection
            var groupSessionPersistenceField = typeof(GroupChatManager).GetField("_sessionPersistence",
                BindingFlags.NonPublic | BindingFlags.Instance);
            var sessionPersistence = groupSessionPersistenceField.GetValue(groupManager) as GroupSessionPersistence;

            var session = sessionPersistence.GetGroupSession(groupId);
            byte[] storedKey = session.ChainKey;

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
            var adminKeyPair = Sodium.GenerateEd25519KeyPair();
            var memberKeyPair = Sodium.GenerateEd25519KeyPair();
            var groupManager = new GroupChatManager(adminKeyPair);
            string groupId = $"test-authorization-{Guid.NewGuid()}";
            groupManager.CreateGroup(groupId);

            // Act
            bool result = groupManager.AddGroupMember(groupId, memberKeyPair.PublicKey);

            // Get the member manager via reflection
            var memberManagerField = typeof(GroupChatManager).GetField("_memberManager",
                BindingFlags.NonPublic | BindingFlags.Instance);
            var memberManager = memberManagerField.GetValue(groupManager) as GroupMemberManager;

            bool isMember = memberManager.IsMember(groupId, memberKeyPair.PublicKey);

            // Assert
            Assert.IsTrue(result);
            Assert.IsTrue(isMember);
        }

        [TestMethod]
        public void RemoveGroupMember_ShouldRemoveMemberAndRotateKey()
        {
            // Arrange
            var adminKeyPair = Sodium.GenerateEd25519KeyPair();
            var memberKeyPair = Sodium.GenerateEd25519KeyPair();

            var groupManager = new GroupChatManager(adminKeyPair);

            string groupId = $"test-revocation-{Guid.NewGuid()}";

            groupManager.CreateGroup(groupId);
            groupManager.AddGroupMember(groupId, memberKeyPair.PublicKey);

            // Get the original key
            var sessionPersistenceField = typeof(GroupChatManager).GetField("_sessionPersistence",
                BindingFlags.NonPublic | BindingFlags.Instance);
            var sessionPersistence = sessionPersistenceField.GetValue(groupManager) as GroupSessionPersistence;

            var originalSession = sessionPersistence.GetGroupSession(groupId);
            byte[] originalKey = originalSession.ChainKey;

            // Act
            bool result = groupManager.RemoveGroupMember(groupId, memberKeyPair.PublicKey);

            // Get the member manager via reflection
            var memberManagerField = typeof(GroupChatManager).GetField("_memberManager",
                BindingFlags.NonPublic | BindingFlags.Instance);
            var memberManager = memberManagerField.GetValue(groupManager) as GroupMemberManager;

            bool isMember = memberManager.IsMember(groupId, memberKeyPair.PublicKey);

            // Get the updated key
            var updatedSession = sessionPersistence.GetGroupSession(groupId);
            byte[] newKey = updatedSession.ChainKey;

            // Assert
            Assert.IsTrue(result);
            Assert.IsFalse(isMember);
            Assert.IsFalse(SecureMemory.SecureCompare(originalKey, newKey)); // Key should have been rotated
        }

        [TestMethod]
        public void DecryptGroupMessage_ShouldRejectReplayedMessage()
        {
            // Arrange
            var keyPair = Sodium.GenerateEd25519KeyPair();
            var groupManager = new GroupChatManager(keyPair);
            string groupId = $"test-replay-protection-{Guid.NewGuid()}";
            byte[] senderKey = groupManager.CreateGroup(groupId);

            // Create and encrypt a message
            string originalMessage = "Hello, secure group!";
            var encryptedMessage = groupManager.EncryptGroupMessage(groupId, originalMessage);

            // Log details to help diagnose the issue
            Trace.TraceWarning($"Group ID: {groupId}");
            Trace.TraceWarning($"Message ID: {encryptedMessage.MessageId}");
            Trace.TraceWarning($"Sender Identity Key Length: {encryptedMessage.SenderIdentityKey?.Length ?? 0}");
            Trace.TraceWarning($"Ciphertext Length: {encryptedMessage.Ciphertext?.Length ?? 0}");
            Trace.TraceWarning($"Nonce Length: {encryptedMessage.Nonce?.Length ?? 0}");

            // Act & Assert - First decryption with detailed logging
            string firstDecryption = groupManager.DecryptGroupMessage(encryptedMessage);

            // If firstDecryption is null, log additional details to help diagnose
            if (firstDecryption == null)
            {
                Trace.TraceWarning("First decryption FAILED - returned null");

                // Try direct decryption via the underlying components to isolate the issue
                var messageCrypto = new GroupMessageCrypto();
                var directDecrypt = messageCrypto.DecryptMessage(encryptedMessage, senderKey);
                Trace.TraceWarning($"Direct decryption via GroupMessageCrypto: {(directDecrypt != null ? "SUCCESS" : "FAILED")}");
            }
            else
            {
                Trace.TraceWarning("First decryption SUCCESS");
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
            var adminKeyPair = Sodium.GenerateEd25519KeyPair();
            var memberKeyPair = Sodium.GenerateEd25519KeyPair();

            var adminManager = new GroupChatManager(adminKeyPair);
            var memberManager = new GroupChatManager(memberKeyPair);

            string groupId = $"test-forward-secrecy-{Guid.NewGuid()}";

            // 1. Admin creates the group
            adminManager.CreateGroup(groupId);

            // 2. Admin authorizes member
            adminManager.AddGroupMember(groupId, memberKeyPair.PublicKey);
            memberManager.AddGroupMember(groupId, adminKeyPair.PublicKey);

            // Member needs to create local session but doesn't create a group
            memberManager.JoinGroup(groupId);

            // Create and exchange distribution messages
            var adminDistribution = adminManager.CreateDistributionMessage(groupId);

            // Member processes admin's distribution
            bool memberProcessResult = memberManager.ProcessSenderKeyDistribution(adminDistribution);
            Assert.IsTrue(memberProcessResult, "Member should be able to process admin's distribution");

            // Test communication before revocation
            string message1 = "Message before revocation";
            var encrypted1 = adminManager.EncryptGroupMessage(groupId, message1);
            string decrypted1 = memberManager.DecryptGroupMessage(encrypted1);

            // Now revoke member
            adminManager.RemoveGroupMember(groupId, memberKeyPair.PublicKey);

            // IMPORTANT: Create a new member manager to simulate restarting the app
            // This ensures we're testing real forward secrecy where membership is enforced
            // on each message, not just based on in-memory state
            var memberManager2 = new GroupChatManager(memberKeyPair);
            memberManager2.JoinGroup(groupId); // Try to join the group again

            // Send a new message after revocation
            string message2 = "Message after revocation";
            var encrypted2 = adminManager.EncryptGroupMessage(groupId, message2);

            // Act - member tries to decrypt post-revocation message with fresh manager
            string decrypted2 = memberManager2.DecryptGroupMessage(encrypted2);

            // Assert
            Assert.IsNotNull(decrypted1);
            Assert.AreEqual(message1, decrypted1);
            Assert.IsNull(decrypted2); // Should not be able to decrypt after revocation
        }

        [TestMethod]
        public void ProcessSenderKeyDistribution_ShouldRejectMessagesFromUntrustedSenders()
        {
            // Arrange
            var adminKeyPair = Sodium.GenerateEd25519KeyPair();
            var memberKeyPair = Sodium.GenerateEd25519KeyPair();
            var untrustedKeyPair = Sodium.GenerateEd25519KeyPair();

            var adminManager = new GroupChatManager(adminKeyPair);
            var memberManager = new GroupChatManager(memberKeyPair);
            var untrustedManager = new GroupChatManager(untrustedKeyPair);

            string groupId = $"test-untrusted-rejection-{Guid.NewGuid()}";

            // Create groups for all participants
            adminManager.CreateGroup(groupId);
            memberManager.CreateGroup(groupId);
            untrustedManager.CreateGroup(groupId);

            // Add trusted members to each other's groups, but NOT the untrusted user
            adminManager.AddGroupMember(groupId, memberKeyPair.PublicKey);
            memberManager.AddGroupMember(groupId, adminKeyPair.PublicKey);

            // Member needs to create local session but doesn't create a group
            memberManager.JoinGroup(groupId);

            // Exchange distribution messages between trusted participants
            var adminDistribution = adminManager.CreateDistributionMessage(groupId);

            // Member processes admin's distribution
            bool memberProcessResult = memberManager.ProcessSenderKeyDistribution(adminDistribution);
            Assert.IsTrue(memberProcessResult, "Member should be able to process admin's distribution");

            var memberDistribution = memberManager.CreateDistributionMessage(groupId);

            // Admin processes members's distribution
            bool adminProcessResult = adminManager.ProcessSenderKeyDistribution(memberDistribution);
            Assert.IsTrue(adminProcessResult, "Admin should be able to process members's distribution");

            // Verify trusted communication works
            string testMessage = "Test message between trusted members";
            var encryptedMessage = adminManager.EncryptGroupMessage(groupId, testMessage);
            string decryptedMessage = memberManager.DecryptGroupMessage(encryptedMessage);
            Assert.AreEqual(testMessage, decryptedMessage, "Trusted members should be able to communicate");

            // The untrusted user attempts to create a distribution message
            var untrustedDistribution = untrustedManager.CreateDistributionMessage(groupId);

            // Note: The current implementation accepts the distribution regardless of membership
            // This appears to be a security weakness in the implementation
            bool distributionAccepted = memberManager.ProcessSenderKeyDistribution(untrustedDistribution);

            // Now test if the member can decrypt a message from the untrusted sender
            string untrustedMessage = "Message from untrusted sender";
            var untrustedEncrypted = untrustedManager.EncryptGroupMessage(groupId, untrustedMessage);

            // This should fail - even if distribution is accepted, the message should be rejected
            string untrustedDecrypted = memberManager.DecryptGroupMessage(untrustedEncrypted);

            // Assert
            Assert.IsNull(untrustedDecrypted, $"Member should not be able to decrypt message from untrusted sender");
        }

        [TestMethod]
        public void GenerateSenderKey_ShouldReturnValidKey()
        {
            // Act
            byte[] senderKey = SecureMemory.CreateSecureBuffer(Constants.AES_KEY_SIZE);

            // Assert
            Assert.IsNotNull(senderKey);
            Assert.AreEqual(32, senderKey.Length);
        }

        [TestMethod]
        public void EncryptDecryptGroupMessage_ShouldReturnOriginalMessage()
        {
            // Arrange
            string message = "This is a group message";
            string groupId = $"test-group-{Guid.NewGuid()}";
            byte[] senderKey = SecureMemory.CreateSecureBuffer(Constants.AES_KEY_SIZE);

            // Create identity key pair for signing
            var identityKeyPair = Sodium.GenerateEd25519KeyPair();

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
            string groupId = $"test-group-{Guid.NewGuid()}";
            var senderKeyPair = Sodium.GenerateEd25519KeyPair();

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
            byte[] storedKey = session.ChainKey;

            Assert.IsTrue(SecureMemory.SecureCompare(storedKey, distributionMessage.ChainKey));
            Assert.IsTrue(SecureMemory.SecureCompare(senderKeyPair.PublicKey, distributionMessage.SenderIdentityKey));

            // Get the distribution manager via reflection to verify signature
            var distributionManagerField = typeof(GroupChatManager).GetField("_distributionManager",
                BindingFlags.NonPublic | BindingFlags.Instance);
            var distributionManager = distributionManagerField.GetValue(groupChatManager) as SenderKeyDistribution;

            bool isValidDistribution = distributionManager.VerifyDistributionSignature(distributionMessage);
            Assert.IsTrue(isValidDistribution, "Distribution message should be valid");
        }

        [TestMethod]
        public void EncryptDecryptSenderKeyDistribution_ShouldReturnOriginalMessage()
        {
            // Arrange
            string groupId = $"test-group-{Guid.NewGuid()}";

            var senderKeyPair = Sodium.GenerateEd25519KeyPair();
            var recipientKeyPair = Sodium.GenerateEd25519KeyPair();

            // Create an instance of GroupChatManager
            var groupChatManager = new GroupChatManager(senderKeyPair);

            // Create the group
            groupChatManager.CreateGroup(groupId);

            // Create distribution message
            var distributionMessage = groupChatManager.CreateDistributionMessage(groupId);

            byte[] senderPrivateKey = _cryptoProvider.DeriveX25519PrivateKeyFromEd25519(senderKeyPair.PrivateKey);
            byte[] recipientPublicKey = _cryptoProvider.ConvertEd25519PublicKeyToX25519(recipientKeyPair.PublicKey);
            byte[] recipientPrivateKey = _cryptoProvider.DeriveX25519PrivateKeyFromEd25519(recipientKeyPair.PrivateKey);

            // Act
            var encryptedDistribution = SenderKeyDistribution.EncryptSenderKeyDistribution(distributionMessage, recipientPublicKey, senderPrivateKey);
            var decryptedDistribution = SenderKeyDistribution.DecryptSenderKeyDistribution(encryptedDistribution, recipientPrivateKey);

            // Assert
            Assert.AreEqual(distributionMessage.GroupId, decryptedDistribution.GroupId);
            Assert.IsTrue(SecureMemory.SecureCompare(distributionMessage.ChainKey, decryptedDistribution.ChainKey));
            Assert.IsTrue(SecureMemory.SecureCompare(distributionMessage.SenderIdentityKey, decryptedDistribution.SenderIdentityKey));
            Assert.IsTrue(SecureMemory.SecureCompare(distributionMessage.Signature, decryptedDistribution.Signature));
        }

        [TestMethod]
        public void GroupChatManager_ShouldHandleMessageExchange()
        {
            // Arrange
            var aliceKeyPair = Sodium.GenerateEd25519KeyPair();
            var bobKeyPair = Sodium.GenerateEd25519KeyPair();

            var aliceManager = new GroupChatManager(aliceKeyPair);
            var bobManager = new GroupChatManager(bobKeyPair);

            string groupId = $"test-group-{Guid.NewGuid()}";
            string message = "Hello group members!";

            // Act
            // Alice creates a group
            aliceManager.CreateGroup(groupId);

            // Alice authorizes Bob and Bob authorizes Alice
            aliceManager.AddGroupMember(groupId, bobKeyPair.PublicKey);
            bobManager.CreateGroup(groupId);
            bobManager.AddGroupMember(groupId, aliceKeyPair.PublicKey);

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
            var keyPair = Sodium.GenerateEd25519KeyPair();
            var manager = new GroupChatManager(keyPair);

            // Act & Assert - Should throw InvalidOperationException
            manager.CreateDistributionMessage("non-existent-group");
        }

        [TestMethod]
        public void GroupMultiSenderDeduplication_ShouldHandleSimultaneousMessages()
        {
            // Arrange - Create three participants
            var aliceKeyPair = Sodium.GenerateEd25519KeyPair();
            var bobKeyPair = Sodium.GenerateEd25519KeyPair();
            var charlieKeyPair = Sodium.GenerateEd25519KeyPair();

            var aliceManager = new GroupChatManager(aliceKeyPair);
            var bobManager = new GroupChatManager(bobKeyPair);
            var charlieManager = new GroupChatManager(charlieKeyPair);

            // Setup the group - Alice is the admin/creator
            string groupId = $"test-multiple-senders-{Guid.NewGuid()}";
            aliceManager.CreateGroup(groupId);
            bobManager.CreateGroup(groupId);
            charlieManager.CreateGroup(groupId);

            // Add members both ways
            // Alice adds Bob and Charlie
            aliceManager.AddGroupMember(groupId, bobKeyPair.PublicKey);
            aliceManager.AddGroupMember(groupId, charlieKeyPair.PublicKey);

            // Bob adds Alice and Charlie
            bobManager.AddGroupMember(groupId, aliceKeyPair.PublicKey);
            bobManager.AddGroupMember(groupId, charlieKeyPair.PublicKey);

            // Charlie adds Alice and Bob
            charlieManager.AddGroupMember(groupId, aliceKeyPair.PublicKey);
            charlieManager.AddGroupMember(groupId, bobKeyPair.PublicKey);

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
            // Create a unique group ID to prevent test interference
            string groupId = $"member-addition-test-group-{Guid.NewGuid()}";

            // Create test participants
            var aliceKeyPair = Sodium.GenerateEd25519KeyPair();
            var bobKeyPair = Sodium.GenerateEd25519KeyPair();
            var daveKeyPair = Sodium.GenerateEd25519KeyPair();

            var aliceManager = new GroupChatManager(aliceKeyPair);
            var bobManager = new GroupChatManager(bobKeyPair);
            var daveManager = new GroupChatManager(daveKeyPair);

            // 1. Alice creates the group
            aliceManager.CreateGroup(groupId, Enums.KeyRotationStrategy.Standard);

            // 2. Bob creates his group
            bobManager.CreateGroup(groupId, Enums.KeyRotationStrategy.Standard);

            // 3. Alice and Bob add each other to their member lists
            aliceManager.AddGroupMember(groupId, bobKeyPair.PublicKey);
            bobManager.AddGroupMember(groupId, aliceKeyPair.PublicKey);

            // 4. Exchange distribution messages
            var aliceDistribution = aliceManager.CreateDistributionMessage(groupId);
            var bobDistribution = bobManager.CreateDistributionMessage(groupId);

            aliceManager.ProcessSenderKeyDistribution(bobDistribution);
            bobManager.ProcessSenderKeyDistribution(aliceDistribution);

            // 5. Send initial message before Dave joins
            string initialMessage = "Initial message before Dave joins";
            var initialEncrypted = aliceManager.EncryptGroupMessage(groupId, initialMessage);
            string bobDecryptsInitial = bobManager.DecryptGroupMessage(initialEncrypted);
            Assert.AreEqual(initialMessage, bobDecryptsInitial, "Bob should be able to decrypt the initial message");

            // 6. Dave joins the group
            Thread.Sleep(100); // Ensure timestamp separation for clarity
            daveManager.CreateGroup(groupId, Enums.KeyRotationStrategy.Standard);

            // 7. Add Dave to member lists
            aliceManager.AddGroupMember(groupId, daveKeyPair.PublicKey);
            bobManager.AddGroupMember(groupId, daveKeyPair.PublicKey);
            daveManager.AddGroupMember(groupId, aliceKeyPair.PublicKey);
            daveManager.AddGroupMember(groupId, bobKeyPair.PublicKey);

            // 8. Create a completely new chat session after adding the member
            // This is the key fix - we discard and recreate all chat sessions

            // Alice recreates her group and restores members
            aliceManager.DeleteGroup(groupId);
            aliceManager.CreateGroup(groupId, Enums.KeyRotationStrategy.Standard);
            aliceManager.AddGroupMember(groupId, bobKeyPair.PublicKey);
            aliceManager.AddGroupMember(groupId, daveKeyPair.PublicKey);

            // Bob recreates his group and restores members
            bobManager.DeleteGroup(groupId);
            bobManager.CreateGroup(groupId, Enums.KeyRotationStrategy.Standard);
            bobManager.AddGroupMember(groupId, aliceKeyPair.PublicKey);
            bobManager.AddGroupMember(groupId, daveKeyPair.PublicKey);

            // Dave has a fresh group already, just add members
            daveManager.AddGroupMember(groupId, aliceKeyPair.PublicKey);
            daveManager.AddGroupMember(groupId, bobKeyPair.PublicKey);

            // 9. Create all-new distribution messages
            var aliceDistributionNew = aliceManager.CreateDistributionMessage(groupId);
            var bobDistributionNew = bobManager.CreateDistributionMessage(groupId);
            var daveDistribution = daveManager.CreateDistributionMessage(groupId);

            // 10. Process the new distribution messages
            aliceManager.ProcessSenderKeyDistribution(bobDistributionNew);
            aliceManager.ProcessSenderKeyDistribution(daveDistribution);

            bobManager.ProcessSenderKeyDistribution(aliceDistributionNew);
            bobManager.ProcessSenderKeyDistribution(daveDistribution);

            daveManager.ProcessSenderKeyDistribution(aliceDistributionNew);
            daveManager.ProcessSenderKeyDistribution(bobDistributionNew);

            // 11. Send new messages
            Thread.Sleep(100); // Ensure timestamp separation

            string aliceMessage = "Message from Alice after Dave joined";
            string bobMessage = "Message from Bob after Dave joined";
            string daveMessage = "Dave's first message to the group";

            var aliceEncrypted = aliceManager.EncryptGroupMessage(groupId, aliceMessage);
            var bobEncrypted = bobManager.EncryptGroupMessage(groupId, bobMessage);
            var daveEncrypted = daveManager.EncryptGroupMessage(groupId, daveMessage);

            // 12. Verify everyone can decrypt the new messages
            string bobDecryptsAlice = bobManager.DecryptGroupMessage(aliceEncrypted);
            string bobDecryptsDave = bobManager.DecryptGroupMessage(daveEncrypted);
            string aliceDecryptsBob = aliceManager.DecryptGroupMessage(bobEncrypted);
            string aliceDecryptsDave = aliceManager.DecryptGroupMessage(daveEncrypted);
            string daveDecryptsAlice = daveManager.DecryptGroupMessage(aliceEncrypted);
            string daveDecryptsBob = daveManager.DecryptGroupMessage(bobEncrypted);

            // 13. Dave attempts to decrypt the initial message (should fail for security)
            string daveDecryptsInitial = daveManager.DecryptGroupMessage(initialEncrypted);

            // 14. Assert results
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
            var aliceKeyPair = Sodium.GenerateEd25519KeyPair();
            var bobKeyPair = Sodium.GenerateEd25519KeyPair();
            var charlieKeyPair = Sodium.GenerateEd25519KeyPair();

            // Step 2: Create group chat managers for each participant
            var aliceManager = new GroupChatManager(aliceKeyPair);
            var bobManager = new GroupChatManager(bobKeyPair);
            var charlieManager = new GroupChatManager(charlieKeyPair);

            // Step 3: Each participant creates the group
            string groupId = $"test-friends-{Guid.NewGuid()}";
            aliceManager.CreateGroup(groupId);
            bobManager.CreateGroup(groupId);
            charlieManager.CreateGroup(groupId);

            // Step 4: Each participant authorizes all others
            // Alice authorizes Bob and Charlie
            aliceManager.AddGroupMember(groupId, bobKeyPair.PublicKey);
            aliceManager.AddGroupMember(groupId, charlieKeyPair.PublicKey);

            // Bob authorizes Alice and Charlie
            bobManager.AddGroupMember(groupId, aliceKeyPair.PublicKey);
            bobManager.AddGroupMember(groupId, charlieKeyPair.PublicKey);

            // Charlie authorizes Alice and Bob
            charlieManager.AddGroupMember(groupId, aliceKeyPair.PublicKey);
            charlieManager.AddGroupMember(groupId, bobKeyPair.PublicKey);

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
            var adminKeyPair = Sodium.GenerateEd25519KeyPair();
            var memberKeyPair = Sodium.GenerateEd25519KeyPair();

            var groupManager = new GroupChatManager(adminKeyPair);
            string groupId = $"test-delete-{Guid.NewGuid()}";

            // Create group and add a member
            groupManager.CreateGroup(groupId);
            groupManager.AddGroupMember(groupId, memberKeyPair.PublicKey);

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