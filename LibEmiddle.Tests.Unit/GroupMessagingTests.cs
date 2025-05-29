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
        private ICryptoProvider _cryptoProvider;
        private KeyPair _defaultKeyPair;

        [TestInitialize]
        public void Setup()
        {
            _cryptoProvider = new CryptoProvider();
            // Generate a default key pair for tests that don't specify identity
            _defaultKeyPair = _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519).GetAwaiter().GetResult();
        }

        [TestMethod]
        public async Task AddGroupMember_ShouldAddMemberToAuthorizedList()
        {
            // Arrange
            var adminKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var memberKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var groupManager = new GroupChatManager(_cryptoProvider, adminKeyPair);
            string groupId = $"test-authorization-{Guid.NewGuid()}";
            string groupName = "Test Authorization Group";

            // Create group
            var session = await groupManager.CreateGroupAsync(groupId, groupName);

            // Act
            bool result = await session.AddMemberAsync(memberKeyPair.PublicKey);

            // Get the member manager directly from the session
            bool isMember = await Task.Run(() => {
                var memberManager = typeof(GroupSession)
                    .GetField("_memberManager", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)
                    .GetValue(session) as GroupMemberManager;

                return memberManager.IsMember(groupId, memberKeyPair.PublicKey);
            });

            // Assert
            Assert.IsTrue(result);
            Assert.IsTrue(isMember);
        }

        [TestMethod]
        public async Task RemoveGroupMember_ShouldRemoveMemberAndRotateKey()
        {
            // Arrange
            var adminKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var memberKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);

            var groupManager = new GroupChatManager(_cryptoProvider, adminKeyPair);

            string groupId = $"test-revocation-{Guid.NewGuid()}";
            string groupName = "Test Revocation Group";

            // Create the group
            var session = await groupManager.CreateGroupAsync(groupId, groupName);

            // Add member
            await session.AddMemberAsync(memberKeyPair.PublicKey);

            // Get the original key
            byte[] originalKey = session.ChainKey;

            // Act
            bool result = await session.RemoveMemberAsync(memberKeyPair.PublicKey);

            // Get the member manager via reflection
            bool isMember = await Task.Run(() => {
                var memberManager = typeof(GroupSession)
                    .GetField("_memberManager", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)
                    .GetValue(session) as GroupMemberManager;

                return memberManager.IsMember(groupId, memberKeyPair.PublicKey);
            });

            // Get the updated key
            byte[] newKey = session.ChainKey;

            // Assert
            Assert.IsTrue(result);
            Assert.IsFalse(isMember);
            Assert.IsFalse(SecureMemory.SecureCompare(originalKey, newKey)); // Key should have been rotated
        }

        [TestMethod]
        public async Task DecryptGroupMessage_ShouldRejectReplayedMessage()
        {
            // Arrange
            var keyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var groupManager = new GroupChatManager(_cryptoProvider, keyPair);
            string groupId = $"test-replay-protection-{Guid.NewGuid()}";
            string groupName = "Test Replay Protection Group";

            // Create the group
            var session = await groupManager.CreateGroupAsync(groupId, groupName);

            // Create and encrypt a message
            string originalMessage = "Hello, secure group!";
            var encryptedMessage = await session.EncryptMessageAsync(originalMessage);

            // Log details to help diagnose the issue
            Trace.TraceWarning($"Group ID: {groupId}");
            Trace.TraceWarning($"Message ID: {encryptedMessage.MessageId}");
            Trace.TraceWarning($"Sender Identity Key Length: {encryptedMessage.SenderIdentityKey?.Length ?? 0}");
            Trace.TraceWarning($"Ciphertext Length: {encryptedMessage.Ciphertext?.Length ?? 0}");
            Trace.TraceWarning($"Nonce Length: {encryptedMessage.Nonce?.Length ?? 0}");

            // Act & Assert - First decryption with detailed logging
            string firstDecryption = await session.DecryptMessageAsync(encryptedMessage);

            // If firstDecryption is null, log additional details to help diagnose
            if (firstDecryption == null)
            {
                Trace.TraceWarning("First decryption FAILED - returned null");

                // Try direct decryption via the underlying components to isolate the issue
                var messageCrypto = typeof(GroupSession)
                    .GetField("_messageCrypto", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)
                    .GetValue(session) as GroupMessageCrypto;

                var directDecrypt = messageCrypto.DecryptMessage(encryptedMessage, session.ChainKey);
                Trace.TraceWarning($"Direct decryption via GroupMessageCrypto: {(directDecrypt != null ? "SUCCESS" : "FAILED")}");
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

            var adminManager = new GroupChatManager(_cryptoProvider, adminKeyPair);
            var memberManager = new GroupChatManager(_cryptoProvider, memberKeyPair);

            string groupId = $"test-forward-secrecy-{Guid.NewGuid()}";
            string groupName = "Test Forward Secrecy Group";

            // 1. Admin creates the group
            var adminSession = await adminManager.CreateGroupAsync(groupId, groupName);

            // 2. Admin authorizes member
            await adminSession.AddMemberAsync(memberKeyPair.PublicKey);

            // 3. Create and exchange distribution messages
            var adminDistribution = adminSession.CreateDistributionMessage();
            adminDistribution.GroupId = groupId;

            // 4. Member joins group
            var memberSession = await memberManager.JoinGroupAsync(
                adminDistribution,
                KeyRotationStrategy.Standard);

            // Add the admin to member's list
            await memberSession.AddMemberAsync(adminKeyPair.PublicKey);

            // 5. Member processes admin's distribution
            bool memberProcessResult = await memberSession.ActivateAsync();
            Assert.IsTrue(memberProcessResult, "Member should be able to process admin's distribution");

            // 6. Test communication before revocation
            string message1 = "Message before revocation";
            var encrypted1 = await adminSession.EncryptMessageAsync(message1);
            string decrypted1 = await memberSession.DecryptMessageAsync(encrypted1);

            // 7. Now revoke member
            await adminSession.RemoveMemberAsync(memberKeyPair.PublicKey);

            // 8. IMPORTANT: Create a new member manager to simulate restarting the app
            // This ensures we're testing real forward secrecy where membership is enforced
            // on each message, not just based on in-memory state
            var memberManager2 = new GroupChatManager(_cryptoProvider, memberKeyPair);
            var memberSession2 = await memberManager2.JoinGroupAsync(adminDistribution,
                KeyRotationStrategy.Standard); // Try to join the group again

            await memberSession2.AddMemberAsync(adminKeyPair.PublicKey);

            // 9. Send a new message after revocation
            string message2 = "Message after revocation";
            var encrypted2 = await adminSession.EncryptMessageAsync(message2);

            // 10. Act - member tries to decrypt post-revocation message with fresh manager
            string decrypted2 = await memberSession2.DecryptMessageAsync(encrypted2);

            // Assert
            Assert.IsNotNull(decrypted1);
            Assert.AreEqual(message1, decrypted1);
            Assert.IsNull(decrypted2); // Should not be able to decrypt after revocation
        }

        [TestMethod]
        public async Task ProcessSenderKeyDistribution_ShouldRejectMessagesFromUntrustedSenders()
        {
            // Arrange
            var adminKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var memberKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var untrustedKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);

            var adminManager = new GroupChatManager(_cryptoProvider, adminKeyPair);
            var memberManager = new GroupChatManager(_cryptoProvider, memberKeyPair);
            var untrustedManager = new GroupChatManager(_cryptoProvider, untrustedKeyPair);

            string groupId = $"test-untrusted-rejection-{Guid.NewGuid()}";
            string groupName = "Test Untrusted Rejection Group";

            // Create groups for all participants
            var adminSession = await adminManager.CreateGroupAsync(groupId, groupName);
            var memberSession = await memberManager.CreateGroupAsync(groupId, groupName);
            var untrustedSession = await untrustedManager.CreateGroupAsync(groupId, groupName);

            // Add trusted members to each other's groups, but NOT the untrusted user
            await adminSession.AddMemberAsync(memberKeyPair.PublicKey);
            await memberSession.AddMemberAsync(adminKeyPair.PublicKey);

            // Exchange distribution messages between trusted participants
            var adminDistribution = adminSession.CreateDistributionMessage();
            adminDistribution.GroupId = groupId;
           
            // Member joins the group
            await memberManager.JoinGroupAsync(adminDistribution);

            // Member processes admin's distribution
            bool memberProcessResult = memberSession.ProcessDistributionMessage(adminDistribution);
            Assert.IsTrue(memberProcessResult, "Member should be able to process admin's distribution");

            var memberDistribution = memberSession.CreateDistributionMessage();

            // Admin processes members's distribution
            bool adminProcessResult = adminSession.ProcessDistributionMessage(memberDistribution);
            Assert.IsTrue(adminProcessResult, "Admin should be able to process members's distribution");

            // Verify trusted communication works
            string testMessage = "Test message between trusted members";
            var encryptedMessage = await adminSession.EncryptMessageAsync(testMessage);
            string decryptedMessage = await memberSession.DecryptMessageAsync(encryptedMessage);
            Assert.AreEqual(testMessage, decryptedMessage, "Trusted members should be able to communicate");

            // The untrusted user attempts to create a distribution message
            var untrustedDistribution = untrustedSession.CreateDistributionMessage();

            // The member attempts to process the distribution message from the untrusted user
            // Note: The security validator should verify that the sender is a member of the group
            bool distributionAccepted = memberSession.ProcessDistributionMessage(untrustedDistribution);

            // Now test if the member can decrypt a message from the untrusted sender
            string untrustedMessage = "Message from untrusted sender";
            var untrustedEncrypted = await untrustedSession.EncryptMessageAsync(untrustedMessage);

            // This should fail - even if distribution is accepted, the message should be rejected
            string untrustedDecrypted = await memberSession.DecryptMessageAsync(untrustedEncrypted);

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
        public async Task EncryptDecryptGroupMessage_ShouldReturnOriginalMessage()
        {
            // Arrange
            string message = "This is a group message";
            string groupId = $"test-group-{Guid.NewGuid()}";

            // Create identity key pair for signing
            var identityKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);

            // Create an instance of GroupMessageCrypto
            var messageCrypto = new GroupMessageCrypto(_cryptoProvider);
            var keyManager = new GroupKeyManager(_cryptoProvider);

            // Initialize sender state with new chain key
            byte[] initialChainKey = keyManager.GenerateInitialChainKey();
            keyManager.InitializeSenderState(groupId, initialChainKey);

            // Get message key and iteration
            var (messageKey, iteration) = keyManager.GetSenderMessageKey(groupId);

            // Get last rotation timestamp
            long rotationTimestamp = keyManager.GetLastRotationTimestamp(groupId);

            // Act
            var encryptedMessage = messageCrypto.EncryptMessage(groupId, message, messageKey, identityKeyPair, rotationTimestamp);
            var decryptedMessage = messageCrypto.DecryptMessage(encryptedMessage, messageKey);

            // Assert
            Assert.AreEqual(message, decryptedMessage);
        }

        [TestMethod]
        public async Task CreateDistributionMessage_ShouldReturnValidMessage()
        {
            // Arrange
            string groupId = $"test-group-{Guid.NewGuid()}";
            string groupName = "Test Group";
            string message = "This is my test message";
            var senderKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);

            // Create an instance of GroupChatManager
            var groupChatManager = new GroupChatManager(_cryptoProvider, senderKeyPair);

            // Create the group
            var session = await groupChatManager.CreateGroupAsync(groupId, groupName);

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
        public async Task GroupChatManager_ShouldHandleMessageExchange()
        {
            // Arrange
            var aliceKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var bobKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);

            var aliceManager = new GroupChatManager(_cryptoProvider, aliceKeyPair);
            var bobManager = new GroupChatManager(_cryptoProvider, bobKeyPair);

            string groupId = $"test-group-{Guid.NewGuid()}";
            string groupName = "Test Message Exchange Group";
            string message = "Hello group members!";

            // Act
            // Alice creates a group
            var aliceSession = await aliceManager.CreateGroupAsync(groupId, groupName);

            // Alice authorizes Bob
            await aliceSession.AddMemberAsync(bobKeyPair.PublicKey);

            // Bob creates/joins group
            var bobSession = await bobManager.CreateGroupAsync(groupId, groupName);

            // Bob authorizes Alice
            await bobSession.AddMemberAsync(aliceKeyPair.PublicKey);

            // Alice creates a distribution message
            var distributionMessage = aliceSession.CreateDistributionMessage();

            // Bob processes the distribution message
            bool processingResult = bobSession.ProcessDistributionMessage(distributionMessage);

            // Alice sends a message
            var encryptedMessage = await aliceSession.EncryptMessageAsync(message);

            // Bob decrypts the message
            string decryptedMessage = await bobSession.DecryptMessageAsync(encryptedMessage);

            // Assert
            Assert.IsTrue(processingResult);
            Assert.AreEqual(message, decryptedMessage);
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidOperationException))]
        public async Task GroupChatManager_CreateDistribution_WithNonExistentGroup_ShouldThrowException()
        {
            // Arrange
            var keyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var groupManager = new GroupChatManager(_cryptoProvider, keyPair);

            // Create a non-existent session directly - this will throw because we don't create the group first
            var badOptions = new GroupSessionOptions { GroupId = "non-existent-group" };

            // Using reflection to create a session directly without proper initialization
            var constructor = typeof(GroupSession).GetConstructor(
                System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Public,
                null,
                new Type[] {
                    typeof(string),
                    typeof(KeyPair),
                    typeof(GroupKeyManager),
                    typeof(GroupMemberManager),
                    typeof(GroupMessageCrypto),
                    typeof(SenderKeyDistribution)
                },
                null);

            // This will create an invalid session that will throw when used
            var invalidSession = constructor.Invoke(new object[] {
                "non-existent-group",
                keyPair,
                new GroupKeyManager(_cryptoProvider),
                new GroupMemberManager(),
                new GroupMessageCrypto(_cryptoProvider),
                new SenderKeyDistribution(_cryptoProvider, new GroupKeyManager(_cryptoProvider))
            }) as GroupSession;

            // Act & Assert - Should throw InvalidOperationException
            invalidSession.CreateDistributionMessage(); // This should throw
        }

        [TestMethod]
        public async Task GroupMultiSenderDeduplication_ShouldHandleSimultaneousMessages()
        {
            // Arrange - Create three participants
            var aliceKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var bobKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var charlieKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);

            var aliceManager = new GroupChatManager(_cryptoProvider, aliceKeyPair);
            var bobManager = new GroupChatManager(_cryptoProvider, bobKeyPair);
            var charlieManager = new GroupChatManager(_cryptoProvider, charlieKeyPair);

            // Setup the group - Alice is the admin/creator
            string groupId = $"test-multiple-senders-{Guid.NewGuid()}";
            string groupName = "Test Multiple Senders Group";

            var aliceSession = await aliceManager.CreateGroupAsync(groupId, groupName);
            var bobSession = await bobManager.CreateGroupAsync(groupId, groupName);
            var charlieSession = await charlieManager.CreateGroupAsync(groupId, groupName);

            // Add members both ways
            // Alice adds Bob and Charlie
            await aliceSession.AddMemberAsync(bobKeyPair.PublicKey);
            await aliceSession.AddMemberAsync(charlieKeyPair.PublicKey);

            // Bob adds Alice and Charlie
            await bobSession.AddMemberAsync(aliceKeyPair.PublicKey);
            await bobSession.AddMemberAsync(charlieKeyPair.PublicKey);

            // Charlie adds Alice and Bob
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
            string groupName = "Member Addition Test Group";

            // Create test participants
            var aliceKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var bobKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var daveKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);

            var aliceManager = new GroupChatManager(_cryptoProvider, aliceKeyPair);
            var bobManager = new GroupChatManager(_cryptoProvider, bobKeyPair);
            var daveManager = new GroupChatManager(_cryptoProvider, daveKeyPair);

            // 1. Alice creates the group
            var aliceSession = await aliceManager.CreateGroupAsync(groupId, groupName, null,
                new GroupSessionOptions { RotationStrategy = KeyRotationStrategy.Standard });

            // 2. Bob creates his group
            var bobSession = await bobManager.CreateGroupAsync(groupId, groupName, null,
                new GroupSessionOptions { RotationStrategy = KeyRotationStrategy.Standard });

            // 3. Alice and Bob add each other to their member lists
            await aliceSession.AddMemberAsync(bobKeyPair.PublicKey);
            await bobSession.AddMemberAsync(aliceKeyPair.PublicKey);

            // 4. Exchange distribution messages
            var aliceDistribution = aliceSession.CreateDistributionMessage();
            var bobDistribution = bobSession.CreateDistributionMessage();

            aliceSession.ProcessDistributionMessage(bobDistribution);
            bobSession.ProcessDistributionMessage(aliceDistribution);

            // 5. Send initial message before Dave joins
            string initialMessage = "Initial message before Dave joins";
            var initialEncrypted = await aliceSession.EncryptMessageAsync(initialMessage);
            string bobDecryptsInitial = await bobSession.DecryptMessageAsync(initialEncrypted);
            Assert.AreEqual(initialMessage, bobDecryptsInitial, "Bob should be able to decrypt the initial message");

            // 6. Dave joins the group
            Thread.Sleep(100); // Ensure timestamp separation for clarity
            var daveSession = await daveManager.CreateGroupAsync(groupId, groupName, null,
                new GroupSessionOptions { RotationStrategy = KeyRotationStrategy.Standard });

            // 7. Add Dave to member lists
            await aliceSession.AddMemberAsync(daveKeyPair.PublicKey);
            await bobSession.AddMemberAsync(daveKeyPair.PublicKey);
            await daveSession.AddMemberAsync(aliceKeyPair.PublicKey);
            await daveSession.AddMemberAsync(bobKeyPair.PublicKey);

            // 8. Create a completely new chat session after adding the member
            // This is the key fix - we need to rotate keys after membership changes
            await aliceSession.RotateKeyAsync();
            await bobSession.RotateKeyAsync();

            // 9. Create all-new distribution messages
            var aliceDistributionNew = aliceSession.CreateDistributionMessage();
            var bobDistributionNew = bobSession.CreateDistributionMessage();
            var daveDistribution = daveSession.CreateDistributionMessage();

            // 10. Process the new distribution messages
            aliceSession.ProcessDistributionMessage(bobDistributionNew);
            aliceSession.ProcessDistributionMessage(daveDistribution);

            bobSession.ProcessDistributionMessage(aliceDistributionNew);
            bobSession.ProcessDistributionMessage(daveDistribution);

            daveSession.ProcessDistributionMessage(aliceDistributionNew);
            daveSession.ProcessDistributionMessage(bobDistributionNew);

            // 11. Send new messages
            Thread.Sleep(100); // Ensure timestamp separation

            string aliceMessage = "Message from Alice after Dave joined";
            string bobMessage = "Message from Bob after Dave joined";
            string daveMessage = "Dave's first message to the group";

            var aliceEncrypted = await aliceSession.EncryptMessageAsync(aliceMessage);
            var bobEncrypted = await bobSession.EncryptMessageAsync(bobMessage);
            var daveEncrypted = await daveSession.EncryptMessageAsync(daveMessage);

            // 12. Verify everyone can decrypt the new messages
            string bobDecryptsAlice = await bobSession.DecryptMessageAsync(aliceEncrypted);
            string bobDecryptsDave = await bobSession.DecryptMessageAsync(daveEncrypted);
            string aliceDecryptsBob = await aliceSession.DecryptMessageAsync(bobEncrypted);
            string aliceDecryptsDave = await aliceSession.DecryptMessageAsync(daveEncrypted);
            string daveDecryptsAlice = await daveSession.DecryptMessageAsync(aliceEncrypted);
            string daveDecryptsBob = await daveSession.DecryptMessageAsync(bobEncrypted);

            // 13. Dave attempts to decrypt the initial message (should fail for security)
            string daveDecryptsInitial = await daveSession.DecryptMessageAsync(initialEncrypted);

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
        public async Task FullGroupMessageFlow_ShouldWorkEndToEnd()
        {
            // This test simulates a group chat between Alice, Bob, and Charlie

            // Step 1: Generate identity keys for the participants
            var aliceKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var bobKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var charlieKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);

            // Step 2: Create group chat managers for each participant
            var aliceManager = new GroupChatManager(_cryptoProvider, aliceKeyPair);
            var bobManager = new GroupChatManager(_cryptoProvider, bobKeyPair);
            var charlieManager = new GroupChatManager(_cryptoProvider, charlieKeyPair);

            // Step 3: Each participant creates the group
            string groupId = $"test-friends-{Guid.NewGuid()}";
            string groupName = "Test Friends Group";

            var aliceSession = await aliceManager.CreateGroupAsync(groupId, groupName);
            var bobSession = await bobManager.CreateGroupAsync(groupId, groupName);
            var charlieSession = await charlieManager.CreateGroupAsync(groupId, groupName);

            // Step 4: Each participant authorizes all others
            // Alice authorizes Bob and Charlie
            await aliceSession.AddMemberAsync(bobKeyPair.PublicKey);
            await aliceSession.AddMemberAsync(charlieKeyPair.PublicKey);

            // Bob authorizes Alice and Charlie
            await bobSession.AddMemberAsync(aliceKeyPair.PublicKey);
            await bobSession.AddMemberAsync(charlieKeyPair.PublicKey);

            // Charlie authorizes Alice and Bob
            await charlieSession.AddMemberAsync(aliceKeyPair.PublicKey);
            await charlieSession.AddMemberAsync(bobKeyPair.PublicKey);

            // Step 5: Each participant creates their distribution message
            var aliceDistribution = aliceSession.CreateDistributionMessage();
            var bobDistribution = bobSession.CreateDistributionMessage();
            var charlieDistribution = charlieSession.CreateDistributionMessage();

            // Step 6: Everyone processes everyone else's distribution
            // Bob and Charlie process Alice's distribution
            bool bobProcessAliceResult = bobSession.ProcessDistributionMessage(aliceDistribution);
            bool charlieProcessAliceResult = charlieSession.ProcessDistributionMessage(aliceDistribution);

            // Alice and Charlie process Bob's distribution
            bool aliceProcessBobResult = aliceSession.ProcessDistributionMessage(bobDistribution);
            bool charlieProcessBobResult = charlieSession.ProcessDistributionMessage(bobDistribution);

            // Alice and Bob process Charlie's distribution
            bool aliceProcessCharlieResult = aliceSession.ProcessDistributionMessage(charlieDistribution);
            bool bobProcessCharlieResult = bobSession.ProcessDistributionMessage(charlieDistribution);

            // Step 7: Alice sends a message to the group
            string aliceMessage = "Hello everyone, this is Alice!";
            var aliceEncryptedMessage = await aliceSession.EncryptMessageAsync(aliceMessage);

            // Bob and Charlie decrypt Alice's message
            string bobDecryptedAliceMessage = await bobSession.DecryptMessageAsync(aliceEncryptedMessage);
            string charlieDecryptedAliceMessage = await charlieSession.DecryptMessageAsync(aliceEncryptedMessage);

            // Step 8: Bob replies to the group
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
        public async Task DeleteGroup_ShouldWorkCorrectly()
        {
            // Arrange
            var adminKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var memberKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);

            var groupManager = new GroupChatManager(_cryptoProvider, adminKeyPair);
            string groupId = $"test-delete-{Guid.NewGuid()}";
            string groupName = "Test Delete Group";

            // Create group and add a member
            var session = await groupManager.CreateGroupAsync(groupId, groupName);
            await session.AddMemberAsync(memberKeyPair.PublicKey);

            // Get the GroupChatManager instance to verify group exists
            bool groupExistsBefore = await Task.Run(() => {
                try
                {
                    // Attempt to get the session (will throw if not exists)
                    groupManager.GetGroupAsync(groupId).GetAwaiter().GetResult();
                    return true;
                }
                catch
                {
                    return false;
                }
            });

            // Act
            bool result = await groupManager.LeaveGroupAsync(groupId);

            // Verify the group no longer exists
            bool groupExistsAfter = await Task.Run(() => {
                try
                {
                    // Attempt to get the session (will throw if not exists)
                    groupManager.GetGroupAsync(groupId).GetAwaiter().GetResult();
                    return true;
                }
                catch
                {
                    return false;
                }
            });

            // Assert
            Assert.IsTrue(groupExistsBefore, "Group should exist before deletion");
            Assert.IsTrue(result, "Delete operation should return true");
            Assert.IsFalse(groupExistsAfter, "Group should not exist after deletion");
        }
    }
}