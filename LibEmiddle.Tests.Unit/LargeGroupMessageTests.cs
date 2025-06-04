using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Reflection;
using System.Threading.Tasks;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;
using LibEmiddle.Messaging.Group;
using LibEmiddle.Core;

namespace LibEmiddle.Tests.Unit
{
    [TestClass]
    public class LargeGroupMessagingTests : IDisposable
    {
        private CryptoProvider _cryptoProvider;

        [TestInitialize]
        public void Setup()
        {
            _cryptoProvider = new CryptoProvider();
        }

        [TestMethod]
        public async Task LargeGroup_TenMembers_ShouldHandleAllMessages()
        {
            // Arrange - Create a group with 10 members
            int memberCount = 10;
            var memberKeyPairs = new List<KeyPair>();
            var groupManagers = new List<GroupChatManager>();

            for (int i = 0; i < memberCount; i++)
            {
                var keyPair = Sodium.GenerateEd25519KeyPair();
                memberKeyPairs.Add(keyPair);
                var manager = new GroupChatManager(keyPair);
                groupManagers.Add(manager);
            }

            string groupId = "large-group-test";

            // Create groups for each member
            for (int i = 0; i < memberCount; i++)
            {
                await groupManagers[i].CreateGroupAsync(
                    groupId,
                    $"Test Group {i}",
                    new List<byte[]>(),  // No initial members - we'll add them explicitly
                    new GroupSessionOptions { GroupId = groupId, RotationStrategy = KeyRotationStrategy.Standard });
            }

            // Each member needs to authorize every other member - bidirectional authorization
            for (int authorizerIdx = 0; authorizerIdx < memberCount; authorizerIdx++)
            {
                var group = await groupManagers[authorizerIdx].GetGroupAsync(groupId);

                for (int targetIdx = 0; targetIdx < memberCount; targetIdx++)
                {
                    if (authorizerIdx != targetIdx) // Don't need to authorize yourself
                    {
                        bool authorizationResult = await group.AddMemberAsync(memberKeyPairs[targetIdx].PublicKey);

                        Assert.IsTrue(authorizationResult,
                            $"Member {authorizerIdx} should authorize member {targetIdx}");
                    }
                }
            }

            // Create distribution messages for all members
            var distributionMessages = new List<SenderKeyDistributionMessage>();
            for (int i = 0; i < memberCount; i++)
            {
                var group = await groupManagers[i].GetGroupAsync(groupId);
                distributionMessages.Add(group.CreateDistributionMessage());
            }

            // Each member processes all other members' distribution messages
            for (int receiverIdx = 0; receiverIdx < memberCount; receiverIdx++)
            {
                Trace.TraceWarning($"Processing distributions for receiver {receiverIdx}");
                var receiverGroup = await groupManagers[receiverIdx].GetGroupAsync(groupId);

                for (int senderIdx = 0; senderIdx < memberCount; senderIdx++)
                {
                    if (receiverIdx != senderIdx)
                    {
                        bool result = receiverGroup.ProcessDistributionMessage(distributionMessages[senderIdx]);

                        // Debug logging for failed distributions
                        if (!result)
                        {
                            string senderKey = Convert.ToBase64String(memberKeyPairs[senderIdx].PublicKey);
                            Trace.TraceWarning($"Failed to process distribution from sender {senderIdx} with key {senderKey}");

                            // Check authorization status - internal reflection access for debug only in tests
                            FieldInfo memberManagerField = typeof(GroupSession).GetField("_memberManager",
                                BindingFlags.NonPublic | BindingFlags.Instance);
                            if (memberManagerField != null)
                            {
                                var memberManager = memberManagerField.GetValue(receiverGroup) as GroupMemberManager;
                                if (memberManager != null)
                                {
                                    bool isMember = memberManager.IsMember(groupId, memberKeyPairs[senderIdx].PublicKey);

                                    string receiverKey = Convert.ToBase64String(memberKeyPairs[receiverIdx].PublicKey);
                                    string senderBase64Key = Convert.ToBase64String(memberKeyPairs[senderIdx].PublicKey);

                                    Trace.TraceWarning($"Receiver {receiverIdx} key: {receiverKey}");
                                    Trace.TraceWarning($"Sender {senderIdx} key: {senderBase64Key}");
                                    Trace.TraceWarning($"Is sender authorized: {isMember}");
                                }
                            }
                        }

                        Assert.IsTrue(result, $"Member {receiverIdx} should process distribution from member {senderIdx}");
                    }
                }
            }

            // Act - Each member sends a message and everyone else receives it
            var messages = new List<string>();
            var encryptedMessages = new List<EncryptedGroupMessage>();

            for (int senderIdx = 0; senderIdx < memberCount; senderIdx++)
            {
                string message = $"Message {senderIdx} from member {senderIdx}";
                messages.Add(message);

                var senderGroup = await groupManagers[senderIdx].GetGroupAsync(groupId);
                encryptedMessages.Add(await senderGroup.EncryptMessageAsync(message));
            }

            // Check that all members can decrypt all messages
            for (int receiverIdx = 0; receiverIdx < memberCount; receiverIdx++)
            {
                var receiverGroup = await groupManagers[receiverIdx].GetGroupAsync(groupId);

                for (int msgIdx = 0; msgIdx < memberCount; msgIdx++)
                {
                    if (receiverIdx == msgIdx)
                    {
                        // Skip the sender's own message
                        continue;
                    }

                    string decryptedMessage = await receiverGroup.DecryptMessageAsync(encryptedMessages[msgIdx]);
                    Assert.IsNotNull(decryptedMessage, $"Member {receiverIdx} should decrypt message {msgIdx}");
                    Assert.AreEqual(messages[msgIdx], decryptedMessage, $"Decrypted message should match original");
                }
            }

            // Dispose
            for (int i = 0; i < memberCount; i++)
            {
                groupManagers[i].Dispose();
            }
        }

        [TestMethod]
        public async Task GroupMember_RemovalSimulation_ShouldNotReceiveNewMessages()
        {
            // Arrange - Create a group with some members
            var aliceKeyPair = Sodium.GenerateEd25519KeyPair();
            var bobKeyPair = Sodium.GenerateEd25519KeyPair();
            var charlieKeyPair = Sodium.GenerateEd25519KeyPair();
            var daveKeyPair = Sodium.GenerateEd25519KeyPair();

            var aliceManager = new GroupChatManager(aliceKeyPair);
            var bobManager = new GroupChatManager(bobKeyPair);
            var charlieManager = new GroupChatManager(charlieKeyPair);
            var daveManager = new GroupChatManager(daveKeyPair);

            string groupId = "member-removal-test";

            // Alice creates the group as admin
            var aliceGroup = await aliceManager.CreateGroupAsync(
                groupId,
                "Member Removal Test",
                new List<byte[]>(),
                new GroupSessionOptions { GroupId = groupId, CreatorIsAdmin = true });

            // Everyone creates their local view of the group
            var bobGroup = await bobManager.CreateGroupAsync(
                groupId, "Bob's View", null,
                new GroupSessionOptions { GroupId = groupId });

            var charlieGroup = await charlieManager.CreateGroupAsync(
                groupId, "Charlie's View", null,
                new GroupSessionOptions { GroupId = groupId });

            var daveGroup = await daveManager.CreateGroupAsync(
                groupId, "Dave's View", null,
                new GroupSessionOptions { GroupId = groupId });

            // All members add each other for bidirectional communication
            await aliceGroup.AddMemberAsync(bobKeyPair.PublicKey);
            await aliceGroup.AddMemberAsync(charlieKeyPair.PublicKey);
            await aliceGroup.AddMemberAsync(daveKeyPair.PublicKey);

            await bobGroup.AddMemberAsync(aliceKeyPair.PublicKey);
            await bobGroup.AddMemberAsync(charlieKeyPair.PublicKey);
            await bobGroup.AddMemberAsync(daveKeyPair.PublicKey);

            await charlieGroup.AddMemberAsync(aliceKeyPair.PublicKey);
            await charlieGroup.AddMemberAsync(bobKeyPair.PublicKey);
            await charlieGroup.AddMemberAsync(daveKeyPair.PublicKey);

            await daveGroup.AddMemberAsync(aliceKeyPair.PublicKey);
            await daveGroup.AddMemberAsync(bobKeyPair.PublicKey);
            await daveGroup.AddMemberAsync(charlieKeyPair.PublicKey);

            // Exchange initial distribution messages
            var aliceDistribution = aliceGroup.CreateDistributionMessage();
            var bobDistribution = bobGroup.CreateDistributionMessage();
            var charlieDistribution = charlieGroup.CreateDistributionMessage();
            var daveDistribution = daveGroup.CreateDistributionMessage();

            // Everyone processes everyone else's distribution
            aliceGroup.ProcessDistributionMessage(bobDistribution);
            aliceGroup.ProcessDistributionMessage(charlieDistribution);
            aliceGroup.ProcessDistributionMessage(daveDistribution);

            bobGroup.ProcessDistributionMessage(aliceDistribution);
            bobGroup.ProcessDistributionMessage(charlieDistribution);
            bobGroup.ProcessDistributionMessage(daveDistribution);

            charlieGroup.ProcessDistributionMessage(aliceDistribution);
            charlieGroup.ProcessDistributionMessage(bobDistribution);
            charlieGroup.ProcessDistributionMessage(daveDistribution);

            daveGroup.ProcessDistributionMessage(aliceDistribution);
            daveGroup.ProcessDistributionMessage(bobDistribution);
            daveGroup.ProcessDistributionMessage(charlieDistribution);

            // Send initial messages to confirm everyone is in the group
            string initialMessage = "Hello everyone!";
            var aliceInitialMsg = await aliceGroup.EncryptMessageAsync(initialMessage);

            // Verify all members can decrypt
            string bobDecryptedInitial = await bobGroup.DecryptMessageAsync(aliceInitialMsg);
            string charlieDecryptedInitial = await charlieGroup.DecryptMessageAsync(aliceInitialMsg);
            string daveDecryptedInitial = await daveGroup.DecryptMessageAsync(aliceInitialMsg);

            Assert.AreEqual(initialMessage, bobDecryptedInitial);
            Assert.AreEqual(initialMessage, charlieDecryptedInitial);
            Assert.AreEqual(initialMessage, daveDecryptedInitial);

            // Act - Simulate Dave being removed
            // In a real implementation, we would call RemoveMemberAsync which triggers a key rotation
            // For this test, we'll create a new group to simulate the key rotation after removal

            // 1. Create new group (in reality, this would be a key rotation after member removal)
            string newGroupId = "member-removal-test-new";

            // Alice creates new group and adds only Bob and Charlie
            var aliceNewGroup = await aliceManager.CreateGroupAsync(
                newGroupId,
                "New Group Without Dave",
                new List<byte[]>(),
                new GroupSessionOptions { GroupId = newGroupId, CreatorIsAdmin = true });

            // Bob and Charlie create their view of the new group
            var bobNewGroup = await bobManager.CreateGroupAsync(
                newGroupId, "Bob's New View", null,
                new GroupSessionOptions { GroupId = newGroupId });

            var charlieNewGroup = await charlieManager.CreateGroupAsync(
                newGroupId, "Charlie's New View", null,
                new GroupSessionOptions { GroupId = newGroupId });

            // Add members to the new group (without Dave)
            await aliceNewGroup.AddMemberAsync(bobKeyPair.PublicKey);
            await aliceNewGroup.AddMemberAsync(charlieKeyPair.PublicKey);

            await bobNewGroup.AddMemberAsync(aliceKeyPair.PublicKey);
            await bobNewGroup.AddMemberAsync(charlieKeyPair.PublicKey);

            await charlieNewGroup.AddMemberAsync(aliceKeyPair.PublicKey);
            await charlieNewGroup.AddMemberAsync(bobKeyPair.PublicKey);

            // 2. Exchange new distribution messages (without Dave)
            var aliceNewDistribution = aliceNewGroup.CreateDistributionMessage();
            var bobNewDistribution = bobNewGroup.CreateDistributionMessage();
            var charlieNewDistribution = charlieNewGroup.CreateDistributionMessage();

            // 3. Process new distributions (without Dave)
            aliceNewGroup.ProcessDistributionMessage(bobNewDistribution);
            aliceNewGroup.ProcessDistributionMessage(charlieNewDistribution);

            bobNewGroup.ProcessDistributionMessage(aliceNewDistribution);
            bobNewGroup.ProcessDistributionMessage(charlieNewDistribution);

            charlieNewGroup.ProcessDistributionMessage(aliceNewDistribution);
            charlieNewGroup.ProcessDistributionMessage(bobNewDistribution);

            // 4. Send a new message to the new group
            string newMessage = "This is a message Dave shouldn't see";
            var aliceNewMsg = await aliceNewGroup.EncryptMessageAsync(newMessage);

            // 5. Verify Bob and Charlie can decrypt
            string bobDecryptedNew = await bobNewGroup.DecryptMessageAsync(aliceNewMsg);
            string charlieDecryptedNew = await charlieNewGroup.DecryptMessageAsync(aliceNewMsg);

            // 6. Try to have Dave decrypt (even if Dave creates his own group, he won't be authorized by others)
            var daveNewGroup = await daveManager.CreateGroupAsync(
                newGroupId, "Dave's Unauthorized View", null,
                new GroupSessionOptions { GroupId = newGroupId });

            await daveNewGroup.AddMemberAsync(aliceKeyPair.PublicKey);
            // But no one has authorized Dave in the new group

            string daveDecryptedNew = await daveNewGroup.DecryptMessageAsync(aliceNewMsg);

            // Assert
            Assert.AreEqual(newMessage, bobDecryptedNew, "Bob should decrypt the new message");
            Assert.AreEqual(newMessage, charlieDecryptedNew, "Charlie should decrypt the new message");
            Assert.IsNull(daveDecryptedNew, "Dave should not be able to decrypt the new message");

            aliceManager.Dispose();
            bobManager.Dispose();
            charlieManager.Dispose();
            daveManager.Dispose();
        }

        [TestMethod]
        public async Task ConcurrentGroupAccess_ShouldHandleThreadSafely()
        {
            // Arrange - Create a group with multiple members
            var aliceKeyPair = Sodium.GenerateEd25519KeyPair();
            var bobKeyPair = Sodium.GenerateEd25519KeyPair();

            var aliceManager = new GroupChatManager(aliceKeyPair);
            var bobManager = new GroupChatManager(bobKeyPair);

            string groupId = "concurrent-access-test";

            // Both create their local view of the group
            var aliceGroup = await aliceManager.CreateGroupAsync(
                groupId,
                "Alice's Group",
                null,
                new GroupSessionOptions { GroupId = groupId });

            var bobGroup = await bobManager.CreateGroupAsync(
                groupId,
                "Bob's Group",
                null,
                new GroupSessionOptions { GroupId = groupId });

            // Both add each other - this is the key for bidirectional communication
            bool aliceAuthBobResult = await aliceGroup.AddMemberAsync(bobKeyPair.PublicKey);
            Assert.IsTrue(aliceAuthBobResult, "Alice should be able to add Bob");

            bool bobAuthAliceResult = await bobGroup.AddMemberAsync(aliceKeyPair.PublicKey);
            Assert.IsTrue(bobAuthAliceResult, "Bob should be able to add Alice");

            // Exchange distribution messages
            var aliceDistribution = aliceGroup.CreateDistributionMessage();
            var bobDistribution = bobGroup.CreateDistributionMessage();

            // Both process each other's distribution messages
            bool aliceProcessResult = aliceGroup.ProcessDistributionMessage(bobDistribution);
            bool bobProcessResult = bobGroup.ProcessDistributionMessage(aliceDistribution);

            // Verify that both could process each other's distribution
            Assert.IsTrue(aliceProcessResult, "Alice should process Bob's distribution successfully");
            Assert.IsTrue(bobProcessResult, "Bob should process Alice's distribution successfully");

            // Act - Simulate concurrent message sending
            const int messageCount = 20;
            var aliceMessages = new ConcurrentDictionary<int, string>();
            var aliceEncryptedMessages = new ConcurrentDictionary<int, EncryptedGroupMessage>();
            var bobMessages = new ConcurrentDictionary<int, string>();
            var bobEncryptedMessages = new ConcurrentDictionary<int, EncryptedGroupMessage>();

            // Create thread-safe collections for results
            var exceptions = new ConcurrentBag<Exception>();
            var decryptionResults = new ConcurrentDictionary<int, string>();

            // Create the messages in advance
            for (int i = 0; i < messageCount; i++)
            {
                aliceMessages[i] = $"Alice message {i}";
                bobMessages[i] = $"Bob message {i}";
            }

            // Create tasks for Alice sending messages
            var aliceTasks = new List<Task>();
            for (int i = 0; i < messageCount; i++)
            {
                int index = i; // Capture for closure
                var task = Task.Run(async () => {
                    try
                    {
                        aliceEncryptedMessages[index] = await aliceGroup.EncryptMessageAsync(aliceMessages[index]);
                    }
                    catch (Exception ex)
                    {
                        exceptions.Add(ex);
                    }
                });
                aliceTasks.Add(task);
            }

            // Create tasks for Bob sending messages
            var bobTasks = new List<Task>();
            for (int i = 0; i < messageCount; i++)
            {
                int index = i; // Capture for closure
                var task = Task.Run(async () => {
                    try
                    {
                        bobEncryptedMessages[index] = await bobGroup.EncryptMessageAsync(bobMessages[index]);
                    }
                    catch (Exception ex)
                    {
                        exceptions.Add(ex);
                    }
                });
                bobTasks.Add(task);
            }

            // Wait for all encryption tasks to complete
            await Task.WhenAll(aliceTasks);
            await Task.WhenAll(bobTasks);

            // Check for exceptions during encryption
            Assert.AreEqual(0, exceptions.Count, "There should be no exceptions during concurrent encryption");

            // Create tasks for Bob decrypting Alice's messages
            var bobDecryptTasks = new List<Task>();
            for (int i = 0; i < messageCount; i++)
            {
                int index = i; // Capture for closure
                var task = Task.Run(async () => {
                    try
                    {
                        string decrypted = await bobGroup.DecryptMessageAsync(aliceEncryptedMessages[index]);
                        if (decrypted != null)
                        {
                            decryptionResults[index] = decrypted;
                        }
                    }
                    catch (Exception ex)
                    {
                        exceptions.Add(ex);
                    }
                });
                bobDecryptTasks.Add(task);
            }

            // Wait for all decryption tasks to complete
            await Task.WhenAll(bobDecryptTasks);

            // Check for exceptions during decryption
            Assert.AreEqual(0, exceptions.Count, "There should be no exceptions during concurrent decryption");

            // Verify all messages were correctly decrypted
            for (int i = 0; i < messageCount; i++)
            {
                Assert.IsTrue(decryptionResults.ContainsKey(i), $"Result for message {i} should exist");
                Assert.AreEqual(aliceMessages[i], decryptionResults[i], $"Decrypted message {i} should match original");
            }

            bobManager.Dispose();
            aliceManager.Dispose();
        }

        [TestCleanup]
        public void Cleanup()
        {
            // Dispose of resources in reverse order of creation
            _cryptoProvider.Dispose();
        }

        public void Dispose()
        {
            Cleanup();
        }
    }
}