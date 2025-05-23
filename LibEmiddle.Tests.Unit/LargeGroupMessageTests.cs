﻿using System;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Concurrent;
using System.Reflection;
using System.Diagnostics;
using LibEmiddle.API;
using LibEmiddle.Messaging.Group;
using LibEmiddle.Models;

namespace LibEmiddle.Tests.Unit
{
    [TestClass]
    public class LargeGroupMessagingTests
    {
        [TestMethod]
        public void LargeGroup_TenMembers_ShouldHandleAllMessages()
        {
            // Arrange - Create a group with 10 members
            int memberCount = 10;
            var memberKeyPairs = new List<(byte[] publicKey, byte[] privateKey)>();
            var groupManagers = new List<GroupChatManager>();

            for (int i = 0; i < memberCount; i++)
            {
                var keyPair = LibEmiddleClient.GenerateSignatureKeyPair();
                memberKeyPairs.Add(keyPair);
                groupManagers.Add(new GroupChatManager(keyPair));
            }

            string groupId = "large-group-test";

            // All members create their own group
            for (int i = 0; i < memberCount; i++)
            {
                groupManagers[i].CreateGroup(groupId);
            }

            // Each member needs to authorize every other member - bidirectional authorization
            for (int authorizerIdx = 0; authorizerIdx < memberCount; authorizerIdx++)
            {
                for (int targetIdx = 0; targetIdx < memberCount; targetIdx++)
                {
                    if (authorizerIdx != targetIdx) // Don't need to authorize yourself
                    {
                        bool authorizationResult = groupManagers[authorizerIdx].AddGroupMember(
                            groupId,
                            memberKeyPairs[targetIdx].publicKey);

                        Assert.IsTrue(authorizationResult,
                            $"Member {authorizerIdx} should authorize member {targetIdx}");
                    }
                }
            }

            // Create distribution messages for all members
            var distributionMessages = new List<SenderKeyDistributionMessage>();
            for (int i = 0; i < memberCount; i++)
            {
                distributionMessages.Add(groupManagers[i].CreateDistributionMessage(groupId));
            }

            // Each member processes all other members' distribution messages
            for (int receiverIdx = 0; receiverIdx < memberCount; receiverIdx++)
            {
                Trace.TraceWarning($"Processing distributions for receiver {receiverIdx}");
                for (int senderIdx = 0; senderIdx < memberCount; senderIdx++)
                {
                    if (receiverIdx != senderIdx)
                    {
                        bool result = groupManagers[receiverIdx].ProcessSenderKeyDistribution(
                            distributionMessages[senderIdx]);

                        // Debug logging for failed distributions
                        if (!result)
                        {
                            string senderKey = Convert.ToBase64String(memberKeyPairs[senderIdx].publicKey);
                            Trace.TraceWarning($"Failed to process distribution from sender {senderIdx} with key {senderKey}");

                            // Check authorization status using reflection
                            var memberManagerField = typeof(GroupChatManager).GetField("_memberManager",
                                BindingFlags.NonPublic | BindingFlags.Instance);
                            var memberManager = memberManagerField.GetValue(groupManagers[receiverIdx]) as GroupMemberManager;

                            bool isMember = memberManager.IsMember(groupId, memberKeyPairs[senderIdx].publicKey);

                            string receiverKey = Convert.ToBase64String(memberKeyPairs[receiverIdx].publicKey);
                            string senderBase64Key = Convert.ToBase64String(memberKeyPairs[senderIdx].publicKey);

                            Trace.TraceWarning($"Receiver {receiverIdx} key: {receiverKey}");
                            Trace.TraceWarning($"Sender {senderIdx} key: {senderBase64Key}");
                            Trace.TraceWarning($"Is sender authorized: {isMember}");
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
                encryptedMessages.Add(groupManagers[senderIdx].EncryptGroupMessage(groupId, message));
            }

            // Check that all members can decrypt all messages
            for (int receiverIdx = 0; receiverIdx < memberCount; receiverIdx++)
            {
                for (int msgIdx = 0; msgIdx < memberCount; msgIdx++)
                {
                    if (receiverIdx == msgIdx)
                    {
                        // Skip the sender's own message
                        continue;
                    }

                    string decryptedMessage = groupManagers[receiverIdx].DecryptGroupMessage(encryptedMessages[msgIdx]);
                    Assert.IsNotNull(decryptedMessage, $"Member {receiverIdx} should decrypt message {msgIdx}");
                    Assert.AreEqual(messages[msgIdx], decryptedMessage, $"Decrypted message should match original");
                }
            }
        }

        [TestMethod]
        public void GroupMember_RemovalSimulation_ShouldNotReceiveNewMessages()
        {
            // Arrange - Create a group with some members
            var aliceKeyPair = LibEmiddleClient.GenerateSignatureKeyPair();
            var bobKeyPair = LibEmiddleClient.GenerateSignatureKeyPair();
            var charlieKeyPair = LibEmiddleClient.GenerateSignatureKeyPair();
            var daveKeyPair = LibEmiddleClient.GenerateSignatureKeyPair();

            var aliceManager = new GroupChatManager(aliceKeyPair);
            var bobManager = new GroupChatManager(bobKeyPair);
            var charlieManager = new GroupChatManager(charlieKeyPair);
            var daveManager = new GroupChatManager(daveKeyPair);

            string groupId = "member-removal-test";

            // Alice creates the group as admin and adds all other members
            aliceManager.CreateGroup(groupId);
            aliceManager.AddGroupMember(groupId, bobKeyPair.publicKey);
            aliceManager.AddGroupMember(groupId, charlieKeyPair.publicKey);
            aliceManager.AddGroupMember(groupId, daveKeyPair.publicKey);

            // Everyone creates their local view of the group
            bobManager.CreateGroup(groupId);
            charlieManager.CreateGroup(groupId);
            daveManager.CreateGroup(groupId);

            // All members need to add Alice and each other for bidirectional communication
            bobManager.AddGroupMember(groupId, aliceKeyPair.publicKey);
            bobManager.AddGroupMember(groupId, charlieKeyPair.publicKey);
            bobManager.AddGroupMember(groupId, daveKeyPair.publicKey);

            charlieManager.AddGroupMember(groupId, aliceKeyPair.publicKey);
            charlieManager.AddGroupMember(groupId, bobKeyPair.publicKey);
            charlieManager.AddGroupMember(groupId, daveKeyPair.publicKey);

            daveManager.AddGroupMember(groupId, aliceKeyPair.publicKey);
            daveManager.AddGroupMember(groupId, bobKeyPair.publicKey);
            daveManager.AddGroupMember(groupId, charlieKeyPair.publicKey);

            // Exchange initial distribution messages
            var aliceDistribution = aliceManager.CreateDistributionMessage(groupId);
            var bobDistribution = bobManager.CreateDistributionMessage(groupId);
            var charlieDistribution = charlieManager.CreateDistributionMessage(groupId);
            var daveDistribution = daveManager.CreateDistributionMessage(groupId);

            // Everyone processes everyone else's distribution
            aliceManager.ProcessSenderKeyDistribution(bobDistribution);
            aliceManager.ProcessSenderKeyDistribution(charlieDistribution);
            aliceManager.ProcessSenderKeyDistribution(daveDistribution);

            bobManager.ProcessSenderKeyDistribution(aliceDistribution);
            bobManager.ProcessSenderKeyDistribution(charlieDistribution);
            bobManager.ProcessSenderKeyDistribution(daveDistribution);

            charlieManager.ProcessSenderKeyDistribution(aliceDistribution);
            charlieManager.ProcessSenderKeyDistribution(bobDistribution);
            charlieManager.ProcessSenderKeyDistribution(daveDistribution);

            daveManager.ProcessSenderKeyDistribution(aliceDistribution);
            daveManager.ProcessSenderKeyDistribution(bobDistribution);
            daveManager.ProcessSenderKeyDistribution(charlieDistribution);

            // Send initial messages to confirm everyone is in the group
            string initialMessage = "Hello everyone!";
            var aliceInitialMsg = aliceManager.EncryptGroupMessage(groupId, initialMessage);

            // Verify all members can decrypt
            string bobDecryptedInitial = bobManager.DecryptGroupMessage(aliceInitialMsg);
            string charlieDecryptedInitial = charlieManager.DecryptGroupMessage(aliceInitialMsg);
            string daveDecryptedInitial = daveManager.DecryptGroupMessage(aliceInitialMsg);

            Assert.AreEqual(initialMessage, bobDecryptedInitial);
            Assert.AreEqual(initialMessage, charlieDecryptedInitial);
            Assert.AreEqual(initialMessage, daveDecryptedInitial);

            // Act - Simulate Dave being removed
            // In a real implementation, we would call RemoveGroupMember which triggers a key rotation
            // For this test, we'll create a new group to simulate the key rotation after removal

            // 1. Create new group (in reality, this would be a key rotation after member removal)
            string newGroupId = "member-removal-test-new";

            // Alice creates new group and adds only Bob and Charlie
            aliceManager.CreateGroup(newGroupId);
            aliceManager.AddGroupMember(newGroupId, bobKeyPair.publicKey);
            aliceManager.AddGroupMember(newGroupId, charlieKeyPair.publicKey);

            // Bob and Charlie create their view of the new group
            bobManager.CreateGroup(newGroupId);
            charlieManager.CreateGroup(newGroupId);

            // Bob and Charlie add Alice and each other
            bobManager.AddGroupMember(newGroupId, aliceKeyPair.publicKey);
            bobManager.AddGroupMember(newGroupId, charlieKeyPair.publicKey);

            charlieManager.AddGroupMember(newGroupId, aliceKeyPair.publicKey);
            charlieManager.AddGroupMember(newGroupId, bobKeyPair.publicKey);

            // 2. Exchange new distribution messages (without Dave)
            var aliceNewDistribution = aliceManager.CreateDistributionMessage(newGroupId);
            var bobNewDistribution = bobManager.CreateDistributionMessage(newGroupId);
            var charlieNewDistribution = charlieManager.CreateDistributionMessage(newGroupId);

            // 3. Process new distributions (without Dave)
            aliceManager.ProcessSenderKeyDistribution(bobNewDistribution);
            aliceManager.ProcessSenderKeyDistribution(charlieNewDistribution);

            bobManager.ProcessSenderKeyDistribution(aliceNewDistribution);
            bobManager.ProcessSenderKeyDistribution(charlieNewDistribution);

            charlieManager.ProcessSenderKeyDistribution(aliceNewDistribution);
            charlieManager.ProcessSenderKeyDistribution(bobNewDistribution);

            // 4. Send a new message to the new group
            string newMessage = "This is a message Dave shouldn't see";
            var aliceNewMsg = aliceManager.EncryptGroupMessage(newGroupId, newMessage);

            // 5. Verify Bob and Charlie can decrypt
            string bobDecryptedNew = bobManager.DecryptGroupMessage(aliceNewMsg);
            string charlieDecryptedNew = charlieManager.DecryptGroupMessage(aliceNewMsg);

            // 6. Try to have Dave decrypt (even if Dave creates his own group, he won't be authorized by others)
            daveManager.CreateGroup(newGroupId);  // Dave tries to join new group
            daveManager.AddGroupMember(newGroupId, aliceKeyPair.publicKey);
            // But no one has authorized Dave in the new group

            string daveDecryptedNew = daveManager.DecryptGroupMessage(aliceNewMsg);

            // Assert
            Assert.AreEqual(newMessage, bobDecryptedNew, "Bob should decrypt the new message");
            Assert.AreEqual(newMessage, charlieDecryptedNew, "Charlie should decrypt the new message");
            Assert.IsNull(daveDecryptedNew, "Dave should not be able to decrypt the new message");
        }

        [TestMethod]
        public void ConcurrentGroupAccess_ShouldHandleThreadSafely()
        {
            // Arrange - Create a group with multiple members
            var aliceKeyPair = LibEmiddleClient.GenerateSignatureKeyPair();
            var bobKeyPair = LibEmiddleClient.GenerateSignatureKeyPair();

            var aliceManager = new GroupChatManager(aliceKeyPair);
            var bobManager = new GroupChatManager(bobKeyPair);

            string groupId = "concurrent-access-test";

            // Both create their local view of the group
            aliceManager.CreateGroup(groupId);
            bobManager.CreateGroup(groupId);

            // Both add each other - this is the key for bidirectional communication
            bool aliceAuthBobResult = aliceManager.AddGroupMember(groupId, bobKeyPair.publicKey);
            Assert.IsTrue(aliceAuthBobResult, "Alice should be able to add Bob");

            bool bobAuthAliceResult = bobManager.AddGroupMember(groupId, aliceKeyPair.publicKey);
            Assert.IsTrue(bobAuthAliceResult, "Bob should be able to add Alice");

            // Exchange distribution messages
            var aliceDistribution = aliceManager.CreateDistributionMessage(groupId);
            var bobDistribution = bobManager.CreateDistributionMessage(groupId);

            // Both process each other's distribution messages
            bool aliceProcessResult = aliceManager.ProcessSenderKeyDistribution(bobDistribution);
            bool bobProcessResult = bobManager.ProcessSenderKeyDistribution(aliceDistribution);

            // Verify that both could process each other's distribution
            Assert.IsTrue(aliceProcessResult, "Alice should process Bob's distribution successfully");
            Assert.IsTrue(bobProcessResult, "Bob should process Alice's distribution successfully");

            // Act - Simulate concurrent message sending
            const int messageCount = 20;
            ConcurrentDictionary<int, string> aliceMessages = new ConcurrentDictionary<int, string>();
            ConcurrentDictionary<int, EncryptedGroupMessage> aliceEncryptedMessages = new ConcurrentDictionary<int, EncryptedGroupMessage>();
            ConcurrentDictionary<int, string> bobMessages = new ConcurrentDictionary<int, string>();
            ConcurrentDictionary<int, EncryptedGroupMessage> bobEncryptedMessages = new ConcurrentDictionary<int, EncryptedGroupMessage>();

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
            var aliceTasks = new List<System.Threading.Tasks.Task>();
            for (int i = 0; i < messageCount; i++)
            {
                int index = i; // Capture for closure
                var task = System.Threading.Tasks.Task.Run(() => {
                    try
                    {
                        aliceEncryptedMessages[index] = aliceManager.EncryptGroupMessage(groupId, aliceMessages[index]);
                    }
                    catch (Exception ex)
                    {
                        exceptions.Add(ex);
                    }
                });
                aliceTasks.Add(task);
            }

            // Create tasks for Bob sending messages
            var bobTasks = new List<System.Threading.Tasks.Task>();
            for (int i = 0; i < messageCount; i++)
            {
                int index = i; // Capture for closure
                var task = System.Threading.Tasks.Task.Run(() => {
                    try
                    {
                        bobEncryptedMessages[index] = bobManager.EncryptGroupMessage(groupId, bobMessages[index]);
                    }
                    catch (Exception ex)
                    {
                        exceptions.Add(ex);
                    }
                });
                bobTasks.Add(task);
            }

            // Wait for all encryption tasks to complete
            System.Threading.Tasks.Task.WaitAll(aliceTasks.ToArray());
            System.Threading.Tasks.Task.WaitAll(bobTasks.ToArray());

            // Check for exceptions during encryption
            Assert.AreEqual(0, exceptions.Count, "There should be no exceptions during concurrent encryption");

            // Create tasks for Bob decrypting Alice's messages
            var bobDecryptTasks = new List<System.Threading.Tasks.Task>();
            for (int i = 0; i < messageCount; i++)
            {
                int index = i; // Capture for closure
                var task = System.Threading.Tasks.Task.Run(() => {
                    try
                    {
                        string decrypted = bobManager.DecryptGroupMessage(aliceEncryptedMessages[index]);
                        decryptionResults[index] = decrypted;
                    }
                    catch (Exception ex)
                    {
                        exceptions.Add(ex);
                    }
                });
                bobDecryptTasks.Add(task);
            }

            // Wait for all decryption tasks to complete
            System.Threading.Tasks.Task.WaitAll(bobDecryptTasks.ToArray());

            // Check for exceptions during decryption
            Assert.AreEqual(0, exceptions.Count, "There should be no exceptions during concurrent decryption");

            // Verify all messages were correctly decrypted
            for (int i = 0; i < messageCount; i++)
            {
                Assert.IsTrue(decryptionResults.ContainsKey(i), $"Result for message {i} should exist");
                Assert.AreEqual(aliceMessages[i], decryptionResults[i], $"Decrypted message {i} should match original");
            }
        }
    }
}