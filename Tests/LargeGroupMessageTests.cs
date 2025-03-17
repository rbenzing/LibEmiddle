using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using E2EELibrary;
using E2EELibrary.GroupMessaging;
using E2EELibrary.Core;
using E2EELibrary.Models;

namespace E2EELibraryTests
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
                var keyPair = E2EEClient.GenerateSignatureKeyPair();
                memberKeyPairs.Add(keyPair);
                groupManagers.Add(new GroupChatManager(keyPair));
            }

            string groupId = "large-group-test";

            // Everyone creates the group
            foreach (var manager in groupManagers)
            {
                manager.CreateGroup(groupId);
            }

            // Create distribution messages for all members
            var distributionMessages = new List<SenderKeyDistributionMessage>();
            foreach (var manager in groupManagers)
            {
                distributionMessages.Add(manager.CreateDistributionMessage(groupId));
            }

            // Each member processes all other members' distribution messages
            for (int receiverIdx = 0; receiverIdx < memberCount; receiverIdx++)
            {
                for (int senderIdx = 0; senderIdx < memberCount; senderIdx++)
                {
                    if (receiverIdx != senderIdx)
                    {
                        bool result = groupManagers[receiverIdx].ProcessSenderKeyDistribution(distributionMessages[senderIdx]);
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
            var aliceKeyPair = E2EEClient.GenerateSignatureKeyPair();
            var bobKeyPair = E2EEClient.GenerateSignatureKeyPair();
            var charlieKeyPair = E2EEClient.GenerateSignatureKeyPair();
            var daveKeyPair = E2EEClient.GenerateSignatureKeyPair();

            var aliceManager = new GroupChatManager(aliceKeyPair);
            var bobManager = new GroupChatManager(bobKeyPair);
            var charlieManager = new GroupChatManager(charlieKeyPair);
            var daveManager = new GroupChatManager(daveKeyPair);

            string groupId = "member-removal-test";

            // Everyone creates and joins the group initially
            aliceManager.CreateGroup(groupId);
            bobManager.CreateGroup(groupId);
            charlieManager.CreateGroup(groupId);
            daveManager.CreateGroup(groupId);

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
            // In a real implementation, we would call RemoveLinkedDevice or similar
            // Since that doesn't exist, we'll simulate by creating a new group with new keys

            // 1. Create new group (in reality, this would be a key rotation after member removal)
            string newGroupId = "member-removal-test-new";
            aliceManager.CreateGroup(newGroupId);
            bobManager.CreateGroup(newGroupId);
            charlieManager.CreateGroup(newGroupId);
            // Dave is excluded

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

            // 6. Try to have Dave decrypt
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
            var aliceKeyPair = E2EEClient.GenerateSignatureKeyPair();
            var bobKeyPair = E2EEClient.GenerateSignatureKeyPair();

            var aliceManager = new GroupChatManager(aliceKeyPair);
            var bobManager = new GroupChatManager(bobKeyPair);

            string groupId = "concurrent-access-test";

            // Set up the group
            aliceManager.CreateGroup(groupId);
            bobManager.CreateGroup(groupId);

            var aliceDistribution = aliceManager.CreateDistributionMessage(groupId);
            var bobDistribution = bobManager.CreateDistributionMessage(groupId);

            aliceManager.ProcessSenderKeyDistribution(bobDistribution);
            bobManager.ProcessSenderKeyDistribution(aliceDistribution);

            // Act - Simulate concurrent message sending
            const int messageCount = 20;
            Dictionary<int, string> aliceMessages = new Dictionary<int, string>();
            Dictionary<int, EncryptedGroupMessage> aliceEncryptedMessages = new Dictionary<int, EncryptedGroupMessage>();
            Dictionary<int, string> bobMessages = new Dictionary<int, string>();
            Dictionary<int, EncryptedGroupMessage> bobEncryptedMessages = new Dictionary<int, EncryptedGroupMessage>();

            // Create thread-safe collections for results
            var exceptions = new System.Collections.Concurrent.ConcurrentBag<Exception>();
            var decryptionResults = new System.Collections.Concurrent.ConcurrentDictionary<int, string>();

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