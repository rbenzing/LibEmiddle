using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using LibEmiddle.KeyExchange;
using LibEmiddle.Models;
using LibEmiddle.API;
using LibEmiddle.Crypto;
using LibEmiddle.Messaging.Group;

namespace LibEmiddle.Tests.Unit
{
    [TestClass]
    public class IntegrationTests
    {
        [TestMethod]
        public void FullE2EEFlow_ShouldWorkEndToEnd()
        {
            // This test simulates a full conversation flow between Alice and Bob

            // Step 1: Generate identity keys for Alice and Bob
            var aliceIdentityKeyPair = LibEmiddleClient.GenerateKeyExchangeKeyPair();
            var bobIdentityKeyPair = LibEmiddleClient.GenerateKeyExchangeKeyPair();

            // Step 2: Bob creates his key bundle and uploads to server
            var bobKeyBundle = X3DHExchange.CreateX3DHKeyBundle();

            // Convert to public bundle (what would be stored on server)
            var bobPublicBundle = new X3DHPublicBundle
            {
                IdentityKey = bobKeyBundle.IdentityKey,
                SignedPreKey = bobKeyBundle.SignedPreKey,
                SignedPreKeySignature = bobKeyBundle.SignedPreKeySignature,
                OneTimePreKeys = bobKeyBundle.OneTimePreKeys
            };

            // Step 3: Alice fetches Bob's bundle and initiates a session
            var aliceSession = X3DHExchange.InitiateX3DHSession(bobPublicBundle, aliceIdentityKeyPair, out var usedOneTimePreKeyId);

            // Create a session ID that will be shared between Alice and Bob
            string sessionId = "alice-bob-session-" + Guid.NewGuid().ToString();

            // Create Alice's initial DoubleRatchet session using immutable constructor
            var aliceDRSession = new DoubleRatchetSession(
                dhRatchetKeyPair: LibEmiddleClient.GenerateKeyExchangeKeyPair(),
                remoteDHRatchetKey: bobPublicBundle.SignedPreKey,
                rootKey: aliceSession.RootKey,
                sendingChainKey: aliceSession.ChainKey,
                receivingChainKey: aliceSession.ChainKey,
                messageNumber: 0,
                sessionId: sessionId
            );

            // Step 4: Alice sends initial message to Bob
            string initialMessage = "Hello Bob, this is Alice!";
            var (aliceUpdatedSession, encryptedMessage) =
                DoubleRatchet.DoubleRatchetEncrypt(aliceDRSession, initialMessage);

            // Add necessary validation fields for enhanced security
            encryptedMessage.MessageId = Guid.NewGuid();
            encryptedMessage.Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            encryptedMessage.SessionId = sessionId;

            // Step 5: Bob receives Alice's initial message 
            // (In reality, Bob would process the X3DH initial message first)

            // Bob creates his DoubleRatchet session
            var bobDRSession = new DoubleRatchetSession(
                dhRatchetKeyPair: (bobKeyBundle.SignedPreKey, bobKeyBundle.GetSignedPreKeyPrivate()),
                remoteDHRatchetKey: encryptedMessage.SenderDHKey,
                rootKey: aliceSession.RootKey, // In reality, Bob would derive this himself
                sendingChainKey: aliceSession.ChainKey,
                receivingChainKey: aliceSession.ChainKey,
                messageNumber: 0,
                sessionId: sessionId // Must match Alice's session ID
            );

            // Bob decrypts Alice's message
            var (bobUpdatedSession, decryptedMessage) =
                DoubleRatchet.DoubleRatchetDecrypt(bobDRSession, encryptedMessage);

            // Verify Bob successfully decrypted the message
            Assert.IsNotNull(bobUpdatedSession, "Bob's session should be updated after decryption");
            Assert.IsNotNull(decryptedMessage, "Bob should successfully decrypt Alice's message");
            Assert.AreEqual(initialMessage, decryptedMessage, "Bob should see Alice's original message");

            // Step 6: Bob replies to Alice
            string replyMessage = "Hi Alice, Bob here!";
            var (bobRepliedSession, bobReplyEncrypted) =
                DoubleRatchet.DoubleRatchetEncrypt(bobUpdatedSession, replyMessage);

            // Add necessary validation fields for enhanced security
            bobReplyEncrypted.MessageId = Guid.NewGuid();
            bobReplyEncrypted.Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            bobReplyEncrypted.SessionId = sessionId;

            // Step 7: Alice decrypts Bob's reply
            var (aliceFinalSession, aliceDecryptedReply) =
                DoubleRatchet.DoubleRatchetDecrypt(aliceUpdatedSession, bobReplyEncrypted);

            // Assert final results
            Assert.IsNotNull(aliceFinalSession, "Alice's session should be updated after decryption");
            Assert.IsNotNull(aliceDecryptedReply, "Alice should successfully decrypt Bob's message");
            Assert.AreEqual(replyMessage, aliceDecryptedReply, "Alice should see Bob's original message");

            // Verify session properties were correctly updated
            Assert.AreNotEqual(aliceDRSession, aliceUpdatedSession, "Alice's initial session should be different from updated session");
            Assert.AreNotEqual(bobDRSession, bobUpdatedSession, "Bob's initial session should be different from updated session");
            Assert.AreNotEqual(aliceUpdatedSession, aliceFinalSession, "Alice's updated session should be different from final session");
            Assert.AreNotEqual(bobUpdatedSession, bobRepliedSession, "Bob's updated session should be different from replied session");

            // Verify message numbers increased
            Assert.AreEqual(1, aliceUpdatedSession.MessageNumber, "Alice's message number should be incremented");
            Assert.AreEqual(1, bobRepliedSession.MessageNumber, "Bob's message number should be incremented");

            // Verify chain keys changed
            Assert.IsFalse(TestsHelpers.AreByteArraysEqual(aliceDRSession.SendingChainKey, aliceUpdatedSession.SendingChainKey),
                "Alice's sending chain key should change after encryption");
            Assert.IsFalse(TestsHelpers.AreByteArraysEqual(bobDRSession.SendingChainKey, bobRepliedSession.SendingChainKey),
                "Bob's sending chain key should change after encryption");

            // Clean up sensitive key material
            bobKeyBundle.ClearPrivateKeys();
        }

        [TestMethod]
        public void FullGroupMessageFlow_ShouldWorkEndToEnd()
        {
            // This test simulates a group chat between Alice, Bob, and Charlie

            // Step 1: Generate identity keys for the participants
            var aliceKeyPair = LibEmiddleClient.GenerateSignatureKeyPair();
            var bobKeyPair = LibEmiddleClient.GenerateSignatureKeyPair();
            var charlieKeyPair = LibEmiddleClient.GenerateSignatureKeyPair();

            // Step 2: Create group chat managers for each participant
            var aliceManager = new GroupChatManager(aliceKeyPair);
            var bobManager = new GroupChatManager(bobKeyPair);
            var charlieManager = new GroupChatManager(charlieKeyPair);

            // Step 3: All participants create their own view of the group 
            // (each participant maintains their own state in our distributed architecture)
            string groupId = "friends-group-123";
            aliceManager.CreateGroup(groupId);
            bobManager.CreateGroup(groupId);
            charlieManager.CreateGroup(groupId);

            // Step 4: Each participant adds the others as members
            // Alice adds Bob and Charlie
            aliceManager.AddGroupMember(groupId, bobKeyPair.publicKey);
            aliceManager.AddGroupMember(groupId, charlieKeyPair.publicKey);

            // Bob adds Alice and Charlie
            bobManager.AddGroupMember(groupId, aliceKeyPair.publicKey);
            bobManager.AddGroupMember(groupId, charlieKeyPair.publicKey);

            // Charlie adds Alice and Bob
            charlieManager.AddGroupMember(groupId, aliceKeyPair.publicKey);
            charlieManager.AddGroupMember(groupId, bobKeyPair.publicKey);

            // Step 5: Each participant creates their distribution message with their sender key
            var aliceDistribution = aliceManager.CreateDistributionMessage(groupId);
            var bobDistribution = bobManager.CreateDistributionMessage(groupId);
            var charlieDistribution = charlieManager.CreateDistributionMessage(groupId);

            // Step 6: Everyone processes everyone else's distribution messages
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
    }
}