using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using LibEmiddle.KeyExchange;
using LibEmiddle.Models;
using LibEmiddle.API;
using LibEmiddle.Abstractions;
using LibEmiddle.Messaging.Group;
using LibEmiddle.Domain;
using LibEmiddle.Crypto;
using LibEmiddle.Core;

namespace LibEmiddle.Tests.Unit
{
    [TestClass]
    public class IntegrationTests
    {
        private CryptoProvider _cryptoProvider;

        [TestInitialize]
        public void Setup()
        {
            _cryptoProvider = new CryptoProvider();
        }

        [TestMethod]
        public void FullE2EEFlow_ShouldWorkEndToEnd()
        {
            // This test simulates a full conversation flow between Alice and Bob

            // Step 1: Generate identity keys for Alice and Bob
            var aliceIdentityKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);
            var bobIdentityKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);

            // Step 2: Bob creates his key bundle and uploads to server
            var bobKeyBundle = X3DHExchange.CreateX3DHKeyBundle(bobIdentityKeyPair);

            // Step 3: Alice fetches Bob's bundle and initiates a session
            SenderSessionResult senderSessionResult = X3DHExchange.InitiateSessionAsSender(
                bobKeyBundle.ToPublicBundle(),
                aliceIdentityKeyPair);

            // Create a session ID that will be shared between Alice and Bob
            string sessionId = $"session-{Guid.NewGuid()}";

            // Step 4: Alice initializes her Double Ratchet session - using correct method from DoubleRatchet class
            var aliceDRSession = DoubleRatchetExchange.InitializeDoubleRatchet(senderSessionResult.SharedKey);

            // Create Alice's initial session using the root key and chain key from initialization
            aliceDRSession = new DoubleRatchetSession(
                dhRatchetKeyPair: _cryptoProvider.GenerateKeyPair(KeyType.X25519),
                remoteDHRatchetKey: bobKeyBundle.SignedPreKey,
                rootKey: aliceDRSession.rootKey,
                sendingChainKey: aliceDRSession.chainKey,
                receivingChainKey: null,
                messageNumberSending: 0,
                messageNumberReceiving: 0,
                sessionId: sessionId
            );

            // Step 5: Alice sends initial message to Bob
            string initialMessage = "Hello Bob, this is Alice!";
            var (aliceUpdatedSession, encryptedMessage) =
                _cryptoProvider.DoubleRatchetEncrypt(aliceDRSession, initialMessage);

            // Step 6: Bob processes the initial message data to establish his session
            var bobSharedKey = X3DHExchange.EstablishSessionAsReceiver(
                senderSessionResult.MessageDataToSend,
                bobKeyBundle);

            // Step 7: Bob initializes his Double Ratchet session
            var bobDRInit = DoubleRatchetExchange.InitializeDoubleRatchet(bobSharedKey);

            // Create Bob's initial session
            var bobDRSession = new DoubleRatchetSession(
                dhRatchetKeyPair: new KeyPair(
                    bobKeyBundle.SignedPreKey,
                    bobKeyBundle.GetSignedPreKeyPrivate()
                ),
                remoteDHRatchetKey: encryptedMessage.SenderDHKey,
                rootKey: bobDRInit.rootKey,
                sendingChainKey: null,
                receivingChainKey: bobDRInit.chainKey,
                messageNumberSending: 0,
                messageNumberReceiving: 0,
                sessionId: sessionId
            );

            // Step 8: Bob decrypts Alice's message
            var (bobUpdatedSession, decryptedMessage) =
                _cryptoProvider.DoubleRatchetDecrypt(bobDRSession, encryptedMessage);

            // Verify Bob successfully decrypted the message
            Assert.IsNotNull(bobUpdatedSession, "Bob's session should be updated after decryption");
            Assert.IsNotNull(decryptedMessage, "Bob should successfully decrypt Alice's message");
            Assert.AreEqual(initialMessage, decryptedMessage, "Bob should see Alice's original message");

            // Step 9: Bob replies to Alice
            string replyMessage = "Hi Alice, Bob here!";
            var (bobRepliedSession, bobReplyEncrypted) =
                _cryptoProvider.DoubleRatchetEncrypt(bobUpdatedSession, replyMessage);

            // Step 10: Alice decrypts Bob's reply
            var (aliceFinalSession, aliceDecryptedReply) =
                _cryptoProvider.DoubleRatchetDecrypt(aliceUpdatedSession, bobReplyEncrypted);

            // Assert final results
            Assert.IsNotNull(aliceFinalSession, "Alice's session should be updated after decryption");
            Assert.IsNotNull(aliceDecryptedReply, "Alice should successfully decrypt Bob's message");
            Assert.AreEqual(replyMessage, aliceDecryptedReply, "Alice should see Bob's original message");

            // Verify session properties were correctly updated
            Assert.AreEqual(sessionId, aliceUpdatedSession.SessionId,
                "Alice's session ID should remain the same after update");
            Assert.AreEqual(sessionId, bobUpdatedSession.SessionId,
                "Bob's session ID should remain the same after update");

            // Verify message numbers increased
            Assert.AreEqual(1, aliceUpdatedSession.MessageNumberSending, "Alice's message number should be incremented");
            Assert.AreEqual(0, bobUpdatedSession.MessageNumberReceiving, "Bob's message number should be correct");

            // Verify chain keys changed
            Assert.IsFalse(SecureMemory.SecureCompare(aliceDRSession.SendingChainKey, aliceUpdatedSession.SendingChainKey),
                "Alice's sending chain key should change after encryption");
            Assert.IsFalse(SecureMemory.SecureCompare(bobDRSession.ReceivingChainKey, bobUpdatedSession.ReceivingChainKey),
                "Bob's receiving chain key should change after decryption");

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
            aliceManager.AddGroupMember(groupId, bobKeyPair.PublicKey);
            aliceManager.AddGroupMember(groupId, charlieKeyPair.PublicKey);

            // Bob adds Alice and Charlie
            bobManager.AddGroupMember(groupId, aliceKeyPair.PublicKey);
            bobManager.AddGroupMember(groupId, charlieKeyPair.PublicKey);

            // Charlie adds Alice and Bob
            charlieManager.AddGroupMember(groupId, aliceKeyPair.PublicKey);
            charlieManager.AddGroupMember(groupId, bobKeyPair.PublicKey);

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