using System;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Security.Cryptography;
using E2EELibrary;
using E2EELibrary.KeyManagement;
using E2EELibrary.Encryption;
using E2EELibrary.KeyExchange;
using E2EELibrary.GroupMessaging;
using E2EELibrary.MultiDevice;
using E2EELibrary.Models;
using E2EELibrary.Core;

namespace E2EELibraryTests
{
    [TestClass]
    public class IntegrationTests
    {
        #region Helper Methods

        /// <summary>
        /// Helper method for byte array comparison
        /// </summary>
        private bool AreByteArraysEqual(byte[] a, byte[] b)
        {
            // Use the secure comparison even in tests to ensure consistent behavior
            return SecureMemory.SecureCompare(a, b);
        }

        #endregion

        [TestMethod]
        public void FullE2EEFlow_ShouldWorkEndToEnd()
        {
            // This test simulates a full conversation flow between Alice and Bob

            // Step 1: Generate identity keys for Alice and Bob
            var aliceIdentityKeyPair = E2EEClient.GenerateKeyExchangeKeyPair();
            var bobIdentityKeyPair = E2EEClient.GenerateKeyExchangeKeyPair();

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
            var aliceSession = X3DHExchange.InitiateX3DHSession(bobPublicBundle, aliceIdentityKeyPair);

            // Create a session ID that will be shared between Alice and Bob
            string sessionId = "alice-bob-session-" + Guid.NewGuid().ToString();

            // Create Alice's initial DoubleRatchet session using immutable constructor
            var aliceDRSession = new DoubleRatchetSession(
                dhRatchetKeyPair: E2EEClient.GenerateKeyExchangeKeyPair(),
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
            Assert.IsFalse(AreByteArraysEqual(aliceDRSession.SendingChainKey, aliceUpdatedSession.SendingChainKey),
                "Alice's sending chain key should change after encryption");
            Assert.IsFalse(AreByteArraysEqual(bobDRSession.SendingChainKey, bobRepliedSession.SendingChainKey),
                "Bob's sending chain key should change after encryption");

            // Clean up sensitive key material
            bobKeyBundle.ClearPrivateKeys();
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

            // Step 3: Alice creates the group as the admin
            string groupId = "friends-group-123";
            aliceManager.CreateGroup(groupId);

            // Step 3.5: Alice authorizes Bob and Charlie as members
            aliceManager.AuthorizeMember(groupId, bobKeyPair.publicKey);
            aliceManager.AuthorizeMember(groupId, charlieKeyPair.publicKey);

            // Step 4: Alice sends her sender key to Bob and Charlie
            var aliceDistribution = aliceManager.CreateDistributionMessage(groupId);

            // Bob and Charlie create their own views of the group and authorize other members
            bobManager.CreateGroup(groupId);
            charlieManager.CreateGroup(groupId);

            // Bob authorizes Alice and Charlie
            bobManager.AuthorizeMember(groupId, aliceKeyPair.publicKey);
            bobManager.AuthorizeMember(groupId, charlieKeyPair.publicKey);

            // Charlie authorizes Alice and Bob
            charlieManager.AuthorizeMember(groupId, aliceKeyPair.publicKey);
            charlieManager.AuthorizeMember(groupId, bobKeyPair.publicKey);

            // Bob and Charlie process Alice's sender key
            bool bobProcessResult = bobManager.ProcessSenderKeyDistribution(aliceDistribution);
            bool charlieProcessResult = charlieManager.ProcessSenderKeyDistribution(aliceDistribution);

            // Step 5: Bob creates his sender key and distributes it
            var bobDistribution = bobManager.CreateDistributionMessage(groupId);

            // Alice and Charlie process Bob's sender key
            bool aliceProcessBobResult = aliceManager.ProcessSenderKeyDistribution(bobDistribution);
            bool charlieProcessBobResult = charlieManager.ProcessSenderKeyDistribution(bobDistribution);

            // Step 6: Charlie creates his sender key and distributes it
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
    }
}