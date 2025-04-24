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
using System.Collections.Generic;
using System.Reflection.Metadata;
using System.Collections.Immutable;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

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
            // Step 1: Generate identity keys for Alice and Bob
            var aliceIdentityKeyPair = Sodium.GenerateEd25519KeyPair();
            var bobIdentityKeyPair = Sodium.GenerateEd25519KeyPair();

            // Step 2: Create Bob's key bundle with the proper identity key
            var bobKeyBundle = X3DHExchange.CreateX3DHKeyBundle(bobIdentityKeyPair);
            var bobPublicBundle = bobKeyBundle.ToPublicBundle();

            // Step 3: Generate a shared secret for Alice and Bob to use
            // This would normally come from a full X3DH exchange
            var sharedSecret = Sodium.GenerateRandomBytes(Constants.AES_KEY_SIZE);

            // Step 4: Derive the Double Ratchet root key and chain keys
            var (rootKey, sendingChainKey) = _cryptoProvider.DeriveDoubleRatchet(sharedSecret);

            // Ensure we have valid chain keys - this is critical
            Assert.IsNotNull(sendingChainKey, "Chain key should not be null");
            Assert.AreEqual(Constants.AES_KEY_SIZE, sendingChainKey.Length, "Chain key should be the correct size");

            // Create session ID that will be consistent between Alice and Bob
            string sessionId = Guid.NewGuid().ToString();

            // Step 5: Set up Alice's DH key pair for the Double Ratchet
            var aliceDHKeyPair = Sodium.GenerateX25519KeyPair();

            // Step 6: Set up Bob's X25519 key pair
            byte[] bobSignedPreKeyPrivate = bobKeyBundle.GetSignedPreKeyPrivate();
            var bobSignedPreKeyPair = new KeyPair(
                bobPublicBundle.SignedPreKey,
                bobSignedPreKeyPrivate
            );

            // Step 7: Initialize Alice's session with properly configured sending chain key
            var aliceSession = new DoubleRatchetSession(
                dhRatchetKeyPair: aliceDHKeyPair,
                remoteDHRatchetKey: bobPublicBundle.SignedPreKey,
                rootKey: rootKey,
                sendingChainKey: sendingChainKey,  // This is the key that needs to be properly initialized
                receivingChainKey: null,    // Receiving chain can be null for the initiator
                messageNumberSending: 0,
                messageNumberReceiving: 0,
                sessionId: sessionId,
                recentlyProcessedIds: ImmutableList<Guid>.Empty,
                processedMessageNumbersReceiving: ImmutableHashSet<int>.Empty,
                skippedMessageKeys: ImmutableDictionary<Tuple<byte[], int>, byte[]>.Empty
            );

            // Double-check that Alice's session is valid and chain key is set
            Assert.IsTrue(_cryptoProvider.ValidateSession(aliceSession), "Alice's session should be valid");
            Assert.IsNotNull(aliceSession.SendingChainKey, "Alice's sending chain key must not be null");

            // Step 8: Alice encrypts a message to Bob
            string initialMessage = "Hello Bob, this is Alice!";
            var (aliceUpdatedSession, encryptedMessage) = _cryptoProvider.DoubleRatchetEncrypt(aliceSession, initialMessage);

            // Verify encryption was successful
            Assert.IsNotNull(encryptedMessage, "Encrypted message should not be null");
            Assert.IsNotNull(encryptedMessage.Ciphertext, "Ciphertext should not be null");

            byte[] receivingChainKey = SecureMemory.SecureCopy(sendingChainKey);

            // Step 9: Initialize Bob's session with properly configured receiving chain key
            var bobSession = new DoubleRatchetSession(
                dhRatchetKeyPair: bobSignedPreKeyPair,
                remoteDHRatchetKey: aliceDHKeyPair.PublicKey,
                rootKey: rootKey,
                sendingChainKey: sendingChainKey,
                receivingChainKey: receivingChainKey, // Bob needs the same chain key that Alice used for sending
                messageNumberSending: 0,
                messageNumberReceiving: 0,
                sessionId: sessionId,
                recentlyProcessedIds: ImmutableList<Guid>.Empty,
                processedMessageNumbersReceiving: ImmutableHashSet<int>.Empty,
                skippedMessageKeys: ImmutableDictionary<Tuple<byte[], int>, byte[]>.Empty
            );

            // Verify Bob's session is valid
            Assert.IsTrue(_cryptoProvider.ValidateSession(bobSession), "Bob's session should be valid");
            Assert.IsNotNull(bobSession.ReceivingChainKey, "Bob's receiving chain key must not be null");

            // Step 10: Bob decrypts Alice's message
            var (bobUpdatedSession, decryptedMessage) = _cryptoProvider.DoubleRatchetDecrypt(bobSession, encryptedMessage);

            // Verify decryption was successful
            Assert.IsNotNull(bobUpdatedSession, "Bob's updated session should not be null");
            Assert.IsNotNull(decryptedMessage, "Decrypted message should not be null");
            Assert.AreEqual(initialMessage, decryptedMessage, "Bob should see Alice's original message");

            // Step 11: Bob replies to Alice
            string replyMessage = "Hi Alice, Bob here!";
            var (bobRepliedSession, bobReplyEncrypted) = _cryptoProvider.DoubleRatchetEncrypt(bobUpdatedSession, replyMessage);

            // Verify Bob's encryption was successful
            Assert.IsNotNull(bobReplyEncrypted, "Bob's encrypted reply should not be null");

            // Step 12: Alice decrypts Bob's reply
            var (aliceFinalSession, aliceDecryptedReply) = _cryptoProvider.DoubleRatchetDecrypt(aliceUpdatedSession, bobReplyEncrypted);

            // Verify Alice correctly decrypted Bob's message
            Assert.IsNotNull(aliceDecryptedReply, "Alice should successfully decrypt Bob's message");
            Assert.AreEqual(replyMessage, aliceDecryptedReply, "Alice should see Bob's original message");

            // Verify session properties were correctly updated
            Assert.AreEqual(1, aliceUpdatedSession.MessageNumberSending, "Alice's message number should be incremented");
            Assert.AreEqual(1, bobUpdatedSession.MessageNumberReceiving, "Bob's message number should be incremented");

            // Clean up sensitive key material
            bobKeyBundle.Dispose();
            SecureMemory.SecureClear(sharedSecret);
            SecureMemory.SecureClear(rootKey);
            SecureMemory.SecureClear(sendingChainKey);
            SecureMemory.SecureClear(receivingChainKey);
            SecureMemory.SecureClear(aliceDHKeyPair.PrivateKey);
            SecureMemory.SecureClear(bobSignedPreKeyPrivate);
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