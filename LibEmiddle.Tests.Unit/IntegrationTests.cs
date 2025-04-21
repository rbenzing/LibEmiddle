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

            // Step 1: Generate identity keys for Alice and Bob with correct formats
            var aliceIdentityKeyPair = Sodium.GenerateEd25519KeyPair();
            var bobIdentityKeyPair = Sodium.GenerateEd25519KeyPair();

            // Create X25519 versions of the keys for Double Ratchet
            var aliceX25519KeyPair = new KeyPair(
                Sodium.ConvertEd25519PublicKeyToX25519(aliceIdentityKeyPair.PublicKey),
                Sodium.ConvertEd25519PrivateKeyToX25519(aliceIdentityKeyPair.PrivateKey)
            );

            // Step 2: Create Bob's key bundle
            var bobKeyBundle = X3DHExchange.CreateX3DHKeyBundle(bobIdentityKeyPair);
            var bobPublicBundle = bobKeyBundle.ToPublicBundle();

            // Step 3: Derive the initial root key and chain keys
            // For testing, we'll use a deterministic approach to ensure proper initialization
            byte[] sharedKey = Sodium.GenerateRandomBytes(Constants.AES_KEY_SIZE);
            var (rootKey, chainKey) = _cryptoProvider.DeriveDoubleRatchet(sharedKey);

            // Generate a session ID that will be consistent between Alice and Bob
            string sessionId = "session-" + Guid.NewGuid().ToString();

            // Step 4: Manually create Alice's Double Ratchet session with properly initialized chain keys
            // The issue might be that chainKey is getting cleared somewhere or isn't properly assigned
            // Let's create a copy to make sure it stays intact
            byte[] aliceChainKey = new byte[chainKey.Length];
            Buffer.BlockCopy(chainKey, 0, aliceChainKey, 0, chainKey.Length);

            // Get the Bob's SPK in X25519 format to ensure compatibility
            byte[] bobSignedPreKey = new byte[bobPublicBundle.SignedPreKey.Length];
            Buffer.BlockCopy(bobPublicBundle.SignedPreKey, 0, bobSignedPreKey, 0, bobPublicBundle.SignedPreKey.Length);

            // Debug verification that chain keys are properly set
            Assert.AreEqual(Constants.AES_KEY_SIZE, aliceChainKey.Length, "Alice's chain key should be the correct size");
            Assert.IsFalse(aliceChainKey.All(b => b == 0), "Alice's chain key should not be all zeros");

            var aliceDRSession = new DoubleRatchetSession(
                dhRatchetKeyPair: aliceX25519KeyPair,
                remoteDHRatchetKey: bobSignedPreKey,
                rootKey: rootKey,
                sendingChainKey: aliceChainKey,  // Use a dedicated copy of the chain key
                receivingChainKey: null,    // Receiver chain key can be null initially
                messageNumberSending: 0,
                messageNumberReceiving: 0,
                sessionId: sessionId,
                recentlyProcessedIds: ImmutableList<Guid>.Empty,
                processedMessageNumbersReceiving: ImmutableHashSet<int>.Empty,
                skippedMessageKeys: ImmutableDictionary<Tuple<byte[], int>, byte[]>.Empty
            );

            // Verify the session is valid before proceeding
            Assert.IsTrue(_cryptoProvider.ValidateSession(aliceDRSession), "Alice's session should be valid before encrypting");

            // Additional debug checks to pinpoint the issue
            Assert.IsNotNull(aliceDRSession.SendingChainKey, "Alice's sending chain key should not be null after initialization");
            Assert.AreEqual(Constants.AES_KEY_SIZE, aliceDRSession.SendingChainKey.Length, "Alice's sending chain key should be the correct size");

            // Try a direct implementation first to see if the issue is in the Double Ratchet implementation
            // or in our test setup
            byte[] msgKey = Sodium.GenerateHmacSha256(new byte[] { 0x01 }, aliceDRSession.SendingChainKey);
            byte[] nextChainKey = Sodium.GenerateHmacSha256(new byte[] { 0x02 }, aliceDRSession.SendingChainKey);

            Assert.IsNotNull(msgKey, "Message key derivation should succeed");
            Assert.IsNotNull(nextChainKey, "Next chain key derivation should succeed");

            // Step 5: Alice sends initial message to Bob
            string initialMessage = "Hello Bob, this is Alice!";
            var (aliceUpdatedDRSession, encryptedMessage) =
                _cryptoProvider.DoubleRatchetEncrypt(aliceDRSession, initialMessage);

            // If we get this far, we know the encryption worked - now set up Bob's session for decryption

            // Create a key pair for Bob using his SignedPreKey (already in X25519 format)
            var bobSignedPreKeyPair = new KeyPair(
                bobPublicBundle.SignedPreKey,
                bobKeyBundle.GetSignedPreKeyPrivate()
            );

            // Make a copy of the chain key for Bob
            byte[] bobChainKey = new byte[chainKey.Length];
            Buffer.BlockCopy(chainKey, 0, bobChainKey, 0, chainKey.Length);

            byte[] senderDHKey = new byte[encryptedMessage.SenderDHKey.Length];
            Buffer.BlockCopy(encryptedMessage.SenderDHKey, 0, senderDHKey, 0, encryptedMessage.SenderDHKey.Length);

            // Step 6: Manually create Bob's Double Ratchet session with properly initialized chain keys
            var bobDRSession = new DoubleRatchetSession(
                dhRatchetKeyPair: bobSignedPreKeyPair,
                remoteDHRatchetKey: senderDHKey,
                rootKey: rootKey,
                sendingChainKey: null,      // Sender chain key can be null initially
                receivingChainKey: bobChainKey, // Use the same chain key for receiving
                messageNumberSending: 0,
                messageNumberReceiving: 0,
                sessionId: sessionId,
                recentlyProcessedIds: ImmutableList<Guid>.Empty,
                processedMessageNumbersReceiving: ImmutableHashSet<int>.Empty,
                skippedMessageKeys: ImmutableDictionary<Tuple<byte[], int>, byte[]>.Empty
            );

            // Verify Bob's session is valid before proceeding
            Assert.IsTrue(_cryptoProvider.ValidateSession(bobDRSession), "Bob's session should be valid before decrypting");

            // Additional debug checks
            Assert.IsNotNull(bobDRSession.ReceivingChainKey, "Bob's receiving chain key should not be null after initialization");
            Assert.AreEqual(Constants.AES_KEY_SIZE, bobDRSession.ReceivingChainKey.Length, "Bob's receiving chain key should be the correct size");

            // Step 7: Bob decrypts Alice's message
            var (bobUpdatedDRSession, decryptedMessage) =
                _cryptoProvider.DoubleRatchetDecrypt(bobDRSession, encryptedMessage);

            // Verify Bob successfully decrypted the message
            Assert.IsNotNull(bobUpdatedDRSession, "Bob's session should be updated after decryption");
            Assert.IsNotNull(decryptedMessage, "Bob should successfully decrypt Alice's message");
            Assert.AreEqual(initialMessage, decryptedMessage, "Bob should see Alice's original message");

            // Step 8: Bob replies to Alice
            string replyMessage = "Hi Alice, Bob here!";
            var (bobRepliedDRSession, bobReplyEncrypted) =
                _cryptoProvider.DoubleRatchetEncrypt(bobUpdatedDRSession, replyMessage);

            // Step 9: Alice decrypts Bob's reply
            var (aliceFinalSession, aliceDecryptedReply) =
                _cryptoProvider.DoubleRatchetDecrypt(aliceUpdatedDRSession, bobReplyEncrypted);

            // Assert final results
            Assert.IsNotNull(aliceFinalSession, "Alice's session should be updated after decryption");
            Assert.IsNotNull(aliceDecryptedReply, "Alice should successfully decrypt Bob's message");
            Assert.AreEqual(replyMessage, aliceDecryptedReply, "Alice should see Bob's original message");

            // Verify session properties were correctly updated
            Assert.AreEqual(encryptedMessage.SessionId, aliceUpdatedDRSession.SessionId,
                "Alice's session ID should remain the same after update");
            Assert.AreEqual(bobReplyEncrypted.SessionId, bobRepliedDRSession.SessionId,
                "Bob's session ID should remain the same after update");

            // Verify message numbers increased
            Assert.AreEqual(1, aliceUpdatedDRSession.MessageNumberSending, "Alice's message number should be incremented");
            Assert.AreEqual(1, bobUpdatedDRSession.MessageNumberReceiving, "Bob's message number should be incremented");

            // Verify chain keys changed
            Assert.IsFalse(SecureMemory.SecureCompare(aliceDRSession.SendingChainKey, aliceUpdatedDRSession.SendingChainKey),
                "Alice's sending chain key should change after encryption");
            Assert.IsFalse(SecureMemory.SecureCompare(bobDRSession.ReceivingChainKey, bobUpdatedDRSession.ReceivingChainKey),
                "Bob's receiving chain key should change after decryption");

            // Clean up sensitive key material
            bobKeyBundle.ClearPrivateKeys();
            SecureMemory.SecureClear(rootKey);
            SecureMemory.SecureClear(chainKey);
            SecureMemory.SecureClear(aliceChainKey);
            SecureMemory.SecureClear(bobChainKey);
            SecureMemory.SecureClear(msgKey);
            SecureMemory.SecureClear(nextChainKey);
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