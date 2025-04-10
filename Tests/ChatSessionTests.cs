using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Linq;
using System.Threading;
using E2EELibrary;
using E2EELibrary.Models;
using E2EELibrary.Core;
using E2EELibrary.KeyExchange;
using E2EELibrary.Encryption;
using E2EELibrary.KeyManagement;
using System.Collections.Generic;

namespace E2EELibraryTests
{
    [TestClass]
    public class ChatSessionTests
    {
        [TestMethod]
        public void X3DHKeyExchange_ShouldEstablishSecureSession()
        {
            // Arrange
            var aliceKeyBundle = X3DHExchange.CreateX3DHKeyBundle(
                numOneTimeKeys: 5 // Generate multiple one-time prekeys
            );

            var bobKeyBundle = X3DHExchange.CreateX3DHKeyBundle(
                numOneTimeKeys: 5
            );

            // Validate bundles before exchange
            Assert.IsTrue(X3DHExchange.ValidateKeyBundle(aliceKeyBundle.ToPublicBundle()));
            Assert.IsTrue(X3DHExchange.ValidateKeyBundle(bobKeyBundle.ToPublicBundle()));

            // Act
            var aliceSession = X3DHExchange.InitiateX3DHSession(
                bobKeyBundle.ToPublicBundle(),
                (aliceKeyBundle.IdentityKey, aliceKeyBundle.GetIdentityKeyPrivate()),
                out var usedOneTimePreKeyId
            );

            // Assert
            Assert.IsNotNull(aliceSession);
            Assert.IsNotNull(aliceSession.RootKey);
            Assert.IsNotNull(aliceSession.ChainKey);
            Assert.IsTrue(usedOneTimePreKeyId.HasValue);
        }

        [TestMethod]
        public void DoubleRatchetSession_ShouldSupportMessageEncryptionDecryption()
        {
            // Arrange
            // Generate proper key pairs for Alice and Bob
            var aliceKeyPair = KeyGenerator.GenerateX25519KeyPair();
            var bobKeyPair = KeyGenerator.GenerateX25519KeyPair();

            // Create a shared secret (simulating X3DH)
            byte[] sharedSecret = X3DHExchange.X3DHKeyExchange(bobKeyPair.publicKey, aliceKeyPair.privateKey);

            // Initialize Double Ratchet
            var (rootKey, chainKey) = DoubleRatchetExchange.InitializeDoubleRatchet(sharedSecret);

            // Create Alice's sending session with proper key pair
            var aliceRatchetSession = new DoubleRatchetSession(
                dhRatchetKeyPair: aliceKeyPair,
                remoteDHRatchetKey: bobKeyPair.publicKey,
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumber: 0,
                sessionId: Guid.NewGuid().ToString()
            );

            // Create Bob's receiving session with the same keys
            var bobRatchetSession = new DoubleRatchetSession(
                dhRatchetKeyPair: bobKeyPair,
                remoteDHRatchetKey: aliceKeyPair.publicKey,
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumber: 0,
                sessionId: aliceRatchetSession.SessionId // Same session ID
            );

            // Act
            string originalMessage = "Secure Double Ratchet message";

            // Alice encrypts a message
            var (aliceUpdatedSession, encryptedMessage) = DoubleRatchet.DoubleRatchetEncrypt(
                aliceRatchetSession,
                originalMessage
            );

            // Bob decrypts the message
            var (bobUpdatedSession, decryptedMessage) = DoubleRatchet.DoubleRatchetDecrypt(
                bobRatchetSession,
                encryptedMessage
            );

            // Assert
            Assert.IsNotNull(decryptedMessage);
            Assert.AreEqual(originalMessage, decryptedMessage);
        }

        [TestMethod]
        public void EndToEndSecureMessaging_ShouldMaintainForwardSecrecy()
        {
            // Arrange
            // Generate proper key pairs for Alice and Bob
            var aliceKeyPair = KeyGenerator.GenerateX25519KeyPair();
            var bobKeyPair = KeyGenerator.GenerateX25519KeyPair();

            // Create a shared secret (simulating X3DH)
            byte[] sharedSecret = X3DHExchange.X3DHKeyExchange(bobKeyPair.publicKey, aliceKeyPair.privateKey);

            // Initialize Double Ratchet
            var (rootKey, chainKey) = DoubleRatchetExchange.InitializeDoubleRatchet(sharedSecret);

            // Create Alice's sending session
            var aliceRatchetSession = new DoubleRatchetSession(
                dhRatchetKeyPair: aliceKeyPair,
                remoteDHRatchetKey: bobKeyPair.publicKey,
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumber: 0,
                sessionId: Guid.NewGuid().ToString()
            );

            // Create Bob's receiving session
            var bobRatchetSession = new DoubleRatchetSession(
                dhRatchetKeyPair: bobKeyPair,
                remoteDHRatchetKey: aliceKeyPair.publicKey,
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumber: 0,
                sessionId: aliceRatchetSession.SessionId
            );

            // Multiple message exchange to test ratcheting
            List<string> sentMessages = new List<string>
            {
                "First message",
                "Second message",
                "Third message"
            };

            DoubleRatchetSession currentAliceSession = aliceRatchetSession;
            DoubleRatchetSession currentBobSession = bobRatchetSession;
            List<string> receivedMessages = new List<string>();

            // Act
            foreach (var message in sentMessages)
            {
                // Alice encrypts a message
                var (updatedAliceSession, encryptedMessage) = DoubleRatchet.DoubleRatchetEncrypt(
                    currentAliceSession,
                    message
                );

                // Bob decrypts the message
                var (updatedBobSession, decryptedMessage) = DoubleRatchet.DoubleRatchetDecrypt(
                    currentBobSession,
                    encryptedMessage
                );

                // Update sessions for next message
                currentAliceSession = updatedAliceSession;
                currentBobSession = updatedBobSession;

                // Collect received messages
                receivedMessages.Add(decryptedMessage);
            }

            // Assert
            CollectionAssert.AreEqual(sentMessages, receivedMessages);
        }

        [TestMethod]
        public void ReplayAttackProtection_ShouldPreventMessageReplay()
        {
            // Arrange
            // Generate proper key pairs
            var aliceKeyPair = KeyGenerator.GenerateX25519KeyPair();
            var bobKeyPair = KeyGenerator.GenerateX25519KeyPair();

            // Create a shared secret (simulating X3DH)
            byte[] sharedSecret = X3DHExchange.X3DHKeyExchange(bobKeyPair.publicKey, aliceKeyPair.privateKey);

            // Initialize Double Ratchet
            var (rootKey, chainKey) = DoubleRatchetExchange.InitializeDoubleRatchet(sharedSecret);

            // Create sender's session
            var aliceRatchetSession = new DoubleRatchetSession(
                dhRatchetKeyPair: aliceKeyPair,
                remoteDHRatchetKey: bobKeyPair.publicKey,
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumber: 0,
                sessionId: Guid.NewGuid().ToString()
            );

            // Create receiver's session
            var bobRatchetSession = new DoubleRatchetSession(
                dhRatchetKeyPair: bobKeyPair,
                remoteDHRatchetKey: aliceKeyPair.publicKey,
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumber: 0,
                sessionId: aliceRatchetSession.SessionId
            );

            // Act
            string originalMessage = "Replay protection test";

            // Alice encrypts a message
            var (_, encryptedMessage) = DoubleRatchet.DoubleRatchetEncrypt(
                aliceRatchetSession,
                originalMessage
            );

            // First decryption should succeed
            var (updatedBobSession, firstDecryption) = DoubleRatchet.DoubleRatchetDecrypt(
                bobRatchetSession,
                encryptedMessage
            );

            // Second decryption should fail (replay attack)
            // Note: We use the updated session because it now contains the processed message ID
            var (_, secondDecryption) = DoubleRatchet.DoubleRatchetDecrypt(
                updatedBobSession,
                encryptedMessage
            );

            // Assert
            Assert.IsNotNull(firstDecryption);
            Assert.AreEqual(originalMessage, firstDecryption);
            Assert.IsNull(secondDecryption, "Replay attack was not prevented - message could be decrypted twice");
        }
    }
}