using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Text;
using System.Security.Cryptography;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Protocol;
using LibEmiddle.Domain;

namespace LibEmiddle.Tests.Unit
{
    [TestClass]
    public class KeyExchangeTests
    {
        private CryptoProvider _cryptoProvider;
        private X3DHProtocol _x3DHProtocol;

        [TestInitialize]
        public void Setup()
        {
            _cryptoProvider = new CryptoProvider();
            _x3DHProtocol = new X3DHProtocol(_cryptoProvider);
        }

        [TestMethod]
        public void X3DHKeyExchange_ShouldProduceSameKeyForBothParties()
        {
            // Arrange
            KeyPair _aliceIdentityKeyPair = Sodium.GenerateX25519KeyPair();
            var alicePublic = _aliceIdentityKeyPair.PublicKey;
            var alicePrivate = _aliceIdentityKeyPair.PrivateKey;

            KeyPair _bobIdentityKeyPair = Sodium.GenerateX25519KeyPair();
            var bobPublic = _bobIdentityKeyPair.PublicKey;
            var bobPrivate = _bobIdentityKeyPair.PrivateKey;

            // Act
            byte[] aliceSharedSecret = _cryptoProvider.ScalarMult(alicePrivate, bobPublic);
            byte[] bobSharedSecret = _cryptoProvider.ScalarMult(bobPrivate, alicePublic);

            // Assert
            CollectionAssert.AreEqual(aliceSharedSecret, bobSharedSecret);
        }

        [TestMethod]
        public void CreateX3DHKeyBundle_ShouldReturnValidBundle()
        {
            // Act
            KeyPair _identityKeyPair = Sodium.GenerateEd25519KeyPair();
            var bundle = _x3DHProtocol.CreateKeyBundleAsync(_identityKeyPair).GetAwaiter().GetResult();

            // Assert
            Assert.IsNotNull(bundle);
            Assert.IsNotNull(bundle.IdentityKey);
            Assert.IsNotNull(bundle.SignedPreKey);
            Assert.IsNotNull(bundle.SignedPreKeySignature);
            Assert.IsNotNull(bundle.OneTimePreKeys);
            Assert.IsNotNull(bundle.GetIdentityKeyPrivate());
            Assert.IsNotNull(bundle.GetSignedPreKeyPrivate());
            Assert.IsTrue(bundle.OneTimePreKeys.Count > 0);

            bool validSignature = _cryptoProvider.VerifySignature(
                bundle.SignedPreKey,  // This is the message that was signed
                bundle.SignedPreKeySignature,  // This is the signature
                bundle.IdentityKey    // This is the public key used to verify
            );

            Assert.IsTrue(validSignature);

            // Clean up sensitive data when done
            bundle.ClearPrivateKeys();
        }

        [TestMethod]
        public void InitiateX3DHSession_ShouldReturnValidSessionData()
        {
            // Arrange
            var bobBundle = _x3DHProtocol.CreateKeyBundleAsync().GetAwaiter().GetResult();
            KeyPair _aliceIdentityKeyPair = Sodium.GenerateX25519KeyPair();
            var alicePublic = _aliceIdentityKeyPair.PublicKey;
            var alicePrivate = _aliceIdentityKeyPair.PrivateKey;
            var bobPublicBundle = new X3DHPublicBundle
            {
                IdentityKey = bobBundle.IdentityKey,
                SignedPreKey = bobBundle.SignedPreKey,
                SignedPreKeySignature = bobBundle.SignedPreKeySignature,
                OneTimePreKeys = bobBundle.OneTimePreKeys,
                // Add the missing properties:
                SignedPreKeyId = bobBundle.SignedPreKeyId,
                OneTimePreKeyIds = bobBundle.OneTimePreKeyIds
            };
            // Act
            var session = _x3DHProtocol.InitiateSessionAsSenderAsync(bobPublicBundle, _aliceIdentityKeyPair).GetAwaiter().GetResult();
            // Assert
            Assert.IsNotNull(session);
            Assert.IsNotNull(session.SharedKey);
            Assert.IsNotNull(session.MessageDataToSend);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void InitiateX3DHSession_WithNullBundle_ShouldThrowException()
        {
            // Arrange
            KeyPair _aliceIdentityKeyPair = Sodium.GenerateX25519KeyPair();

            // Act & Assert - Should throw ArgumentNullException
            _x3DHProtocol.InitiateSessionAsSenderAsync(null, _aliceIdentityKeyPair).GetAwaiter().GetResult();
        }

        [TestMethod]
        public void InitiateX3DHSession_WithoutOneTimePreKeys_ShouldStillWork()
        {
            // Arrange
            var bobBundle = _x3DHProtocol.CreateKeyBundleAsync().GetAwaiter().GetResult();
            KeyPair _aliceIdentityKeyPair = Sodium.GenerateX25519KeyPair();
            var bobPublicBundle = new X3DHPublicBundle
            {
                IdentityKey = bobBundle.IdentityKey,
                SignedPreKey = bobBundle.SignedPreKey,
                SignedPreKeySignature = bobBundle.SignedPreKeySignature,
                SignedPreKeyId = bobBundle.SignedPreKeyId, // Make sure this is set
                OneTimePreKeys = null, // No one-time pre-keys available
                OneTimePreKeyIds = null // No one-time pre-key IDs needed
            };

            // Act
            var session = _x3DHProtocol.InitiateSessionAsSenderAsync(bobPublicBundle, _aliceIdentityKeyPair).GetAwaiter().GetResult();

            // Assert
            Assert.IsNotNull(session);
            Assert.IsNotNull(session.SharedKey);
            Assert.IsNotNull(session.MessageDataToSend);
            Assert.IsFalse(session.MessageDataToSend.RecipientOneTimePreKeyId == null, "Should not have used a one-time pre-key");
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void InitiateX3DHSession_WithInvalidSignedPreKey_ShouldThrowException()
        {
            // Arrange
            var bobBundle = _x3DHProtocol.CreateKeyBundleAsync().GetAwaiter().GetResult();
            KeyPair _aliceIdentityKeyPair = Sodium.GenerateX25519KeyPair();

            // Create a bundle with invalid signed pre-key (all zeros)
            var bobPublicBundle = new X3DHPublicBundle
            {
                IdentityKey = bobBundle.IdentityKey,
                SignedPreKey = new byte[Constants.X25519_KEY_SIZE], // All zeros
                SignedPreKeySignature = bobBundle.SignedPreKeySignature,
                OneTimePreKeys = bobBundle.OneTimePreKeys
            };

            // Act & Assert - Should throw ArgumentException
            var sessionResult = _x3DHProtocol.InitiateSessionAsSenderAsync(bobPublicBundle, _aliceIdentityKeyPair).GetAwaiter().GetResult();
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void InitiateX3DHSession_WithInvalidSignature_ShouldThrowException()
        {
            // Arrange
            var bobBundle = _x3DHProtocol.CreateKeyBundleAsync().GetAwaiter().GetResult();
            KeyPair _aliceIdentityKeyPair = Sodium.GenerateX25519KeyPair();

            // Tamper with the signature
            byte[] tamperedSignature = new byte[bobBundle.SignedPreKeySignature.Length];
            Array.Copy(bobBundle.SignedPreKeySignature, tamperedSignature, tamperedSignature.Length);
            if (tamperedSignature.Length > 0)
                tamperedSignature[0] ^= 0xFF; // Flip bits in first byte

            var bobPublicBundle = new X3DHPublicBundle
            {
                IdentityKey = bobBundle.IdentityKey,
                SignedPreKey = bobBundle.SignedPreKey,
                SignedPreKeySignature = tamperedSignature,
                OneTimePreKeys = bobBundle.OneTimePreKeys
            };

            // Act & Assert - Should throw ArgumentException
            var sessionResult = _x3DHProtocol.InitiateSessionAsSenderAsync(bobPublicBundle, _aliceIdentityKeyPair);
        }

        [TestMethod]
        public void X3DHSessionWithUpdatedChainKey_ShouldMaintainCorrectState()
        {
            // Arrange
            var recipientId = Encoding.Default.GetBytes("recipient-id");
            var senderId = Encoding.Default.GetBytes("sender-id");
            var ephemeralKey = new byte[32]; // dummy ephemeral key
            bool usedOneTimePreKey = true;
            byte[] rootKey = new byte[32];
            byte[] originalChainKey = new byte[32];
            byte[] newChainKey = new byte[32];

            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(ephemeralKey);
                rng.GetBytes(rootKey);
                rng.GetBytes(originalChainKey);
                rng.GetBytes(newChainKey);
            }

            // Create a session
            var session = new X3DHSession(
                recipientId,
                senderId,
                ephemeralKey,
                usedOneTimePreKey,
                rootKey,
                originalChainKey);

            // Act - Update chain key
            var updatedSession = session.WithUpdatedChainKey(newChainKey);

            // Assert
            Assert.IsNotNull(updatedSession);
            Assert.AreNotSame(session, updatedSession, "Should be a new object instance");
            CollectionAssert.AreEqual(recipientId, updatedSession.RecipientIdentityKey, "Recipient identity key should be preserved");
            CollectionAssert.AreEqual(senderId, updatedSession.SenderIdentityKey, "Sender identity key should be preserved");
            CollectionAssert.AreEqual(ephemeralKey, updatedSession.EphemeralKey, "Ephemeral key should be preserved");
            Assert.AreEqual(usedOneTimePreKey, updatedSession.UsedOneTimePreKey, "UsedOneTimePreKey flag should be preserved");
            CollectionAssert.AreEqual(rootKey, updatedSession.RootKey, "Root key should be preserved");
            CollectionAssert.AreEqual(newChainKey, updatedSession.ChainKey, "Chain key should be updated");
            CollectionAssert.AreNotEqual(originalChainKey, updatedSession.ChainKey, "Chain key should be different from original");
        }

        [TestMethod]
        public void X3DHSessionWithUpdatedKeys_ShouldMaintainCorrectState()
        {
            // Arrange
            var recipientId = Encoding.Default.GetBytes("recipient-id");
            var senderId = Encoding.Default.GetBytes("sender-id");
            var ephemeralKey = new byte[32]; // dummy ephemeral key
            bool usedOneTimePreKey = true;
            byte[] oldRootKey = new byte[32];
            byte[] oldChainKey = new byte[32];
            byte[] newRootKey = new byte[32];
            byte[] newChainKey = new byte[32];

            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(ephemeralKey);
                rng.GetBytes(oldRootKey);
                rng.GetBytes(oldChainKey);
                rng.GetBytes(newRootKey);
                rng.GetBytes(newChainKey);
            }

            // Create a session
            var session = new X3DHSession(
                recipientId,
                senderId,
                ephemeralKey,
                usedOneTimePreKey,
                oldRootKey,
                oldChainKey);

            // Act - Update both root key and chain key
            var updatedSession = session.WithUpdatedKeys(newRootKey, newChainKey);

            // Assert
            Assert.IsNotNull(updatedSession);
            Assert.AreNotSame(session, updatedSession, "Should be a new object instance");
            CollectionAssert.AreEqual(recipientId, updatedSession.RecipientIdentityKey, "Recipient identity key should be preserved");
            CollectionAssert.AreEqual(senderId, updatedSession.SenderIdentityKey, "Sender identity key should be preserved");
            CollectionAssert.AreEqual(ephemeralKey, updatedSession.EphemeralKey, "Ephemeral key should be preserved");
            Assert.AreEqual(usedOneTimePreKey, updatedSession.UsedOneTimePreKey, "UsedOneTimePreKey flag should be preserved");
            CollectionAssert.AreEqual(newRootKey, updatedSession.RootKey, "Root key should be updated");
            CollectionAssert.AreEqual(newChainKey, updatedSession.ChainKey, "Chain key should be updated");
            CollectionAssert.AreNotEqual(oldRootKey, updatedSession.RootKey, "Root key should be different from original");
            CollectionAssert.AreNotEqual(oldChainKey, updatedSession.ChainKey, "Chain key should be different from original");
        }
    }
}