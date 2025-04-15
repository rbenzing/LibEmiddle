using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Text;
using System.Security.Cryptography;
using LibEmiddle.API;
using LibEmiddle.KeyExchange;
using LibEmiddle.Models;
using LibEmiddle.Domain;
using LibEmiddle.Abstractions;
using LibEmiddle.Crypto;
using LibEmiddle.Messaging.Transport;

namespace LibEmiddle.Tests.Unit
{
    [TestClass]
    public class KeyExchangeTests
    {
        private CryptoProvider _cryptoProvider;

        [TestInitialize]
        public void Setup()
        {
            _cryptoProvider = new CryptoProvider();
        }

        [TestMethod]
        public void X3DHKeyExchange_ShouldProduceSameKeyForBothParties()
        {
            // Arrange
            KeyPair _aliceIdentityKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.X25519);
            var alicePublic = _aliceIdentityKeyPair.PublicKey;
            var alicePrivate = _aliceIdentityKeyPair.PrivateKey;

            KeyPair _bobIdentityKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.X25519);
            var bobPublic = _bobIdentityKeyPair.PublicKey;
            var bobPrivate = _bobIdentityKeyPair.PrivateKey;

            // Act
            byte[] aliceSharedSecret = X3DHExchange.PerformX25519DH(bobPublic, alicePrivate);
            byte[] bobSharedSecret = X3DHExchange.PerformX25519DH(alicePublic, bobPrivate);

            // Assert
            CollectionAssert.AreEqual(aliceSharedSecret, bobSharedSecret);
        }

        [TestMethod]
        public void CreateX3DHKeyBundle_ShouldReturnValidBundle()
        {
            // Act
            var bundle = X3DHExchange.CreateX3DHKeyBundle();

            // Assert
            Assert.IsNotNull(bundle);
            Assert.IsNotNull(bundle.IdentityKey);
            Assert.IsNotNull(bundle.SignedPreKey);
            Assert.IsNotNull(bundle.SignedPreKeySignature);
            Assert.IsNotNull(bundle.OneTimePreKeys);
            Assert.IsNotNull(bundle.GetIdentityKeyPrivate());
            Assert.IsNotNull(bundle.GetSignedPreKeyPrivate());
            Assert.IsTrue(bundle.OneTimePreKeys.Count > 0);

            // The issue is in the parameter order - the first parameter should be the message (SignedPreKey in this case)
            // In the KeyAuth class and MessageSigning class, the order is:
            // (message, signature, publicKey) not (signature, message, publicKey)
            bool validSignature = _cryptoProvider.Verify(
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
            var bobBundle = X3DHExchange.CreateX3DHKeyBundle();
            KeyPair _aliceIdentityKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.X25519);
            var alicePublic = _aliceIdentityKeyPair.PublicKey;
            var alicePrivate = _aliceIdentityKeyPair.PrivateKey;

            var bobPublicBundle = new X3DHPublicBundle
            {
                IdentityKey = bobBundle.IdentityKey,
                SignedPreKey = bobBundle.SignedPreKey,
                SignedPreKeySignature = bobBundle.SignedPreKeySignature,
                OneTimePreKeys = bobBundle.OneTimePreKeys
            };

            // Act
            var session = X3DHExchange.InitiateX3DHSession(bobPublicBundle, _aliceIdentityKeyPair, out var usedOneTimePreKeyId);

            // Assert
            Assert.IsNotNull(session);
            Assert.IsNotNull(session.RootKey);
            Assert.IsNotNull(session.ChainKey);
            CollectionAssert.AreEqual(bobBundle.IdentityKey, session.RecipientIdentityKey);
            CollectionAssert.AreEqual(alicePublic, session.SenderIdentityKey);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void InitiateX3DHSession_WithNullBundle_ShouldThrowException()
        {
            // Arrange
            KeyPair _aliceIdentityKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.X25519);
            
            // Act & Assert - Should throw ArgumentNullException
            X3DHExchange.InitiateX3DHSession(null, _aliceIdentityKeyPair, out var usedOneTimePreKeyId);
        }

        [TestMethod]
        public void InitiateX3DHSession_WithoutOneTimePreKeys_ShouldStillWork()
        {
            // Arrange
            var bobBundle = X3DHExchange.CreateX3DHKeyBundle();
            KeyPair _aliceIdentityKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.X25519);

            var bobPublicBundle = new X3DHPublicBundle
            {
                IdentityKey = bobBundle.IdentityKey,
                SignedPreKey = bobBundle.SignedPreKey,
                SignedPreKeySignature = bobBundle.SignedPreKeySignature,
                OneTimePreKeys = null // No one-time pre-keys available
            };

            // Act
            var session = X3DHExchange.InitiateX3DHSession(bobPublicBundle, _aliceIdentityKeyPair, out var usedOneTimePreKeyId);

            // Assert
            Assert.IsNotNull(session);
            Assert.IsNotNull(session.RootKey);
            Assert.IsNotNull(session.ChainKey);
            Assert.IsFalse(session.UsedOneTimePreKey, "Should not have used a one-time pre-key");
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void InitiateX3DHSession_WithInvalidSignedPreKey_ShouldThrowException()
        {
            // Arrange
            var bobBundle = X3DHExchange.CreateX3DHKeyBundle();
            KeyPair _aliceIdentityKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.X25519);

            // Create a bundle with invalid signed pre-key (all zeros)
            var bobPublicBundle = new X3DHPublicBundle
            {
                IdentityKey = bobBundle.IdentityKey,
                SignedPreKey = new byte[Constants.X25519_KEY_SIZE], // All zeros
                SignedPreKeySignature = bobBundle.SignedPreKeySignature,
                OneTimePreKeys = bobBundle.OneTimePreKeys
            };

            // Act & Assert - Should throw ArgumentException
            X3DHExchange.InitiateX3DHSession(bobPublicBundle, _aliceIdentityKeyPair, out var usedOneTimePreKeyId);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void InitiateX3DHSession_WithInvalidSignature_ShouldThrowException()
        {
            // Arrange
            var bobBundle = X3DHExchange.CreateX3DHKeyBundle();
            KeyPair _aliceIdentityKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.X25519);

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
            X3DHExchange.InitiateX3DHSession(bobPublicBundle, _aliceIdentityKeyPair, out var usedOneTimePreKeyId);
        }

        [TestMethod]
        public void X3DHSessionWithUpdatedChainKey_ShouldMaintainCorrectState()
        {
            // Arrange
            var recipientId = Encoding.UTF8.GetBytes("recipient-id");
            var senderId = Encoding.UTF8.GetBytes("sender-id");
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
            var recipientId = Encoding.UTF8.GetBytes("recipient-id");
            var senderId = Encoding.UTF8.GetBytes("sender-id");
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