using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using LibEmiddle.Models;
using LibEmiddle.KeyExchange;
using LibEmiddle.Core;
using LibEmiddle.API;
using LibEmiddle.Abstractions;
using LibEmiddle.Domain;
using LibEmiddle.Crypto;

namespace LibEmiddle.Tests.Unit
{
    [TestClass]
    public class X3DHExceptionTests
    {
        private CryptoProvider _cryptoProvider;

        [TestInitialize]
        public void Setup()
        {
            _cryptoProvider = new CryptoProvider();
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void X3DHKeyExchange_NullRecipientKey_ShouldThrowException()
        {
            // Arrange
            KeyPair _identityKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.X25519);
            var senderPrivate = _identityKeyPair.PrivateKey;

            // Act - should throw ArgumentNullException
            X3DHExchange.PerformX25519DH(null, senderPrivate);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void X3DHKeyExchange_NullSenderKey_ShouldThrowException()
        {
            // Arrange
            KeyPair _identityKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.X25519);
            var recipientPublic = _identityKeyPair.PublicKey;

            // Act - should throw ArgumentNullException
            X3DHExchange.PerformX25519DH(recipientPublic, null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void X3DHKeyExchange_InvalidRecipientKeyLength_ShouldThrowException()
        {
            // Arrange
            KeyPair _identityKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.X25519);
            var senderPrivate = _identityKeyPair.PrivateKey;
            byte[] invalidLengthKey = new byte[16]; // Invalid length (should be 32)

            // Act - should throw ArgumentException
            X3DHExchange.PerformX25519DH(invalidLengthKey, senderPrivate);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void X3DHKeyExchange_InvalidSenderKeyLength_ShouldThrowException()
        {
            // Arrange
            KeyPair _identityKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.X25519);
            var recipientPublic = _identityKeyPair.PublicKey;
            byte[] invalidLengthKey = new byte[16]; // Invalid length (should be 32)

            // Act - should throw ArgumentException
            X3DHExchange.PerformX25519DH(recipientPublic, invalidLengthKey);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void InitiateX3DHSession_InvalidSignature_ShouldThrowException()
        {
            // Arrange
            var bobBundle = X3DHExchange.CreateX3DHKeyBundle();
            KeyPair _aliceIdentityKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.X25519);
            var alicePublic = _aliceIdentityKeyPair.PublicKey;
            var alicePrivate = _aliceIdentityKeyPair.PrivateKey;

            // Create a bundle with invalid signature
            var invalidBundle = new X3DHPublicBundle
            {
                IdentityKey = bobBundle.IdentityKey,
                SignedPreKey = bobBundle.SignedPreKey,
                SignedPreKeySignature = new byte[64], // Invalid signature (all zeros)
                OneTimePreKeys = bobBundle.OneTimePreKeys
            };

            // Act - should throw ArgumentException
            X3DHExchange.InitiateX3DHSession(invalidBundle, _aliceIdentityKeyPair, out var usedOneTimePreKeyId);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void InitiateX3DHSession_InvalidPublicKey_ShouldThrowException()
        {
            // Arrange
            var bobBundle = X3DHExchange.CreateX3DHKeyBundle();
            KeyPair _aliceIdentityKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.X25519);

            // Create a bundle with invalid public key
            var invalidBundle = new X3DHPublicBundle
            {
                IdentityKey = bobBundle.IdentityKey,
                SignedPreKey = new byte[32], // Invalid key (all zeros)
                SignedPreKeySignature = bobBundle.SignedPreKeySignature,
                OneTimePreKeys = bobBundle.OneTimePreKeys
            };

            // Act - should throw ArgumentException
            X3DHExchange.InitiateX3DHSession(invalidBundle, _aliceIdentityKeyPair, out var usedOneTimePreKeyId);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void InitiateX3DHSession_MissingRequiredKeys_ShouldThrowException()
        {
            // Arrange
            KeyPair _aliceIdentityKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.X25519);

            // Create a bundle with missing keys
            var invalidBundle = new X3DHPublicBundle
            {
                IdentityKey = null, // Missing identity key
                SignedPreKey = null, // Missing signed pre key
                SignedPreKeySignature = new byte[64],
                OneTimePreKeys = new List<byte[]>()
            };

            // Act - should throw ArgumentException
            X3DHExchange.InitiateX3DHSession(invalidBundle, _aliceIdentityKeyPair, out var usedOneTimePreKeyId);
        }

        [TestMethod]
        public void InitiateX3DHSession_InvalidOneTimePreKeys_ShouldSkipInvalidKeys()
        {
            KeyPair _bobSignKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);

            // Arrange
            var bobBundle = X3DHExchange.CreateX3DHKeyBundle(_bobSignKeyPair);
            
            // Create a bundle with both valid and invalid one-time pre-keys
            List<byte[]> mixedPreKeys = new List<byte[]>();

            // Add some valid keys
            if (bobBundle.OneTimePreKeys != null)
            {
                foreach (var key in bobBundle.OneTimePreKeys)
                {
                    mixedPreKeys.Add(key);
                }
            }

            // Add some invalid keys
            mixedPreKeys.Add(null); // Null key
            mixedPreKeys.Add(new byte[16]); // Wrong length key
            mixedPreKeys.Add(new byte[32]); // All zeros key

            var mixedBundle = new X3DHPublicBundle
            {
                IdentityKey = bobBundle.IdentityKey,
                SignedPreKey = bobBundle.SignedPreKey,
                SignedPreKeySignature = bobBundle.SignedPreKeySignature,
                OneTimePreKeys = mixedPreKeys
            };

            // Act - Should not throw exception, but should skip invalid keys
            var session = X3DHExchange.InitiateX3DHSession(mixedBundle, _bobSignKeyPair, out var usedOneTimePreKeyId);

            // Assert
            Assert.IsNotNull(session, "Session should be created despite invalid pre-keys");
        }

        [TestMethod]
        public void X3DHKeyExchange_ProvidesForwardSecrecy()
        {
            // Arrange - Create an authentic communication channel
            var aliceKeyPair = LibEmiddleClient.GenerateKeyExchangeKeyPair();
            var bobKeyPair = LibEmiddleClient.GenerateKeyExchangeKeyPair();

            var bobBundle = X3DHExchange.CreateX3DHKeyBundle();

            // Generate initial session
            var initialSession = X3DHExchange.InitiateX3DHSession(
                new X3DHPublicBundle
                {
                    IdentityKey = bobBundle.IdentityKey,
                    SignedPreKey = bobBundle.SignedPreKey,
                    SignedPreKeySignature = bobBundle.SignedPreKeySignature,
                    OneTimePreKeys = bobBundle.OneTimePreKeys
                },
                aliceKeyPair,
                out uint? usedOneTimePreKeyId
            );

            // Initialize Double Ratchet root key and chain key
            var rootKey = initialSession.RootKey;
            var chainKey = initialSession.ChainKey;

            // Act
            // Simulate multiple message exchanges with ratchet steps
            byte[] currentRootKey = rootKey;
            byte[] currentChainKey = chainKey;

            // Store message keys for later verification
            List<byte[]> messageKeys = new List<byte[]>();

            // Perform several ratchet steps
            for (int i = 0; i < 5; i++)
            {
                var (newChainKey, messageKey) = DoubleRatchetExchange.RatchetStep(currentChainKey);
                messageKeys.Add(messageKey);
                currentChainKey = newChainKey;

                // Periodically perform DH ratchet step
                if (i % 2 == 1)
                {
                    var ephemeralKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.X25519);
                    var dh = X3DHExchange.PerformX25519DH(bobKeyPair.PublicKey, ephemeralKeyPair.PrivateKey);
                    var (newRootKey, nextChainKey) = DoubleRatchetExchange.DHRatchetStep(currentRootKey, dh);

                    currentRootKey = newRootKey;
                    currentChainKey = nextChainKey;
                }
            }

            // Now simulate compromise of final keys
            byte[] compromisedRootKey = currentRootKey;
            byte[] compromisedChainKey = currentChainKey;

            // Try to derive earlier message keys from compromised keys
            var (_, attemptedMessageKey) = DoubleRatchetExchange.RatchetStep(compromisedChainKey);

            // Assert
            // If forward secrecy is maintained, the derived message key should not match any previous keys
            foreach (var originalKey in messageKeys)
            {
                Assert.IsFalse(SecureMemory.SecureCompare(attemptedMessageKey, originalKey),
                    "Compromised keys should not be able to derive previous message keys");
            }
        }

        [TestMethod]
        public void CreateX3DHKeyBundle_CreatesValidBundle()
        {
            // Ensure the crypto provider is initialized.
            _cryptoProvider.Initialize();

            // Generate an Ed25519 key pair for the identity (used for signing).
            KeyPair identityKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);

            // Act: Create the X3DH bundle.
            var bundle = X3DHExchange.CreateX3DHKeyBundle(identityKeyPair);

            // Assert that the basic bundle fields are present.
            Assert.IsNotNull(bundle, "Bundle should not be null");
            Assert.IsNotNull(bundle.IdentityKey, "Identity key should not be null");
            Assert.IsNotNull(bundle.SignedPreKey, "Signed pre-key should not be null");
            Assert.IsNotNull(bundle.SignedPreKeySignature, "Signature should not be null");
            Assert.IsNotNull(bundle.OneTimePreKeys, "One-time pre-keys should not be null");
            Assert.IsTrue(bundle.OneTimePreKeys.Count > 0, "Bundle should contain at least one pre-key");

            // Assert that private keys are accessible.
            Assert.IsNotNull(bundle.GetIdentityKeyPrivate(), "Private identity key should be accessible");
            Assert.IsNotNull(bundle.GetSignedPreKeyPrivate(), "Private signed pre-key should be accessible");

            // --- Signature Verification ---
            // Verify the signature on the signed pre-key using the identity (Ed25519) public key.
            int verifyResult = Sodium.crypto_sign_ed25519_verify_detached(
                 bundle.SignedPreKeySignature,
                 bundle.SignedPreKey,
                 (ulong)bundle.SignedPreKey.Length,
                 bundle.IdentityKey);

            bool validSignature = (verifyResult == 0);
            Assert.IsTrue(validSignature, "Signature should be valid");

            // Test that clearing private keys works.
            bundle.ClearPrivateKeys();
            Assert.IsNull(bundle.GetIdentityKeyPrivate(), "Private identity key should be cleared");
            Assert.IsNull(bundle.GetSignedPreKeyPrivate(), "Private signed pre-key should be cleared");
        }
    }
}