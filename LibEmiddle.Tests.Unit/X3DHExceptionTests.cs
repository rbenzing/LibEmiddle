using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.Protocol;
using LibEmiddle.Domain.Enums;
using LibEmiddle.Abstractions;

namespace LibEmiddle.Tests.Unit
{
    [TestClass]
    public class X3DHExceptionTests
    {
        private ICryptoProvider _cryptoProvider;
        private IX3DHProtocol _x3dhProtocol;

        [TestInitialize]
        public void Setup()
        {
            _cryptoProvider = new CryptoProvider();
            _x3dhProtocol = new X3DHProtocol(_cryptoProvider);
        }

        [TestCleanup]
        public void Cleanup()
        {
            (_cryptoProvider as IDisposable)?.Dispose();
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void ScalarMult_NullRecipientKey_ShouldThrowException()
        {
            // Arrange
            KeyPair identityKeyPair = Sodium.GenerateX25519KeyPair();
            byte[] senderPrivate = identityKeyPair.PrivateKey;

            // Act - should throw ArgumentNullException
            _cryptoProvider.ScalarMult(null, senderPrivate);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void ScalarMult_NullSenderKey_ShouldThrowException()
        {
            // Arrange
            KeyPair identityKeyPair = Sodium.GenerateX25519KeyPair();
            byte[] recipientPublic = identityKeyPair.PublicKey;

            // Act - should throw ArgumentNullException
            _cryptoProvider.ScalarMult(recipientPublic, null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void ScalarMult_InvalidRecipientKeyLength_ShouldThrowException()
        {
            // Arrange
            KeyPair identityKeyPair = Sodium.GenerateX25519KeyPair();
            byte[] senderPrivate = identityKeyPair.PrivateKey;
            byte[] invalidLengthKey = new byte[16]; // Invalid length (should be 32)

            // Act - should throw ArgumentException
            _cryptoProvider.ScalarMult(invalidLengthKey, senderPrivate);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void ScalarMult_InvalidSenderKeyLength_ShouldThrowException()
        {
            // Arrange
            KeyPair identityKeyPair = Sodium.GenerateX25519KeyPair();
            byte[] recipientPublic = identityKeyPair.PublicKey;
            byte[] invalidLengthKey = new byte[16]; // Invalid length (should be 32)

            // Act - should throw ArgumentException
            _cryptoProvider.ScalarMult(recipientPublic, invalidLengthKey);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public async Task InitiateSessionAsSender_InvalidSignature_ShouldThrowException()
        {
            // Arrange
            var bobBundle = await CreateTestX3DHKeyBundleAsync();
            KeyPair aliceIdentityKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);

            // Create a bundle with invalid signature
            var invalidBundle = new X3DHPublicBundle
            {
                IdentityKey = bobBundle.IdentityKey,
                SignedPreKey = bobBundle.SignedPreKey,
                SignedPreKeyId = bobBundle.SignedPreKeyId,
                SignedPreKeySignature = new byte[64], // Invalid signature (all zeros)
                OneTimePreKeys = bobBundle.OneTimePreKeys,
                OneTimePreKeyIds = bobBundle.OneTimePreKeyIds,
                CreationTimestamp = bobBundle.CreationTimestamp,
                ProtocolVersion = bobBundle.ProtocolVersion
            };

            // Act - should throw ArgumentException
            await _x3dhProtocol.InitiateSessionAsSenderAsync(invalidBundle, aliceIdentityKeyPair);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public async Task InitiateSessionAsSender_InvalidPublicKey_ShouldThrowException()
        {
            // Arrange
            var bobBundle = await CreateTestX3DHKeyBundleAsync();
            KeyPair aliceIdentityKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);

            // Create a bundle with invalid public key
            var invalidBundle = new X3DHPublicBundle
            {
                IdentityKey = bobBundle.IdentityKey,
                SignedPreKey = new byte[32], // Invalid key (all zeros)
                SignedPreKeyId = bobBundle.SignedPreKeyId,
                SignedPreKeySignature = bobBundle.SignedPreKeySignature,
                OneTimePreKeys = bobBundle.OneTimePreKeys,
                OneTimePreKeyIds = bobBundle.OneTimePreKeyIds,
                CreationTimestamp = bobBundle.CreationTimestamp,
                ProtocolVersion = bobBundle.ProtocolVersion
            };

            // Act - should throw ArgumentException
            await _x3dhProtocol.InitiateSessionAsSenderAsync(invalidBundle, aliceIdentityKeyPair);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public async Task InitiateSessionAsSender_MissingRequiredKeys_ShouldThrowException()
        {
            // Arrange
            KeyPair aliceIdentityKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);

            // Create a bundle with missing keys
            var invalidBundle = new X3DHPublicBundle
            {
                IdentityKey = null, // Missing identity key
                SignedPreKey = null, // Missing signed pre key
                SignedPreKeyId = 1,
                SignedPreKeySignature = new byte[64],
                OneTimePreKeys = new List<byte[]>(),
                OneTimePreKeyIds = new List<uint>(),
                CreationTimestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ProtocolVersion = ProtocolVersion.FULL_VERSION
            };

            // Act - should throw ArgumentException
            await _x3dhProtocol.InitiateSessionAsSenderAsync(invalidBundle, aliceIdentityKeyPair);
        }

        [TestMethod]
        public async Task InitiateSessionAsSender_InvalidOneTimePreKeys_ShouldSkipInvalidKeys()
        {
            // Arrange
            KeyPair bobSignKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);

            // Create a test bundle
            var bobBundle = await _x3dhProtocol.CreateKeyBundleAsync(bobSignKeyPair, 5);

            // Create a bundle with both valid and invalid one-time pre-keys
            List<byte[]> mixedPreKeys = new List<byte[]>();
            List<uint> preKeyIds = new List<uint>();

            // Add valid keys from the original bundle
            if (bobBundle.OneTimePreKeys != null && bobBundle.OneTimePreKeyIds != null)
            {
                for (int i = 0; i < bobBundle.OneTimePreKeys.Count; i++)
                {
                    mixedPreKeys.Add(bobBundle.OneTimePreKeys[i]);
                    preKeyIds.Add(bobBundle.OneTimePreKeyIds[i]);
                }
            }

            // Add some invalid keys with corresponding IDs
            byte[] invalidKey1 = new byte[16]; // Wrong length key
            byte[] invalidKey2 = new byte[32]; // All zeros key (invalid for X25519)

            mixedPreKeys.Add(invalidKey1);
            preKeyIds.Add(999);

            mixedPreKeys.Add(invalidKey2);
            preKeyIds.Add(1000);

            var mixedBundle = new X3DHPublicBundle
            {
                IdentityKey = bobBundle.IdentityKey,
                SignedPreKey = bobBundle.SignedPreKey,
                SignedPreKeyId = bobBundle.SignedPreKeyId,
                SignedPreKeySignature = bobBundle.SignedPreKeySignature,
                OneTimePreKeys = mixedPreKeys,
                OneTimePreKeyIds = preKeyIds,
                CreationTimestamp = bobBundle.CreationTimestamp,
                ProtocolVersion = bobBundle.ProtocolVersion
            };

            // Act - Should not throw exception, but should skip invalid keys
            var result = await _x3dhProtocol.InitiateSessionAsSenderAsync(mixedBundle, bobSignKeyPair);

            // Assert
            Assert.IsNotNull(result, "Session result should be created despite invalid pre-keys");
            Assert.IsNotNull(result.SharedKey, "Shared key should be generated");
            Assert.IsNotNull(result.MessageDataToSend, "Message data should be generated");
        }

        [TestMethod]
        public async Task X3DHProtocol_ProvidesForwardSecrecy()
        {
            // Arrange
            // Generate identity key pairs for Alice and Bob
            var aliceKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var bobKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);

            // Create Bob's bundle
            var bobBundle = await _x3dhProtocol.CreateKeyBundleAsync(bobKeyPair);

            // Initialize X3DH session
            var x3dhResult = await _x3dhProtocol.InitiateSessionAsSenderAsync(
                new X3DHPublicBundle
                {
                    IdentityKey = bobBundle.IdentityKey,
                    SignedPreKey = bobBundle.SignedPreKey,
                    SignedPreKeyId = bobBundle.SignedPreKeyId,
                    SignedPreKeySignature = bobBundle.SignedPreKeySignature,
                    OneTimePreKeys = bobBundle.OneTimePreKeys,
                    OneTimePreKeyIds = bobBundle.OneTimePreKeyIds,
                    CreationTimestamp = bobBundle.CreationTimestamp,
                    ProtocolVersion = bobBundle.ProtocolVersion
                },
                aliceKeyPair
            );

            var sessionId = "session-" + Guid.NewGuid().ToString();

            // Initialize Double Ratchet protocol
            var doubleRatchetProtocol = new DoubleRatchetProtocol(_cryptoProvider);
            var initialSession = await doubleRatchetProtocol.InitializeSessionAsSenderAsync(
                x3dhResult.SharedKey,
                bobBundle.SignedPreKey,
                sessionId
            );

            // Act
            // List to store encrypted messages for later verification
            var encryptedMessages = new List<EncryptedMessage>();
            var currentSession = initialSession;

            // Generate a series of encrypted messages
            for (int i = 0; i < 5; i++)
            {
                var message = $"Test message {i}";
                var (updatedSession, encryptedMessage) = await doubleRatchetProtocol.EncryptAsync(
                    currentSession,
                    message,
                    KeyRotationStrategy.Standard
                );

                encryptedMessages.Add(encryptedMessage);
                currentSession = updatedSession;
            }

            // Now simulate key compromise by creating a fresh session with final keys
            var compromisedSession = new DoubleRatchetSession
            {
                SessionId = currentSession.SessionId,
                RootKey = currentSession.RootKey,
                SenderChainKey = currentSession.SenderChainKey,
                ReceiverChainKey = currentSession.ReceiverChainKey,
                SenderRatchetKeyPair = currentSession.SenderRatchetKeyPair,
                ReceiverRatchetPublicKey = currentSession.ReceiverRatchetPublicKey,
                PreviousReceiverRatchetPublicKey = currentSession.PreviousReceiverRatchetPublicKey,
                SendMessageNumber = currentSession.SendMessageNumber,
                ReceiveMessageNumber = currentSession.ReceiveMessageNumber,
                IsInitialized = true,
                CreationTimestamp = currentSession.CreationTimestamp
            };

            // Try to decrypt earlier messages with the compromised session
            // This should fail due to forward secrecy
            bool canDecryptEarlierMessages = false;

            for (int i = 0; i < encryptedMessages.Count - 1; i++)
            {
                try
                {
                    var (_, decryptedMessage) = await doubleRatchetProtocol.DecryptAsync(
                        compromisedSession,
                        encryptedMessages[i]
                    );

                    if (decryptedMessage != null)
                    {
                        canDecryptEarlierMessages = true;
                        break;
                    }
                }
                catch
                {
                    // Exception expected due to forward secrecy
                }
            }

            // Assert
            Assert.IsFalse(canDecryptEarlierMessages, "Compromised keys should not be able to decrypt earlier messages (forward secrecy)");
        }

        [TestMethod]
        public async Task CreateKeyBundle_CreatesValidBundle()
        {
            // Arrange
            // Generate an Ed25519 key pair for the identity (used for signing)
            KeyPair identityKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);

            // Act
            var bundle = await _x3dhProtocol.CreateKeyBundleAsync(identityKeyPair);

            // Assert
            Assert.IsNotNull(bundle, "Bundle should not be null");
            Assert.IsNotNull(bundle.IdentityKey, "Identity key should not be null");
            Assert.IsNotNull(bundle.SignedPreKey, "Signed pre-key should not be null");
            Assert.IsNotNull(bundle.SignedPreKeySignature, "Signature should not be null");
            Assert.IsNotNull(bundle.OneTimePreKeys, "One-time pre-keys should not be null");
            Assert.IsTrue(bundle.OneTimePreKeys.Count > 0, "Bundle should contain at least one pre-key");
            Assert.IsTrue(bundle.SignedPreKeyId > 0, "Signed pre-key ID should be greater than zero");

            // Assert that private keys are accessible
            Assert.IsNotNull(bundle.GetIdentityKeyPrivate(), "Private identity key should be accessible");
            Assert.IsNotNull(bundle.GetSignedPreKeyPrivate(), "Private signed pre-key should be accessible");

            // Verify the signature on the signed pre-key using the identity (Ed25519) public key
            bool validSignature = _cryptoProvider.VerifySignature(
                bundle.SignedPreKey,
                bundle.SignedPreKeySignature,
                bundle.IdentityKey);

            Assert.IsTrue(validSignature, "Signature should be valid");

            // Test that clearing private keys works
            bundle.ClearPrivateKeys();
            Assert.IsNull(bundle.GetIdentityKeyPrivate(), "Private identity key should be cleared");
            Assert.IsNull(bundle.GetSignedPreKeyPrivate(), "Private signed pre-key should be cleared");
        }

        [TestMethod]
        public async Task ValidateKeyBundle_ValidatesSignatures()
        {
            // Arrange
            var bundle = await CreateTestX3DHKeyBundleAsync();

            // Act
            bool isValid = await _x3dhProtocol.ValidateKeyBundleAsync(bundle.ToPublicBundle());

            // Assert
            Assert.IsTrue(isValid, "Valid bundle should pass validation");

            // Modify signature and test again
            var modifiedBundle = new X3DHPublicBundle
            {
                IdentityKey = bundle.IdentityKey,
                SignedPreKey = bundle.SignedPreKey,
                SignedPreKeyId = bundle.SignedPreKeyId,
                SignedPreKeySignature = new byte[64], // Invalid signature (all zeros)
                OneTimePreKeys = bundle.OneTimePreKeys,
                OneTimePreKeyIds = bundle.OneTimePreKeyIds,
                CreationTimestamp = bundle.CreationTimestamp,
                ProtocolVersion = bundle.ProtocolVersion
            };

            bool isInvalidBundleValid = await _x3dhProtocol.ValidateKeyBundleAsync(modifiedBundle);
            Assert.IsFalse(isInvalidBundleValid, "Bundle with invalid signature should fail validation");
        }

        [TestMethod]
        public async Task EstablishSessionAsReceiver_MissingRequiredKeys_ShouldThrowException()
        {
            // Arrange
            var bobBundle = await CreateTestX3DHKeyBundleAsync();

            // Create incomplete initial message data
            var incompleteMessage = new InitialMessageData(
                null, // Missing sender identity key
                await _cryptoProvider.GenerateKeyPairAsync(KeyType.X25519)
                    is KeyPair keyPair ? keyPair.PublicKey : null,
                bobBundle.SignedPreKeyId,
                null
            );

            // Act & Assert
            await Assert.ThrowsExceptionAsync<ArgumentException>(
                async () => await _x3dhProtocol.EstablishSessionAsReceiverAsync(incompleteMessage, bobBundle),
                "Should throw ArgumentException for missing sender identity key"
            );
        }

        #region Helper Methods

        private async Task<X3DHKeyBundle> CreateTestX3DHKeyBundleAsync()
        {
            // Generate an identity key pair
            KeyPair identityKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);

            // Create a complete bundle
            return await _x3dhProtocol.CreateKeyBundleAsync(identityKeyPair, 5);
        }

        #endregion
    }
}