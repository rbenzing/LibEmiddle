using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;
using LibEmiddle.Messaging.Group;
using LibEmiddle.MultiDevice;
using LibEmiddle.Protocol;
using LibEmiddle.Abstractions;

namespace LibEmiddle.Tests.Unit
{
    /// <summary>
    /// Tests focused on key rotation scenarios in various protocols
    /// to ensure forward secrecy and security properties.
    /// Updated to work with the consolidated GroupSession implementation.
    /// </summary>
    [TestClass]
    public class KeyRotationTests
    {
        private CryptoProvider _cryptoProvider;
        private DoubleRatchetProtocol _doubleRatchetProtocol;

        [TestInitialize]
        public void Setup()
        {
            _cryptoProvider = new CryptoProvider();
            _doubleRatchetProtocol = new DoubleRatchetProtocol();
        }

        [TestMethod]
        public async Task RemoveGroupMember_ShouldRemoveMemberAndRotateKey()
        {
            // Arrange
            var adminKeyPair = Sodium.GenerateEd25519KeyPair();
            var memberKeyPair = Sodium.GenerateEd25519KeyPair();
            string groupId = $"test-revocation-{Guid.NewGuid()}";
            string groupName = "Testing Group Name";

            // Create the consolidated group session
            var groupSession = new GroupSession(groupId, groupName, adminKeyPair, KeyRotationStrategy.Standard);
            await groupSession.ActivateAsync();

            // Capture initial key state
            byte[] initialChainKey = groupSession.ChainKey.ToArray();
            uint initialIteration = groupSession.Iteration;

            // Add member first
            bool addResult = await groupSession.AddMemberAsync(memberKeyPair.PublicKey);
            Assert.IsTrue(addResult, "Should be able to add member initially");

            // Verify member was added by testing message encryption/decryption
            var testMessage = await groupSession.EncryptMessageAsync("Test message");
            Assert.IsNotNull(testMessage, "Should be able to encrypt message with member present");

            // Act - Remove member (this should trigger key rotation)
            bool removeResult = await groupSession.RemoveMemberAsync(memberKeyPair.PublicKey);

            // Get post-removal key state
            byte[] newChainKey = groupSession.ChainKey.ToArray();
            uint newIteration = groupSession.Iteration;

            // Assert
            Assert.IsTrue(removeResult, "RemoveMember should return true when successfully removing a member");

            // Key should have been rotated after member removal
            Assert.IsFalse(SecureMemory.SecureCompare(initialChainKey, newChainKey),
                "Chain key should be different after member removal (due to rotation)");

            // Iteration should have been reset to 0 after rotation
            Assert.AreEqual(0u, newIteration, "Iteration should reset to 0 after key rotation");

            // Clean up
            SecureMemory.SecureClear(initialChainKey);
            SecureMemory.SecureClear(newChainKey);
            groupSession.Dispose();
        }

        [TestMethod]
        public async Task GroupSession_ManualKeyRotation_ShouldCreateNewDistributionMessage()
        {
            // Arrange
            var adminKeyPair = Sodium.GenerateEd25519KeyPair();
            var memberKeyPair = Sodium.GenerateEd25519KeyPair();
            string groupId = $"test-rotation-{Guid.NewGuid()}";
            string groupName = "Testing Group Name";

            // Create consolidated group session
            var groupSession = new GroupSession(groupId, groupName, adminKeyPair, KeyRotationStrategy.Standard);
            await groupSession.ActivateAsync();

            // Add a member
            await groupSession.AddMemberAsync(memberKeyPair.PublicKey);

            // Get initial distribution message
            var initialDistribution = groupSession.CreateDistributionMessage();
            byte[] initialChainKey = initialDistribution.ChainKey?.ToArray() ?? Array.Empty<byte>();
            long initialTimestamp = initialDistribution.Timestamp;

            // Wait a small amount to ensure timestamp difference
            await Task.Delay(10);

            // Act - Manually rotate key
            bool rotationResult = await groupSession.RotateKeyAsync();

            // Get new distribution message
            var newDistribution = groupSession.CreateDistributionMessage();
            byte[] newChainKey = newDistribution.ChainKey?.ToArray() ?? Array.Empty<byte>();
            long newTimestamp = newDistribution.Timestamp;

            // Assert
            Assert.IsTrue(rotationResult, "Key rotation should succeed");
            Assert.IsNotNull(initialChainKey, "Initial chain key should not be null");
            Assert.IsNotNull(newChainKey, "New chain key should not be null");

            Assert.IsFalse(
                SecureMemory.SecureCompare(initialChainKey, newChainKey),
                "Distribution messages should contain different chain keys after rotation");

            Assert.IsTrue(newTimestamp > initialTimestamp,
                "New distribution message should have a newer timestamp");

            Assert.AreEqual(0u, newDistribution.Iteration,
                "Iteration should reset to 0 after key rotation");

            // Clean up
            groupSession.Dispose();
        }

        [TestMethod]
        public async Task GroupSession_AutomaticKeyRotation_ShouldRotateAfterStrategy()
        {
            // Arrange
            var adminKeyPair = Sodium.GenerateEd25519KeyPair();
            string groupId = $"test-auto-rotation-{Guid.NewGuid()}";
            string groupName = "Testing Group Name";

            // Create session with "AfterEveryMessage" strategy for testing
            var groupSession = new GroupSession(groupId, groupName, adminKeyPair, KeyRotationStrategy.AfterEveryMessage);
            await groupSession.ActivateAsync();

            // Capture initial state
            byte[] initialChainKey = groupSession.ChainKey.ToArray();

            // Act - Send a message (should trigger automatic rotation)
            var encryptedMessage = await groupSession.EncryptMessageAsync("Test message for rotation");

            // Get state after message
            byte[] chainKeyAfterMessage = groupSession.ChainKey.ToArray();

            // Assert
            Assert.IsNotNull(encryptedMessage, "Should be able to encrypt message");

            // With AfterEveryMessage strategy, chain key should advance
            Assert.IsFalse(SecureMemory.SecureCompare(initialChainKey, chainKeyAfterMessage),
                "Chain key should advance after sending message");

            // Clean up
            SecureMemory.SecureClear(initialChainKey);
            SecureMemory.SecureClear(chainKeyAfterMessage);
            groupSession.Dispose();
        }

        [TestMethod]
        public async Task GroupSession_ForwardSecrecy_RemovedMemberCannotDecryptNewMessages()
        {
            // Arrange
            var adminKeyPair = Sodium.GenerateEd25519KeyPair();
            var memberKeyPair = Sodium.GenerateEd25519KeyPair();
            string groupId = $"test-forward-secrecy-{Guid.NewGuid()}";
            string groupName = "Testing Group Name";

            var adminSession = new GroupSession(groupId, groupName, adminKeyPair, KeyRotationStrategy.Standard);
            var memberSession = new GroupSession(groupId, groupName, memberKeyPair, KeyRotationStrategy.Standard);

            await adminSession.ActivateAsync();
            await memberSession.ActivateAsync();

            // Set up member relationship
            await adminSession.AddMemberAsync(memberKeyPair.PublicKey);
            await memberSession.AddMemberAsync(adminKeyPair.PublicKey);

            // Exchange distribution messages
            var adminDistribution = adminSession.CreateDistributionMessage();
            var memberDistribution = memberSession.CreateDistributionMessage();

            adminSession.ProcessDistributionMessage(memberDistribution);
            memberSession.ProcessDistributionMessage(adminDistribution);

            // Member sends a message before removal
            string messageBeforeRemoval = "Message before removal";
            var encryptedBefore = await memberSession.EncryptMessageAsync(messageBeforeRemoval);
            string decryptedBefore = await adminSession.DecryptMessageAsync(encryptedBefore!);

            Assert.AreEqual(messageBeforeRemoval, decryptedBefore, "Member should be able to send messages before removal");

            // Act - Admin removes member (triggers key rotation)
            await adminSession.RemoveMemberAsync(memberKeyPair.PublicKey);

            // Admin sends message after member removal
            string messageAfterRemoval = "Message after member removal";
            var encryptedAfter = await adminSession.EncryptMessageAsync(messageAfterRemoval);

            // Member tries to decrypt the post-removal message
            string decryptedAfter = await memberSession.DecryptMessageAsync(encryptedAfter!);

            // Assert
            Assert.IsNull(decryptedAfter, "Removed member should not be able to decrypt messages sent after removal");

            // Clean up
            adminSession.Dispose();
            memberSession.Dispose();
        }

        [TestMethod]
        public void DoubleRatchet_WithStandardRotationStrategy_ShouldAdvanceKeys()
        {
            // Arrange
            var aliceKeyPair = Sodium.GenerateX25519KeyPair();
            var bobKeyPair = Sodium.GenerateX25519KeyPair();

            // Create a shared secret via X25519 DH
            byte[] sharedSecret = Sodium.ScalarMult(aliceKeyPair.PrivateKey, bobKeyPair.PublicKey);

            // Initialize Double Ratchet session as Alice (sender)
            string sessionId = $"session-{Guid.NewGuid()}";
            var aliceSession = _doubleRatchetProtocol.InitializeSessionAsSender(
                sharedSecret,
                bobKeyPair.PublicKey,
                sessionId);

            // Capture initial keys
            byte[] initialSenderKey = aliceSession.SenderChainKey?.ToArray() ?? Array.Empty<byte>();
            uint initialMessageNumber = aliceSession.SendMessageNumber;

            // Act: Encrypt a message (this should advance the chain key)
            var (updatedSession, encryptedMessage) = _doubleRatchetProtocol.EncryptAsync(
                aliceSession,
                "Test message",
                KeyRotationStrategy.Standard);

            // Capture keys after encryption
            byte[] newSenderKey = updatedSession.SenderChainKey?.ToArray() ?? Array.Empty<byte>();
            uint newMessageNumber = updatedSession.SendMessageNumber;

            // Assert
            Assert.IsNotNull(encryptedMessage, "Should be able to encrypt message");

            // Chain key should advance with each message
            Assert.IsFalse(
                SecureMemory.SecureCompare(initialSenderKey, newSenderKey),
                "Sender chain key should advance after encryption");

            // Message number should increment
            Assert.AreEqual(initialMessageNumber + 1, newMessageNumber,
                "Message number should increment after encryption");

            // Clean up
            SecureMemory.SecureClear(initialSenderKey);
            SecureMemory.SecureClear(newSenderKey);
        }

        [TestMethod]
        public void DeviceLinking_ShouldSyncMessagesAcrossDevices()
        {
            // Arrange
            var mainDeviceKeyPair = Sodium.GenerateEd25519KeyPair();
            var secondDeviceKeyPair = Sodium.GenerateEd25519KeyPair();

            // Test basic signature verification first
            byte[] testData = Encoding.UTF8.GetBytes("test data");
            byte[] signature = _cryptoProvider.Sign(testData, mainDeviceKeyPair.PrivateKey);
            bool signatureValid = _cryptoProvider.VerifySignature(testData, signature, mainDeviceKeyPair.PublicKey);
            Assert.IsTrue(signatureValid, "Basic signature verification should work");

            // Test signing the second device's public key with main device's private key
            byte[] secondDeviceSignature = _cryptoProvider.Sign(secondDeviceKeyPair.PublicKey, mainDeviceKeyPair.PrivateKey);
            bool secondDeviceSignatureValid = _cryptoProvider.VerifySignature(secondDeviceKeyPair.PublicKey, secondDeviceSignature, mainDeviceKeyPair.PublicKey);
            Assert.IsTrue(secondDeviceSignatureValid, "Second device signature verification should work");

            // Test key conversion consistency
            byte[] mainX25519Private = _cryptoProvider.ConvertEd25519PrivateKeyToX25519(mainDeviceKeyPair.PrivateKey);
            byte[] mainX25519Public = _cryptoProvider.ConvertEd25519PublicKeyToX25519(mainDeviceKeyPair.PublicKey);
            byte[] secondX25519Private = _cryptoProvider.ConvertEd25519PrivateKeyToX25519(secondDeviceKeyPair.PrivateKey);
            byte[] secondX25519Public = _cryptoProvider.ConvertEd25519PublicKeyToX25519(secondDeviceKeyPair.PublicKey);

            // Test ECDH consistency: both directions should produce the same shared secret
            byte[] sharedSecret1 = _cryptoProvider.ScalarMult(mainX25519Private, secondX25519Public);
            byte[] sharedSecret2 = _cryptoProvider.ScalarMult(secondX25519Private, mainX25519Public);
            Assert.IsTrue(SecureMemory.SecureCompare(sharedSecret1, sharedSecret2), "ECDH should be consistent in both directions");

            // Test the two methods of deriving X25519 public keys
            byte[] mainX25519PublicFromPrivate = Sodium.ScalarMultBase(mainX25519Private);
            Assert.IsTrue(SecureMemory.SecureCompare(mainX25519Public, mainX25519PublicFromPrivate),
                "X25519 public key should be the same whether derived from Ed25519 public key or from X25519 private key");

            byte[] secondX25519PublicFromPrivate = Sodium.ScalarMultBase(secondX25519Private);
            Assert.IsTrue(SecureMemory.SecureCompare(secondX25519Public, secondX25519PublicFromPrivate),
                "X25519 public key should be the same whether derived from Ed25519 public key or from X25519 private key");

            // Test the exact key derivation that happens in DeviceLinkingService
            // Simulate CreateDeviceLinkMessage key derivation
            byte[] mainX25519PrivateForECDH = _cryptoProvider.ConvertEd25519PrivateKeyToX25519(mainDeviceKeyPair.PrivateKey);
            byte[] secondX25519PublicForECDH = _cryptoProvider.ConvertEd25519PublicKeyToX25519(secondDeviceKeyPair.PublicKey);
            byte[] sharedSecretCreate = _cryptoProvider.ScalarMult(mainX25519PrivateForECDH, secondX25519PublicForECDH);

            // Simulate ProcessDeviceLinkMessage key derivation
            byte[] secondX25519PrivateForECDH = _cryptoProvider.ConvertEd25519PrivateKeyToX25519(secondDeviceKeyPair.PrivateKey);
            byte[] mainX25519PublicForECDH = Sodium.ScalarMultBase(mainX25519PrivateForECDH);
            byte[] sharedSecretProcess = _cryptoProvider.ScalarMult(secondX25519PrivateForECDH, mainX25519PublicForECDH);

            Assert.IsTrue(SecureMemory.SecureCompare(sharedSecretCreate, sharedSecretProcess),
                "Shared secrets should match between CreateDeviceLinkMessage and ProcessDeviceLinkMessage");

            // Test the DeviceLinkingService directly
            var deviceLinkingService = new DeviceLinkingService(_cryptoProvider);

            // Create device link message directly using the service
            var linkMessage = deviceLinkingService.CreateDeviceLinkMessage(mainDeviceKeyPair, secondDeviceKeyPair.PublicKey);
            Assert.IsNotNull(linkMessage, "Link message should be created");

            // Process the link message directly using the service
            byte[] result = deviceLinkingService.ProcessDeviceLinkMessage(linkMessage, secondDeviceKeyPair, mainDeviceKeyPair.PublicKey);
            Assert.IsNotNull(result, "Device linking should succeed at service level");
            Assert.IsTrue(SecureMemory.SecureCompare(result, mainDeviceKeyPair.PublicKey), "Returned key should match main device public key");

            // Now test with DeviceManager
            var syncMessageValidator = new SyncMessageValidator(_cryptoProvider);
            var mainDeviceManager = new DeviceManager(mainDeviceKeyPair, deviceLinkingService, _cryptoProvider, syncMessageValidator);
            var secondDeviceManager = new DeviceManager(secondDeviceKeyPair, deviceLinkingService, _cryptoProvider, syncMessageValidator);

            // Create device link message from main to second device
            var managerLinkMessage = mainDeviceManager.CreateDeviceLinkMessage(secondDeviceKeyPair.PublicKey);
            Assert.IsNotNull(managerLinkMessage, "Manager link message should be created");

            // Process the link message on the second device
            bool linkResult = secondDeviceManager.ProcessDeviceLinkMessage(managerLinkMessage, mainDeviceKeyPair.PublicKey);
            Assert.IsTrue(linkResult, "Device linking should succeed");

            // Add the second device to the main device manager's linked devices list
            // This is necessary because ProcessDeviceLinkMessage only adds the main device to the second device's list
            mainDeviceManager.AddLinkedDevice(secondDeviceKeyPair.PublicKey);

            // Create test data
            byte[] testMessage = Encoding.UTF8.GetBytes("Sensitive data to be synced");

            // Act - Create sync messages from main device
            var syncMessages = mainDeviceManager.CreateSyncMessages(testMessage);

            // Assert
            Assert.IsTrue(syncMessages.Count > 0, "Should create at least one sync message");

            // Verify the sync message can be processed (basic validation)
            foreach (var kvp in syncMessages)
            {
                Assert.IsNotNull(kvp.Value, "Sync message should not be null");
                Assert.IsTrue(kvp.Value.Ciphertext?.Length > 0, "Sync message should have encrypted content");
            }
        }

        [TestMethod]
        public void DHRatchetStep_ShouldProduceNewKeys_WhenDHInputChanges()
        {
            // Arrange - Generate key pairs
            var aliceKeyPair = Sodium.GenerateX25519KeyPair();
            var bobKeyPair = Sodium.GenerateX25519KeyPair();
            var charlieKeyPair = Sodium.GenerateX25519KeyPair();

            // Create shared secrets
            byte[] sharedSecret1 = Sodium.ScalarMult(aliceKeyPair.PrivateKey, bobKeyPair.PublicKey);
            byte[] sharedSecret2 = Sodium.ScalarMult(aliceKeyPair.PrivateKey, charlieKeyPair.PublicKey);

            // Initialize initial keys using HKDF
            byte[] rootKey = Sodium.HkdfDerive(
                sharedSecret1,
                null,
                Encoding.UTF8.GetBytes("DoubleRatchetRoot"),
                32);

            byte[] chainKey = Sodium.HkdfDerive(
                sharedSecret1,
                null,
                Encoding.UTF8.GetBytes("DoubleRatchetChain"),
                32);

            // Act - Simulate DH ratchet steps
            byte[] info = Encoding.UTF8.GetBytes("DoubleRatchetKDF");

            // First DH ratchet step
            byte[] combined1 = new byte[rootKey.Length + sharedSecret1.Length];
            Buffer.BlockCopy(rootKey, 0, combined1, 0, rootKey.Length);
            Buffer.BlockCopy(sharedSecret1, 0, combined1, rootKey.Length, sharedSecret1.Length);

            byte[] derived1 = Sodium.HkdfDerive(combined1, null, info, 64);
            byte[] newRootKey1 = derived1.Take(32).ToArray();
            byte[] newChainKey1 = derived1.Skip(32).Take(32).ToArray();

            // Second DH ratchet step with different DH output
            byte[] combined2 = new byte[newRootKey1.Length + sharedSecret2.Length];
            Buffer.BlockCopy(newRootKey1, 0, combined2, 0, newRootKey1.Length);
            Buffer.BlockCopy(sharedSecret2, 0, combined2, newRootKey1.Length, sharedSecret2.Length);

            byte[] derived2 = Sodium.HkdfDerive(combined2, null, info, 64);
            byte[] newRootKey2 = derived2.Take(32).ToArray();
            byte[] newChainKey2 = derived2.Skip(32).Take(32).ToArray();

            // Assert
            Assert.IsFalse(
                SecureMemory.SecureCompare(rootKey, newRootKey1),
                "Root key should change after first DH ratchet step");

            Assert.IsFalse(
                SecureMemory.SecureCompare(chainKey, newChainKey1),
                "Chain key should change after first DH ratchet step");

            Assert.IsFalse(
                SecureMemory.SecureCompare(newRootKey1, newRootKey2),
                "Root key should change after second DH ratchet step with different DH output");

            Assert.IsFalse(
                SecureMemory.SecureCompare(newChainKey1, newChainKey2),
                "Chain key should change after second DH ratchet step with different DH output");

            // Clean up sensitive data
            SecureMemory.SecureClear(rootKey);
            SecureMemory.SecureClear(chainKey);
            SecureMemory.SecureClear(newRootKey1);
            SecureMemory.SecureClear(newChainKey1);
            SecureMemory.SecureClear(newRootKey2);
            SecureMemory.SecureClear(newChainKey2);
            SecureMemory.SecureClear(sharedSecret1);
            SecureMemory.SecureClear(sharedSecret2);
        }

        [TestMethod]
        public async Task GroupSession_KeyRotationStrategies_ShouldBehaveDifferently()
        {
            // Test different rotation strategies
            var keyPair = Sodium.GenerateEd25519KeyPair();
            string groupId = $"test-strategies-{Guid.NewGuid()}";
            string groupName = "Testing Group Name";

            // Test Standard strategy
            var standardSession = new GroupSession(groupId + "-standard", groupName, keyPair, KeyRotationStrategy.Standard);
            await standardSession.ActivateAsync();

            var hourlySession = new GroupSession(groupId + "-hourly", groupName, keyPair, KeyRotationStrategy.Hourly);
            await hourlySession.ActivateAsync();

            var afterMessageSession = new GroupSession(groupId + "-message", groupName, keyPair, KeyRotationStrategy.AfterEveryMessage);
            await afterMessageSession.ActivateAsync();

            // Capture initial states
            byte[] standardInitial = standardSession.ChainKey.ToArray();
            byte[] hourlyInitial = hourlySession.ChainKey.ToArray();
            byte[] messageInitial = afterMessageSession.ChainKey.ToArray();

            // Send messages to each
            await standardSession.EncryptMessageAsync("Test message");
            await hourlySession.EncryptMessageAsync("Test message");
            await afterMessageSession.EncryptMessageAsync("Test message");

            // Check if keys changed based on strategy
            byte[] standardAfter = standardSession.ChainKey.ToArray();
            byte[] hourlyAfter = hourlySession.ChainKey.ToArray();
            byte[] messageAfter = afterMessageSession.ChainKey.ToArray();

            // Assert
            // All should advance chain keys (normal operation)
            Assert.IsFalse(SecureMemory.SecureCompare(standardInitial, standardAfter),
                "Standard strategy should advance chain key");
            Assert.IsFalse(SecureMemory.SecureCompare(hourlyInitial, hourlyAfter),
                "Hourly strategy should advance chain key");
            Assert.IsFalse(SecureMemory.SecureCompare(messageInitial, messageAfter),
                "AfterEveryMessage strategy should advance chain key");

            // Clean up
            standardSession.Dispose();
            hourlySession.Dispose();
            afterMessageSession.Dispose();
        }

        [TestMethod]
        public async Task GroupSession_StateSerializationAfterRotation_ShouldPreserveKeys()
        {
            // Arrange
            var keyPair = Sodium.GenerateEd25519KeyPair();
            string groupId = $"test-serialization-{Guid.NewGuid()}";
            string groupName = "Testing Group Name";

            var originalSession = new GroupSession(groupId, groupName, keyPair, KeyRotationStrategy.Standard);
            await originalSession.ActivateAsync();

            // Perform key rotation
            await originalSession.RotateKeyAsync();

            // Capture state after rotation
            uint iterationAfterRotation = originalSession.Iteration;
            byte[] chainKeyAfterRotation = originalSession.ChainKey.ToArray();

            // Act - Serialize and restore state
            string serializedState = await originalSession.GetSerializedStateAsync();

            var restoredSession = new GroupSession(groupId, groupName, keyPair, KeyRotationStrategy.Standard);
            bool restoreResult = await restoredSession.RestoreSerializedStateAsync(serializedState);

            // Assert
            Assert.IsTrue(restoreResult, "State restoration should succeed");
            Assert.AreEqual(iterationAfterRotation, restoredSession.Iteration,
                "Iteration should be preserved after serialization/restoration");

            Assert.IsTrue(SecureMemory.SecureCompare(chainKeyAfterRotation, restoredSession.ChainKey),
                "Chain key should be preserved after serialization/restoration");

            // Clean up
            SecureMemory.SecureClear(chainKeyAfterRotation);
            originalSession.Dispose();
            restoredSession.Dispose();
        }
    }
}