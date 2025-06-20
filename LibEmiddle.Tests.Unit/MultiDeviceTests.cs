﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Text.Json;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;
using LibEmiddle.MultiDevice;
using LibEmiddle.Abstractions;

namespace LibEmiddle.Tests.Unit
{
    [TestClass]
    public class MultiDeviceTests
    {
        private ICryptoProvider _cryptoProvider;
        private IDeviceLinkingService _deviceLinkingService;

        [TestInitialize]
        public void Setup()
        {
            _cryptoProvider = new CryptoProvider();
            _deviceLinkingService = new DeviceLinkingService(_cryptoProvider);
        }

        [TestCleanup]
        public void Cleanup()
        {
            (_cryptoProvider as IDisposable)?.Dispose();
            (_deviceLinkingService as IDisposable)?.Dispose();
        }

        #region Device Linking Tests

        [TestMethod]
        public void DeriveSharedKeyForNewDevice_ShouldProduceConsistentKey()
        {
            // Arrange
            byte[] existingSharedKey = _cryptoProvider.GenerateRandomBytes(32);
            var newDeviceKeyPair = Sodium.GenerateEd25519KeyPair();
            var publicKey = Sodium.ConvertEd25519PrivateKeyToX25519PublicKey(newDeviceKeyPair.PrivateKey);

            // Act
            byte[] derivedKey1 = _deviceLinkingService.DeriveSharedKeyForNewDevice(
                existingSharedKey, publicKey);

            byte[] derivedKey2 = _deviceLinkingService.DeriveSharedKeyForNewDevice(
                existingSharedKey, publicKey);

            // Assert
            CollectionAssert.AreEqual(derivedKey1, derivedKey2, "Derived keys should be consistent for the same inputs");
        }

        [TestMethod]
        public void CreateDeviceLinkMessage_ShouldCreateValidMessage()
        {
            // Arrange
            var mainDeviceKeyPair = Sodium.GenerateEd25519KeyPair();
            var newDeviceKeyPair = Sodium.GenerateEd25519KeyPair();

            var publicKey = Sodium.ConvertEd25519PrivateKeyToX25519PublicKey(newDeviceKeyPair.PrivateKey);

            // Act
            var encryptedMessage = _deviceLinkingService.CreateDeviceLinkMessage(
                mainDeviceKeyPair, publicKey);

            // Assert
            Assert.IsNotNull(encryptedMessage, "Encrypted message should not be null");
            Assert.IsNotNull(encryptedMessage.Ciphertext, "Ciphertext should not be null");
            Assert.IsNotNull(encryptedMessage.Nonce, "Nonce should not be null");
            Assert.IsTrue(encryptedMessage.Ciphertext.Length > 0, "Ciphertext should not be empty");
            Assert.IsTrue(encryptedMessage.Nonce.Length == Constants.NONCE_SIZE, "Nonce should have the correct size");
        }

        [TestMethod]
        public void ProcessDeviceLinkMessage_WithValidMessage_ShouldReturnMainDevicePublicKey()
        {
            // Arrange
            // Generate key pairs for main device and new device
            var mainDeviceKeyPair = Sodium.GenerateEd25519KeyPair();
            var newDeviceKeyPair = Sodium.GenerateEd25519KeyPair();

            // Create a device link message from the main device to the new device
            // Pass the new device's Ed25519 public key (not the X25519 derived key)
            var encryptedMessage = _deviceLinkingService.CreateDeviceLinkMessage(
                mainDeviceKeyPair,
                newDeviceKeyPair.PublicKey);

            // Act - Pass the main device's Ed25519 public key as the expected key
            byte[] result = _deviceLinkingService.ProcessDeviceLinkMessage(
                encryptedMessage,
                newDeviceKeyPair,
                mainDeviceKeyPair.PublicKey);  // This should be the main device's Ed25519 public key

            // Assert: The method should return the main device's Ed25519 public key
            Assert.IsNotNull(result, "Valid device link message should be processed successfully");
            CollectionAssert.AreEqual(mainDeviceKeyPair.PublicKey, result,
                "The returned main device public key should match the original");
        }

        [TestMethod]
        public void ProcessDeviceLinkMessage_WithInvalidMessage_ShouldReturnNull()
        {
            // Arrange
            // Generate key pairs for main device and new device
            var mainDeviceKeyPair = Sodium.GenerateEd25519KeyPair();
            var newDeviceKeyPair = Sodium.GenerateEd25519KeyPair();
            var unrelatedKeyPair = Sodium.GenerateEd25519KeyPair(); // For tampering

            // Create a device link message from the main device to the new device
            var encryptedMessage = _deviceLinkingService.CreateDeviceLinkMessage(
                mainDeviceKeyPair,
                newDeviceKeyPair.PublicKey);

            // Tamper with the message to simulate an invalid message
            // Create a copy of the encrypted message with corrupted ciphertext
            var tamperedMessage = new EncryptedMessage
            {
                Ciphertext = encryptedMessage.Ciphertext.ToArray(), // Make a copy
                Nonce = encryptedMessage.Nonce.ToArray(),
                SessionId = encryptedMessage.SessionId,
                MessageId = encryptedMessage.MessageId,
                SenderDHKey = encryptedMessage.SenderDHKey?.ToArray(),
                SenderMessageNumber = encryptedMessage.SenderMessageNumber,
                Timestamp = encryptedMessage.Timestamp
            };

            // Modify a byte to corrupt the message
            tamperedMessage.Ciphertext[tamperedMessage.Ciphertext.Length / 2] ^= 0xFF;

            // Act - Pass the wrong public key to simulate wrong main device
            byte[] result = _deviceLinkingService.ProcessDeviceLinkMessage(
                tamperedMessage,  // Use the tampered message
                newDeviceKeyPair,
                unrelatedKeyPair.PublicKey);  // Use unrelated key to simulate wrong device

            // Assert
            Assert.IsNull(result, "Result should be null for an invalid message");
        }

        [TestMethod]
        public void ProcessDeviceLinkMessage_WithNullMessage_ShouldThrowException()
        {
            // Arrange
            var newDeviceKeyPair = Sodium.GenerateEd25519KeyPair();
            var mainDeviceKeyPair = Sodium.GenerateEd25519KeyPair();

            // Act & Assert - Should throw ArgumentNullException
            Assert.ThrowsException<ArgumentNullException>(() => {
                _deviceLinkingService.ProcessDeviceLinkMessage(null, newDeviceKeyPair, mainDeviceKeyPair.PublicKey);
            });
        }

        #endregion

        #region Device Manager Tests

        [TestMethod]
        public void DeviceManager_ShouldCreateValidSyncMessages()
        {
            // Arrange
            var mainDeviceKeyPair = Sodium.GenerateEd25519KeyPair();
            var secondDeviceKeyPair = Sodium.GenerateX25519KeyPair();

            // Create manager
            using var manager = new DeviceManager(mainDeviceKeyPair, _deviceLinkingService, _cryptoProvider);

            // Add the second device
            manager.AddLinkedDevice(secondDeviceKeyPair.PublicKey);

            // Verify the device count
            Assert.AreEqual(1, manager.GetLinkedDeviceCount(), "Should have one linked device");

            // Data to sync
            byte[] syncData = Encoding.Default.GetBytes("This is sync data");

            // Act
            var syncMessages = manager.CreateSyncMessages(syncData);

            // Assert
            Assert.IsNotNull(syncMessages, "Sync messages should not be null");
            Assert.AreEqual(1, syncMessages.Count, "Should create one message for one linked device");

            // Get the first (and only) message without relying on specific dictionary keys
            var message = syncMessages.Values.First();
            Assert.IsNotNull(message.Ciphertext, "Ciphertext should not be null");
            Assert.IsNotNull(message.Nonce, "Nonce should not be null");
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void DeviceManager_AddLinkedDevice_WithNull_ShouldThrowException()
        {
            // Arrange
            var mainDeviceKeyPair = Sodium.GenerateEd25519KeyPair();
            var manager = new DeviceManager(mainDeviceKeyPair, _deviceLinkingService, _cryptoProvider);

            // Act & Assert - Should throw ArgumentNullException
            manager.AddLinkedDevice(null);
        }

        [TestMethod]
        public void DeviceManager_ProcessSyncMessage_ShouldReturnSyncData()
        {
            Trace.TraceWarning("Starting test setup");

            // 1. Generate key pairs
            var mainDeviceKeyPair = Sodium.GenerateEd25519KeyPair();
            var secondDeviceKeyPair = Sodium.GenerateX25519KeyPair();

            Trace.TraceWarning($"Generated keys - Main device pub key length: {mainDeviceKeyPair.PublicKey.Length}, Second device pub key length: {secondDeviceKeyPair.PublicKey.Length}");

            // 2. Create test sync data
            byte[] originalSyncData = Encoding.Default.GetBytes("Test sync data for multi-device processing");
            Trace.TraceWarning($"Created test sync data, length: {originalSyncData.Length}");

            // 3. Set up device managers
            var mainDeviceManager = new DeviceManager(mainDeviceKeyPair, _deviceLinkingService, _cryptoProvider);
            var secondDeviceManager = new DeviceManager(secondDeviceKeyPair, _deviceLinkingService, _cryptoProvider);

            // Link devices to each other
            mainDeviceManager.AddLinkedDevice(secondDeviceKeyPair.PublicKey);
            secondDeviceManager.AddLinkedDevice(mainDeviceKeyPair.PublicKey);

            Trace.TraceWarning("Added linked devices to each manager");

            // 4. Create sync messages from main device
            var syncMessages = mainDeviceManager.CreateSyncMessages(originalSyncData);
            Assert.IsTrue(syncMessages.Count > 0, "Should create at least one sync message");

            // Get the message for the second device - use the first (and only) message since there's only one linked device
            Assert.AreEqual(1, syncMessages.Count, "Should have exactly one sync message");
            var messageForSecondDevice = syncMessages.Values.First();

            Trace.TraceWarning($"Created sync message, ciphertext length: {messageForSecondDevice.Ciphertext?.Length}");

            // 5. Process the sync message on the second device
            byte[] receivedData = secondDeviceManager.ProcessSyncMessage(messageForSecondDevice, mainDeviceKeyPair.PublicKey);

            // Assert
            Assert.IsNotNull(receivedData, "The received sync data should not be null");
            Assert.AreEqual(originalSyncData.Length, receivedData.Length,
                "Received data length should match original sync data length");
            CollectionAssert.AreEqual(originalSyncData, receivedData,
                "The received data should match the original");
        }

        [TestMethod]
        public void DeviceManager_ProcessSyncMessage_WithTamperedMessage_ShouldReturnNull()
        {
            // Arrange
            var mainDeviceKeyPair = Sodium.GenerateEd25519KeyPair();
            var secondDeviceKeyPair = Sodium.GenerateX25519KeyPair();

            // Create managers
            var mainDeviceManager = new DeviceManager(mainDeviceKeyPair, _deviceLinkingService, _cryptoProvider);
            var secondDeviceManager = new DeviceManager(secondDeviceKeyPair, _deviceLinkingService, _cryptoProvider);

            // Link devices
            mainDeviceManager.AddLinkedDevice(secondDeviceKeyPair.PublicKey);
            secondDeviceManager.AddLinkedDevice(mainDeviceKeyPair.PublicKey);

            // Create sync data
            byte[] syncData = Encoding.Default.GetBytes("Sync data that will be tampered with");

            // Main device creates sync messages
            var syncMessages = mainDeviceManager.CreateSyncMessages(syncData);

            // Get the message for the second device - use the first (and only) message since there's only one linked device
            Assert.AreEqual(1, syncMessages.Count, "Should have exactly one sync message");
            var messageForSecondDevice = syncMessages.Values.First();

            // Tamper with the message
            if (messageForSecondDevice.Ciphertext != null && messageForSecondDevice.Ciphertext.Length > 0)
            {
                // Create a copy of the message to avoid modifying the original
                var tamperedMessage = new EncryptedMessage
                {
                    Ciphertext = messageForSecondDevice.Ciphertext.ToArray(),
                    Nonce = messageForSecondDevice.Nonce?.ToArray(),
                    SessionId = messageForSecondDevice.SessionId,
                    MessageId = messageForSecondDevice.MessageId,
                    SenderDHKey = messageForSecondDevice.SenderDHKey?.ToArray(),
                    SenderMessageNumber = messageForSecondDevice.SenderMessageNumber,
                    Timestamp = messageForSecondDevice.Timestamp
                };

                // Tamper with the middle byte
                int middleIndex = tamperedMessage.Ciphertext.Length / 2;
                tamperedMessage.Ciphertext[middleIndex] ^= 0xFF; // Flip bits

                // Act
                byte[] receivedSyncData = secondDeviceManager.ProcessSyncMessage(tamperedMessage, mainDeviceKeyPair.PublicKey);

                // Assert
                Assert.IsNull(receivedSyncData, "Processing a tampered sync message should return null");
            }
            else
            {
                Assert.Fail("Failed to create valid ciphertext for tampering test");
            }
        }

        #endregion

        #region Extended Tests

        [TestMethod]
        public void DeviceManager_MultipleLinkedDevices_ShouldCreateMessagesForAll()
        {
            // Arrange - Create a main device and multiple secondary devices
            var mainDeviceKeyPair = Sodium.GenerateEd25519KeyPair();
            var secondDeviceKeyPair = Sodium.GenerateX25519KeyPair();
            var thirdDeviceKeyPair = Sodium.GenerateX25519KeyPair();
            var fourthDeviceKeyPair = Sodium.GenerateX25519KeyPair();

            // Create device manager for main device
            var mainDeviceManager = new DeviceManager(mainDeviceKeyPair, _deviceLinkingService, _cryptoProvider);

            // Link multiple devices
            mainDeviceManager.AddLinkedDevice(secondDeviceKeyPair.PublicKey);
            mainDeviceManager.AddLinkedDevice(thirdDeviceKeyPair.PublicKey);
            mainDeviceManager.AddLinkedDevice(fourthDeviceKeyPair.PublicKey);

            // Create sync data
            byte[] syncData = Encoding.Default.GetBytes("Test sync data for multiple devices");

            // Act
            var syncMessages = mainDeviceManager.CreateSyncMessages(syncData);

            // Assert
            Assert.IsNotNull(syncMessages, "Sync messages should not be null");
            Assert.AreEqual(3, syncMessages.Count, "Should create messages for all three linked devices");

            // Verify that we have exactly 3 messages without relying on specific dictionary keys
            Assert.AreEqual(3, syncMessages.Count, "Should have exactly three sync messages for the three linked devices");

            // Verify message content
            foreach (var entry in syncMessages)
            {
                Assert.IsNotNull(entry.Value.Ciphertext, "Ciphertext should not be null");
                Assert.IsNotNull(entry.Value.Nonce, "Nonce should not be null");
            }
        }

        [TestMethod]
        public void DeviceManager_RemoveLinkedDevice_ShouldNotCreateMessageForRemovedDevice()
        {
            // Arrange - Create devices
            var mainDeviceKeyPair = Sodium.GenerateEd25519KeyPair();
            var secondDeviceKeyPair = Sodium.GenerateX25519KeyPair();
            var thirdDeviceKeyPair = Sodium.GenerateX25519KeyPair();

            // Create device manager for main device
            var mainDeviceManager = new DeviceManager(mainDeviceKeyPair, _deviceLinkingService, _cryptoProvider);

            // Link devices
            mainDeviceManager.AddLinkedDevice(secondDeviceKeyPair.PublicKey);
            mainDeviceManager.AddLinkedDevice(thirdDeviceKeyPair.PublicKey);

            // Create sync data
            byte[] syncData = Encoding.Default.GetBytes("Test sync data");

            // First verify both devices get messages
            var initialSyncMessages = mainDeviceManager.CreateSyncMessages(syncData);
            Assert.AreEqual(2, initialSyncMessages.Count, "Should initially create messages for both linked devices");

            // Now remove one device
            bool removed = mainDeviceManager.RemoveLinkedDevice(thirdDeviceKeyPair.PublicKey);
            Assert.IsTrue(removed, "Should successfully remove the device");

            // Act
            var syncMessages = mainDeviceManager.CreateSyncMessages(syncData);

            // Assert
            Assert.IsNotNull(syncMessages, "Sync messages should not be null");
            Assert.AreEqual(1, syncMessages.Count, "Should create message only for the second device");

            // Since we know there should be exactly one message and it should be for the second device,
            // we can verify this without relying on the exact dictionary key format
            Assert.AreEqual(1, syncMessages.Count, "Should have exactly one sync message for the remaining device");
        }

        [TestMethod]
        public void DeviceManager_AddSameDeviceMultipleTimes_ShouldOnlyAddOnce()
        {
            // Arrange
            var mainDeviceKeyPair = Sodium.GenerateEd25519KeyPair();
            var secondDeviceKeyPair = Sodium.GenerateX25519KeyPair();

            // Create device manager
            var mainDeviceManager = new DeviceManager(mainDeviceKeyPair, _deviceLinkingService, _cryptoProvider);

            // Add the same device multiple times
            mainDeviceManager.AddLinkedDevice(secondDeviceKeyPair.PublicKey);
            mainDeviceManager.AddLinkedDevice(secondDeviceKeyPair.PublicKey);
            mainDeviceManager.AddLinkedDevice(secondDeviceKeyPair.PublicKey);

            // Create sync data
            byte[] syncData = Encoding.Default.GetBytes("Test sync data for duplicate device");

            // Act
            var syncMessages = mainDeviceManager.CreateSyncMessages(syncData);

            // Assert - With the improved implementation, duplicates are prevented
            Assert.AreEqual(1, syncMessages.Count, "Device manager should prevent duplicate linked devices");

            // Verify the device count
            Assert.AreEqual(1, mainDeviceManager.GetLinkedDeviceCount(), "Should only have one linked device");

            // Verify device is linked
            Assert.IsTrue(mainDeviceManager.IsDeviceLinked(secondDeviceKeyPair.PublicKey), "Device should be linked");
        }

        [TestMethod]
        public void CreateDeviceRevocationMessage_AndVerify_ShouldWork()
        {
            // Arrange
            var identityKeyPair = Sodium.GenerateEd25519KeyPair();
            var deviceToRevokeKeyPair = Sodium.GenerateX25519KeyPair();
            const string revocationReason = "Device compromised";

            // Act - Create revocation message
            var revocationMessage = _deviceLinkingService.CreateDeviceRevocationMessage(
                identityKeyPair,
                deviceToRevokeKeyPair.PublicKey,
                revocationReason);

            // Assert
            Assert.IsNotNull(revocationMessage, "Revocation message should not be null");
            Assert.IsNotNull(revocationMessage.RevokedDevicePublicKey, "Revoked device public key should not be null");
            Assert.IsNotNull(revocationMessage.UserIdentityPublicKey, "User identity public key should not be null");
            Assert.IsNotNull(revocationMessage.Signature, "Signature should not be null");
            Assert.AreEqual(revocationReason, revocationMessage.Reason, "Reason should match");

            // Verify the revocation message
            bool isValid = _deviceLinkingService.VerifyDeviceRevocationMessage(
                revocationMessage,
                identityKeyPair.PublicKey);

            Assert.IsTrue(isValid, "Revocation message should verify as valid");

            // Verify with incorrect key should fail
            var wrongKeyPair = Sodium.GenerateEd25519KeyPair();
            bool isInvalid = _deviceLinkingService.VerifyDeviceRevocationMessage(
                revocationMessage,
                wrongKeyPair.PublicKey);

            Assert.IsFalse(isInvalid, "Verification should fail with wrong key");
        }

        [TestMethod]
        public void ExportAndImportRevocations_ShouldPreserveState()
        {
            // Arrange
            var identityKeyPair = Sodium.GenerateEd25519KeyPair();
            var deviceToRevokeKeyPair = Sodium.GenerateX25519KeyPair();

            // Create a device manager
            var deviceManager = new DeviceManager(identityKeyPair, _deviceLinkingService, _cryptoProvider);

            // Create a revocation message
            var revocationMessage = deviceManager.CreateDeviceRevocationMessage(
                deviceToRevokeKeyPair.PublicKey,
                "Device lost");

            Assert.IsTrue(deviceManager.IsDeviceRevoked(deviceToRevokeKeyPair.PublicKey),
                "Device should be marked as revoked");

            // Export revocations
            string exportedData = deviceManager.ExportRevocations();
            Assert.IsFalse(string.IsNullOrEmpty(exportedData), "Exported data should not be empty");

            // Create a new manager and import
            var newManager = new DeviceManager(identityKeyPair, _deviceLinkingService, _cryptoProvider);
            int importedCount = newManager.ImportRevocations(exportedData);

            // Assert
            Assert.AreEqual(1, importedCount, "Should import one revocation");
            Assert.IsTrue(newManager.IsDeviceRevoked(deviceToRevokeKeyPair.PublicKey),
                "Device should still be revoked after import");
        }

        #endregion
    }
}