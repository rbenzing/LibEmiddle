using System;
using System.Security.Cryptography;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using LibEmiddle.MultiDevice;
using LibEmiddle.Core;
using LibEmiddle.KeyExchange;
using LibEmiddle.Models;
using System.Linq;
using System.Collections.Generic;
using System.Text.Json;
using System.Diagnostics;
using LibEmiddle.Abstractions;
using LibEmiddle.Messaging.Transport;
using LibEmiddle.Domain;
using LibEmiddle.Crypto;

namespace LibEmiddle.Tests.Unit
{
    [TestClass]
    public class MultiDeviceTests
    {
        private CryptoProvider _cryptoProvider;

        [TestInitialize]
        public void Setup()
        {
            _cryptoProvider = new CryptoProvider();
        }

        #region Device Linking Tests

        [TestMethod]
        public void DeriveSharedKeyForNewDevice_ShouldProduceConsistentKey()
        {
            // Arrange
            byte[] existingSharedKey = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(existingSharedKey);
            }

            var newDeviceKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);

            // Act
            byte[] derivedKey1 = DeviceLinking.DeriveSharedKeyForNewDevice(
                existingSharedKey, newDeviceKeyPair.PublicKey);

            byte[] derivedKey2 = DeviceLinking.DeriveSharedKeyForNewDevice(
                existingSharedKey, newDeviceKeyPair.PublicKey);

            // Assert
            Assert.IsTrue(TestsHelpers.AreByteArraysEqual(derivedKey1, derivedKey2));
        }

        [TestMethod]
        public void CreateDeviceLinkMessage_ShouldCreateValidMessage()
        {
            // Arrange
            var mainDeviceKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);
            var newDeviceKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);

            // Act
            var encryptedMessage = DeviceLinking.CreateDeviceLinkMessage(
                mainDeviceKeyPair, newDeviceKeyPair.PublicKey);

            // Assert
            Assert.IsNotNull(encryptedMessage);
            Assert.IsNotNull(encryptedMessage.Ciphertext);
            Assert.IsNotNull(encryptedMessage.Nonce);
        }

        [TestMethod]
        public void ProcessDeviceLinkMessage_WithValidMessage_ShouldWorkWithImplementation()
        {
            // Arrange
            // Generate key pairs for main device and new device
            var mainDeviceKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);
            var newDeviceKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);

            // Create a device link message from the main device to the new device
            var encryptedMessage = DeviceLinking.CreateDeviceLinkMessage(
                mainDeviceKeyPair,
                newDeviceKeyPair.PublicKey);

            // Act
            byte[] result = DeviceLinking.ProcessDeviceLinkMessage(
                encryptedMessage,
                newDeviceKeyPair,
                mainDeviceKeyPair.PublicKey);

            // Assert: With our updated implementation, a valid message returns the main device's Ed25519 public key.
            Assert.IsNotNull(result, "Valid device link message should be processed successfully.");
            Assert.IsTrue(TestsHelpers.AreByteArraysEqual(result, mainDeviceKeyPair.PublicKey),
                "The returned main device public key should match the original.");
        }

        [TestMethod]
        public void ProcessDeviceLinkMessage_WithInvalidMessage_ShouldReturnNull()
        {
            // Arrange
            // Generate key pairs for main device and new device
            var mainDeviceKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);
            var newDeviceKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);
            var unrelatedKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519); // For tampering

            // Create a device link message from the main device to the new device
            var encryptedMessage = DeviceLinking.CreateDeviceLinkMessage(
                mainDeviceKeyPair,
                newDeviceKeyPair.PublicKey);

            // Tamper with the message to simulate an invalid message
            // Create a copy of the encrypted message with corrupted ciphertext
            var tamperedMessage = new EncryptedMessage
            {
                Ciphertext = new byte[encryptedMessage.Ciphertext.Length],
                Nonce = encryptedMessage.Nonce
            };

            // Copy the ciphertext and then tamper with it
            Buffer.BlockCopy(encryptedMessage.Ciphertext, 0, tamperedMessage.Ciphertext, 0, encryptedMessage.Ciphertext.Length);
            // Modify a byte to corrupt the message
            tamperedMessage.Ciphertext[tamperedMessage.Ciphertext.Length / 2] ^= 0xFF;

            // Act - Pass the wrong public key (unrelatedKeyPair) to simulate wrong main device
            byte[] result = DeviceLinking.ProcessDeviceLinkMessage(
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
            var newDeviceKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);
            var mainDeviceKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);

            // Act & Assert - Should throw ArgumentNullException
            Assert.ThrowsException<ArgumentNullException>(() => {
                DeviceLinking.ProcessDeviceLinkMessage(null, newDeviceKeyPair, mainDeviceKeyPair.PublicKey);
            });
        }

        #endregion

        #region Device Manager Tests

        [TestMethod]
        public void MultiDeviceManager_ShouldCreateValidSyncMessages()
        {
            // Arrange
            var mainDeviceKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);
            var secondDeviceKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);

            // Derive X25519 keys for the second device
            byte[] secondDeviceX25519Private = _cryptoProvider.DeriveX25519PrivateKeyFromEd25519(secondDeviceKeyPair.PrivateKey);
            byte[] secondDeviceX25519Public = SecureMemory.CreateSecureBuffer(Constants.X25519_KEY_SIZE);
            Sodium.ComputePublicKey(secondDeviceX25519Public, secondDeviceX25519Private);

            // Validate the derived X25519 public key
            bool isValid = _cryptoProvider.ValidateX25519PublicKey(secondDeviceX25519Public);
            Assert.IsTrue(isValid, "The X25519 public key should be valid");

            // Create manager
            var manager = new DeviceManager(mainDeviceKeyPair);

            // Add the X25519 public key
            manager.AddLinkedDevice(secondDeviceX25519Public);

            // Data to sync
            byte[] syncData = Encoding.UTF8.GetBytes("This is sync data");

            // Act
            var syncMessages = manager.CreateSyncMessages(syncData);

            // Assert
            Assert.IsNotNull(syncMessages);
            Assert.AreEqual(1, syncMessages.Count);
            string deviceId = Convert.ToBase64String(secondDeviceX25519Public);
            Assert.IsTrue(syncMessages.ContainsKey(deviceId));
            var message = syncMessages[deviceId];
            Assert.IsNotNull(message.Ciphertext);
            Assert.IsNotNull(message.Nonce);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void MultiDeviceManager_AddLinkedDevice_WithNull_ShouldThrowException()
        {
            // Arrange
            var mainDeviceKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);
            var manager = new DeviceManager(mainDeviceKeyPair);

            // Act & Assert - Should throw ArgumentNullException
            manager.AddLinkedDevice(null);
        }

        [TestMethod]
        public void MultiDeviceManager_ProcessSyncMessage_ShouldReturnSyncData()
        {
            Trace.TraceWarning("Starting test setup");

            // 1. Generate key pairs: main device uses an Ed25519 key pair for signing;
            // second device can use X25519 for key agreement.
            var mainDeviceKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);
            var secondDeviceKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.X25519);

            Trace.TraceWarning($"Generated keys - Main device pub key length: {mainDeviceKeyPair.PublicKey.Length}, Second device pub key length: {secondDeviceKeyPair.PublicKey.Length}");

            string mainDeviceKeyBase64 = Convert.ToBase64String(mainDeviceKeyPair.PublicKey);
            string secondDeviceKeyBase64 = Convert.ToBase64String(secondDeviceKeyPair.PublicKey);
            Trace.TraceWarning($"Main device key (Base64) length: {mainDeviceKeyBase64.Length}");
            Trace.TraceWarning($"Second device key (Base64) length: {secondDeviceKeyBase64.Length}");

            // 2. Create our test sync data
            byte[] originalSyncData = Encoding.UTF8.GetBytes("Test sync data for multi-device processing");
            Trace.TraceWarning($"Created test sync data, length: {originalSyncData.Length}");

            // 3. Manually create and process the sync message with signing
            Trace.TraceWarning("Creating sync message manually for better debugging...");

            try
            {
                // Sign the sync data using the main device's private signing key (Ed25519)
                byte[] signature = MessageSigning.SignMessage(originalSyncData, mainDeviceKeyPair.PrivateKey);
                Trace.TraceWarning($"Created signature, length: {signature.Length}");

                // Create the sync message JSON manually
                var syncMessage = new
                {
                    senderPublicKey = Convert.ToBase64String(mainDeviceKeyPair.PublicKey),
                    data = Convert.ToBase64String(originalSyncData),
                    signature = Convert.ToBase64String(signature),
                    timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    protocolVersion = "LibEmiddle/v1.0"
                };

                // Serialize to JSON string
                string jsonMessage = JsonSerializer.Serialize(syncMessage);
                Trace.TraceWarning($"Serialized JSON message, length: {jsonMessage.Length}");

                // Convert to X25519 keys
                byte[] secondDeviceX25519Private = _cryptoProvider.DeriveX25519PrivateKeyFromEd25519(secondDeviceKeyPair.PrivateKey);
                byte[] secondDeviceX25519Public = SecureMemory.CreateSecureBuffer(Constants.X25519_KEY_SIZE); 
                Sodium.ComputePublicKey(secondDeviceX25519Public, secondDeviceX25519Private);
                byte[] mainDeviceX25519Public = SecureMemory.CreateSecureBuffer(Constants.X25519_KEY_SIZE); 
                Sodium.ComputePublicKey(mainDeviceX25519Public, _cryptoProvider.DeriveX25519PrivateKeyFromEd25519(mainDeviceKeyPair.PrivateKey));

                // Now manually perform X3DH key exchange for encryption between devices
                byte[] sharedSecret = X3DHExchange.PerformX25519DH(
                    secondDeviceX25519Public,
                    mainDeviceX25519Public);
                Trace.TraceWarning($"Performed X3DH key exchange, shared secret length: {sharedSecret.Length}");

                // Encrypt the message with AES using the shared secret
                byte[] nonce = _cryptoProvider.GenerateNonce();
                byte[] messageBytes = Encoding.UTF8.GetBytes(jsonMessage);
                byte[] ciphertext = _cryptoProvider.Encrypt(messageBytes, sharedSecret, nonce);
                Trace.TraceWarning($"Encrypted message, ciphertext length: {ciphertext.Length}");

                // Create the encrypted message
                var encryptedMessage = new EncryptedMessage
                {
                    Ciphertext = ciphertext,
                    Nonce = nonce,
                    SenderDHKey = mainDeviceKeyPair.PublicKey,
                    Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    MessageId = Guid.NewGuid()
                };

                // Verify we can decrypt it manually
                Trace.TraceWarning("Verifying manual decryption works...");
                byte[] sharedSecret2 = X3DHExchange.PerformX25519DH(
                    mainDeviceKeyPair.PublicKey,
                    secondDeviceKeyPair.PrivateKey);
                byte[] decryptedBytes = _cryptoProvider.Decrypt(encryptedMessage.Ciphertext, sharedSecret2, encryptedMessage.Nonce);
                string decryptedJson = Encoding.UTF8.GetString(decryptedBytes);
                Trace.TraceWarning($"Decrypted JSON successfully.");

                // Parse the decrypted JSON and verify fields, signature, etc.
                var parsedMessage = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(decryptedJson);
                string senderKeyBase64 = parsedMessage["senderPublicKey"].GetString();
                string dataBase64 = parsedMessage["data"].GetString();
                string sigBase64 = parsedMessage["signature"].GetString();

                byte[] extractedSenderKey = Convert.FromBase64String(senderKeyBase64);
                byte[] extractedData = Convert.FromBase64String(dataBase64);
                byte[] extractedSignature = Convert.FromBase64String(sigBase64);
                bool signatureValid = MessageSigning.VerifySignature(extractedData, extractedSignature, extractedSenderKey);
                Trace.TraceWarning($"Signature verification result: {signatureValid}");
                bool dataMatches = originalSyncData.SequenceEqual(extractedData);
                Trace.TraceWarning($"Extracted data matches original: {dataMatches}");

                // Now test with the DeviceManager
                Trace.TraceWarning("\nNow testing with DeviceManager...");
                var mainDeviceManager = new DeviceManager(new KeyPair(mainDeviceKeyPair.PublicKey, mainDeviceKeyPair.PrivateKey));
                var secondDeviceManager = new DeviceManager(new KeyPair(secondDeviceKeyPair.PublicKey, secondDeviceKeyPair.PrivateKey));
                mainDeviceManager.AddLinkedDevice(secondDeviceKeyPair.PublicKey);
                secondDeviceManager.AddLinkedDevice(mainDeviceKeyPair.PublicKey);
                Trace.TraceWarning($"Second device linked device count: {secondDeviceManager.GetLinkedDeviceCount()}");

                byte[] receivedData = secondDeviceManager.ProcessSyncMessage(encryptedMessage, mainDeviceKeyPair.PublicKey);

                if (receivedData != null)
                {
                    Trace.TraceWarning($"Successfully processed with DeviceManager, received data length: {receivedData.Length}");
                }
                else
                {
                    Trace.TraceWarning("DeviceManager.ProcessSyncMessage returned null");
                }

                Assert.IsNotNull(receivedData, "The received sync data should not be null");
                Assert.AreEqual(originalSyncData.Length, receivedData.Length,
                    $"Received data length should match original sync data length");
                CollectionAssert.AreEqual(originalSyncData, receivedData,
                    "The received data should match the original");
            }
            catch (Exception ex)
            {
                Trace.TraceWarning($"Exception during test: {ex.Message}");
                Trace.TraceWarning(ex.StackTrace);
                throw;
            }
        }

        [TestMethod]
        public void MultiDeviceManager_ProcessSyncMessage_WithTamperedMessage_ShouldReturnNull()
        {
            // Arrange
            var mainDeviceKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);
            var secondDeviceKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);

            // Convert to X25519 keys
            byte[] secondDeviceX25519Private = _cryptoProvider.DeriveX25519PrivateKeyFromEd25519(secondDeviceKeyPair.PrivateKey);
            byte[] secondDeviceX25519Public = SecureMemory.CreateSecureBuffer(Constants.X25519_KEY_SIZE); 
            Sodium.ComputePublicKey(secondDeviceX25519Public, secondDeviceX25519Private);
            byte[] mainDeviceX25519Public = SecureMemory.CreateSecureBuffer(Constants.X25519_KEY_SIZE); 
            Sodium.ComputePublicKey(mainDeviceX25519Public, _cryptoProvider.DeriveX25519PrivateKeyFromEd25519(mainDeviceKeyPair.PrivateKey));

            // Create managers
            var mainDeviceManager = new DeviceManager(mainDeviceKeyPair);
            var secondDeviceManager = new DeviceManager(secondDeviceKeyPair);

            // Link devices
            mainDeviceManager.AddLinkedDevice(secondDeviceX25519Public);
            secondDeviceManager.AddLinkedDevice(mainDeviceX25519Public);

            // Create sync data
            byte[] syncData = Encoding.UTF8.GetBytes("Sync data that will be tampered with");

            // Main device creates sync messages
            var syncMessages = mainDeviceManager.CreateSyncMessages(syncData);
            var messageForSecondDevice = syncMessages[Convert.ToBase64String(secondDeviceX25519Public)];

            // Tamper with the message
            if (messageForSecondDevice.Ciphertext != null && messageForSecondDevice.Ciphertext.Length > 0)
            {
                int middleIndex = messageForSecondDevice.Ciphertext.Length / 2;
                messageForSecondDevice.Ciphertext[middleIndex] ^= 0xFF; // Flip bits
            }

            // Act
            byte[] receivedSyncData = secondDeviceManager.ProcessSyncMessage(messageForSecondDevice, mainDeviceX25519Public);

            // Assert
            Assert.IsNull(receivedSyncData, "Processing a tampered sync message should return null");
        }

        #endregion

        #region Extended

        [TestMethod]
        public void DeviceManager_MultipleLinkedDevices_ShouldCreateMessagesForAll()
        {
            // Arrange - Create a main device and multiple secondary devices
            var mainDeviceKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);
            var secondDeviceKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);
            var thirdDeviceKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);
            var fourthDeviceKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);

            // Create X25519 keys for each device for linking
            byte[] secondDeviceX25519Public = SecureMemory.CreateSecureBuffer(Constants.X25519_KEY_SIZE); 
            Sodium.ComputePublicKey(
                secondDeviceX25519Public,
                _cryptoProvider.DeriveX25519PrivateKeyFromEd25519(secondDeviceKeyPair.PrivateKey));
            byte[] thirdDeviceX25519Public = SecureMemory.CreateSecureBuffer(Constants.X25519_KEY_SIZE); 
            Sodium.ComputePublicKey(
                thirdDeviceX25519Public,
                _cryptoProvider.DeriveX25519PrivateKeyFromEd25519(thirdDeviceKeyPair.PrivateKey));
            byte[] fourthDeviceX25519Public = SecureMemory.CreateSecureBuffer(Constants.X25519_KEY_SIZE); 
            Sodium.ComputePublicKey(
                fourthDeviceX25519Public,
                _cryptoProvider.DeriveX25519PrivateKeyFromEd25519(fourthDeviceKeyPair.PrivateKey));

            // Create device manager for main device
            var mainDeviceManager = new DeviceManager(mainDeviceKeyPair);

            // Link multiple devices
            mainDeviceManager.AddLinkedDevice(secondDeviceX25519Public);
            mainDeviceManager.AddLinkedDevice(thirdDeviceX25519Public);
            mainDeviceManager.AddLinkedDevice(fourthDeviceX25519Public);

            // Create sync data
            byte[] syncData = Encoding.UTF8.GetBytes("Test sync data for multiple devices");

            // Act
            var syncMessages = mainDeviceManager.CreateSyncMessages(syncData);

            // Assert
            Assert.IsNotNull(syncMessages, "Sync messages should not be null");
            Assert.AreEqual(3, syncMessages.Count, "Should create messages for all three linked devices");

            // Check that all devices have messages
            string secondDeviceId = Convert.ToBase64String(secondDeviceX25519Public);
            string thirdDeviceId = Convert.ToBase64String(thirdDeviceX25519Public);
            string fourthDeviceId = Convert.ToBase64String(fourthDeviceX25519Public);

            Assert.IsTrue(syncMessages.ContainsKey(secondDeviceId), "Should contain message for second device");
            Assert.IsTrue(syncMessages.ContainsKey(thirdDeviceId), "Should contain message for third device");
            Assert.IsTrue(syncMessages.ContainsKey(fourthDeviceId), "Should contain message for fourth device");

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
            // This test verifies that if we had a way to remove linked devices,
            // messages wouldn't be created for them

            // Arrange - Create devices
            var mainDeviceKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);
            var secondDeviceKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);
            var thirdDeviceKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);

            // Create X25519 keys for each device for linking
            byte[] secondDeviceX25519Public = SecureMemory.CreateSecureBuffer(Constants.X25519_KEY_SIZE); 
            Sodium.ComputePublicKey(
                secondDeviceX25519Public,
                _cryptoProvider.DeriveX25519PrivateKeyFromEd25519(secondDeviceKeyPair.PrivateKey));
            byte[] thirdDeviceX25519Public = SecureMemory.CreateSecureBuffer(Constants.X25519_KEY_SIZE); 
            Sodium.ComputePublicKey(
                thirdDeviceX25519Public,
                _cryptoProvider.DeriveX25519PrivateKeyFromEd25519(thirdDeviceKeyPair.PrivateKey));

            // Create device manager for main device
            var mainDeviceManager = new DeviceManager(mainDeviceKeyPair);

            // Link devices
            mainDeviceManager.AddLinkedDevice(secondDeviceX25519Public);
            mainDeviceManager.AddLinkedDevice(thirdDeviceX25519Public);

            // Create sync data
            byte[] syncData = Encoding.UTF8.GetBytes("Test sync data");

            // First verify both devices get messages
            var initialSyncMessages = mainDeviceManager.CreateSyncMessages(syncData);
            Assert.AreEqual(2, initialSyncMessages.Count, "Should initially create messages for both linked devices");

            // Create a new DeviceManager with only one device linked
            // (since we can't remove devices with the current API)
            var updatedDeviceManager = new DeviceManager(mainDeviceKeyPair);
            updatedDeviceManager.AddLinkedDevice(secondDeviceX25519Public);
            // Note: thirdDeviceX25519Public is not added (simulating removal)

            // Act
            var syncMessages = updatedDeviceManager.CreateSyncMessages(syncData);

            // Assert
            Assert.IsNotNull(syncMessages, "Sync messages should not be null");
            Assert.AreEqual(1, syncMessages.Count, "Should create message only for the second device");

            string secondDeviceId = Convert.ToBase64String(secondDeviceX25519Public);
            string thirdDeviceId = Convert.ToBase64String(thirdDeviceX25519Public);

            Assert.IsTrue(syncMessages.ContainsKey(secondDeviceId), "Should contain message for second device");
            Assert.IsFalse(syncMessages.ContainsKey(thirdDeviceId), "Should not contain message for third device");
        }

        [TestMethod]
        public void DeviceManager_ExpiredSyncMessage_ShouldReturnNull()
        {
            // Arrange
            var mainDeviceKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);
            var secondDeviceKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);

            // Convert to X25519 keys
            byte[] secondDeviceX25519Private = _cryptoProvider.DeriveX25519PrivateKeyFromEd25519(secondDeviceKeyPair.PrivateKey);
            byte[] secondDeviceX25519Public = SecureMemory.CreateSecureBuffer(Constants.X25519_KEY_SIZE); 
            Sodium.ComputePublicKey(secondDeviceX25519Public, secondDeviceX25519Private);
            byte[] mainDeviceX25519Public = SecureMemory.CreateSecureBuffer(Constants.X25519_KEY_SIZE); 
            Sodium.ComputePublicKey(mainDeviceX25519Public, _cryptoProvider.DeriveX25519PrivateKeyFromEd25519(mainDeviceKeyPair.PrivateKey));

            // Create managers
            var mainDeviceManager = new DeviceManager(mainDeviceKeyPair);
            var secondDeviceManager = new DeviceManager(secondDeviceKeyPair);

            // Link devices
            mainDeviceManager.AddLinkedDevice(secondDeviceX25519Public);
            secondDeviceManager.AddLinkedDevice(mainDeviceX25519Public);

            // Create a sync message with old timestamp
            byte[] syncData = Encoding.UTF8.GetBytes("Test sync data with old timestamp");
            var syncMessages = mainDeviceManager.CreateSyncMessages(syncData);
            var messageForSecondDevice = syncMessages[Convert.ToBase64String(secondDeviceX25519Public)];

            // Manually create a custom sync message with an old timestamp (more than 5 minutes old)
            byte[] sharedSecret = X3DHExchange.PerformX25519DH(secondDeviceX25519Public,
                _cryptoProvider.DeriveX25519PrivateKeyFromEd25519(mainDeviceKeyPair.PrivateKey));

            // Create sync message with timestamp that's too old
            var syncMessage = new DeviceSyncMessage
            {
                SenderPublicKey = mainDeviceKeyPair.PublicKey,
                Data = syncData,
                Signature = MessageSigning.SignMessage(syncData, mainDeviceKeyPair.PrivateKey),
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - 6 * 60 * 1000 // 6 minutes old
            };

            // Serialize
            string json = JsonSerializer.Serialize(new
            {
                senderPublicKey = Convert.ToBase64String(syncMessage.SenderPublicKey),
                data = Convert.ToBase64String(syncMessage.Data),
                signature = Convert.ToBase64String(syncMessage.Signature),
                timestamp = syncMessage.Timestamp
            });

            // Encrypt
            byte[] plaintext = Encoding.UTF8.GetBytes(json);
            byte[] nonce = _cryptoProvider.GenerateNonce();
            byte[] ciphertext = _cryptoProvider.Encrypt(plaintext, sharedSecret, nonce);

            var expiredMessage = new EncryptedMessage
            {
                Ciphertext = ciphertext,
                Nonce = nonce
            };

            // Act
            byte[] receivedSyncData = secondDeviceManager.ProcessSyncMessage(expiredMessage, mainDeviceX25519Public);

            // Assert
            Assert.IsNull(receivedSyncData, "Processing an expired sync message should return null");
        }

        [TestMethod]
        public void DeviceManager_AddSameDeviceMultipleTimes_ShouldOnlyAddOnce()
        {
            // Arrange
            var mainDeviceKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);
            var secondDeviceKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);

            // Create X25519 keys
            byte[] secondDeviceX25519Public = SecureMemory.CreateSecureBuffer(Constants.X25519_KEY_SIZE); 
            Sodium.ComputePublicKey(
                secondDeviceX25519Public,
                _cryptoProvider.DeriveX25519PrivateKeyFromEd25519(secondDeviceKeyPair.PrivateKey));

            // Create device manager
            var mainDeviceManager = new DeviceManager(mainDeviceKeyPair);

            // Add the same device multiple times
            mainDeviceManager.AddLinkedDevice(secondDeviceX25519Public);
            mainDeviceManager.AddLinkedDevice(secondDeviceX25519Public);
            mainDeviceManager.AddLinkedDevice(secondDeviceX25519Public);

            // Create sync data
            byte[] syncData = Encoding.UTF8.GetBytes("Test sync data for duplicate device");

            // Act
            var syncMessages = mainDeviceManager.CreateSyncMessages(syncData);

            // Assert - With the improved implementation, duplicates are prevented
            Assert.AreEqual(1, syncMessages.Count, "Device manager should prevent duplicate linked devices");

            // All messages should be for the same device
            string deviceId = Convert.ToBase64String(secondDeviceX25519Public);
            Assert.IsTrue(syncMessages.ContainsKey(deviceId), "Message should be for the correct device ID");

            // Verify the device count using the new method
            Assert.AreEqual(1, mainDeviceManager.GetLinkedDeviceCount(), "Should only have one linked device");

            // Verify device is linked using the new method
            Assert.IsTrue(mainDeviceManager.IsDeviceLinked(secondDeviceX25519Public), "Device should be linked");
        }

        #endregion
    }
}