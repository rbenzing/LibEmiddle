using System;
using System.Security.Cryptography;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using E2EELibrary;
using E2EELibrary.KeyManagement;
using E2EELibrary.MultiDevice;
using E2EELibrary.Core;
using E2EELibrary.Communication;
using E2EELibrary.Encryption;
using E2EELibrary.KeyExchange;
using E2EELibrary.Models;
using System.Linq;
using System.Collections.Generic;
using System.Text.Json;

namespace E2EELibraryTests
{
    [TestClass]
    public class MultiDeviceTests
    {
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

            var newDeviceKeyPair = LibEmiddleClient.GenerateKeyExchangeKeyPair();

            // Act
            byte[] derivedKey1 = DeviceLinking.DeriveSharedKeyForNewDevice(
                existingSharedKey, newDeviceKeyPair.publicKey);

            byte[] derivedKey2 = DeviceLinking.DeriveSharedKeyForNewDevice(
                existingSharedKey, newDeviceKeyPair.publicKey);

            // Assert
            Assert.IsTrue(TestsHelpers.AreByteArraysEqual(derivedKey1, derivedKey2));
        }

        [TestMethod]
        public void CreateDeviceLinkMessage_ShouldCreateValidMessage()
        {
            // Arrange
            var mainDeviceKeyPair = LibEmiddleClient.GenerateSignatureKeyPair();
            var newDeviceKeyPair = LibEmiddleClient.GenerateSignatureKeyPair();

            // Act
            var encryptedMessage = LibEmiddleClient.CreateDeviceLinkMessage(
                mainDeviceKeyPair, newDeviceKeyPair.publicKey);

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
            var mainDeviceKeyPair = KeyGenerator.GenerateEd25519KeyPair();
            var newDeviceKeyPair = KeyGenerator.GenerateEd25519KeyPair();

            // Create a device link message from the main device to the new device
            var encryptedMessage = DeviceLinking.CreateDeviceLinkMessage(
                mainDeviceKeyPair,
                newDeviceKeyPair.publicKey);

            // Act
            byte[] result = DeviceLinking.ProcessDeviceLinkMessage(
                encryptedMessage,
                newDeviceKeyPair,
                mainDeviceKeyPair.publicKey);

            // Assert: With our updated implementation, a valid message returns the main device's Ed25519 public key.
            Assert.IsNotNull(result, "Valid device link message should be processed successfully.");
            Assert.IsTrue(TestsHelpers.AreByteArraysEqual(result, mainDeviceKeyPair.publicKey),
                "The returned main device public key should match the original.");
        }

        [TestMethod]
        public void ProcessDeviceLinkMessage_WithInvalidMessage_ShouldReturnNull()
        {
            // Arrange
            // Generate key pairs for main device and new device
            var mainDeviceKeyPair = KeyGenerator.GenerateEd25519KeyPair();
            var newDeviceKeyPair = KeyGenerator.GenerateEd25519KeyPair();
            var unrelatedKeyPair = KeyGenerator.GenerateEd25519KeyPair(); // For tampering

            // Create a device link message from the main device to the new device
            var encryptedMessage = DeviceLinking.CreateDeviceLinkMessage(
                mainDeviceKeyPair,
                newDeviceKeyPair.publicKey);

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
                unrelatedKeyPair.publicKey);  // Use unrelated key to simulate wrong device

            // Assert
            Assert.IsNull(result, "Result should be null for an invalid message");
        }

        [TestMethod]
        public void ProcessDeviceLinkMessage_WithNullMessage_ShouldThrowException()
        {
            // Arrange
            var newDeviceKeyPair = KeyGenerator.GenerateEd25519KeyPair();
            var mainDeviceKeyPair = KeyGenerator.GenerateEd25519KeyPair();

            // Act & Assert - Should throw ArgumentNullException
            Assert.ThrowsException<ArgumentNullException>(() => {
                DeviceLinking.ProcessDeviceLinkMessage(null, newDeviceKeyPair, mainDeviceKeyPair.publicKey);
            });
        }

        #endregion

        #region Device Manager Tests

        [TestMethod]
        public void MultiDeviceManager_ShouldCreateValidSyncMessages()
        {
            // Arrange
            var mainDeviceKeyPair = LibEmiddleClient.GenerateSignatureKeyPair();
            var secondDeviceKeyPair = LibEmiddleClient.GenerateSignatureKeyPair();

            // Derive X25519 keys for the second device
            byte[] secondDeviceX25519Private = KeyConversion.DeriveX25519PrivateKeyFromEd25519(secondDeviceKeyPair.privateKey);
            byte[] secondDeviceX25519Public = Sodium.ScalarMultBase(secondDeviceX25519Private);

            // Validate the derived X25519 public key
            bool isValid = KeyValidation.ValidateX25519PublicKey(secondDeviceX25519Public);
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
            var mainDeviceKeyPair = LibEmiddleClient.GenerateSignatureKeyPair();
            var manager = new DeviceManager(mainDeviceKeyPair);

            // Act & Assert - Should throw ArgumentNullException
            manager.AddLinkedDevice(null);
        }

        [TestMethod]
        public void MultiDeviceManager_ProcessSyncMessage_ShouldReturnSyncData()
        {
            Console.WriteLine("Starting test setup");

            // 1. Generate X25519 keypairs directly to avoid conversion issues
            var mainDeviceKeyPair = KeyGenerator.GenerateX25519KeyPair();
            var secondDeviceKeyPair = KeyGenerator.GenerateX25519KeyPair();
            Console.WriteLine($"Generated X25519 key pairs - Main device pub key length: {mainDeviceKeyPair.publicKey.Length}, Second device pub key length: {secondDeviceKeyPair.publicKey.Length}");

            string mainDeviceKeyBase64 = Convert.ToBase64String(mainDeviceKeyPair.publicKey);
            string secondDeviceKeyBase64 = Convert.ToBase64String(secondDeviceKeyPair.publicKey);
            Console.WriteLine($"Main device key (Base64): {mainDeviceKeyBase64}");
            Console.WriteLine($"Second device key (Base64): {secondDeviceKeyBase64}");

            // 2. Create our test sync data
            byte[] originalSyncData = Encoding.UTF8.GetBytes("Test sync data for multi-device processing");
            Console.WriteLine($"Created test sync data, length: {originalSyncData.Length}");

            // 3. Let's manually create and process the sync message using direct methods instead of DeviceManager
            Console.WriteLine("Creating sync message manually for better debugging...");

            try
            {
                // Implement manual signing, encryption, and decryption for the sync message
                byte[] signature = MessageSigning.SignMessage(originalSyncData, mainDeviceKeyPair.privateKey);
                Console.WriteLine($"Created signature, length: {signature.Length}");

                // Create the sync message JSON manually
                var syncMessage = new
                {
                    senderPublicKey = Convert.ToBase64String(mainDeviceKeyPair.publicKey),
                    data = Convert.ToBase64String(originalSyncData),
                    signature = Convert.ToBase64String(signature),
                    timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    protocolVersion = "E2EELibrary/v1.0"
                };

                // Serialize to JSON string
                string jsonMessage = System.Text.Json.JsonSerializer.Serialize(syncMessage);
                Console.WriteLine($"Serialized JSON message, length: {jsonMessage.Length}");
                Console.WriteLine($"JSON content: {jsonMessage}");

                // Now we'll manually perform X3DH key exchange
                byte[] sharedSecret = X3DHExchange.X3DHKeyExchange(
                    secondDeviceKeyPair.publicKey,
                    mainDeviceKeyPair.privateKey);
                Console.WriteLine($"Performed X3DH key exchange, shared secret length: {sharedSecret.Length}");

                // Encrypt the message with AES using the shared secret
                byte[] nonce = NonceGenerator.GenerateNonce();
                byte[] messageBytes = Encoding.UTF8.GetBytes(jsonMessage);
                byte[] ciphertext = AES.AESEncrypt(messageBytes, sharedSecret, nonce);
                Console.WriteLine($"Encrypted message, ciphertext length: {ciphertext.Length}");

                // Create the encrypted message
                var encryptedMessage = new EncryptedMessage
                {
                    Ciphertext = ciphertext,
                    Nonce = nonce,
                    SenderDHKey = mainDeviceKeyPair.publicKey,
                    Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    MessageId = Guid.NewGuid()
                };

                // Verify we can decrypt it manually
                Console.WriteLine("Verifying manual decryption works...");

                // First, let's try manual decryption - this should work if everything is set up correctly
                byte[] sharedSecret2 = X3DHExchange.X3DHKeyExchange(
                    mainDeviceKeyPair.publicKey,
                    secondDeviceKeyPair.privateKey);

                byte[] decryptedBytes = AES.AESDecrypt(encryptedMessage.Ciphertext, sharedSecret2, encryptedMessage.Nonce);
                string decryptedJson = Encoding.UTF8.GetString(decryptedBytes);
                Console.WriteLine($"Decrypted JSON successfully: {decryptedJson}");

                // Parse the decrypted JSON
                var parsedMessage = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(decryptedJson);

                // Extract and verify the fields
                string senderKeyBase64 = parsedMessage["senderPublicKey"].GetString();
                string dataBase64 = parsedMessage["data"].GetString();
                string sigBase64 = parsedMessage["signature"].GetString();

                byte[] extractedSenderKey = Convert.FromBase64String(senderKeyBase64);
                byte[] extractedData = Convert.FromBase64String(dataBase64);
                byte[] extractedSignature = Convert.FromBase64String(sigBase64);

                // Verify the signature
                bool signatureValid = MessageSigning.VerifySignature(extractedData, extractedSignature, extractedSenderKey);
                Console.WriteLine($"Signature verification result: {signatureValid}");

                // Verify the extracted data matches the original
                bool dataMatches = originalSyncData.SequenceEqual(extractedData);
                Console.WriteLine($"Extracted data matches original: {dataMatches}");

                // Now let's try with the device manager
                Console.WriteLine("\nNow testing with DeviceManager...");

                // Create device managers
                var mainDeviceManager = new DeviceManager((mainDeviceKeyPair.publicKey, mainDeviceKeyPair.privateKey));
                var secondDeviceManager = new DeviceManager((secondDeviceKeyPair.publicKey, secondDeviceKeyPair.privateKey));

                // Add linked devices in both directions
                mainDeviceManager.AddLinkedDevice(secondDeviceKeyPair.publicKey);
                secondDeviceManager.AddLinkedDevice(mainDeviceKeyPair.publicKey);

                Console.WriteLine($"Second device linked device count: {secondDeviceManager.GetLinkedDeviceCount()}");

                // Now try to process with the second device manager
                byte[] receivedData = secondDeviceManager.ProcessSyncMessage(encryptedMessage, mainDeviceKeyPair.publicKey);

                if (receivedData != null)
                {
                    Console.WriteLine($"Successfully processed with DeviceManager, received data length: {receivedData.Length}");
                }
                else
                {
                    Console.WriteLine("DeviceManager.ProcessSyncMessage returned null");

                    // Let's add a temporary method to the DeviceManager class for debugging:
                    /*
                    // Add this method to DeviceManager.cs:
                    public bool TestDecryption(EncryptedMessage message, byte[] senderPublicKey, byte[] recipientPrivateKey)
                    {
                        try {
                            byte[] sharedSecret = X3DHExchange.X3DHKeyExchange(senderPublicKey, recipientPrivateKey);
                            byte[] decrypted = AES.AESDecrypt(message.Ciphertext, sharedSecret, message.Nonce);
                            string json = Encoding.UTF8.GetString(decrypted);
                            Console.WriteLine($"Test decryption succeeded, JSON: {json}");
                            return true;
                        }
                        catch (Exception ex) {
                            Console.WriteLine($"Test decryption failed: {ex.Message}");
                            return false;
                        }
                    }
                    */

                    // Use the debug method if you add it
                    //bool decryptionWorked = secondDeviceManager.TestDecryption(
                    //    encryptedMessage, 
                    //    mainDeviceKeyPair.publicKey, 
                    //    secondDeviceKeyPair.privateKey);
                    //Console.WriteLine($"Debug decryption test result: {decryptionWorked}");
                }

                // Continue with the standard assertions
                Assert.IsNotNull(receivedData, "The received sync data should not be null");
                Assert.AreEqual(originalSyncData.Length, receivedData.Length,
                    $"Received data length should match original sync data length");
                CollectionAssert.AreEqual(originalSyncData, receivedData,
                    "The received data should match the original");

            }
            catch (Exception ex)
            {
                Console.WriteLine($"Exception during test: {ex.Message}");
                Console.WriteLine(ex.StackTrace);
                throw;
            }
        }

        [TestMethod]
        public void MultiDeviceManager_ProcessSyncMessage_WithTamperedMessage_ShouldReturnNull()
        {
            // Arrange
            var mainDeviceKeyPair = LibEmiddleClient.GenerateSignatureKeyPair();
            var secondDeviceKeyPair = LibEmiddleClient.GenerateSignatureKeyPair();

            // Convert to X25519 keys
            byte[] secondDeviceX25519Private = KeyConversion.DeriveX25519PrivateKeyFromEd25519(secondDeviceKeyPair.privateKey);
            byte[] secondDeviceX25519Public = Sodium.ScalarMultBase(secondDeviceX25519Private);
            byte[] mainDeviceX25519Public = Sodium.ScalarMultBase(KeyConversion.DeriveX25519PrivateKeyFromEd25519(mainDeviceKeyPair.privateKey));

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
            var mainDeviceKeyPair = LibEmiddleClient.GenerateSignatureKeyPair();
            var secondDeviceKeyPair = LibEmiddleClient.GenerateSignatureKeyPair();
            var thirdDeviceKeyPair = LibEmiddleClient.GenerateSignatureKeyPair();
            var fourthDeviceKeyPair = LibEmiddleClient.GenerateSignatureKeyPair();

            // Create X25519 keys for each device for linking
            byte[] secondDeviceX25519Public = Sodium.ScalarMultBase(
                KeyConversion.DeriveX25519PrivateKeyFromEd25519(secondDeviceKeyPair.privateKey));
            byte[] thirdDeviceX25519Public = Sodium.ScalarMultBase(
                KeyConversion.DeriveX25519PrivateKeyFromEd25519(thirdDeviceKeyPair.privateKey));
            byte[] fourthDeviceX25519Public = Sodium.ScalarMultBase(
                KeyConversion.DeriveX25519PrivateKeyFromEd25519(fourthDeviceKeyPair.privateKey));

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
            var mainDeviceKeyPair = LibEmiddleClient.GenerateSignatureKeyPair();
            var secondDeviceKeyPair = LibEmiddleClient.GenerateSignatureKeyPair();
            var thirdDeviceKeyPair = LibEmiddleClient.GenerateSignatureKeyPair();

            // Create X25519 keys for each device for linking
            byte[] secondDeviceX25519Public = Sodium.ScalarMultBase(
                KeyConversion.DeriveX25519PrivateKeyFromEd25519(secondDeviceKeyPair.privateKey));
            byte[] thirdDeviceX25519Public = Sodium.ScalarMultBase(
                KeyConversion.DeriveX25519PrivateKeyFromEd25519(thirdDeviceKeyPair.privateKey));

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
            var mainDeviceKeyPair = LibEmiddleClient.GenerateSignatureKeyPair();
            var secondDeviceKeyPair = LibEmiddleClient.GenerateSignatureKeyPair();

            // Convert to X25519 keys
            byte[] secondDeviceX25519Private = KeyConversion.DeriveX25519PrivateKeyFromEd25519(secondDeviceKeyPair.privateKey);
            byte[] secondDeviceX25519Public = Sodium.ScalarMultBase(secondDeviceX25519Private);
            byte[] mainDeviceX25519Public = Sodium.ScalarMultBase(KeyConversion.DeriveX25519PrivateKeyFromEd25519(mainDeviceKeyPair.privateKey));

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
            byte[] sharedSecret = X3DHExchange.X3DHKeyExchange(secondDeviceX25519Public,
                KeyConversion.DeriveX25519PrivateKeyFromEd25519(mainDeviceKeyPair.privateKey));

            // Create sync message with timestamp that's too old
            var syncMessage = new DeviceSyncMessage
            {
                SenderPublicKey = mainDeviceKeyPair.publicKey,
                Data = syncData,
                Signature = MessageSigning.SignMessage(syncData, mainDeviceKeyPair.privateKey),
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - (6 * 60 * 1000) // 6 minutes old
            };

            // Serialize
            string json = System.Text.Json.JsonSerializer.Serialize(new
            {
                senderPublicKey = Convert.ToBase64String(syncMessage.SenderPublicKey),
                data = Convert.ToBase64String(syncMessage.Data),
                signature = Convert.ToBase64String(syncMessage.Signature),
                timestamp = syncMessage.Timestamp
            });

            // Encrypt
            byte[] plaintext = Encoding.UTF8.GetBytes(json);
            byte[] nonce = NonceGenerator.GenerateNonce();
            byte[] ciphertext = AES.AESEncrypt(plaintext, sharedSecret, nonce);

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
            var mainDeviceKeyPair = LibEmiddleClient.GenerateSignatureKeyPair();
            var secondDeviceKeyPair = LibEmiddleClient.GenerateSignatureKeyPair();

            // Create X25519 keys
            byte[] secondDeviceX25519Public = Sodium.ScalarMultBase(
                KeyConversion.DeriveX25519PrivateKeyFromEd25519(secondDeviceKeyPair.privateKey));

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