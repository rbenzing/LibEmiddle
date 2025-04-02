using System;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using E2EELibrary;
using E2EELibrary.MultiDevice;
using E2EELibrary.Models;
using E2EELibrary.KeyManagement;
using E2EELibrary.Core;

namespace E2EELibraryTests
{
    [TestClass]
    public class DeviceRevocationTests
    {
        [TestMethod]
        public void CreateDeviceRevocationMessage_ShouldCreateValidMessage()
        {
            // Arrange
            var authorityKeyPair = KeyGenerator.GenerateEd25519KeyPair();
            var deviceToRevokeKeyPair = KeyGenerator.GenerateEd25519KeyPair();

            // Act
            var revocationMessage = LibEmiddleClient.CreateDeviceRevocationMessage(
                deviceToRevokeKeyPair.publicKey,
                authorityKeyPair);

            // Assert
            Assert.IsNotNull(revocationMessage);
            Assert.IsNotNull(revocationMessage.RevokedDeviceKey);
            Assert.IsNotNull(revocationMessage.Signature);
            Assert.IsTrue(revocationMessage.RevocationTimestamp > 0);

            // Verify signature contains valid timestamp
            long currentTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            Assert.IsTrue(Math.Abs(currentTime - revocationMessage.RevocationTimestamp) < 5000,
                "Timestamp should be close to current time");

            // Key should match the provided key
            CollectionAssert.AreEqual(deviceToRevokeKeyPair.publicKey, revocationMessage.RevokedDeviceKey);
        }

        [TestMethod]
        public void ValidateDeviceRevocationMessage_WithValidMessage_ShouldReturnTrue()
        {
            // Arrange
            var authorityKeyPair = KeyGenerator.GenerateEd25519KeyPair();
            var deviceToRevokeKeyPair = KeyGenerator.GenerateEd25519KeyPair();

            var revocationMessage = LibEmiddleClient.CreateDeviceRevocationMessage(
                deviceToRevokeKeyPair.publicKey,
                authorityKeyPair);

            // Act
            bool isValid = LibEmiddleClient.ValidateDeviceRevocationMessage(
                revocationMessage,
                authorityKeyPair.publicKey);

            // Assert
            Assert.IsTrue(isValid, "Valid revocation message should validate successfully");
        }

        [TestMethod]
        public void ValidateDeviceRevocationMessage_WithWrongSigningKey_ShouldReturnFalse()
        {
            // Arrange
            var authorityKeyPair = KeyGenerator.GenerateEd25519KeyPair();
            var differentKeyPair = KeyGenerator.GenerateEd25519KeyPair();
            var deviceToRevokeKeyPair = KeyGenerator.GenerateEd25519KeyPair();

            var revocationMessage = LibEmiddleClient.CreateDeviceRevocationMessage(
                deviceToRevokeKeyPair.publicKey,
                authorityKeyPair);

            // Act - Validate with a different public key than the one that signed
            bool isValid = LibEmiddleClient.ValidateDeviceRevocationMessage(
                revocationMessage,
                differentKeyPair.publicKey);

            // Assert
            Assert.IsFalse(isValid, "Validation should fail with wrong public key");
        }

        [TestMethod]
        public void ValidateDeviceRevocationMessage_WithTamperedMessage_ShouldReturnFalse()
        {
            // Arrange
            var authorityKeyPair = KeyGenerator.GenerateEd25519KeyPair();
            var deviceToRevokeKeyPair = KeyGenerator.GenerateEd25519KeyPair();

            var revocationMessage = LibEmiddleClient.CreateDeviceRevocationMessage(
                deviceToRevokeKeyPair.publicKey,
                authorityKeyPair);

            // Create a tampered copy with a different timestamp
            var tamperedMessage = new DeviceRevocationMessage
            {
                RevokedDeviceKey = revocationMessage.RevokedDeviceKey,
                RevocationTimestamp = revocationMessage.RevocationTimestamp + 10000, // Change timestamp
                Signature = revocationMessage.Signature // Keep the original signature
            };

            // Act
            bool isValid = LibEmiddleClient.ValidateDeviceRevocationMessage(
                tamperedMessage,
                authorityKeyPair.publicKey);

            // Assert
            Assert.IsFalse(isValid, "Validation should fail with tampered message");
        }

        [TestMethod]
        public void DeviceManager_RevokeLinkedDevice_ShouldCreateValidRevocationAndRemoveDevice()
        {
            // Arrange
            var mainDeviceKeyPair = KeyGenerator.GenerateEd25519KeyPair();
            var deviceToRevokeKeyPair = KeyGenerator.GenerateEd25519KeyPair();

            // Create X25519 key for the device to revoke
            byte[] deviceToRevokeX25519Public = Sodium.ScalarMultBase(
                KeyConversion.DeriveX25519PrivateKeyFromEd25519(deviceToRevokeKeyPair.privateKey));

            // Create a device manager and link a device
            var deviceManager = new DeviceManager(mainDeviceKeyPair);
            deviceManager.AddLinkedDevice(deviceToRevokeX25519Public);

            // Verify device is linked
            Assert.IsTrue(deviceManager.IsDeviceLinked(deviceToRevokeX25519Public),
                "Device should be linked before revocation");
            Assert.AreEqual(1, deviceManager.GetLinkedDeviceCount(),
                "Should have one linked device");

            // Act
            var revocationMessage = deviceManager.RevokeLinkedDevice(deviceToRevokeX25519Public);

            // Assert
            // Verify revocation message
            Assert.IsNotNull(revocationMessage, "Should create a revocation message");

            // The revoked key in the message should match our device's key
            Assert.IsTrue(SecureMemory.SecureCompare(deviceToRevokeX25519Public, revocationMessage.RevokedDeviceKey),
                "Revocation message should contain the correct device key");

            // Device should no longer be linked
            Assert.IsFalse(deviceManager.IsDeviceLinked(deviceToRevokeX25519Public),
                "Device should no longer be linked after revocation");
            Assert.AreEqual(0, deviceManager.GetLinkedDeviceCount(),
                "Should have zero linked devices after revocation");

            // Validate the revocation message
            bool isValid = revocationMessage.Validate(mainDeviceKeyPair.publicKey);
            Assert.IsTrue(isValid, "Revocation message should be valid");
        }

        [TestMethod]
        public void DeviceManager_ProcessRevocationMessage_ShouldRemoveLinkedDevice()
        {
            // Arrange
            var mainDeviceKeyPair = KeyGenerator.GenerateEd25519KeyPair();
            var otherDeviceKeyPair = KeyGenerator.GenerateEd25519KeyPair();
            var deviceToRevokeKeyPair = KeyGenerator.GenerateEd25519KeyPair();

            // Create X25519 key for the device to revoke
            byte[] deviceToRevokeX25519Public = Sodium.ScalarMultBase(
                KeyConversion.DeriveX25519PrivateKeyFromEd25519(deviceToRevokeKeyPair.privateKey));

            // Create two device managers
            var mainDeviceManager = new DeviceManager(mainDeviceKeyPair);
            var otherDeviceManager = new DeviceManager(otherDeviceKeyPair);

            // Link the device to both managers
            mainDeviceManager.AddLinkedDevice(deviceToRevokeX25519Public);
            otherDeviceManager.AddLinkedDevice(deviceToRevokeX25519Public);

            // Create a revocation message from the main device
            var revocationMessage = mainDeviceManager.CreateRevocationMessage(deviceToRevokeX25519Public);

            // Act - Process the revocation message on the other device
            bool result = otherDeviceManager.ProcessRevocationMessage(revocationMessage, mainDeviceKeyPair.publicKey);

            // Assert
            Assert.IsTrue(result, "Processing valid revocation message should succeed");
            Assert.IsFalse(otherDeviceManager.IsDeviceLinked(deviceToRevokeX25519Public),
                "Device should be removed after processing revocation message");
        }

        [TestMethod]
        public void DeviceManager_ProcessRevocationMessage_WithInvalidSignature_ShouldReturnFalse()
        {
            // Arrange
            var mainDeviceKeyPair = KeyGenerator.GenerateEd25519KeyPair();
            var otherDeviceKeyPair = KeyGenerator.GenerateEd25519KeyPair();
            var deviceToRevokeKeyPair = KeyGenerator.GenerateEd25519KeyPair();

            // Create X25519 key for the device to revoke
            byte[] deviceToRevokeX25519Public = Sodium.ScalarMultBase(
                KeyConversion.DeriveX25519PrivateKeyFromEd25519(deviceToRevokeKeyPair.privateKey));

            // Create two device managers
            var mainDeviceManager = new DeviceManager(mainDeviceKeyPair);
            var otherDeviceManager = new DeviceManager(otherDeviceKeyPair);

            // Link the device to the other manager
            otherDeviceManager.AddLinkedDevice(deviceToRevokeX25519Public);

            // Create a valid revocation message
            var revocationMessage = mainDeviceManager.CreateRevocationMessage(deviceToRevokeX25519Public);

            // Create a tampered copy with a different timestamp
            var tamperedMessage = new DeviceRevocationMessage
            {
                RevokedDeviceKey = revocationMessage.RevokedDeviceKey,
                RevocationTimestamp = revocationMessage.RevocationTimestamp + 10000, // Change timestamp
                Signature = revocationMessage.Signature // Keep the original signature
            };

            // Act - Process the tampered revocation message
            bool result = otherDeviceManager.ProcessRevocationMessage(tamperedMessage, mainDeviceKeyPair.publicKey);

            // Assert
            Assert.IsFalse(result, "Processing tampered revocation message should fail");
            Assert.IsTrue(otherDeviceManager.IsDeviceLinked(deviceToRevokeX25519Public),
                "Device should still be linked after failed revocation");
        }

        [TestMethod]
        [ExpectedException(typeof(KeyNotFoundException))]
        public void DeviceManager_RevokeLinkedDevice_UnknownDevice_ShouldThrowException()
        {
            // Arrange
            var mainDeviceKeyPair = KeyGenerator.GenerateEd25519KeyPair();
            var deviceToRevokeKeyPair = KeyGenerator.GenerateEd25519KeyPair();

            // Create X25519 key for the device to revoke
            byte[] deviceToRevokeX25519Public = Sodium.ScalarMultBase(
                KeyConversion.DeriveX25519PrivateKeyFromEd25519(deviceToRevokeKeyPair.privateKey));

            // Create a device manager without linking the device
            var deviceManager = new DeviceManager(mainDeviceKeyPair);

            // Act & Assert - Should throw KeyNotFoundException
            deviceManager.RevokeLinkedDevice(deviceToRevokeX25519Public);
        }

        [TestMethod]
        public void DeviceRevocationMessage_Validate_WithNullFields_ShouldReturnFalse()
        {
            // Arrange
            var authorityKeyPair = KeyGenerator.GenerateEd25519KeyPair();

            // Create invalid revocation messages
            var nullKeyMessage = new DeviceRevocationMessage
            {
                RevokedDeviceKey = null,
                RevocationTimestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                Signature = new byte[64]
            };

            var nullSignatureMessage = new DeviceRevocationMessage
            {
                RevokedDeviceKey = new byte[32],
                RevocationTimestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                Signature = null
            };

            var zeroTimestampMessage = new DeviceRevocationMessage
            {
                RevokedDeviceKey = new byte[32],
                RevocationTimestamp = 0,
                Signature = new byte[64]
            };

            // Act
            bool nullKeyResult = nullKeyMessage.Validate(authorityKeyPair.publicKey);
            bool nullSignatureResult = nullSignatureMessage.Validate(authorityKeyPair.publicKey);
            bool zeroTimestampResult = zeroTimestampMessage.Validate(authorityKeyPair.publicKey);

            // Assert
            Assert.IsFalse(nullKeyResult, "Validation should fail with null revoked device key");
            Assert.IsFalse(nullSignatureResult, "Validation should fail with null signature");
            Assert.IsFalse(zeroTimestampResult, "Validation should fail with zero timestamp");
        }

        [TestMethod]
        public void E2EEClient_CreateDeviceRevocationMessage_CombinesDataCorrectly()
        {
            // Arrange
            var authorityKeyPair = KeyGenerator.GenerateEd25519KeyPair();
            var deviceToRevokeKeyPair = KeyGenerator.GenerateEd25519KeyPair();

            // Act
            var revocationMessage = LibEmiddleClient.CreateDeviceRevocationMessage(
                deviceToRevokeKeyPair.publicKey,
                authorityKeyPair);

            // Manually combine data for verification
            byte[] timestampBytes = BitConverter.GetBytes(revocationMessage.RevocationTimestamp);
            byte[] dataToSign = new byte[deviceToRevokeKeyPair.publicKey.Length + timestampBytes.Length];

            deviceToRevokeKeyPair.publicKey.AsSpan().CopyTo(dataToSign.AsSpan(0, deviceToRevokeKeyPair.publicKey.Length));
            timestampBytes.AsSpan().CopyTo(dataToSign.AsSpan(deviceToRevokeKeyPair.publicKey.Length));

            // Verify the signature directly
            bool isValidManually = LibEmiddleClient.VerifySignature(dataToSign, revocationMessage.Signature, authorityKeyPair.publicKey);

            // Assert
            Assert.IsTrue(isValidManually, "Signature validation should pass with manually combined data");
        }
    }
}