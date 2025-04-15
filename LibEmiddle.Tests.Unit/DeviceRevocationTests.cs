using System;
using System.Collections.Generic;
using System.Security;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using LibEmiddle.MultiDevice;
using LibEmiddle.Models;
using LibEmiddle.Core;
using LibEmiddle.API;
using LibEmiddle.Abstractions;
using LibEmiddle.Crypto;

namespace LibEmiddle.Tests.Unit
{
    [TestClass]
    public class DeviceRevocationTests
    {
        private CryptoProvider _cryptoProvider;

        [TestInitialize]
        public void Setup()
        {
            _cryptoProvider = new CryptoProvider();
        }

        [TestMethod]
        public void CreateDeviceRevocationMessage_ShouldCreateValidMessage()
        {
            // Arrange
            var authorityKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);
            var deviceToRevokeKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);

            // Act
            var revocationMessage = LibEmiddleClient.CreateDeviceRevocationMessage(
                deviceToRevokeKeyPair.PublicKey,
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
            CollectionAssert.AreEqual(deviceToRevokeKeyPair.PublicKey, revocationMessage.RevokedDeviceKey);
        }

        [TestMethod]
        public void ValidateDeviceRevocationMessage_WithValidMessage_ShouldReturnTrue()
        {
            // Arrange
            var authorityKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);
            var deviceToRevokeKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);

            var revocationMessage = LibEmiddleClient.CreateDeviceRevocationMessage(
                deviceToRevokeKeyPair.PublicKey,
                authorityKeyPair);

            // Act
            bool isValid = LibEmiddleClient.ValidateDeviceRevocationMessage(
                revocationMessage,
                authorityKeyPair.PublicKey);

            // Assert
            Assert.IsTrue(isValid, "Valid revocation message should validate successfully");
        }

        [TestMethod]
        public void ValidateDeviceRevocationMessage_WithWrongSigningKey_ShouldReturnFalse()
        {
            // Arrange
            var authorityKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);
            var differentKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);
            var deviceToRevokeKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);

            var revocationMessage = LibEmiddleClient.CreateDeviceRevocationMessage(
                deviceToRevokeKeyPair.PublicKey,
                authorityKeyPair);

            // Act - Validate with a different public key than the one that signed
            bool isValid = LibEmiddleClient.ValidateDeviceRevocationMessage(
                revocationMessage,
                differentKeyPair.PublicKey);

            // Assert
            Assert.IsFalse(isValid, "Validation should fail with wrong public key");
        }

        [TestMethod]
        public void ValidateDeviceRevocationMessage_WithTamperedMessage_ShouldReturnFalse()
        {
            // Arrange
            var authorityKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);
            var deviceToRevokeKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);

            var revocationMessage = LibEmiddleClient.CreateDeviceRevocationMessage(
                deviceToRevokeKeyPair.PublicKey,
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
                authorityKeyPair.PublicKey);

            // Assert
            Assert.IsFalse(isValid, "Validation should fail with tampered message");
        }

        [TestMethod]
        public void DeviceManager_RevokeLinkedDevice_ShouldCreateValidRevocationAndRemoveDevice()
        {
            // Arrange
            var mainDeviceKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);
            var deviceToRevokeKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);

            // Create X25519 key for the device to revoke
            byte[] deviceToRevokeX25519Public = Sodium.ScalarMultBase(
                _cryptoProvider.DeriveX25519PrivateKeyFromEd25519(deviceToRevokeKeyPair.PrivateKey));

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
            bool isValid = revocationMessage.Validate(mainDeviceKeyPair.PublicKey);
            Assert.IsTrue(isValid, "Revocation message should be valid");
        }

        [TestMethod]
        public void DeviceManager_ProcessRevocationMessage_ShouldRemoveLinkedDevice()
        {
            // Arrange
            var mainDeviceKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);
            var otherDeviceKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);
            var deviceToRevokeKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);

            // Create X25519 key for the device to revoke
            byte[] deviceToRevokeX25519Public = Sodium.ScalarMultBase(
                _cryptoProvider.DeriveX25519PrivateKeyFromEd25519(deviceToRevokeKeyPair.PrivateKey));

            // Create two device managers
            var mainDeviceManager = new DeviceManager(mainDeviceKeyPair);
            var otherDeviceManager = new DeviceManager(otherDeviceKeyPair);

            // Link the device to both managers
            mainDeviceManager.AddLinkedDevice(deviceToRevokeX25519Public);
            otherDeviceManager.AddLinkedDevice(deviceToRevokeX25519Public);

            // Create a revocation message from the main device
            var revocationMessage = mainDeviceManager.CreateRevocationMessage(deviceToRevokeX25519Public);

            // Act - Process the revocation message on the other device
            bool result = otherDeviceManager.ProcessRevocationMessage(revocationMessage, mainDeviceKeyPair.PublicKey);

            // Assert
            Assert.IsTrue(result, "Processing valid revocation message should succeed");
            Assert.IsFalse(otherDeviceManager.IsDeviceLinked(deviceToRevokeX25519Public),
                "Device should be removed after processing revocation message");
        }

        [TestMethod]
        public void DeviceManager_ProcessRevocationMessage_WithInvalidSignature_ShouldReturnFalse()
        {
            // Arrange
            var mainDeviceKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);
            var otherDeviceKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);
            var deviceToRevokeKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);

            // Create X25519 key for the device to revoke
            byte[] deviceToRevokeX25519Public = Sodium.ScalarMultBase(
                _cryptoProvider.DeriveX25519PrivateKeyFromEd25519(deviceToRevokeKeyPair.PrivateKey));

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
            bool result = otherDeviceManager.ProcessRevocationMessage(tamperedMessage, mainDeviceKeyPair.PublicKey);

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
            var mainDeviceKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);
            var deviceToRevokeKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);

            // Create X25519 key for the device to revoke
            byte[] deviceToRevokeX25519Public = Sodium.ScalarMultBase(
                _cryptoProvider.DeriveX25519PrivateKeyFromEd25519(deviceToRevokeKeyPair.PrivateKey));

            // Create a device manager without linking the device
            var deviceManager = new DeviceManager(mainDeviceKeyPair);

            // Act & Assert - Should throw KeyNotFoundException
            deviceManager.RevokeLinkedDevice(deviceToRevokeX25519Public);
        }

        [TestMethod]
        public void DeviceRevocationMessage_Validate_WithNullFields_ShouldReturnFalse()
        {
            // Arrange
            var authorityKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);

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
            bool nullKeyResult = nullKeyMessage.Validate(authorityKeyPair.PublicKey);
            bool nullSignatureResult = nullSignatureMessage.Validate(authorityKeyPair.PublicKey);
            bool zeroTimestampResult = zeroTimestampMessage.Validate(authorityKeyPair.PublicKey);

            // Assert
            Assert.IsFalse(nullKeyResult, "Validation should fail with null revoked device key");
            Assert.IsFalse(nullSignatureResult, "Validation should fail with null signature");
            Assert.IsFalse(zeroTimestampResult, "Validation should fail with zero timestamp");
        }

        [TestMethod]
        public void E2EEClient_CreateDeviceRevocationMessage_CombinesDataCorrectly()
        {
            // Arrange
            var authorityKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);
            var deviceToRevokeKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);

            // Act
            var revocationMessage = LibEmiddleClient.CreateDeviceRevocationMessage(
                deviceToRevokeKeyPair.PublicKey,
                authorityKeyPair);

            // Manually combine data for verification
            byte[] timestampBytes = BitConverter.GetBytes(revocationMessage.RevocationTimestamp);
            byte[] dataToSign = new byte[deviceToRevokeKeyPair.PublicKey.Length + timestampBytes.Length];

            deviceToRevokeKeyPair.PublicKey.AsSpan().CopyTo(dataToSign.AsSpan(0, deviceToRevokeKeyPair.PublicKey.Length));
            timestampBytes.AsSpan().CopyTo(dataToSign.AsSpan(deviceToRevokeKeyPair.PublicKey.Length));

            // Verify the signature directly
            bool isValidManually = _cryptoProvider.Verify(dataToSign, revocationMessage.Signature, authorityKeyPair.PublicKey);

            // Assert
            Assert.IsTrue(isValidManually, "Signature validation should pass with manually combined data");
        }

        [TestMethod]
        public void RevokedDevice_ShouldNotBeAddedAgain()
        {
            // Arrange
            var identityKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);
            var deviceManager = new DeviceManager(identityKeyPair);
            var deviceKey = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519).PublicKey;

            // Act
            deviceManager.AddLinkedDevice(deviceKey);
            Assert.IsTrue(deviceManager.IsDeviceLinked(deviceKey));

            // Revoke the device
            deviceManager.RevokeLinkedDevice(deviceKey);
            Assert.IsFalse(deviceManager.IsDeviceLinked(deviceKey));

            // Attempt to add it again
            bool exceptionThrown = false;
            try
            {
                deviceManager.AddLinkedDevice(deviceKey);
            }
            catch (SecurityException)
            {
                exceptionThrown = true;
            }

            // Assert
            Assert.IsTrue(exceptionThrown, "Expected SecurityException was not thrown");
            Assert.IsFalse(deviceManager.IsDeviceLinked(deviceKey));
        }

        [TestMethod]
        public void RevokedDevices_ShouldBeTracked_EvenAfterRestart()
        {
            // Arrange
            var identityKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);
            var deviceManager = new DeviceManager(identityKeyPair);
            var device1 = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519).PublicKey;
            var device2 = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519).PublicKey;

            // Act - Add and revoke device1
            deviceManager.AddLinkedDevice(device1);
            deviceManager.AddLinkedDevice(device2);

            deviceManager.RevokeLinkedDevice(device1);

            // Export linked devices
            string password = "test_password";
            byte[] exportedData = deviceManager.ExportLinkedDevices(password);

            // Create a new device manager (simulate restart)
            var newDeviceManager = new DeviceManager(identityKeyPair);

            // Import linked devices
            newDeviceManager.ImportLinkedDevices(exportedData, password);

            // Assert
            Assert.IsFalse(newDeviceManager.IsDeviceLinked(device1),
                "Revoked device should not be linked after import");
            Assert.IsTrue(newDeviceManager.IsDeviceLinked(device2),
                "Non-revoked device should still be linked after import");

            // Try to add the revoked device again
            bool exceptionThrown = false;
            try
            {
                newDeviceManager.AddLinkedDevice(device1);
            }
            catch (SecurityException)
            {
                exceptionThrown = true;
            }

            Assert.IsTrue(exceptionThrown,
                "Should throw SecurityException when adding previously revoked device");
        }
    }
}