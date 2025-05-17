using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Security;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.MultiDevice;
using LibEmiddle.Domain;

namespace LibEmiddle.Tests.Unit
{
    [TestClass]
    public class DeviceRevocationTests
    {
        private CryptoProvider _cryptoProvider;
        private DeviceLinkingService _deviceLinkingSvc;
        private KeyPair _authorityKeyPair;

        [TestInitialize]
        public void Setup()
        {
            _cryptoProvider = new CryptoProvider();
            _deviceLinkingSvc = new DeviceLinkingService(_cryptoProvider);

            _authorityKeyPair = Sodium.GenerateEd25519KeyPair();
        }

        [TestMethod]
        public void CreateDeviceRevocationMessage_ShouldCreateValidMessage()
        {
            // Arrange
            var deviceToRevokeKeyPair = Sodium.GenerateEd25519KeyPair();

            // Act
            var revocationMessage = _deviceLinkingSvc.CreateDeviceRevocationMessage(
                _authorityKeyPair,
                deviceToRevokeKeyPair.PublicKey);

            // Assert
            Assert.IsNotNull(revocationMessage);
            Assert.IsNotNull(revocationMessage.RevokedDevicePublicKey);
            Assert.IsNotNull(revocationMessage.UserIdentityPublicKey);
            Assert.IsNotNull(revocationMessage.Signature);
            Assert.IsTrue(revocationMessage.Timestamp > 0);

            // Verify signature contains valid timestamp
            long currentTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            Assert.IsTrue(Math.Abs(currentTime - revocationMessage.Timestamp) < 5000,
                "Timestamp should be close to current time");

            // Key should match the provided key
            CollectionAssert.AreEqual(deviceToRevokeKeyPair.PublicKey, revocationMessage.RevokedDevicePublicKey);
        }

        [TestMethod]
        public void ValidateDeviceRevocationMessage_WithValidMessage_ShouldReturnTrue()
        {
            // Arrange
            var authorityKeyPair = Sodium.GenerateEd25519KeyPair();
            var deviceToRevokeKeyPair = Sodium.GenerateEd25519KeyPair();

            var revocationMessage = _deviceLinkingSvc.CreateDeviceRevocationMessage(
                _authorityKeyPair,
                deviceToRevokeKeyPair.PublicKey);

            // Act
            bool isValid = _deviceLinkingSvc.VerifyDeviceRevocationMessage(
                revocationMessage,
                authorityKeyPair.PublicKey);

            // Assert
            Assert.IsTrue(revocationMessage.IsValid(), "Revocation message should validate true");
            Assert.IsTrue(isValid, "Verified revocation message should validate true");
        }

        [TestMethod]
        public void ValidateDeviceRevocationMessage_WithWrongSigningKey_ShouldReturnFalse()
        {
            // Arrange
            var authorityKeyPair = Sodium.GenerateEd25519KeyPair();
            var differentKeyPair = Sodium.GenerateEd25519KeyPair();
            var deviceToRevokeKeyPair = Sodium.GenerateEd25519KeyPair();

            var revocationMessage = _deviceLinkingSvc.CreateDeviceRevocationMessage(
                _authorityKeyPair,
                deviceToRevokeKeyPair.PublicKey);

            // Act - Validate with a different public key than the one that signed
            bool isValid = _deviceLinkingSvc.VerifyDeviceRevocationMessage(
                revocationMessage,
                differentKeyPair.PublicKey);

            // Assert
            Assert.IsFalse(isValid, "Validation should fail with wrong public key");
        }

        [TestMethod]
        public void ValidateDeviceRevocationMessage_WithTamperedMessage_ShouldReturnFalse()
        {
            // Arrange
            var authorityKeyPair = Sodium.GenerateEd25519KeyPair();
            var deviceToRevokeKeyPair = Sodium.GenerateEd25519KeyPair();

            var revocationMessage = _deviceLinkingSvc.CreateDeviceRevocationMessage(
                _authorityKeyPair,
                deviceToRevokeKeyPair.PublicKey);

            // Create a tampered copy with a different timestamp
            var tamperedMessage = new DeviceRevocationMessage
            {
                UserIdentityPublicKey = revocationMessage.UserIdentityPublicKey,
                RevokedDevicePublicKey = revocationMessage.RevokedDevicePublicKey,
                Timestamp = revocationMessage.Timestamp + 10000, // Change timestamp
                Signature = revocationMessage.Signature // Keep the original signature
            };

            // Act
            bool isValid = _deviceLinkingSvc.VerifyDeviceRevocationMessage(
                tamperedMessage,
                authorityKeyPair.PublicKey);

            // Assert
            Assert.IsFalse(isValid, "Validation should fail with tampered message");
        }

        [TestMethod]
        public void DeviceManager_RevokeLinkedDevice_ShouldCreateValidRevocationAndRemoveDevice()
        {
            // Arrange
            var mainDeviceKeyPair = Sodium.GenerateEd25519KeyPair();
            var deviceToRevokeKeyPair = Sodium.GenerateEd25519KeyPair();

            // Create X25519 key for the device to revoke
            byte[] deviceToRevokeX25519Public = SecureMemory.CreateSecureBuffer(32);
            Sodium.ComputePublicKey(
                deviceToRevokeX25519Public, 
                _cryptoProvider.ConvertEd25519PrivateKeyToX25519(deviceToRevokeKeyPair.PrivateKey));

            // Create a device manager and link a device
            var deviceManager = new DeviceManager(mainDeviceKeyPair);
            deviceManager.AddLinkedDevice(deviceToRevokeX25519Public);

            // Verify device is linked
            Assert.IsTrue(deviceManager.IsDeviceLinked(deviceToRevokeX25519Public),
                "Device should be linked before revocation");
            Assert.AreEqual(1, deviceManager.GetLinkedDeviceCount(),
                "Should have one linked device");

            // Act
            bool isRemoved = deviceManager.RemoveLinkedDevice(deviceToRevokeX25519Public);
            bool isValid = deviceManager.IsDeviceRevoked(mainDeviceKeyPair.PublicKey);

            // Assert
            Assert.IsTrue(isRemoved, "Device was successfully removed");
            Assert.IsTrue(isValid, "Device is not in the devices dictionary");
        }

        [TestMethod]
        public void DeviceManager_ProcessRevocationMessage_ShouldRemoveLinkedDevice()
        {
            // Arrange
            var mainDeviceKeyPair = Sodium.GenerateEd25519KeyPair();
            var otherDeviceKeyPair = Sodium.GenerateEd25519KeyPair();
            var deviceToRevokeKeyPair = Sodium.GenerateEd25519KeyPair();

            // Create X25519 key for the device to revoke
            byte[] deviceToRevokeX25519Public = SecureMemory.CreateSecureBuffer(32);
            Sodium.ComputePublicKey(deviceToRevokeX25519Public,
                _cryptoProvider.ConvertEd25519PrivateKeyToX25519(deviceToRevokeKeyPair.PrivateKey));

            // Create two device managers
            var mainDeviceManager = new DeviceManager(mainDeviceKeyPair);
            var otherDeviceManager = new DeviceManager(otherDeviceKeyPair);

            // Link the device to both managers
            mainDeviceManager.AddLinkedDevice(deviceToRevokeX25519Public);
            otherDeviceManager.AddLinkedDevice(deviceToRevokeX25519Public);

            // Create a revocation message from the main device
            var revocationMessage = mainDeviceManager.CreateDeviceRevocationMessage(deviceToRevokeX25519Public);

            // Act - Process the revocation message on the other device
            bool result = otherDeviceManager.ProcessDeviceRevocationMessage(revocationMessage);

            // Assert
            Assert.IsTrue(result, "Processing valid revocation message should succeed");
            Assert.IsFalse(otherDeviceManager.IsDeviceLinked(deviceToRevokeX25519Public),
                "Device should be removed after processing revocation message");
        }

        [TestMethod]
        public void DeviceManager_ProcessRevocationMessage_WithInvalidSignature_ShouldReturnFalse()
        {
            // Arrange
            var mainDeviceKeyPair = Sodium.GenerateEd25519KeyPair();
            var otherDeviceKeyPair = Sodium.GenerateEd25519KeyPair();
            var deviceToRevokeKeyPair = Sodium.GenerateEd25519KeyPair();

            // Create X25519 key for the device to revoke
            byte[] deviceToRevokeX25519Public = SecureMemory.CreateSecureBuffer(32);
            Sodium.ComputePublicKey(
                deviceToRevokeX25519Public,
                _cryptoProvider.ConvertEd25519PrivateKeyToX25519(deviceToRevokeKeyPair.PrivateKey));

            // Create two device managers
            var mainDeviceManager = new DeviceManager(mainDeviceKeyPair);
            var otherDeviceManager = new DeviceManager(otherDeviceKeyPair);

            // Link the device to the other manager
            otherDeviceManager.AddLinkedDevice(deviceToRevokeX25519Public);

            // Create a valid revocation message
            var revocationMessage = mainDeviceManager.CreateDeviceRevocationMessage(deviceToRevokeX25519Public);

            // Create a tampered copy with a different timestamp
            var tamperedMessage = new DeviceRevocationMessage
            {
                UserIdentityPublicKey = revocationMessage.UserIdentityPublicKey,
                RevokedDevicePublicKey = revocationMessage.RevokedDevicePublicKey,
                Timestamp = revocationMessage.Timestamp + 10000, // Change timestamp
                Signature = revocationMessage.Signature // Keep the original signature
            };

            // Act - Process the tampered revocation message
            bool result = otherDeviceManager.ProcessDeviceRevocationMessage(tamperedMessage);

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
            var mainDeviceKeyPair = Sodium.GenerateEd25519KeyPair();
            var deviceToRevokeKeyPair = Sodium.GenerateEd25519KeyPair();

            // Create X25519 key for the device to revoke
            byte[] deviceToRevokeX25519Public = SecureMemory.CreateSecureBuffer(32);
            Sodium.ComputePublicKey(
                deviceToRevokeX25519Public,
                _cryptoProvider.ConvertEd25519PrivateKeyToX25519(deviceToRevokeKeyPair.PrivateKey));

            // Create a device manager without linking the deviceToRevokeKeyPair
            var deviceManager = new DeviceManager(mainDeviceKeyPair);

            // Act & Assert - Should throw InvalidOperationException
            deviceManager.RemoveLinkedDevice(deviceToRevokeX25519Public);
        }

        [TestMethod]
        public void DeviceRevocationMessage_Validate_WithNullFields_ShouldReturnFalse()
        {
            // Arrange
            var authorityKeyPair = Sodium.GenerateEd25519KeyPair();

            // Create invalid revocation messages
            var nullKeyMessage = new DeviceRevocationMessage
            {
                UserIdentityPublicKey = authorityKeyPair.PublicKey,
                RevokedDevicePublicKey = null,
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                Signature = new byte[64]
            };

            var nullSignatureMessage = new DeviceRevocationMessage
            {
                UserIdentityPublicKey = authorityKeyPair.PublicKey,
                RevokedDevicePublicKey = new byte[32],
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                Signature = null
            };

            var zeroTimestampMessage = new DeviceRevocationMessage
            {
                UserIdentityPublicKey = authorityKeyPair.PublicKey,
                RevokedDevicePublicKey = new byte[32],
                Timestamp = 0,
                Signature = new byte[64]
            };

            // Act
            bool nullKeyResult = nullKeyMessage.IsValid();
            bool nullSignatureResult = nullSignatureMessage.IsValid();
            bool zeroTimestampResult = zeroTimestampMessage.IsValid();

            // Assert
            Assert.IsFalse(nullKeyResult, "Validation should fail with null revoked device key");
            Assert.IsFalse(nullSignatureResult, "Validation should fail with null signature");
            Assert.IsFalse(zeroTimestampResult, "Validation should fail with zero timestamp");
        }

        [TestMethod]
        public void E2EEClient_CreateDeviceRevocationMessage_CombinesDataCorrectly()
        {
            // Arrange
            var authorityKeyPair = Sodium.GenerateEd25519KeyPair();
            var deviceToRevokeKeyPair = Sodium.GenerateEd25519KeyPair();

            // Act
            var revocationMessage = _deviceLinkingSvc.CreateDeviceRevocationMessage(
                _authorityKeyPair,
                deviceToRevokeKeyPair.PublicKey);

            // Manually combine data for verification
            byte[] timestampBytes = BitConverter.GetBytes(revocationMessage.Timestamp);
            byte[] dataToSign = new byte[deviceToRevokeKeyPair.PublicKey.Length + timestampBytes.Length];

            deviceToRevokeKeyPair.PublicKey.AsSpan().CopyTo(dataToSign.AsSpan(0, deviceToRevokeKeyPair.PublicKey.Length));
            timestampBytes.AsSpan().CopyTo(dataToSign.AsSpan(deviceToRevokeKeyPair.PublicKey.Length));

            // Verify the signature directly
            bool isValidManually = _cryptoProvider.VerifySignature(dataToSign, revocationMessage.Signature, authorityKeyPair.PublicKey);

            // Assert
            Assert.IsTrue(isValidManually, "Signature validation should pass with manually combined data");
        }

        [TestMethod]
        public void RevokedDevice_ShouldNotBeAddedAgain()
        {
            // Arrange
            var identityKeyPair = Sodium.GenerateEd25519KeyPair();
            var deviceManager = new DeviceManager(identityKeyPair);
            var deviceKeyPair = Sodium.GenerateEd25519KeyPair();

            // Act
            deviceManager.AddLinkedDevice(deviceKeyPair.PublicKey);
            Assert.IsTrue(deviceManager.IsDeviceLinked(deviceKeyPair.PublicKey));

            // Revoke the device
            deviceManager.RemoveLinkedDevice(deviceKeyPair.PublicKey);
            Assert.IsFalse(deviceManager.IsDeviceLinked(deviceKeyPair.PublicKey));

            // Attempt to add it again
            bool exceptionThrown = false;
            try
            {
                deviceManager.AddLinkedDevice(deviceKeyPair.PublicKey);
            }
            catch (SecurityException)
            {
                exceptionThrown = true;
            }

            // Assert
            Assert.IsTrue(exceptionThrown, "Expected SecurityException was not thrown");
            Assert.IsFalse(deviceManager.IsDeviceLinked(deviceKeyPair.PublicKey));
        }

        [TestMethod]
        public void RevokedDevices_ShouldBeTracked_EvenAfterRestart()
        {
            // Arrange
            var identityKeyPair = Sodium.GenerateEd25519KeyPair();
            var deviceManager = new DeviceManager(identityKeyPair);
            var device1 = Sodium.GenerateEd25519KeyPair().PublicKey;
            var device2 = Sodium.GenerateEd25519KeyPair().PublicKey;

            // Act - Add and revoke device1
            deviceManager.AddLinkedDevice(device1);
            deviceManager.AddLinkedDevice(device2);

            deviceManager.RemoveLinkedDevice(device1);

            // Export linked devices
            string exportedData = deviceManager.ExportLinkedDevices();

            // Create a new device manager (simulate restart)
            var newDeviceManager = new DeviceManager(identityKeyPair);

            // Import linked devices
            newDeviceManager.ImportLinkedDevices(exportedData);

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