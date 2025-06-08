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
        private CryptoProvider _cryptoProvider = null!;
        private DeviceLinkingService _deviceLinkingSvc = null!;
        private KeyPair _authorityKeyPair;

        [TestInitialize]
        public void Setup()
        {
            _cryptoProvider = new CryptoProvider();
            _deviceLinkingSvc = new DeviceLinkingService(_cryptoProvider);
            _authorityKeyPair = Sodium.GenerateEd25519KeyPair();
        }

        [TestCleanup]
        public void Cleanup()
        {
            _cryptoProvider?.Dispose();
            _deviceLinkingSvc?.Dispose();
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

            // Verify timestamp contains valid timestamp
            long currentTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            Assert.IsTrue(Math.Abs(currentTime - revocationMessage.Timestamp) < 5000,
                "Timestamp should be close to current time");

            // The revoked device key should match what we provided (after normalization)
            Assert.AreEqual(32, revocationMessage.RevokedDevicePublicKey.Length);
        }

        [TestMethod]
        public void ValidateDeviceRevocationMessage_WithValidMessage_ShouldReturnTrue()
        {
            // Arrange - Use the same authority key pair for both creation and verification
            var deviceToRevokeKeyPair = Sodium.GenerateEd25519KeyPair();

            var revocationMessage = _deviceLinkingSvc.CreateDeviceRevocationMessage(
                _authorityKeyPair,
                deviceToRevokeKeyPair.PublicKey);

            // Act - Verify with the same authority key pair that created the message
            bool isValid = _deviceLinkingSvc.VerifyDeviceRevocationMessage(
                revocationMessage,
                _authorityKeyPair.PublicKey);

            // Assert
            Assert.IsTrue(revocationMessage.IsValid(), "Revocation message should validate true");
            Assert.IsTrue(isValid, "Verified revocation message should validate true");
        }

        [TestMethod]
        public void ValidateDeviceRevocationMessage_WithWrongSigningKey_ShouldReturnFalse()
        {
            // Arrange
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
            var deviceToRevokeKeyPair = Sodium.GenerateEd25519KeyPair();

            var revocationMessage = _deviceLinkingSvc.CreateDeviceRevocationMessage(
                _authorityKeyPair,
                deviceToRevokeKeyPair.PublicKey);

            // Create a tampered copy with a different timestamp
            var tamperedMessage = new DeviceRevocationMessage
            {
                Id = revocationMessage.Id,
                UserIdentityPublicKey = revocationMessage.UserIdentityPublicKey,
                RevokedDevicePublicKey = revocationMessage.RevokedDevicePublicKey,
                Timestamp = revocationMessage.Timestamp + 10000, // Change timestamp
                Signature = revocationMessage.Signature, // Keep the original signature
                Reason = revocationMessage.Reason,
                Version = revocationMessage.Version
            };

            // Act
            bool isValid = _deviceLinkingSvc.VerifyDeviceRevocationMessage(
                tamperedMessage,
                _authorityKeyPair.PublicKey);

            // Assert
            Assert.IsFalse(isValid, "Validation should fail with tampered message");
        }

        [TestMethod]
        public void DeviceManager_RemoveLinkedDevice_ShouldRemoveDevice()
        {
            // Arrange
            var mainDeviceKeyPair = Sodium.GenerateEd25519KeyPair();
            var deviceToRemoveKeyPair = Sodium.GenerateEd25519KeyPair();

            // Create a device manager and link a device
            var deviceManager = new DeviceManager(mainDeviceKeyPair, _deviceLinkingSvc, _cryptoProvider);
            deviceManager.AddLinkedDevice(deviceToRemoveKeyPair.PublicKey);

            // Verify device is linked
            Assert.IsTrue(deviceManager.IsDeviceLinked(deviceToRemoveKeyPair.PublicKey),
                "Device should be linked before removal");
            Assert.AreEqual(1, deviceManager.GetLinkedDeviceCount(),
                "Should have one linked device");

            // Act
            bool isRemoved = deviceManager.RemoveLinkedDevice(deviceToRemoveKeyPair.PublicKey);

            // Assert
            Assert.IsTrue(isRemoved, "Device removal should succeed");
            Assert.IsFalse(deviceManager.IsDeviceLinked(deviceToRemoveKeyPair.PublicKey),
                "Device should no longer be linked after removal");
            Assert.AreEqual(0, deviceManager.GetLinkedDeviceCount(),
                "Should have zero linked devices after removal");
        }

        [TestMethod]
        public void DeviceManager_ProcessRevocationMessage_ShouldRemoveLinkedDevice()
        {
            // Arrange
            var userIdentityKeyPair = Sodium.GenerateEd25519KeyPair(); // Same identity for both devices
            var deviceToRevokeKeyPair = Sodium.GenerateEd25519KeyPair();

            // Create two device managers with the same user identity (simulating different devices of same user)
            var mainDeviceManager = new DeviceManager(userIdentityKeyPair, _deviceLinkingSvc, _cryptoProvider);
            var otherDeviceManager = new DeviceManager(userIdentityKeyPair, _deviceLinkingSvc, _cryptoProvider);

            // Link the device to both managers
            mainDeviceManager.AddLinkedDevice(deviceToRevokeKeyPair.PublicKey);
            otherDeviceManager.AddLinkedDevice(deviceToRevokeKeyPair.PublicKey);

            // Create a revocation message from the main device
            var revocationMessage = mainDeviceManager.CreateDeviceRevocationMessage(deviceToRevokeKeyPair.PublicKey);

            // Act - Process the revocation message on the other device
            bool result = otherDeviceManager.ProcessDeviceRevocationMessage(revocationMessage);

            // Assert
            Assert.IsTrue(result, "Processing valid revocation message should succeed");
            Assert.IsFalse(otherDeviceManager.IsDeviceLinked(deviceToRevokeKeyPair.PublicKey),
                "Device should be removed after processing revocation message");
        }

        [TestMethod]
        public void DeviceManager_ProcessRevocationMessage_WithInvalidSignature_ShouldReturnFalse()
        {
            // Arrange
            var userIdentityKeyPair = Sodium.GenerateEd25519KeyPair(); // Same identity for both devices
            var deviceToRevokeKeyPair = Sodium.GenerateEd25519KeyPair();

            // Create two device managers with the same user identity
            var mainDeviceManager = new DeviceManager(userIdentityKeyPair, _deviceLinkingSvc, _cryptoProvider);
            var otherDeviceManager = new DeviceManager(userIdentityKeyPair, _deviceLinkingSvc, _cryptoProvider);

            // Link the device to the other manager
            otherDeviceManager.AddLinkedDevice(deviceToRevokeKeyPair.PublicKey);

            // Create a valid revocation message
            var revocationMessage = mainDeviceManager.CreateDeviceRevocationMessage(deviceToRevokeKeyPair.PublicKey);

            // Create a tampered copy with a different timestamp
            var tamperedMessage = new DeviceRevocationMessage
            {
                Id = revocationMessage.Id,
                UserIdentityPublicKey = revocationMessage.UserIdentityPublicKey,
                RevokedDevicePublicKey = revocationMessage.RevokedDevicePublicKey,
                Timestamp = revocationMessage.Timestamp + 10000, // Change timestamp
                Signature = revocationMessage.Signature, // Keep the original signature
                Reason = revocationMessage.Reason,
                Version = revocationMessage.Version
            };

            // Act - Process the tampered revocation message
            bool result = otherDeviceManager.ProcessDeviceRevocationMessage(tamperedMessage);

            // Assert
            Assert.IsFalse(result, "Processing tampered revocation message should fail");
            Assert.IsTrue(otherDeviceManager.IsDeviceLinked(deviceToRevokeKeyPair.PublicKey),
                "Device should still be linked after failed revocation");
        }

        [TestMethod]
        public void DeviceManager_RemoveLinkedDevice_UnknownDevice_ShouldReturnFalse()
        {
            // Arrange
            var mainDeviceKeyPair = Sodium.GenerateEd25519KeyPair();
            var deviceToRemoveKeyPair = Sodium.GenerateEd25519KeyPair();

            // Create a device manager without linking the device
            var deviceManager = new DeviceManager(mainDeviceKeyPair, _deviceLinkingSvc, _cryptoProvider);

            // Act - Try to remove a device that was never linked
            bool result = deviceManager.RemoveLinkedDevice(deviceToRemoveKeyPair.PublicKey);

            // Assert - Should return false, not throw exception
            Assert.IsFalse(result, "Removing non-existent device should return false");
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
        public void DeviceLinkingService_SignatureDataFormat_ShouldMatchImplementation()
        {
            // Arrange
            var deviceToRevokeKeyPair = Sodium.GenerateEd25519KeyPair();

            // Act
            var revocationMessage = _deviceLinkingSvc.CreateDeviceRevocationMessage(
                _authorityKeyPair,
                deviceToRevokeKeyPair.PublicKey);

            // Verify the signature is valid using the service's own verification
            bool isValid = _deviceLinkingSvc.VerifyDeviceRevocationMessage(
                revocationMessage,
                _authorityKeyPair.PublicKey);

            // Assert
            Assert.IsTrue(isValid, "Signature validation should pass using the service's verification method");
        }

        [TestMethod]
        public void AddRevokedDevice_ShouldNotBeAddedAgain()
        {
            // Arrange
            var identityKeyPair = Sodium.GenerateEd25519KeyPair();
            var deviceManager = new DeviceManager(identityKeyPair, _deviceLinkingSvc, _cryptoProvider);
            var deviceKeyPair = Sodium.GenerateX25519KeyPair();

            // Act
            deviceManager.AddLinkedDevice(deviceKeyPair.PublicKey);
            Assert.IsTrue(deviceManager.IsDeviceLinked(deviceKeyPair.PublicKey));

            // Create and process a revocation message (which tracks the revocation)
            var revocationMessage = deviceManager.CreateDeviceRevocationMessage(deviceKeyPair.PublicKey);
            bool processed = deviceManager.ProcessDeviceRevocationMessage(revocationMessage);
            Assert.IsTrue(processed, "Revocation should be processed successfully");
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
            var deviceManager = new DeviceManager(identityKeyPair, _deviceLinkingSvc, _cryptoProvider);
            var device1 = Sodium.GenerateEd25519KeyPair().PublicKey;
            var device2 = Sodium.GenerateEd25519KeyPair().PublicKey;

            // Act - Add devices and revoke device1
            deviceManager.AddLinkedDevice(device1);
            deviceManager.AddLinkedDevice(device2);

            // Create and process revocation for device1 (this tracks the revocation)
            var revocationMessage = deviceManager.CreateDeviceRevocationMessage(device1);
            deviceManager.ProcessDeviceRevocationMessage(revocationMessage);

            // Export both linked devices and revocations
            string exportedDevices = deviceManager.ExportLinkedDevices();
            string exportedRevocations = deviceManager.ExportRevocations();

            // Create a new device manager (simulate restart)
            var newDeviceManager = new DeviceManager(identityKeyPair, _deviceLinkingSvc, _cryptoProvider);

            // Import both linked devices and revocations
            newDeviceManager.ImportLinkedDevices(exportedDevices);
            newDeviceManager.ImportRevocations(exportedRevocations);

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