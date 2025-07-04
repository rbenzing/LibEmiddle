﻿using System;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using LibEmiddle.API;
using LibEmiddle.Messaging.Transport;
using LibEmiddle.Core;
using LibEmiddle.Domain;
using LibEmiddle.Crypto;

namespace LibEmiddle.Tests.Unit
{
    [TestClass]
    public class SignatureTests
    {
        private CryptoProvider _cryptoProvider;

        [TestInitialize]
        public void Setup()
        {
            _cryptoProvider = new CryptoProvider();
        }

        [TestMethod]
        public void SignAndVerifyMessage_ShouldVerifyCorrectly()
        {
            // Arrange
            byte[] message = Encoding.Default.GetBytes("This is a message to be signed");
            KeyPair _identityKeyPair = Sodium.GenerateEd25519KeyPair();
            var publicKey = _identityKeyPair.PublicKey;
            var privateKey = _identityKeyPair.PrivateKey;

            // Act
            byte[] signature = _cryptoProvider.Sign(message, privateKey);
            bool isValid = _cryptoProvider.VerifySignature(message, signature, publicKey);

            // Assert
            Assert.IsTrue(isValid);
        }

        [TestMethod]
        public void VerifySignature_WithTamperedMessage_ShouldReturnFalse()
        {
            // Arrange
            byte[] originalMessage = Encoding.Default.GetBytes("This is a message to be signed");
            byte[] tamperedMessage = Encoding.Default.GetBytes("This is a tampered message");
            KeyPair _identityKeyPair = Sodium.GenerateEd25519KeyPair();
            var publicKey = _identityKeyPair.PublicKey;
            var privateKey = _identityKeyPair.PrivateKey;

            // Act
            byte[] signature = _cryptoProvider.Sign(originalMessage, privateKey);
            bool isValid = _cryptoProvider.VerifySignature(tamperedMessage, signature, publicKey);

            // Assert
            Assert.IsFalse(isValid);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void SignMessage_WithNullPrivateKey_ShouldThrowException()
        {
            // Arrange
            byte[] message = Encoding.Default.GetBytes("Test message");

            // Act & Assert - Should throw ArgumentNullException
            _cryptoProvider.Sign(message, null);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void SignMessage_WithX25519PrivateKey_ShouldNotWork()
        {
            // Arrange
            byte[] message = Encoding.Default.GetBytes("Message to sign with X25519 key");
            KeyPair _identityKeyPair = Sodium.GenerateX25519KeyPair();
            var privateKey = _identityKeyPair.PrivateKey;

            // Act
            byte[] signature = Sodium.SignDetached(message, privateKey);

            Assert.IsTrue(signature == null);
        }

        [TestMethod]
        public void SigningPerformance_ShouldBeReasonable()
        {
            // Arrange
            byte[] smallMessage = Encoding.Default.GetBytes("Small message");
            byte[] mediumMessage = SecureMemory.CreateSecureBuffer(1024); // 1KB
            byte[] largeMessage = SecureMemory.CreateSecureBuffer(1024 * 10); // 10KB

            KeyPair _signIdentityKeyPair = Sodium.GenerateEd25519KeyPair();
            var publicKey = _signIdentityKeyPair.PublicKey;
            var originalPrivateKey = _signIdentityKeyPair.PrivateKey;

            // Create copies of the private key since Sign() method clears it
            byte[] privateKey1 = new byte[originalPrivateKey.Length];
            byte[] privateKey2 = new byte[originalPrivateKey.Length];
            byte[] privateKey3 = new byte[originalPrivateKey.Length];

            Array.Copy(originalPrivateKey, privateKey1, originalPrivateKey.Length);
            Array.Copy(originalPrivateKey, privateKey2, originalPrivateKey.Length);
            Array.Copy(originalPrivateKey, privateKey3, originalPrivateKey.Length);

            // Act - Measure signing time
            System.Diagnostics.Stopwatch stopwatch = new System.Diagnostics.Stopwatch();

            // Small message
            stopwatch.Start();
            byte[] smallSignature = _cryptoProvider.Sign(smallMessage, privateKey1);
            stopwatch.Stop();
            long smallSignTime = stopwatch.ElapsedMilliseconds;

            // Medium message
            stopwatch.Restart();
            byte[] mediumSignature = _cryptoProvider.Sign(mediumMessage, privateKey2);
            stopwatch.Stop();
            long mediumSignTime = stopwatch.ElapsedMilliseconds;

            // Large message
            stopwatch.Restart();
            byte[] largeSignature = _cryptoProvider.Sign(largeMessage, privateKey3);
            stopwatch.Stop();
            long largeSignTime = stopwatch.ElapsedMilliseconds;

            // Assert - Verify signatures and check performance is reasonable
            Assert.IsTrue(_cryptoProvider.VerifySignature(smallMessage, smallSignature, publicKey));
            Assert.IsTrue(_cryptoProvider.VerifySignature(mediumMessage, mediumSignature, publicKey));
            Assert.IsTrue(_cryptoProvider.VerifySignature(largeMessage, largeSignature, publicKey));

            // Small message should be fast (we're using a loose constraint to allow for slow CI environments)
            Assert.IsTrue(smallSignTime < 500, $"Small message signing took {smallSignTime}ms");

            // Performance should scale somewhat linearly with message size
            double smallToMediumRatio = (double)mediumMessage.Length / smallMessage.Length;
            double signTimeRatio = (double)mediumSignTime / Math.Max(1, smallSignTime); // Avoid div by zero

            // Allow for overhead - actual ratio will vary but should not be exponential
            // Ed25519 is constant time for the same size input, but there's still overhead for larger messages
            Assert.IsTrue(signTimeRatio < smallToMediumRatio * 3,
                $"Signing time doesn't scale reasonably with message size. Message size ratio: {smallToMediumRatio}, time ratio: {signTimeRatio}");
        }

        [TestMethod]
        public void LongTermCryptographicIdentity_ShouldBeSecure()
        {
            // Generate multiple key pairs
            KeyPair _signIdentityKeyPair1 = Sodium.GenerateEd25519KeyPair();
            KeyPair _signIdentityKeyPair2 = Sodium.GenerateEd25519KeyPair();
            KeyPair _signIdentityKeyPair3 = Sodium.GenerateEd25519KeyPair();


            // Ensure keys meet minimum security requirements
            Assert.AreEqual(32, _signIdentityKeyPair1.PublicKey.Length, "Ed25519 public key should be 32 bytes");
            Assert.AreEqual(64, _signIdentityKeyPair1.PrivateKey.Length, "Ed25519 private key should be 64 bytes");

            // Ensure all generated keys are different
            CollectionAssert.AreNotEqual(_signIdentityKeyPair1.PublicKey, _signIdentityKeyPair2.PublicKey);
            CollectionAssert.AreNotEqual(_signIdentityKeyPair1.PublicKey, _signIdentityKeyPair3.PublicKey);
            CollectionAssert.AreNotEqual(_signIdentityKeyPair2.PublicKey, _signIdentityKeyPair3.PublicKey);

            CollectionAssert.AreNotEqual(_signIdentityKeyPair1.PrivateKey, _signIdentityKeyPair2.PrivateKey);
            CollectionAssert.AreNotEqual(_signIdentityKeyPair1.PrivateKey, _signIdentityKeyPair3.PrivateKey);
            CollectionAssert.AreNotEqual(_signIdentityKeyPair2.PrivateKey, _signIdentityKeyPair3.PrivateKey);

            // Test signature functionality
            string message = "Cryptographic identity test message";
            byte[] messageBytes = Encoding.Default.GetBytes(message);

            byte[] signature1 = _cryptoProvider.Sign(messageBytes, _signIdentityKeyPair1.PrivateKey);
            byte[] signature2 = _cryptoProvider.Sign(messageBytes, _signIdentityKeyPair2.PrivateKey);
            byte[] signature3 = _cryptoProvider.Sign(messageBytes, _signIdentityKeyPair3.PrivateKey);

            // Ensure signatures are different for different keys
            CollectionAssert.AreNotEqual(signature1, signature2);
            CollectionAssert.AreNotEqual(signature1, signature3);
            CollectionAssert.AreNotEqual(signature2, signature3);

            // Ensure signatures verify correctly
            Assert.IsTrue(_cryptoProvider.VerifySignature(messageBytes, signature1, _signIdentityKeyPair1.PublicKey));
            Assert.IsTrue(_cryptoProvider.VerifySignature(messageBytes, signature2, _signIdentityKeyPair2.PublicKey));
            Assert.IsTrue(_cryptoProvider.VerifySignature(messageBytes, signature3, _signIdentityKeyPair3.PublicKey));

            // Ensure signatures don't verify with the wrong key
            Assert.IsFalse(_cryptoProvider.VerifySignature(messageBytes, signature1, _signIdentityKeyPair2.PublicKey));
            Assert.IsFalse(_cryptoProvider.VerifySignature(messageBytes, signature2, _signIdentityKeyPair3.PublicKey));
            Assert.IsFalse(_cryptoProvider.VerifySignature(messageBytes, signature3, _signIdentityKeyPair1.PublicKey));
        }
    }
}