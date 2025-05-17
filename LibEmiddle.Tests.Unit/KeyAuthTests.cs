using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using LibEmiddle.Core;
using LibEmiddle.Domain;
using LibEmiddle.Crypto;

namespace LibEmiddle.Tests.Unit
{
    [TestClass]
    public class KeyAuthLoadTests
    {
        private CryptoProvider _cryptoProvider;

        [TestInitialize]
        public void Setup()
        {
            _cryptoProvider = new CryptoProvider();
        }

        [TestMethod]
        public void GenerateKeyPair_UnderHighLoad_ShouldStillGenerateValidPairs()
        {
            const int ITERATIONS = 1000;
            var keyPairs = new List<KeyPair>();

            object lockObject = new object();

            Parallel.For(0, ITERATIONS, _ =>
            {
                var keyPair = Sodium.GenerateX25519KeyPair();
                lock (lockObject)
                {
                    keyPairs.Add(keyPair);
                }
            });

            Assert.AreEqual(ITERATIONS, keyPairs.Count, "Should generate unique key pairs under load");

            // Validate uniqueness of keys
            var uniquePublicKeys = keyPairs
                .Select(kp => Convert.ToBase64String(kp.PublicKey))
                .Distinct()
                .Count();

            var uniquePrivateKeys = keyPairs
                .Select(kp => Convert.ToBase64String(kp.PrivateKey))
                .Distinct()
                .Count();

            Assert.AreEqual(ITERATIONS, uniquePublicKeys, "Public keys should be unique");
            Assert.AreEqual(ITERATIONS, uniquePrivateKeys, "Private keys should be unique");
        }

        [TestMethod]
        public void SignAndVerify_WithLargeMessage_ShouldWorkCorrectly()
        {
            // Arrange
            var keyPair = Sodium.GenerateEd25519KeyPair();
            var largeMessage = SecureMemory.CreateSecureBuffer(1024 * 1024); // 1MB message

            // Act
            byte[] signature = _cryptoProvider.Sign(largeMessage, keyPair.PrivateKey);

            // Assert
            bool verified = _cryptoProvider.VerifySignature(largeMessage, signature, keyPair.PublicKey);
            Assert.IsTrue(verified, "Large message signature should verify correctly");
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void SignDetached_InvalidPrivateKeyLength_ShouldThrowException()
        {
            // Arrange
            var message = new byte[100];
            var invalidPrivateKey = new byte[32]; // Wrong length

            // Act & Assert
            _cryptoProvider.Sign(message, invalidPrivateKey);
        }

        [TestMethod]
        public void VerifyDetached_TamperedSignature_ShouldReturnFalse()
        {
            // Arrange
            var keyPair = Sodium.GenerateEd25519KeyPair();
            var message = Encoding.Default.GetBytes("Test message");
            var signature = _cryptoProvider.Sign(message, keyPair.PrivateKey);

            // Tamper with signature
            signature[0] ^= 0xFF;

            // Act
            bool verified = _cryptoProvider.VerifySignature(message, signature, keyPair.PublicKey);

            // Assert
            Assert.IsFalse(verified, "Tampered signature should not verify");
        }
    }
}