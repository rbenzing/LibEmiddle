using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using E2EELibrary.Core;

namespace E2EELibraryTests
{
    [TestClass]
    public class KeyAuthLoadTests
    {
        [TestMethod]
        public void GenerateKeyPair_UnderHighLoad_ShouldStillGenerateValidPairs()
        {
            const int ITERATIONS = 1000;
            var keyPairs = new List<KeyAuth.KeyPair>();

            object lockObject = new object();

            Parallel.For(0, ITERATIONS, _ =>
            {
                var keyPair = KeyAuth.GenerateKeyPair();
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
            var keyPair = KeyAuth.GenerateKeyPair();
            var largeMessage = new byte[1024 * 1024]; // 1MB message
            new Random().NextBytes(largeMessage);

            // Act
            byte[] signature = KeyAuth.SignDetached(largeMessage, keyPair.PrivateKey);

            // Assert
            bool verified = KeyAuth.VerifyDetached(signature, largeMessage, keyPair.PublicKey);
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
            KeyAuth.SignDetached(message, invalidPrivateKey);
        }

        [TestMethod]
        public void VerifyDetached_TamperedSignature_ShouldReturnFalse()
        {
            // Arrange
            var keyPair = KeyAuth.GenerateKeyPair();
            var message = Encoding.UTF8.GetBytes("Test message");
            var signature = KeyAuth.SignDetached(message, keyPair.PrivateKey);

            // Tamper with signature
            signature[0] ^= 0xFF;

            // Act
            bool verified = KeyAuth.VerifyDetached(signature, message, keyPair.PublicKey);

            // Assert
            Assert.IsFalse(verified, "Tampered signature should not verify");
        }
    }
}