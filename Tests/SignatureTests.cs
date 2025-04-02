using System;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using E2EELibrary;
using E2EELibrary.Communication;

namespace E2EELibraryTests
{
    [TestClass]
    public class SignatureTests
    {
        [TestMethod]
        public void SignAndVerifyMessage_ShouldVerifyCorrectly()
        {
            // Arrange
            byte[] message = Encoding.UTF8.GetBytes("This is a message to be signed");
            var (publicKey, privateKey) = LibEmiddleClient.GenerateSignatureKeyPair();

            // Act
            byte[] signature = LibEmiddleClient.SignMessage(message, privateKey);
            bool isValid = LibEmiddleClient.VerifySignature(message, signature, publicKey);

            // Assert
            Assert.IsTrue(isValid);
        }

        [TestMethod]
        public void VerifySignature_WithTamperedMessage_ShouldReturnFalse()
        {
            // Arrange
            byte[] originalMessage = Encoding.UTF8.GetBytes("This is a message to be signed");
            byte[] tamperedMessage = Encoding.UTF8.GetBytes("This is a tampered message");
            var (publicKey, privateKey) = LibEmiddleClient.GenerateSignatureKeyPair();

            // Act
            byte[] signature = LibEmiddleClient.SignMessage(originalMessage, privateKey);
            bool isValid = LibEmiddleClient.VerifySignature(tamperedMessage, signature, publicKey);

            // Assert
            Assert.IsFalse(isValid);
        }

        [TestMethod]
        public void SignAndVerifyTextMessage_ShouldVerifyCorrectly()
        {
            // Arrange
            string message = "This is a text message to be signed";
            var (publicKey, privateKey) = LibEmiddleClient.GenerateSignatureKeyPair();

            // Act
            string signatureBase64 = LibEmiddleClient.SignTextMessage(message, privateKey);
            bool isValid = LibEmiddleClient.VerifyTextMessage(message, signatureBase64, publicKey);

            // Assert
            Assert.IsTrue(isValid);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void SignMessage_WithNullPrivateKey_ShouldThrowException()
        {
            // Arrange
            byte[] message = Encoding.UTF8.GetBytes("Test message");

            // Act & Assert - Should throw ArgumentNullException
            LibEmiddleClient.SignMessage(message, null);
        }

        [TestMethod]
        public void VerifyTextMessage_WithInvalidBase64_ShouldReturnFalse()
        {
            // Arrange
            string message = "Test message";
            var (publicKey, _) = LibEmiddleClient.GenerateSignatureKeyPair();
            string invalidBase64 = "not valid base64!@#$";

            // Act
            bool result = LibEmiddleClient.VerifyTextMessage(message, invalidBase64, publicKey);

            // Assert
            Assert.IsFalse(result);
        }

        [TestMethod]
        public void SignMessage_WithX25519PrivateKey_ShouldStillWork()
        {
            // Arrange
            byte[] message = Encoding.UTF8.GetBytes("Message to sign with X25519 key");
            var (publicKey, privateKey) = LibEmiddleClient.GenerateKeyExchangeKeyPair(); // X25519 key pair

            // Act
            byte[] signature = MessageSigning.SignMessage(message, privateKey);

            // We can't verify with X25519 public key directly, so this is just testing that signing doesn't throw

            // Assert
            Assert.IsNotNull(signature);
            Assert.IsTrue(signature.Length > 0);
        }

        [TestMethod]
        public void SigningPerformance_ShouldBeReasonable()
        {
            // Arrange
            byte[] smallMessage = Encoding.UTF8.GetBytes("Small message");
            byte[] mediumMessage = new byte[1024]; // 1KB
            byte[] largeMessage = new byte[1024 * 10]; // 10KB

            // Generate some sample data
            Random random = new Random();
            random.NextBytes(mediumMessage);
            random.NextBytes(largeMessage);

            var (publicKey, privateKey) = LibEmiddleClient.GenerateSignatureKeyPair();

            // Act - Measure signing time
            System.Diagnostics.Stopwatch stopwatch = new System.Diagnostics.Stopwatch();

            // Small message
            stopwatch.Start();
            byte[] smallSignature = LibEmiddleClient.SignMessage(smallMessage, privateKey);
            stopwatch.Stop();
            long smallSignTime = stopwatch.ElapsedMilliseconds;

            // Medium message
            stopwatch.Restart();
            byte[] mediumSignature = LibEmiddleClient.SignMessage(mediumMessage, privateKey);
            stopwatch.Stop();
            long mediumSignTime = stopwatch.ElapsedMilliseconds;

            // Large message
            stopwatch.Restart();
            byte[] largeSignature = LibEmiddleClient.SignMessage(largeMessage, privateKey);
            stopwatch.Stop();
            long largeSignTime = stopwatch.ElapsedMilliseconds;

            // Assert - Verify signatures and check performance is reasonable
            Assert.IsTrue(LibEmiddleClient.VerifySignature(smallMessage, smallSignature, publicKey));
            Assert.IsTrue(LibEmiddleClient.VerifySignature(mediumMessage, mediumSignature, publicKey));
            Assert.IsTrue(LibEmiddleClient.VerifySignature(largeMessage, largeSignature, publicKey));

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
            var keyPair1 = LibEmiddleClient.GenerateSignatureKeyPair();
            var keyPair2 = LibEmiddleClient.GenerateSignatureKeyPair();
            var keyPair3 = LibEmiddleClient.GenerateSignatureKeyPair();

            // Ensure keys meet minimum security requirements
            Assert.AreEqual(32, keyPair1.publicKey.Length, "Ed25519 public key should be 32 bytes");
            Assert.AreEqual(64, keyPair1.privateKey.Length, "Ed25519 private key should be 64 bytes");

            // Ensure all generated keys are different
            CollectionAssert.AreNotEqual(keyPair1.publicKey, keyPair2.publicKey);
            CollectionAssert.AreNotEqual(keyPair1.publicKey, keyPair3.publicKey);
            CollectionAssert.AreNotEqual(keyPair2.publicKey, keyPair3.publicKey);

            CollectionAssert.AreNotEqual(keyPair1.privateKey, keyPair2.privateKey);
            CollectionAssert.AreNotEqual(keyPair1.privateKey, keyPair3.privateKey);
            CollectionAssert.AreNotEqual(keyPair2.privateKey, keyPair3.privateKey);

            // Test signature functionality
            string message = "Cryptographic identity test message";
            byte[] messageBytes = Encoding.UTF8.GetBytes(message);

            byte[] signature1 = LibEmiddleClient.SignMessage(messageBytes, keyPair1.privateKey);
            byte[] signature2 = LibEmiddleClient.SignMessage(messageBytes, keyPair2.privateKey);
            byte[] signature3 = LibEmiddleClient.SignMessage(messageBytes, keyPair3.privateKey);

            // Ensure signatures are different for different keys
            CollectionAssert.AreNotEqual(signature1, signature2);
            CollectionAssert.AreNotEqual(signature1, signature3);
            CollectionAssert.AreNotEqual(signature2, signature3);

            // Ensure signatures verify correctly
            Assert.IsTrue(LibEmiddleClient.VerifySignature(messageBytes, signature1, keyPair1.publicKey));
            Assert.IsTrue(LibEmiddleClient.VerifySignature(messageBytes, signature2, keyPair2.publicKey));
            Assert.IsTrue(LibEmiddleClient.VerifySignature(messageBytes, signature3, keyPair3.publicKey));

            // Ensure signatures don't verify with the wrong key
            Assert.IsFalse(LibEmiddleClient.VerifySignature(messageBytes, signature1, keyPair2.publicKey));
            Assert.IsFalse(LibEmiddleClient.VerifySignature(messageBytes, signature2, keyPair3.publicKey));
            Assert.IsFalse(LibEmiddleClient.VerifySignature(messageBytes, signature3, keyPair1.publicKey));
        }
    }
}