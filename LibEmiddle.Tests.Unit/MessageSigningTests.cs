using System;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using LibEmiddle.Core;
using LibEmiddle.Domain;
using LibEmiddle.Messaging.Transport;

namespace LibEmiddle.Tests.Unit
{
    [TestClass]
    public class MessageSigningTests
    {
        // ---------------------------------------------------------------------------
        // SignMessage + VerifySignature
        // ---------------------------------------------------------------------------

        [TestMethod]
        public void SignMessage_VerifySignature_RoundTrip_ShouldSucceed()
        {
            // Arrange
            KeyPair keyPair = Sodium.GenerateEd25519KeyPair();
            byte[] message = Encoding.UTF8.GetBytes("Hello, LibEmiddle!");

            // Act
            byte[] signature = MessageSigning.SignMessage(message, keyPair.PrivateKey);
            bool valid = MessageSigning.VerifySignature(message, signature, keyPair.PublicKey);

            // Assert
            Assert.IsNotNull(signature, "Signature must not be null.");
            Assert.AreEqual(Constants.ED25519_SIGNATURE_SIZE, signature.Length,
                $"Signature must be {Constants.ED25519_SIGNATURE_SIZE} bytes.");
            Assert.IsTrue(valid, "Signature should verify correctly for the original message.");
        }

        [TestMethod]
        public void VerifySignature_TamperedMessage_ShouldReturnFalse()
        {
            // Arrange
            KeyPair keyPair = Sodium.GenerateEd25519KeyPair();
            byte[] original = Encoding.UTF8.GetBytes("Authentic message content");
            byte[] tampered = Encoding.UTF8.GetBytes("Tampered message content!");

            // Act
            byte[] signature = MessageSigning.SignMessage(original, keyPair.PrivateKey);
            bool valid = MessageSigning.VerifySignature(tampered, signature, keyPair.PublicKey);

            // Assert
            Assert.IsFalse(valid, "Signature must not verify for a tampered message.");
        }

        [TestMethod]
        public void VerifySignature_WrongPublicKey_ShouldReturnFalse()
        {
            // Arrange
            KeyPair signer = Sodium.GenerateEd25519KeyPair();
            KeyPair other  = Sodium.GenerateEd25519KeyPair();
            byte[] message = Encoding.UTF8.GetBytes("Signed with signer key");

            // Act
            byte[] signature = MessageSigning.SignMessage(message, signer.PrivateKey);
            bool valid = MessageSigning.VerifySignature(message, signature, other.PublicKey);

            // Assert
            Assert.IsFalse(valid, "Signature must not verify under a different public key.");
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void SignMessage_WrongSizePrivateKey_ShouldThrowArgumentException()
        {
            // Arrange — X25519 key is 32 bytes, not the required 64-byte Ed25519 size
            KeyPair x25519Pair = Sodium.GenerateX25519KeyPair();
            byte[] message = Encoding.UTF8.GetBytes("Test");

            // Act — must throw because private key is wrong size
            MessageSigning.SignMessage(message, x25519Pair.PrivateKey);
        }

        [TestMethod]
        public void SignMessage_BinaryData_ShouldSignAndVerify()
        {
            // Arrange — raw binary payload, not text
            KeyPair keyPair = Sodium.GenerateEd25519KeyPair();
            byte[] binaryData = new byte[256];
            for (int i = 0; i < binaryData.Length; i++)
                binaryData[i] = (byte)(i & 0xFF);

            // Act
            byte[] signature = MessageSigning.SignMessage(binaryData, keyPair.PrivateKey);
            bool valid = MessageSigning.VerifySignature(binaryData, signature, keyPair.PublicKey);

            // Assert
            Assert.IsTrue(valid, "Binary data should sign and verify correctly.");
        }

        // ---------------------------------------------------------------------------
        // SignTextMessage + VerifyTextMessage
        // ---------------------------------------------------------------------------

        [TestMethod]
        public void SignTextMessage_VerifyTextMessage_RoundTrip_ShouldSucceed()
        {
            // Arrange
            KeyPair keyPair = Sodium.GenerateEd25519KeyPair();
            string message = "Hello from SignTextMessage";

            // Act
            string signatureBase64 = MessageSigning.SignTextMessage(message, keyPair.PrivateKey);
            bool valid = MessageSigning.VerifyTextMessage(message, signatureBase64, keyPair.PublicKey);

            // Assert
            Assert.IsFalse(string.IsNullOrEmpty(signatureBase64), "Signature must not be null or empty.");
            Assert.IsTrue(valid, "Text message signature should verify correctly.");
        }

        [TestMethod]
        public void VerifyTextMessage_TamperedMessage_ShouldReturnFalse()
        {
            // Arrange
            KeyPair keyPair = Sodium.GenerateEd25519KeyPair();
            string original = "Original text message";
            string tampered = "Tampered text message";

            // Act
            string signatureBase64 = MessageSigning.SignTextMessage(original, keyPair.PrivateKey);
            bool valid = MessageSigning.VerifyTextMessage(tampered, signatureBase64, keyPair.PublicKey);

            // Assert
            Assert.IsFalse(valid, "Tampered text message must fail verification.");
        }

        [TestMethod]
        public void VerifyTextMessage_InvalidBase64Signature_ShouldReturnFalse()
        {
            // Arrange
            KeyPair keyPair = Sodium.GenerateEd25519KeyPair();

            // Act — malformed Base64
            bool valid = MessageSigning.VerifyTextMessage("some message", "not-valid-base64!!!", keyPair.PublicKey);

            // Assert
            Assert.IsFalse(valid, "An invalid Base64 signature must return false, not throw.");
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void SignTextMessage_EmptyMessage_ShouldThrowArgumentException()
        {
            // Arrange
            KeyPair keyPair = Sodium.GenerateEd25519KeyPair();

            // Act — empty string is rejected by contract
            MessageSigning.SignTextMessage(string.Empty, keyPair.PrivateKey);
        }

        // ---------------------------------------------------------------------------
        // SignObject<T> + VerifyObject<T>
        // ---------------------------------------------------------------------------

        [TestMethod]
        public void SignObject_VerifyObject_RoundTrip_ShouldSucceed()
        {
            // Arrange
            KeyPair keyPair = Sodium.GenerateEd25519KeyPair();
            var payload = new SamplePayload { Id = 42, Name = "test-object" };

            // Act
            byte[] signature = MessageSigning.SignObject(payload, keyPair.PrivateKey).ToArray();
            bool valid = MessageSigning.VerifyObject(payload, signature, keyPair.PublicKey);

            // Assert
            Assert.IsTrue(valid, "Object signature should verify correctly for the same object state.");
        }

        [TestMethod]
        public void VerifyObject_ModifiedObject_ShouldReturnFalse()
        {
            // Arrange
            KeyPair keyPair = Sodium.GenerateEd25519KeyPair();
            var original = new SamplePayload { Id = 1, Name = "original" };
            var modified = new SamplePayload { Id = 1, Name = "modified" };

            // Act
            byte[] signature = MessageSigning.SignObject(original, keyPair.PrivateKey).ToArray();
            bool valid = MessageSigning.VerifyObject(modified, signature, keyPair.PublicKey);

            // Assert
            Assert.IsFalse(valid, "Modified object must not verify against the original signature.");
        }

        // ---------------------------------------------------------------------------
        // Cross-encoding consistency: UTF-8 bytes are used (not platform-dependent)
        // ---------------------------------------------------------------------------

        [TestMethod]
        public void SignTextMessage_UsesUtf8Encoding_NotPlatformDefault()
        {
            // Arrange — characters outside ASCII to expose encoding differences
            KeyPair keyPair = Sodium.GenerateEd25519KeyPair();
            string message = "Unicode: \u00e9\u00e0\u00fc\u4e2d\u6587";

            // Act — sign via the text API (which uses UTF-8 internally)
            string signatureBase64 = MessageSigning.SignTextMessage(message, keyPair.PrivateKey);

            // Manually compute what signing the UTF-8 bytes directly would produce
            byte[] utf8Bytes = Encoding.UTF8.GetBytes(message);
            byte[] sigFromUtf8 = MessageSigning.SignMessage(utf8Bytes, keyPair.PrivateKey);
            string expectedBase64 = Convert.ToBase64String(sigFromUtf8);

            // Assert — both must be byte-for-byte identical, proving UTF-8 was used
            Assert.AreEqual(expectedBase64, signatureBase64,
                "SignTextMessage must use UTF-8 encoding, consistent with SignMessage(UTF8 bytes).");
        }

        // ---------------------------------------------------------------------------
        // Helper type used by SignObject tests
        // ---------------------------------------------------------------------------

        private sealed class SamplePayload
        {
            public int Id { get; set; }
            public string Name { get; set; } = string.Empty;
        }
    }
}
