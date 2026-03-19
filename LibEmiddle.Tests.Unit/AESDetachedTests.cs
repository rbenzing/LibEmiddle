using System;
using System.Security.Cryptography;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;

namespace LibEmiddle.Tests.Unit
{
    /// <summary>
    /// Unit tests for AES.AESEncryptDetached and AES.AESDecryptDetached.
    /// These methods operate in detached-tag mode: ciphertext and authentication
    /// tag are returned separately, unlike the combined-tag AESEncrypt / AESDecrypt.
    /// </summary>
    [TestClass]
    public class AESDetachedTests
    {
        // Shared key and nonce helpers
        private static byte[] GenerateKey()
        {
            byte[] key = new byte[Constants.AES_KEY_SIZE]; // 32 bytes
            RandomNumberGenerator.Fill(key);
            return key;
        }

        private static byte[] GenerateNonce()
        {
            byte[] nonce = new byte[Constants.NONCE_SIZE]; // 12 bytes
            RandomNumberGenerator.Fill(nonce);
            return nonce;
        }

        // ---------------------------------------------------------------------------
        // Encrypt -> Decrypt round-trip
        // ---------------------------------------------------------------------------

        [TestMethod]
        public void AESEncryptDetached_DecryptDetached_RoundTrip_ShouldReturnOriginalPlaintext()
        {
            // Arrange
            byte[] key       = GenerateKey();
            byte[] nonce     = GenerateNonce();
            byte[] plaintext = Encoding.UTF8.GetBytes("AES-GCM detached mode round-trip test");

            // Act
            byte[] ciphertext = AES.AESEncryptDetached(plaintext, key, nonce, out byte[] tag);
            byte[] decrypted  = AES.AESDecryptDetached(ciphertext, tag, key, nonce);

            // Assert
            CollectionAssert.AreEqual(plaintext, decrypted,
                "Decrypted output must equal the original plaintext.");
        }

        [TestMethod]
        public void AESEncryptDetached_ProducesSeparateCiphertextAndTag()
        {
            // Arrange
            byte[] key       = GenerateKey();
            byte[] nonce     = GenerateNonce();
            byte[] plaintext = Encoding.UTF8.GetBytes("Tag separation test");

            // Act
            byte[] ciphertext = AES.AESEncryptDetached(plaintext, key, nonce, out byte[] tag);

            // Assert — ciphertext is same length as plaintext (no tag appended)
            Assert.AreEqual(plaintext.Length, ciphertext.Length,
                "Detached ciphertext must be the same length as the plaintext (tag is separate).");
            Assert.AreEqual(Constants.AUTH_TAG_SIZE, tag.Length,
                $"Authentication tag must be {Constants.AUTH_TAG_SIZE} bytes.");
        }

        [TestMethod]
        public void AESEncryptDetached_WithAdditionalData_DecryptSucceeds()
        {
            // Arrange
            byte[] key            = GenerateKey();
            byte[] nonce          = GenerateNonce();
            byte[] plaintext      = Encoding.UTF8.GetBytes("AEAD plaintext");
            byte[] additionalData = Encoding.UTF8.GetBytes("authenticated-header");

            // Act
            byte[] ciphertext = AES.AESEncryptDetached(plaintext, key, nonce, out byte[] tag, additionalData);
            byte[] decrypted  = AES.AESDecryptDetached(ciphertext, tag, key, nonce, additionalData);

            // Assert
            CollectionAssert.AreEqual(plaintext, decrypted,
                "Decryption with matching additional data must succeed.");
        }

        // ---------------------------------------------------------------------------
        // Tampered ciphertext — authentication must fail
        // ---------------------------------------------------------------------------

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void AESDecryptDetached_TamperedCiphertext_ShouldThrowCryptographicException()
        {
            // Arrange
            byte[] key       = GenerateKey();
            byte[] nonce     = GenerateNonce();
            byte[] plaintext = Encoding.UTF8.GetBytes("Message to tamper");

            byte[] ciphertext = AES.AESEncryptDetached(plaintext, key, nonce, out byte[] tag);

            // Flip one bit in the ciphertext body
            ciphertext[0] ^= 0xFF;

            // Act — must throw
            AES.AESDecryptDetached(ciphertext, tag, key, nonce);
        }

        // ---------------------------------------------------------------------------
        // Tampered authentication tag — authentication must fail
        // ---------------------------------------------------------------------------

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void AESDecryptDetached_TamperedTag_ShouldThrowCryptographicException()
        {
            // Arrange
            byte[] key       = GenerateKey();
            byte[] nonce     = GenerateNonce();
            byte[] plaintext = Encoding.UTF8.GetBytes("Message with tampered tag");

            byte[] ciphertext = AES.AESEncryptDetached(plaintext, key, nonce, out byte[] tag);

            // Corrupt the authentication tag
            tag[0] ^= 0x01;

            // Act — must throw
            AES.AESDecryptDetached(ciphertext, tag, key, nonce);
        }

        // ---------------------------------------------------------------------------
        // Wrong key — authentication must fail
        // ---------------------------------------------------------------------------

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void AESDecryptDetached_WrongKey_ShouldThrowCryptographicException()
        {
            // Arrange
            byte[] correctKey = GenerateKey();
            byte[] wrongKey   = GenerateKey(); // different key
            byte[] nonce      = GenerateNonce();
            byte[] plaintext  = Encoding.UTF8.GetBytes("Key mismatch test");

            byte[] ciphertext = AES.AESEncryptDetached(plaintext, correctKey, nonce, out byte[] tag);

            // Act — decrypt with wrong key must fail
            AES.AESDecryptDetached(ciphertext, tag, wrongKey, nonce);
        }

        // ---------------------------------------------------------------------------
        // Wrong nonce — authentication must fail
        // ---------------------------------------------------------------------------

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void AESDecryptDetached_WrongNonce_ShouldThrowCryptographicException()
        {
            // Arrange
            byte[] key          = GenerateKey();
            byte[] encryptNonce = GenerateNonce();
            byte[] wrongNonce   = GenerateNonce();
            byte[] plaintext    = Encoding.UTF8.GetBytes("Nonce mismatch test");

            byte[] ciphertext = AES.AESEncryptDetached(plaintext, key, encryptNonce, out byte[] tag);

            // Act — decrypting with a different nonce must fail
            AES.AESDecryptDetached(ciphertext, tag, key, wrongNonce);
        }

        // ---------------------------------------------------------------------------
        // Wrong additional data — authentication must fail
        // ---------------------------------------------------------------------------

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void AESDecryptDetached_WrongAdditionalData_ShouldThrowCryptographicException()
        {
            // Arrange
            byte[] key             = GenerateKey();
            byte[] nonce           = GenerateNonce();
            byte[] plaintext       = Encoding.UTF8.GetBytes("AEAD integrity test");
            byte[] originalAD      = Encoding.UTF8.GetBytes("correct-header");
            byte[] differentAD     = Encoding.UTF8.GetBytes("wrong-header");

            byte[] ciphertext = AES.AESEncryptDetached(plaintext, key, nonce, out byte[] tag, originalAD);

            // Act — must fail because additional data does not match
            AES.AESDecryptDetached(ciphertext, tag, key, nonce, differentAD);
        }

        // ---------------------------------------------------------------------------
        // Input validation — invalid key size
        // ---------------------------------------------------------------------------

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void AESEncryptDetached_InvalidKeySize_ShouldThrowArgumentException()
        {
            // Arrange — 16-byte key is too short (requires 32 bytes)
            byte[] shortKey  = new byte[16];
            byte[] nonce     = GenerateNonce();
            byte[] plaintext = Encoding.UTF8.GetBytes("Key size validation");

            // Act
            AES.AESEncryptDetached(plaintext, shortKey, nonce, out _);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void AESEncryptDetached_InvalidNonceSize_ShouldThrowArgumentException()
        {
            // Arrange — 8-byte nonce is too short (requires 12 bytes)
            byte[] key       = GenerateKey();
            byte[] shortNonce = new byte[8];
            byte[] plaintext = Encoding.UTF8.GetBytes("Nonce size validation");

            // Act
            AES.AESEncryptDetached(plaintext, key, shortNonce, out _);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void AESEncryptDetached_EmptyPlaintext_ShouldThrowArgumentNullException()
        {
            // Arrange — empty span maps to the "IsEmpty" guard which throws ArgumentNullException
            byte[] key   = GenerateKey();
            byte[] nonce = GenerateNonce();

            // Act
            AES.AESEncryptDetached(ReadOnlySpan<byte>.Empty, key, nonce, out _);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void AESDecryptDetached_InvalidTagSize_ShouldThrowArgumentException()
        {
            // Arrange — tag must be exactly AUTH_TAG_SIZE (16) bytes
            byte[] key         = GenerateKey();
            byte[] nonce       = GenerateNonce();
            byte[] plaintext   = Encoding.UTF8.GetBytes("Tag size validation");
            byte[] ciphertext  = AES.AESEncryptDetached(plaintext, key, nonce, out _);
            byte[] shortTag    = new byte[8]; // too short

            // Act
            AES.AESDecryptDetached(ciphertext, shortTag, key, nonce);
        }

        // ---------------------------------------------------------------------------
        // Deterministic output: same inputs produce same ciphertext
        // ---------------------------------------------------------------------------

        [TestMethod]
        public void AESEncryptDetached_SameInputs_ProduceSameOutput()
        {
            // Arrange
            byte[] key       = GenerateKey();
            byte[] nonce     = GenerateNonce();
            byte[] plaintext = Encoding.UTF8.GetBytes("Deterministic AES-GCM output test");

            // Act
            byte[] ct1 = AES.AESEncryptDetached(plaintext, key, nonce, out byte[] tag1);
            byte[] ct2 = AES.AESEncryptDetached(plaintext, key, nonce, out byte[] tag2);

            // Assert — AES-GCM is deterministic for the same key/nonce/plaintext
            CollectionAssert.AreEqual(ct1, ct2, "Ciphertext must be identical for the same inputs.");
            CollectionAssert.AreEqual(tag1, tag2, "Tag must be identical for the same inputs.");
        }
    }
}
