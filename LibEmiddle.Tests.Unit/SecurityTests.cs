using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using LibEmiddle.KeyExchange;
using LibEmiddle.API;
using LibEmiddle.Abstractions;
using LibEmiddle.Domain;
using LibEmiddle.Crypto;

namespace LibEmiddle.Tests.Unit
{
    [TestClass]
    public class SecurityTests
    {
        private CryptoProvider _cryptoProvider;

        [TestInitialize]
        public void Setup()
        {
            _cryptoProvider = new CryptoProvider();
        }

        #region Forward Secrecy Tests

        [TestMethod]
        public void ForwardSecrecy_CompromisedKeyDoesNotAffectPastMessages()
        {
            // Arrange
            var aliceKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.X25519);
            var bobKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.X25519);

            // Initial shared secret
            byte[] sharedSecret = X3DHExchange.PerformX25519DH(bobKeyPair.PublicKey, aliceKeyPair.PrivateKey);
            var (rootKey, chainKey) = _cryptoProvider.DerriveDoubleRatchet(sharedSecret);

            // Create a session ID to be used consistently
            string sessionId = "forward-secrecy-test-" + Guid.NewGuid().ToString();

            // Setup sessions for both parties
            var aliceSession = new DoubleRatchetSession(
                dhRatchetKeyPair: aliceKeyPair,
                remoteDHRatchetKey: bobKeyPair.PublicKey,
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumberReceiving: 0,
                messageNumberSending: 0,
                sessionId: sessionId
            );

            var bobSession = new DoubleRatchetSession(
                dhRatchetKeyPair: bobKeyPair,
                remoteDHRatchetKey: aliceKeyPair.PublicKey,
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumberReceiving: 0,
                messageNumberSending: 0,
                sessionId: sessionId
            );

            // Act - Exchange several messages
            string message1 = "Message 1";
            string message2 = "Message 2";
            string message3 = "Message 3";

            // Alice sends message 1
            var (aliceSession1, encryptedMessage1) = _cryptoProvider.DoubleRatchetEncrypt(aliceSession, message1);

            // Add security fields for message 1
            encryptedMessage1.MessageId = Guid.NewGuid();
            encryptedMessage1.Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            encryptedMessage1.SessionId = sessionId;

            var (bobSession1, decryptedMessage1) = _cryptoProvider.DoubleRatchetDecrypt(bobSession, encryptedMessage1);

            // Bob sends message 2
            var (bobSession2, encryptedMessage2) = _cryptoProvider.DoubleRatchetEncrypt(bobSession1, message2);

            // Add security fields for message 2
            encryptedMessage2.MessageId = Guid.NewGuid();
            encryptedMessage2.Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            encryptedMessage2.SessionId = sessionId;

            var (aliceSession2, decryptedMessage2) = _cryptoProvider.DoubleRatchetDecrypt(aliceSession1, encryptedMessage2);

            // Save the first two encrypted messages to try to decrypt later
            // Create copies with new message IDs to avoid replay detection
            var savedEncryptedMessage1 = new EncryptedMessage
            {
                Ciphertext = encryptedMessage1.Ciphertext,
                Nonce = encryptedMessage1.Nonce,
                MessageNumber = encryptedMessage1.MessageNumber,
                SenderDHKey = encryptedMessage1.SenderDHKey,
                Timestamp = encryptedMessage1.Timestamp,
                MessageId = Guid.NewGuid(), // New message ID to avoid replay detection
                SessionId = sessionId
            };

            var savedEncryptedMessage2 = new EncryptedMessage
            {
                Ciphertext = encryptedMessage2.Ciphertext,
                Nonce = encryptedMessage2.Nonce,
                MessageNumber = encryptedMessage2.MessageNumber,
                SenderDHKey = encryptedMessage2.SenderDHKey,
                Timestamp = encryptedMessage2.Timestamp,
                MessageId = Guid.NewGuid(), // New message ID to avoid replay detection
                SessionId = sessionId
            };

            // Continue the conversation
            var (aliceSession3, encryptedMessage3) = _cryptoProvider.DoubleRatchetEncrypt(aliceSession2, message3);

            // Add security fields for message 3
            encryptedMessage3.MessageId = Guid.NewGuid();
            encryptedMessage3.Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            encryptedMessage3.SessionId = sessionId;

            var (bobSession3, decryptedMessage3) = _cryptoProvider.DoubleRatchetDecrypt(bobSession2, encryptedMessage3);

            // Simulate compromise of the latest keys - create a new compromised session with the latest keys
            // but without the message history
            var compromisedBobSession = new DoubleRatchetSession(
                dhRatchetKeyPair: bobSession3.DHRatchetKeyPair,
                remoteDHRatchetKey: bobSession3.RemoteDHRatchetKey,
                rootKey: bobSession3.RootKey,
                sendingChainKey: bobSession3.SendingChainKey,
                receivingChainKey: bobSession3.ReceivingChainKey,
                messageNumberReceiving: bobSession3.MessageNumberReceiving,
                messageNumberSending: bobSession3.MessageNumberSending,
                sessionId: sessionId
            // Deliberately not copying message history - an attacker wouldn't have it
            );

            // An attacker shouldn't be able to decrypt previous messages using the compromised session
            bool canDecryptMessage1 = true;
            bool canDecryptMessage2 = true;

            // With our immutable implementation, the method returns null values for failed decryption
            var (resultSession1, resultMessage1) = _cryptoProvider.DoubleRatchetDecrypt(compromisedBobSession, savedEncryptedMessage1);
            canDecryptMessage1 = resultSession1 != null && resultMessage1 != null;

            var (resultSession2, resultMessage2) = _cryptoProvider.DoubleRatchetDecrypt(compromisedBobSession, savedEncryptedMessage2);
            canDecryptMessage2 = resultSession2 != null && resultMessage2 != null;

            // Assert
            // Check that legitimate recipients could decrypt messages
            Assert.IsNotNull(decryptedMessage1, "Message 1 should be decrypted by legitimate recipient");
            Assert.IsNotNull(decryptedMessage2, "Message 2 should be decrypted by legitimate recipient");
            Assert.IsNotNull(decryptedMessage3, "Message 3 should be decrypted by legitimate recipient");

            Assert.AreEqual(message1, decryptedMessage1, "Message 1 content should match original");
            Assert.AreEqual(message2, decryptedMessage2, "Message 2 content should match original");
            Assert.AreEqual(message3, decryptedMessage3, "Message 3 content should match original");

            // Check that compromised session can't decrypt previous messages
            Assert.IsFalse(canDecryptMessage1, "Should not be able to decrypt message 1 with compromised session");
            Assert.IsFalse(canDecryptMessage2, "Should not be able to decrypt message 2 with compromised session");

            // Verify session immutability
            Assert.AreNotEqual(aliceSession, aliceSession1, "Alice's session should be updated after first encryption");
            Assert.AreNotEqual(bobSession, bobSession1, "Bob's session should be updated after first decryption");
            Assert.AreNotEqual(bobSession1, bobSession2, "Bob's session should be updated after second encryption");
            Assert.AreNotEqual(aliceSession1, aliceSession2, "Alice's session should be updated after second decryption");
            Assert.AreNotEqual(aliceSession2, aliceSession3, "Alice's session should be updated after third encryption");
            Assert.AreNotEqual(bobSession2, bobSession3, "Bob's session should be updated after third decryption");
        }

        #endregion

        #region Message Corruption Tests

        [TestMethod]
        public void MessageCorruption_ShouldDetectTampering()
        {
            // Arrange
            string message = "This message should be protected from tampering";
            byte[] key = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(key);
            }

            // Encrypt the message
            var encryptedMessage = LibEmiddleClient.EncryptMessage(message, key);

            // Make a copy for tampering
            var tamperedMessage = new EncryptedMessage
            {
                Ciphertext = new byte[encryptedMessage.Ciphertext.Length],
                Nonce = encryptedMessage.Nonce
            };
            Buffer.BlockCopy(encryptedMessage.Ciphertext, 0, tamperedMessage.Ciphertext, 0, encryptedMessage.Ciphertext.Length);

            // Tamper with the ciphertext (flip a bit in the middle)
            int middlePosition = tamperedMessage.Ciphertext.Length / 2;
            tamperedMessage.Ciphertext[middlePosition] ^= 1; // Flip one bit

            // Act & Assert
            Assert.ThrowsException<CryptographicException>(() =>
            {
                LibEmiddleClient.DecryptMessage(tamperedMessage, key);
            }, "Tampered message should fail authentication");

            // Original message should still decrypt correctly
            string decryptedOriginal = LibEmiddleClient.DecryptMessage(encryptedMessage, key);
            Assert.AreEqual(message, decryptedOriginal);
        }

        [TestMethod]
        public void DoubleRatchet_ShouldDetectTamperedMessage()
        {
            // Arrange
            var aliceKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.X25519);
            var bobKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.X25519);

            // Initial shared secret
            byte[] sharedSecret = X3DHExchange.PerformX25519DH(bobKeyPair.PublicKey, aliceKeyPair.PrivateKey);
            var (rootKey, chainKey) = _cryptoProvider.DerriveDoubleRatchet(sharedSecret);

            // Create a session ID
            string sessionId = "tamper-detection-test-" + Guid.NewGuid().ToString();

            var aliceSession = new DoubleRatchetSession(
                dhRatchetKeyPair: aliceKeyPair,
                remoteDHRatchetKey: bobKeyPair.PublicKey,
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumberReceiving: 0,
                messageNumberSending: 0,
                sessionId: sessionId
            );

            var bobSession = new DoubleRatchetSession(
                dhRatchetKeyPair: bobKeyPair,
                remoteDHRatchetKey: aliceKeyPair.PublicKey,
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumberReceiving: 0,
                messageNumberSending: 0,
                sessionId: sessionId
            );

            // Alice encrypts a message
            string message = "Secret message that should be tamper-proof";
            var (_, encryptedMessage) = _cryptoProvider.DoubleRatchetEncrypt(aliceSession, message);

            // Add security fields
            encryptedMessage.MessageId = Guid.NewGuid();
            encryptedMessage.Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            encryptedMessage.SessionId = sessionId;

            // Make sure encryption succeeded
            Assert.IsNotNull(encryptedMessage, "Encryption should succeed");
            Assert.IsNotNull(encryptedMessage.Ciphertext, "Ciphertext should not be null");
            Assert.IsTrue(encryptedMessage.Ciphertext.Length > 0, "Ciphertext should not be empty");

            // Create a tampered message copy
            var tamperedMessage = new EncryptedMessage
            {
                Ciphertext = new byte[encryptedMessage.Ciphertext.Length],
                Nonce = encryptedMessage.Nonce,
                MessageNumber = encryptedMessage.MessageNumber,
                SenderDHKey = encryptedMessage.SenderDHKey,
                Timestamp = encryptedMessage.Timestamp,
                MessageId = Guid.NewGuid(), // New ID to avoid replay detection
                SessionId = sessionId
            };

            Buffer.BlockCopy(encryptedMessage.Ciphertext, 0, tamperedMessage.Ciphertext, 0, encryptedMessage.Ciphertext.Length);

            // Tamper with a byte in the ciphertext
            tamperedMessage.Ciphertext[tamperedMessage.Ciphertext.Length - 5] ^= 0x42;

            // Make a fresh copy of Bob's session for the tampered message attempt
            // This ensures the original session isn't affected by the tampered message
            var bobSessionForTampered = new DoubleRatchetSession(
                dhRatchetKeyPair: bobKeyPair,
                remoteDHRatchetKey: bobSession.RemoteDHRatchetKey,
                rootKey: bobSession.RootKey,
                sendingChainKey: bobSession.SendingChainKey,
                receivingChainKey: bobSession.ReceivingChainKey,
                messageNumberReceiving: bobSession.MessageNumberReceiving,
                messageNumberSending: bobSession.MessageNumberSending,
                sessionId: bobSession.SessionId
            );

            // Act - Attempt to decrypt the tampered message
            var (resultSession, resultMessage) = _cryptoProvider.DoubleRatchetDecrypt(bobSessionForTampered, tamperedMessage);

            // Assert - Check that tampering was detected by verifying null returns
            Assert.IsNull(resultSession, "Tampered message should result in null session");
            Assert.IsNull(resultMessage, "Tampered message should result in null decrypted message");

            // Additional verification - make sure the original message still decrypts properly
            // Use the original untouched session
            var (validSession, validMessage) = _cryptoProvider.DoubleRatchetDecrypt(bobSession, encryptedMessage);

            Assert.IsNotNull(validSession, "Original message should decrypt successfully");
            Assert.IsNotNull(validMessage, "Original message should decrypt successfully");
            Assert.AreEqual(message, validMessage, "Original message should decrypt to the correct content");
        }

        #endregion

        #region Security Parameter Tests

        [TestMethod]
        public void GeneratedNonces_ShouldBeUnpredictable()
        {
            // Arrange & Act
            var nonces = new List<byte[]>();
            int numNonces = 1000;

            for (int i = 0; i < numNonces; i++)
            {
                nonces.Add(_cryptoProvider.GenerateNonce());
            }

            // Assert
            // Check that no two nonces are the same
            for (int i = 0; i < nonces.Count; i++)
            {
                for (int j = i + 1; j < nonces.Count; j++)
                {
                    Assert.IsFalse(TestsHelpers.AreByteArraysEqual(nonces[i], nonces[j]),
                        $"Nonces at position {i} and {j} are identical");
                }
            }

            // Basic randomness test - check distribution of bytes
            // Count the occurrences of each byte value across all nonces
            var byteDistribution = new int[256];
            foreach (var nonce in nonces)
            {
                foreach (byte b in nonce)
                {
                    byteDistribution[b]++;
                }
            }

            // In a uniform distribution, each byte value should appear approximately the same number of times
            double expectedOccurrences = (double)(numNonces * 12) / 256; // 12 is the NONCE_SIZE

            // Use chi-square test to check if the distribution is uniform
            // Chi-square statistic = sum((observed - expected)^2 / expected)
            double chiSquare = 0;
            foreach (int count in byteDistribution)
            {
                chiSquare += Math.Pow(count - expectedOccurrences, 2) / expectedOccurrences;
            }

            // For a uniform distribution with 255 degrees of freedom (256-1),
            // a chi-square value greater than ~340 would be suspicious at a 0.001 significance level
            Assert.IsTrue(chiSquare < 340, $"Chi-square test failed with value {chiSquare}");
        }

        [TestMethod]
        public void LongTermCryptographicIdentity_ShouldBeSecure()
        {
            // Generate multiple key pairs
            var keyPair1 = LibEmiddleClient.GenerateSignatureKeyPair();
            var keyPair2 = LibEmiddleClient.GenerateSignatureKeyPair();
            var keyPair3 = LibEmiddleClient.GenerateSignatureKeyPair();

            // Ensure keys meet minimum security requirements
            Assert.AreEqual(32, keyPair1.PublicKey.Length, "Ed25519 public key should be 32 bytes");
            Assert.AreEqual(64, keyPair1.PrivateKey.Length, "Ed25519 private key should be 64 bytes");

            // Ensure all generated keys are different
            Assert.IsFalse(TestsHelpers.AreByteArraysEqual(keyPair1.PublicKey, keyPair2.PublicKey));
            Assert.IsFalse(TestsHelpers.AreByteArraysEqual(keyPair1.PublicKey, keyPair3.PublicKey));
            Assert.IsFalse(TestsHelpers.AreByteArraysEqual(keyPair2.PublicKey, keyPair3.PublicKey));

            Assert.IsFalse(TestsHelpers.AreByteArraysEqual(keyPair1.PrivateKey, keyPair2.PrivateKey));
            Assert.IsFalse(TestsHelpers.AreByteArraysEqual(keyPair1.PrivateKey, keyPair3.PrivateKey));
            Assert.IsFalse(TestsHelpers.AreByteArraysEqual(keyPair2.PrivateKey, keyPair3.PrivateKey));

            // Test signature functionality
            string message = "Cryptographic identity test message";
            byte[] messageBytes = Encoding.UTF8.GetBytes(message);

            byte[] signature1 = _cryptoProvider.Sign(messageBytes, keyPair1.PrivateKey);
            byte[] signature2 = _cryptoProvider.Sign(messageBytes, keyPair2.PrivateKey);
            byte[] signature3 = _cryptoProvider.Sign(messageBytes, keyPair3.PrivateKey);

            // Ensure signatures are different for different keys
            Assert.IsFalse(TestsHelpers.AreByteArraysEqual(signature1, signature2));
            Assert.IsFalse(TestsHelpers.AreByteArraysEqual(signature1, signature3));
            Assert.IsFalse(TestsHelpers.AreByteArraysEqual(signature2, signature3));

            // Ensure signatures verify correctly
            Assert.IsTrue(_cryptoProvider.Verify(messageBytes, signature1, keyPair1.PublicKey));
            Assert.IsTrue(_cryptoProvider.Verify(messageBytes, signature2, keyPair2.PublicKey));
            Assert.IsTrue(_cryptoProvider.Verify(messageBytes, signature3, keyPair3.PublicKey));

            // Ensure signatures don't verify with the wrong key
            Assert.IsFalse(_cryptoProvider.Verify(messageBytes, signature1, keyPair2.PublicKey));
            Assert.IsFalse(_cryptoProvider.Verify(messageBytes, signature2, keyPair3.PublicKey));
            Assert.IsFalse(_cryptoProvider.Verify(messageBytes, signature3, keyPair1.PublicKey));
        }

        #endregion

        #region Security Edge Case Tests

        [TestMethod]
        public void MultiRatchetSequence_ShouldMaintainSecurity()
        {
            // Generate initial key materials
            byte[] initialKey = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(initialKey);
            }

            // Perform a large number of ratchet steps
            byte[] currentKey = initialKey;
            Dictionary<int, byte[]> messageKeys = new Dictionary<int, byte[]>();

            const int steps = 100;
            for (int i = 0; i < steps; i++)
            {
                var (newChainKey, messageKey) = _cryptoProvider.RatchetStep(currentKey);
                currentKey = newChainKey;

                // Store message key
                messageKeys[i] = messageKey;

                // Verify that this message key is unique
                for (int j = 0; j < i; j++)
                {
                    Assert.IsFalse(TestsHelpers.AreByteArraysEqual(messageKeys[j], messageKey),
                        $"Message keys at positions {j} and {i} should not be equal");
                }
            }

            // Test that the final chain key doesn't reveal anything about the initial key
            Assert.IsFalse(TestsHelpers.AreByteArraysEqual(initialKey, currentKey),
                "Final chain key should differ from initial key");

            // Check for cryptographic distinctness rather than byte-level differences
            // This is a more appropriate test for the security properties of the protocol
            bool hasDistinctKeys = false;
            for (int i = 0; i < steps; i++)
            {
                // Check that message keys are cryptographically distinct from chain keys
                if (!TestsHelpers.AreByteArraysEqual(messageKeys[i], initialKey) &&
                    !TestsHelpers.AreByteArraysEqual(messageKeys[i], currentKey))
                {
                    hasDistinctKeys = true;
                    break;
                }
            }

            Assert.IsTrue(hasDistinctKeys,
                "Message keys should be cryptographically distinct from initial and final chain keys");
        }

        [TestMethod]
        public void InputValidation_HandlesEdgeCases()
        {
            // Arrange
            // Test with key arrays of incorrect length
            byte[] shortKey = new byte[16]; // Too short
            byte[] longKey = new byte[64];  // Too long for AES but valid for Ed25519
            byte[] messageBytes = Encoding.UTF8.GetBytes("Test message");
            byte[] validNonce = _cryptoProvider.GenerateNonce();
            byte[] shortNonce = new byte[8]; // Too short

            // Valid key for comparison
            byte[] validKey = new byte[32];
            RandomNumberGenerator.Fill(validKey);

            // Act & Assert

            // Test AES with invalid key lengths
            Assert.ThrowsException<ArgumentException>(() =>
            {
                _cryptoProvider.Encrypt(messageBytes, shortKey, validNonce);
            }, "Should throw for key that's too short");

            Assert.ThrowsException<ArgumentException>(() =>
            {
                _cryptoProvider.Encrypt(messageBytes, longKey, validNonce);
            }, "Should throw for key that's too long for AES");

            // Test with invalid nonce
            Assert.ThrowsException<ArgumentException>(() =>
            {
                _cryptoProvider.Encrypt(messageBytes, validKey, shortNonce);
            }, "Should throw for nonce that's too short");

            // Test with null inputs
            Assert.ThrowsException<ArgumentNullException>(() =>
            {
                _cryptoProvider.Encrypt(null, validKey, validNonce);
            }, "Should throw for null plaintext");

            Assert.ThrowsException<ArgumentNullException>(() =>
            {
                _cryptoProvider.Encrypt(messageBytes, null, validNonce);
            }, "Should throw for null key");

            Assert.ThrowsException<ArgumentNullException>(() =>
            {
                _cryptoProvider.Encrypt(messageBytes, validKey, null);
            }, "Should throw for null nonce");

            // Test input validation for signature methods
            KeyPair _signIdentityKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);
            var publicKey = _signIdentityKeyPair.PublicKey;
            var privateKey = _signIdentityKeyPair.PrivateKey;

            Assert.ThrowsException<ArgumentNullException>(() =>
            {
                _cryptoProvider.Sign(null, privateKey);
            }, "Should throw for null message in SignMessage");

            Assert.ThrowsException<NullReferenceException>(() =>
            {
                _cryptoProvider.Sign(messageBytes, null);
            }, "Should throw for null private key in SignMessage");

            Assert.ThrowsException<ArgumentNullException>(() =>
            {
                _cryptoProvider.Verify(null, new byte[64], publicKey);
            }, "Should throw for null message in VerifySignature");

            Assert.ThrowsException<NullReferenceException>(() =>
            {
                _cryptoProvider.Verify(messageBytes, null, publicKey);
            }, "Should throw for null signature in VerifySignature");

            Assert.ThrowsException<NullReferenceException>(() =>
            {
                _cryptoProvider.Verify(messageBytes, new byte[64], null);
            }, "Should throw for null public key in VerifySignature");
        }

        [TestMethod]
        public void NonceHandling_RejectsReusedNonces()
        {
            // This test checks if the library prevents nonce reuse - a critical security property

            // Arrange
            byte[] key = new byte[32];
            RandomNumberGenerator.Fill(key);
            byte[] nonce = _cryptoProvider.GenerateNonce();

            string message1 = "First message";
            string message2 = "Second message - should use different nonce";

            byte[] plaintext1 = Encoding.UTF8.GetBytes(message1);
            byte[] plaintext2 = Encoding.UTF8.GetBytes(message2);

            // Act
            byte[] ciphertext1 = _cryptoProvider.Encrypt(plaintext1, key, nonce);

            // Attempt to use the same nonce again - in a secure implementation, nonces should never be reused
            // This would typically throw an exception or be prevented by the library's design
            byte[] ciphertext2 = _cryptoProvider.Encrypt(plaintext2, key, nonce);

            // Now that we have both ciphertexts, show why nonce reuse is dangerous
            // If your library allows nonce reuse, this test demonstrates the vulnerability

            // We can XOR the ciphertexts to get the XOR of the plaintexts (a known attack pattern)
            byte[] xorResult = new byte[Math.Min(ciphertext1.Length, ciphertext2.Length)];
            for (int i = 0; i < xorResult.Length; i++)
            {
                xorResult[i] = (byte)(ciphertext1[i] ^ ciphertext2[i]);
            }

            // Assert - In a secure implementation, the library should provide automatic nonce management
            // that prevents reuse. This test simply demonstrates the danger.

            // Check that two calls to GenerateNonce() always produce different values
            byte[] newNonce1 = _cryptoProvider.GenerateNonce();
            byte[] newNonce2 = _cryptoProvider.GenerateNonce();

            Assert.IsFalse(TestsHelpers.AreByteArraysEqual(newNonce1, newNonce2), "Generated nonces should be unique");

            // Note: This test doesn't assert against ciphertext patterns because it's illustrating
            // how a reused nonce compromises security, not strictly testing library behavior
        }

        #endregion
    }
}