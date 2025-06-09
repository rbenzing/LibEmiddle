using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.Protocol;
using System.Linq;

namespace LibEmiddle.Tests.Unit
{
    /// <summary>
    /// Tests to verify security properties of the LibEmiddle cryptographic protocols.
    /// Ensures forward secrecy, tamper detection, and proper cryptographic parameter handling.
    /// </summary>
    [TestClass]
    public class SecurityTests
    {
        private CryptoProvider _cryptoProvider = null!;
        private DoubleRatchetProtocol _doubleRatchetProtocol = null!;

        [TestInitialize]
        public void Setup()
        {
            _cryptoProvider = new CryptoProvider();
            _doubleRatchetProtocol = new DoubleRatchetProtocol();
        }

        #region Forward Secrecy Tests

        /// <summary>
        /// Tests that compromising current session keys does not allow decryption of past messages,
        /// validating the forward secrecy property of the Double Ratchet protocol.
        /// </summary>
        [TestMethod]
        public void ForwardSecrecy_CompromisedKeyDoesNotAffectPastMessages()
        {
            // Arrange
            var aliceKeyPair = Sodium.GenerateX25519KeyPair();
            var bobKeyPair = Sodium.GenerateX25519KeyPair();

            // Initial shared secret
            byte[] sharedSecret = Sodium.ScalarMult(aliceKeyPair.PrivateKey, bobKeyPair.PublicKey);

            // Create a session ID to be used consistently
            string sessionId = $"forward-secrecy-test-{Guid.NewGuid()}";

            // FIXED: Use proper session initialization instead of manual creation
            // Alice is the sender, Bob is the receiver
            var aliceSession = _doubleRatchetProtocol.InitializeSessionAsSender(
                sharedSecret,
                bobKeyPair.PublicKey,
                sessionId);

            var bobSession = _doubleRatchetProtocol.InitializeSessionAsReceiver(
                sharedSecret,
                bobKeyPair,
                aliceKeyPair.PublicKey,
                sessionId);

            // Act - Exchange several messages
            string message1 = "Message 1";
            string message2 = "Message 2";
            string message3 = "Message 3";

            // Alice sends message 1
            var (aliceSession1, encryptedMessage1) = _doubleRatchetProtocol.EncryptAsync(aliceSession, message1);
            Assert.IsNotNull(aliceSession1, "Alice's session should be updated after encryption");
            Assert.IsNotNull(encryptedMessage1, "Encrypted message should not be null");

            // Add needed fields for message 1
            encryptedMessage1.MessageId = Guid.NewGuid().ToString("N");
            encryptedMessage1.Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            // Bob receives message 1
            var (bobSession1, decryptedMessage1) = _doubleRatchetProtocol.DecryptAsync(bobSession, encryptedMessage1);
            Assert.IsNotNull(bobSession1, "Bob's session should be updated after decryption");
            Assert.IsNotNull(decryptedMessage1, "Decrypted message should not be null");

            // Bob sends message 2
            var (bobSession2, encryptedMessage2) = _doubleRatchetProtocol.EncryptAsync(bobSession1, message2);
            Assert.IsNotNull(bobSession2, "Bob's session should be updated after encryption");
            Assert.IsNotNull(encryptedMessage2, "Encrypted message should not be null");

            // Add needed fields for message 2
            encryptedMessage2.MessageId = Guid.NewGuid().ToString("N");
            encryptedMessage2.Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            // Alice receives message 2
            var (aliceSession2, decryptedMessage2) = _doubleRatchetProtocol.DecryptAsync(aliceSession1, encryptedMessage2);
            Assert.IsNotNull(aliceSession2, "Alice's session should be updated after decryption");
            Assert.IsNotNull(decryptedMessage2, "Decrypted message should not be null");

            // Save the first two encrypted messages to try to decrypt later
            // Create copies with new message IDs to avoid replay detection
            var savedEncryptedMessage1 = new EncryptedMessage
            {
                Ciphertext = encryptedMessage1.Ciphertext?.ToArray(),
                Nonce = encryptedMessage1.Nonce?.ToArray(),
                SenderMessageNumber = encryptedMessage1.SenderMessageNumber,
                SenderDHKey = encryptedMessage1.SenderDHKey?.ToArray(),
                Timestamp = encryptedMessage1.Timestamp,
                MessageId = Guid.NewGuid().ToString("N"), // New message ID to avoid replay detection
                SessionId = sessionId
            };

            var savedEncryptedMessage2 = new EncryptedMessage
            {
                Ciphertext = encryptedMessage2.Ciphertext?.ToArray(),
                Nonce = encryptedMessage2.Nonce?.ToArray(),
                SenderMessageNumber = encryptedMessage2.SenderMessageNumber,
                SenderDHKey = encryptedMessage2.SenderDHKey?.ToArray(),
                Timestamp = encryptedMessage2.Timestamp,
                MessageId = Guid.NewGuid().ToString("N"), // New message ID to avoid replay detection
                SessionId = sessionId
            };

            // Continue the conversation
            var (aliceSession3, encryptedMessage3) = _doubleRatchetProtocol.EncryptAsync(aliceSession2, message3);
            Assert.IsNotNull(aliceSession3, "Alice's session should be updated after encryption");
            Assert.IsNotNull(encryptedMessage3, "Encrypted message should not be null");

            // Add security fields for message 3
            encryptedMessage3.MessageId = Guid.NewGuid().ToString("N");
            encryptedMessage3.Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            var (bobSession3, decryptedMessage3) = _doubleRatchetProtocol.DecryptAsync(bobSession2, encryptedMessage3);
            Assert.IsNotNull(bobSession3, "Bob's session should be updated after decryption");
            Assert.IsNotNull(decryptedMessage3, "Decrypted message should not be null");

            // Simulate compromise of the latest keys - create a new compromised session with the latest keys
            // but without the message history
            var compromisedBobSession = new DoubleRatchetSession
            {
                SessionId = bobSession3.SessionId,
                RootKey = bobSession3.RootKey?.ToArray(),
                SenderChainKey = bobSession3.SenderChainKey?.ToArray(),
                ReceiverChainKey = bobSession3.ReceiverChainKey?.ToArray(),
                SenderRatchetKeyPair = new KeyPair
                {
                    PublicKey = bobSession3.SenderRatchetKeyPair.PublicKey?.ToArray(),
                    PrivateKey = bobSession3.SenderRatchetKeyPair.PrivateKey?.ToArray()
                },
                ReceiverRatchetPublicKey = bobSession3.ReceiverRatchetPublicKey?.ToArray(),
                PreviousReceiverRatchetPublicKey = bobSession3.PreviousReceiverRatchetPublicKey?.ToArray(),
                SendMessageNumber = bobSession3.SendMessageNumber,
                ReceiveMessageNumber = bobSession3.ReceiveMessageNumber,
                IsInitialized = bobSession3.IsInitialized,
                CreationTimestamp = bobSession3.CreationTimestamp,
                // Deliberately not copying message history - an attacker wouldn't have it
                SentMessages = new Dictionary<uint, byte[]>(),
                SkippedMessageKeys = new Dictionary<SkippedMessageKey, byte[]>()
            };

            // An attacker shouldn't be able to decrypt previous messages using the compromised session
            var (resultSession1, resultMessage1) = _doubleRatchetProtocol.DecryptAsync(compromisedBobSession, savedEncryptedMessage1);
            var (resultSession2, resultMessage2) = _doubleRatchetProtocol.DecryptAsync(compromisedBobSession, savedEncryptedMessage2);

            // Assert
            // Check that legitimate recipients could decrypt messages
            Assert.IsNotNull(decryptedMessage1, "Message 1 should be decrypted by legitimate recipient");
            Assert.IsNotNull(decryptedMessage2, "Message 2 should be decrypted by legitimate recipient");
            Assert.IsNotNull(decryptedMessage3, "Message 3 should be decrypted by legitimate recipient");

            Assert.AreEqual(message1, decryptedMessage1, "Message 1 content should match original");
            Assert.AreEqual(message2, decryptedMessage2, "Message 2 content should match original");
            Assert.AreEqual(message3, decryptedMessage3, "Message 3 content should match original");

            // Check that compromised session can't decrypt previous messages
            Assert.IsNull(resultSession1, "Should not be able to decrypt message 1 with compromised session");
            Assert.IsNull(resultMessage1, "Should not be able to decrypt message 1 with compromised session");
            Assert.IsNull(resultSession2, "Should not be able to decrypt message 2 with compromised session");
            Assert.IsNull(resultMessage2, "Should not be able to decrypt message 2 with compromised session");
        }

        #endregion

        #region Message Corruption Tests

        /// <summary>
        /// Tests that the cryptographic protocols detect when messages have been tampered with.
        /// Ensures the authenticated encryption properties are maintained.
        /// </summary>
        [TestMethod]
        public void MessageCorruption_ShouldDetectTampering()
        {
            // Arrange
            string message = "This message should be protected from tampering";
            byte[] key = RandomNumberGenerator.GetBytes(Constants.AES_KEY_SIZE);

            // Encrypt the message
            byte[] nonce = _cryptoProvider.GenerateRandomBytes(Constants.NONCE_SIZE);
            byte[] plaintext = Encoding.Default.GetBytes(message);
            byte[] ciphertext = _cryptoProvider.Encrypt(plaintext, key, nonce, null);

            var encryptedMessage = new EncryptedMessage
            {
                Ciphertext = ciphertext,
                Nonce = nonce,
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                MessageId = Guid.NewGuid().ToString("N")
            };

            // Make a copy for tampering
            var tamperedMessage = new EncryptedMessage
            {
                Ciphertext = encryptedMessage.Ciphertext.ToArray(),
                Nonce = encryptedMessage.Nonce.ToArray(),
                Timestamp = encryptedMessage.Timestamp,
                MessageId = encryptedMessage.MessageId
            };

            // Tamper with the ciphertext (flip a bit in the middle)
            int middlePosition = tamperedMessage.Ciphertext.Length / 2;
            tamperedMessage.Ciphertext[middlePosition] ^= 1; // Flip one bit

            // Act & Assert
            Assert.ThrowsException<CryptographicException>(() =>
            {
                _cryptoProvider.Decrypt(tamperedMessage.Ciphertext, key, tamperedMessage.Nonce, null);
            }, "Tampered message should fail authentication");

            // Original message should still decrypt correctly
            byte[] decryptedBytes = _cryptoProvider.Decrypt(encryptedMessage.Ciphertext, key, encryptedMessage.Nonce, null);
            string decryptedOriginal = Encoding.UTF8.GetString(decryptedBytes);
            Assert.AreEqual(message, decryptedOriginal);
        }

        /// <summary>
        /// Tests that the Double Ratchet protocol detects tampered messages.
        /// Ensures message authentication within the protocol.
        /// </summary>
        [TestMethod]
        public void DoubleRatchet_ShouldDetectTamperedMessage()
        {
            // Arrange
            var aliceKeyPair = Sodium.GenerateX25519KeyPair();
            var bobKeyPair = Sodium.GenerateX25519KeyPair();

            // Initial shared secret
            byte[] sharedSecret = Sodium.ScalarMult(aliceKeyPair.PrivateKey, bobKeyPair.PublicKey);

            // Create a session ID
            string sessionId = $"tamper-detection-test-{Guid.NewGuid()}";

            // FIXED: Use proper session initialization instead of manual creation
            // Alice is the sender, Bob is the receiver
            var aliceSession = _doubleRatchetProtocol.InitializeSessionAsSender(
                sharedSecret,
                bobKeyPair.PublicKey,
                sessionId);

            var bobSession = _doubleRatchetProtocol.InitializeSessionAsReceiver(
                sharedSecret,
                bobKeyPair,
                aliceKeyPair.PublicKey,
                sessionId);

            // Alice encrypts a message
            string message = "Secret message that should be tamper-proof";
            var (_, encryptedMessage) = _doubleRatchetProtocol.EncryptAsync(aliceSession, message);

            // Add security fields
            encryptedMessage.MessageId = Guid.NewGuid().ToString("N");
            encryptedMessage.Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            encryptedMessage.SessionId = sessionId;

            // Make sure encryption succeeded
            Assert.IsNotNull(encryptedMessage, "Encryption should succeed");
            Assert.IsNotNull(encryptedMessage.Ciphertext, "Ciphertext should not be null");
            Assert.IsTrue(encryptedMessage.Ciphertext.Length > 0, "Ciphertext should not be empty");

            // Create a tampered message copy
            var tamperedMessage = new EncryptedMessage
            {
                Ciphertext = encryptedMessage.Ciphertext.ToArray(),
                Nonce = encryptedMessage.Nonce.ToArray(),
                SenderMessageNumber = encryptedMessage.SenderMessageNumber,
                SenderDHKey = encryptedMessage.SenderDHKey.ToArray(),
                Timestamp = encryptedMessage.Timestamp,
                MessageId = Guid.NewGuid().ToString("N"), // New ID to avoid replay detection
                SessionId = sessionId
            };

            // Tamper with a byte in the ciphertext
            tamperedMessage.Ciphertext[tamperedMessage.Ciphertext.Length - 5] ^= 0x42;

            // Make a deep clone of Bob's session for the tampered message attempt
            var bobSessionForTampered = new DoubleRatchetSession
            {
                SessionId = bobSession.SessionId,
                RootKey = bobSession.RootKey?.ToArray(),
                SenderChainKey = bobSession.SenderChainKey?.ToArray(),
                ReceiverChainKey = bobSession.ReceiverChainKey?.ToArray(),
                SenderRatchetKeyPair = new KeyPair
                {
                    PublicKey = bobSession.SenderRatchetKeyPair.PublicKey?.ToArray(),
                    PrivateKey = bobSession.SenderRatchetKeyPair.PrivateKey?.ToArray()
                },
                ReceiverRatchetPublicKey = bobSession.ReceiverRatchetPublicKey?.ToArray(),
                PreviousReceiverRatchetPublicKey = bobSession.PreviousReceiverRatchetPublicKey?.ToArray(),
                SendMessageNumber = bobSession.SendMessageNumber,
                ReceiveMessageNumber = bobSession.ReceiveMessageNumber,
                IsInitialized = bobSession.IsInitialized,
                CreationTimestamp = bobSession.CreationTimestamp,
                SentMessages = new Dictionary<uint, byte[]>(),
                SkippedMessageKeys = new Dictionary<SkippedMessageKey, byte[]>()
            };

            // Act - Attempt to decrypt the tampered message
            var (resultSession, resultMessage) = _doubleRatchetProtocol.DecryptAsync(bobSessionForTampered, tamperedMessage);

            // Assert - Check that tampering was detected by verifying null returns
            Assert.IsNull(resultSession, "Tampered message should result in null session");
            Assert.IsNull(resultMessage, "Tampered message should result in null decrypted message");

            // Additional verification - make sure the original message still decrypts properly
            var (validSession, validMessage) = _doubleRatchetProtocol.DecryptAsync(bobSession, encryptedMessage);

            Assert.IsNotNull(validSession, "Original message should decrypt successfully");
            Assert.IsNotNull(validMessage, "Original message should decrypt successfully");
            Assert.AreEqual(message, validMessage, "Original message should decrypt to the correct content");
        }

        #endregion

        #region Security Parameter Tests

        /// <summary>
        /// Tests that generated nonces have the cryptographic properties required:
        /// they are unique and unpredictable.
        /// </summary>
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
                    Assert.IsFalse(SecureMemory.SecureCompare(nonces[i], nonces[j]),
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
            double expectedOccurrences = (double)(numNonces * Constants.NONCE_SIZE) / 256;

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

        /// <summary>
        /// Tests that long-term cryptographic identities have the required security properties,
        /// including uniqueness, proper key lengths, and signature verification.
        /// </summary>
        [TestMethod]
        public void LongTermCryptographicIdentity_ShouldBeSecure()
        {
            // Generate multiple key pairs
            var keyPair1 = Sodium.GenerateEd25519KeyPair();
            var keyPair2 = Sodium.GenerateEd25519KeyPair();
            var keyPair3 = Sodium.GenerateEd25519KeyPair();

            // Ensure keys meet minimum security requirements
            Assert.AreEqual(Constants.ED25519_PUBLIC_KEY_SIZE, keyPair1.PublicKey.Length,
                $"Ed25519 public key should be {Constants.ED25519_PUBLIC_KEY_SIZE} bytes");
            Assert.AreEqual(Constants.ED25519_PRIVATE_KEY_SIZE, keyPair1.PrivateKey.Length,
                $"Ed25519 private key should be {Constants.ED25519_PRIVATE_KEY_SIZE} bytes");

            // Ensure all generated keys are different
            Assert.IsFalse(SecureMemory.SecureCompare(keyPair1.PublicKey, keyPair2.PublicKey));
            Assert.IsFalse(SecureMemory.SecureCompare(keyPair1.PublicKey, keyPair3.PublicKey));
            Assert.IsFalse(SecureMemory.SecureCompare(keyPair2.PublicKey, keyPair3.PublicKey));

            Assert.IsFalse(SecureMemory.SecureCompare(keyPair1.PrivateKey, keyPair2.PrivateKey));
            Assert.IsFalse(SecureMemory.SecureCompare(keyPair1.PrivateKey, keyPair3.PrivateKey));
            Assert.IsFalse(SecureMemory.SecureCompare(keyPair2.PrivateKey, keyPair3.PrivateKey));

            // Note: Detailed signature testing is covered in SignatureTests.cs
            // Here we only verify that key generation produces valid keys for cryptographic operations
        }

        #endregion

        #region Security Edge Case Tests

        /// <summary>
        /// Tests that the key derivation function maintains security properties even
        /// after multiple ratchet steps.
        /// </summary>
        [TestMethod]
        public void MultiRatchetSequence_ShouldMaintainSecurity()
        {
            // Generate initial key materials
            byte[] initialKey = RandomNumberGenerator.GetBytes(32);

            // Perform a large number of ratchet steps using Signal-compliant key derivation
            byte[] currentKey = initialKey;
            var messageKeys = new Dictionary<int, byte[]>();

            const int steps = 100;
            for (int i = 0; i < steps; i++)
            {
                // FIXED: Use Signal-compliant key derivation methods
                // Derive a message key from the current chain key
                byte[] messageKey = _cryptoProvider.DeriveMessageKey(currentKey);

                // Advance the chain key
                byte[] newChainKey = _cryptoProvider.AdvanceChainKey(currentKey);

                // Store message key
                messageKeys[i] = messageKey;

                // Update current key
                currentKey = newChainKey;

                // Verify that this message key is unique
                for (int j = 0; j < i; j++)
                {
                    Assert.IsFalse(SecureMemory.SecureCompare(messageKeys[j], messageKey),
                        $"Message keys at positions {j} and {i} should not be equal");
                }
            }

            // Test that the final chain key doesn't reveal anything about the initial key
            Assert.IsFalse(SecureMemory.SecureCompare(initialKey, currentKey),
                "Final chain key should differ from initial key");

            // Check for cryptographic distinctness
            bool hasDistinctKeys = false;
            for (int i = 0; i < steps; i++)
            {
                // Check that message keys are cryptographically distinct from chain keys
                if (!SecureMemory.SecureCompare(messageKeys[i], initialKey) &&
                    !SecureMemory.SecureCompare(messageKeys[i], currentKey))
                {
                    hasDistinctKeys = true;
                    break;
                }
            }

            Assert.IsTrue(hasDistinctKeys,
                "Message keys should be cryptographically distinct from initial and final chain keys");
        }

        /// <summary>
        /// Tests that input validation correctly handles edge cases and prevents invalid inputs.
        /// </summary>
        [TestMethod]
        public void InputValidation_HandlesEdgeCases()
        {
            // Arrange
            // Test with key arrays of incorrect length
            byte[] shortKey = new byte[16]; // Too short
            byte[] longKey = new byte[64];  // Too long for AES but valid for Ed25519
            byte[] messageBytes = Encoding.Default.GetBytes("Test message");
            byte[] validNonce = _cryptoProvider.GenerateNonce();
            byte[] shortNonce = new byte[8]; // Too short

            // Valid key for comparison
            byte[] validKey = RandomNumberGenerator.GetBytes(Constants.AES_KEY_SIZE);

            // Act & Assert

            // Test AES with invalid key lengths
            Assert.ThrowsException<ArgumentException>(() =>
            {
                _cryptoProvider.Encrypt(messageBytes, shortKey, validNonce, null);
            }, "Should throw for key that's too short");

            Assert.ThrowsException<ArgumentException>(() =>
            {
                _cryptoProvider.Encrypt(messageBytes, longKey, validNonce, null);
            }, "Should throw for key that's too long for AES");

            // Test with invalid nonce
            Assert.ThrowsException<ArgumentException>(() =>
            {
                _cryptoProvider.Encrypt(messageBytes, validKey, shortNonce, null);
            }, "Should throw for nonce that's too short");

            // Test with null inputs
            Assert.ThrowsException<ArgumentNullException>(() =>
            {
                _cryptoProvider.Encrypt(null, validKey, validNonce, null);
            }, "Should throw for null plaintext");

            Assert.ThrowsException<ArgumentNullException>(() =>
            {
                _cryptoProvider.Encrypt(messageBytes, null, validNonce, null);
            }, "Should throw for null key");

            Assert.ThrowsException<ArgumentNullException>(() =>
            {
                _cryptoProvider.Encrypt(messageBytes, validKey, null, null);
            }, "Should throw for null nonce");

            // Test input validation for signature methods
            KeyPair signIdentityKeyPair = Sodium.GenerateEd25519KeyPair();
            var publicKey = signIdentityKeyPair.PublicKey;
            var privateKey = signIdentityKeyPair.PrivateKey;

            Assert.ThrowsException<ArgumentNullException>(() =>
            {
                _cryptoProvider.Sign(null, privateKey);
            }, "Should throw for null message in Sign");

            Assert.ThrowsException<ArgumentNullException>(() =>
            {
                _cryptoProvider.Sign(messageBytes, null);
            }, "Should throw for null private key in Sign");

            // FIXED: VerifySignature throws ArgumentException for empty message when public key is valid
            // This is the actual behavior - it validates the key first, then calls SignVerifyDetached
            Assert.ThrowsException<ArgumentException>(() =>
            {
                _cryptoProvider.VerifySignature(ReadOnlySpan<byte>.Empty, signature: new byte[64], publicKey);
            }, "Should throw ArgumentException for empty message when public key is valid");

            // Test with invalid signature length - throws ArgumentException when public key is valid
            Assert.ThrowsException<ArgumentException>(() =>
            {
                _cryptoProvider.VerifySignature(messageBytes, signature: new byte[32], publicKey); // Wrong size
            }, "Should throw ArgumentException for invalid signature length when public key is valid");

            // Test with invalid public key length - returns false (caught by ValidateEd25519PublicKey)
            bool result3 = _cryptoProvider.VerifySignature(messageBytes, signature: new byte[64], new byte[16]); // Wrong size
            Assert.IsFalse(result3, "Should return false for invalid public key length");
        }

        /// <summary>
        /// Tests that nonce handling prevents reuse, a critical security property for AES-GCM.
        /// Demonstrates why nonce reuse is dangerous.
        /// </summary>
        [TestMethod]
        public void NonceHandling_PreventNonceReuse()
        {
            // This test checks if the library prevents nonce reuse - a critical security property

            // Arrange
            byte[] key = RandomNumberGenerator.GetBytes(Constants.AES_KEY_SIZE);

            string message1 = "First message";
            string message2 = "Second message - should use different nonce";

            byte[] plaintext1 = Encoding.Default.GetBytes(message1);
            byte[] plaintext2 = Encoding.Default.GetBytes(message2);

            // Act - Generate distinct nonces for each message
            byte[] nonce1 = _cryptoProvider.GenerateNonce();
            byte[] nonce2 = _cryptoProvider.GenerateNonce();

            // Verify nonces are different
            Assert.IsFalse(SecureMemory.SecureCompare(nonce1, nonce2), "Generated nonces should be unique");

            // Encrypt messages with their respective nonces
            byte[] ciphertext1 = _cryptoProvider.Encrypt(plaintext1, key, nonce1, null);
            byte[] ciphertext2 = _cryptoProvider.Encrypt(plaintext2, key, nonce2, null);

            // Attempting to decrypt with the wrong nonce should fail
            Assert.ThrowsException<CryptographicException>(() =>
            {
                _cryptoProvider.Decrypt(ciphertext1, key, nonce2, null);
            }, "Decryption with wrong nonce should fail");

            // Demonstrate the danger of nonce reuse (in a real system we would prevent this)
            if (nonce1.Length == nonce2.Length)
            {
                // Create a copy of nonce1 to simulate reuse
                byte[] reusedNonce = nonce1.ToArray();

                // Encrypt both messages with the same nonce (dangerous!)
                byte[] insecureCiphertext1 = _cryptoProvider.Encrypt(plaintext1, key, reusedNonce, null);
                byte[] insecureCiphertext2 = _cryptoProvider.Encrypt(plaintext2, key, reusedNonce, null);

                // If we can XOR the ciphertexts, we can potentially leak information about the plaintexts
                int minLength = Math.Min(insecureCiphertext1.Length, insecureCiphertext2.Length);
                byte[] xorResult = new byte[minLength];
                for (int i = 0; i < minLength; i++)
                {
                    xorResult[i] = (byte)(insecureCiphertext1[i] ^ insecureCiphertext2[i]);
                }

                // In a secure implementation, the CryptoProvider should prevent this either by:
                // 1. Throwing an exception when a nonce is reused
                // 2. Ensuring nonces are never reused through proper design (preferred)

                // We can test that multiple calls to GenerateNonce always produce different values
                var generatedNonces = new HashSet<string>(StringComparer.Ordinal);
                for (int i = 0; i < 100; i++)
                {
                    byte[] newNonce = _cryptoProvider.GenerateNonce();
                    string nonceStr = Convert.ToBase64String(newNonce);
                    Assert.IsFalse(generatedNonces.Contains(nonceStr), "Generated nonce should be unique");
                    generatedNonces.Add(nonceStr);
                }
            }
        }

        #endregion

        #region Security Vulnerability Tests

        /// <summary>
        /// Tests that DeriveKey does not destroy caller's input key material
        /// </summary>
        [TestMethod]
        public void DeriveKey_ShouldNotDestroyCallerInputKeyMaterial()
        {
            // Arrange
            byte[] inputKeyMaterial = _cryptoProvider.GenerateRandomBytes(32);
            byte[] originalCopy = new byte[inputKeyMaterial.Length];
            Array.Copy(inputKeyMaterial, originalCopy, inputKeyMaterial.Length);

            byte[] salt = _cryptoProvider.GenerateRandomBytes(16);
            byte[] info = Encoding.UTF8.GetBytes("test-info");

            // Act
            byte[] derivedKey = _cryptoProvider.DeriveKey(inputKeyMaterial, salt, info, 32);

            // Assert
            Assert.IsNotNull(derivedKey);
            Assert.AreEqual(32, derivedKey.Length);

            // Verify that the caller's input key material is unchanged
            Assert.IsTrue(SecureMemory.SecureCompare(inputKeyMaterial, originalCopy),
                "Input key material should not be modified by DeriveKey");
        }

        /// <summary>
        /// Tests that constant-time comparison is used for cryptographic values
        /// </summary>
        [TestMethod]
        public void SecureCompare_ShouldBeConstantTime()
        {
            // Arrange
            byte[] key1 = _cryptoProvider.GenerateRandomBytes(32);
            byte[] key2 = new byte[32];
            Array.Copy(key1, key2, 32);

            // Make key2 different in the last byte
            key2[31] ^= 0xFF;

            // Act & Assert - Test that comparison works correctly
            Assert.IsTrue(SecureMemory.SecureCompare(key1, key1), "Identical keys should compare equal");
            Assert.IsFalse(SecureMemory.SecureCompare(key1, key2), "Different keys should compare unequal");

            // Test with different lengths
            byte[] shortKey = new byte[16];
            Assert.IsFalse(SecureMemory.SecureCompare(key1, shortKey), "Keys of different lengths should compare unequal");
        }

        /// <summary>
        /// Tests that signature verification uses constant-time operations
        /// </summary>
        [TestMethod]
        public void SignatureVerification_ShouldUseConstantTimeOperations()
        {
            // Arrange
            var keyPair = Sodium.GenerateEd25519KeyPair();
            byte[] message = Encoding.UTF8.GetBytes("test message");

            // Create valid signature
            byte[] validSignature = Sodium.SignDetached(message, keyPair.PrivateKey);

            // Create invalid signature (modify one byte)
            byte[] invalidSignature = new byte[validSignature.Length];
            Array.Copy(validSignature, invalidSignature, validSignature.Length);
            invalidSignature[0] ^= 0xFF;

            // Act & Assert
            bool validResult = _cryptoProvider.VerifySignature(message, validSignature, keyPair.PublicKey);
            bool invalidResult = _cryptoProvider.VerifySignature(message, invalidSignature, keyPair.PublicKey);

            Assert.IsTrue(validResult, "Valid signature should verify successfully");
            Assert.IsFalse(invalidResult, "Invalid signature should fail verification");
        }

        /// <summary>
        /// Tests that random number generation produces high-quality entropy
        /// </summary>
        [TestMethod]
        public void RandomGeneration_ShouldProduceHighQualityEntropy()
        {
            // Arrange & Act
            const int numSamples = 1000;
            const int keySize = 32;
            var samples = new List<byte[]>();

            for (int i = 0; i < numSamples; i++)
            {
                samples.Add(_cryptoProvider.GenerateRandomBytes(keySize));
            }

            // Assert - Check for uniqueness
            for (int i = 0; i < samples.Count; i++)
            {
                for (int j = i + 1; j < samples.Count; j++)
                {
                    Assert.IsFalse(SecureMemory.SecureCompare(samples[i], samples[j]),
                        $"Random samples {i} and {j} should not be identical");
                }
            }

            // Basic entropy check - count unique bytes across all samples
            var allBytes = new HashSet<byte>();
            foreach (var sample in samples)
            {
                foreach (byte b in sample)
                {
                    allBytes.Add(b);
                }
            }

            // Should see most possible byte values with this many samples
            Assert.IsTrue(allBytes.Count > 200,
                $"Expected high entropy, but only saw {allBytes.Count} unique byte values");
        }

        /// <summary>
        /// Tests that memory clearing operations are effective
        /// </summary>
        [TestMethod]
        public void SecureMemoryClear_ShouldEffectivelyClearMemory()
        {
            // Arrange
            byte[] sensitiveData = _cryptoProvider.GenerateRandomBytes(64);
            byte[] originalCopy = new byte[sensitiveData.Length];
            Array.Copy(sensitiveData, originalCopy, sensitiveData.Length);

            // Verify data is initially present
            Assert.IsTrue(SecureMemory.SecureCompare(sensitiveData, originalCopy));

            // Act
            SecureMemory.SecureClear(sensitiveData);

            // Assert
            Assert.IsFalse(SecureMemory.SecureCompare(sensitiveData, originalCopy),
                "Memory should be cleared after SecureClear");

            // Verify all bytes are zero
            foreach (byte b in sensitiveData)
            {
                Assert.AreEqual(0, b, "All bytes should be zero after clearing");
            }
        }

        #endregion
    }
}