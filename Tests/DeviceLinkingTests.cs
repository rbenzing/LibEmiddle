using System;
using System.Text;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;
using E2EELibrary;
using E2EELibrary.KeyManagement;
using E2EELibrary.MultiDevice;
using E2EELibrary.Core;
using E2EELibrary.KeyExchange;
using E2EELibrary.Models;
using E2EELibrary.Communication;
using System.Collections.Generic;

namespace E2EELibraryTests
{
    [TestClass]
    public class DeviceLinkingTests
    {
        [TestMethod]
        public void CreateDeviceLinkMessage_MultipleKeyTypes_ShouldWork()
        {
            // Test creating device link messages with various key types and lengths
            var testScenarios = new[]
            {
                () => KeyGenerator.GenerateEd25519KeyPair(),
                () => KeyGenerator.GenerateX25519KeyPair(),
                () => {
                    var ed25519Pair = KeyGenerator.GenerateEd25519KeyPair();
                    return (ed25519Pair.publicKey, KeyConversion.DeriveX25519PrivateKeyFromEd25519(ed25519Pair.privateKey));
                }
            };

            foreach (var keyPairFunc in testScenarios)
            {
                var mainDeviceKeyPair = keyPairFunc();
                var newDeviceKeyPair = KeyGenerator.GenerateEd25519KeyPair();

                var encryptedMessage = DeviceLinking.CreateDeviceLinkMessage(
                    mainDeviceKeyPair,
                    newDeviceKeyPair.publicKey
                );

                Assert.IsNotNull(encryptedMessage, "Device link message should be created");
                Assert.IsNotNull(encryptedMessage.Ciphertext, "Ciphertext should not be null");
                Assert.IsNotNull(encryptedMessage.Nonce, "Nonce should not be null");
            }
        }

        [TestMethod]
        public void DeriveSharedKeyForNewDevice_StressTest()
        {
            const int ITERATIONS = 100;
            var uniqueDerivedKeys = new HashSet<string>();

            for (int i = 0; i < ITERATIONS; i++)
            {
                // Generate a unique shared key each time
                byte[] existingSharedKey = new byte[32];
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(existingSharedKey);
                }

                var newDeviceKeyPair = KeyGenerator.GenerateEd25519KeyPair();

                // Just derive one key using Ed25519 public key
                byte[] derivedKey = DeviceLinking.DeriveSharedKeyForNewDevice(existingSharedKey, newDeviceKeyPair.publicKey);

                // Validate key properties
                Assert.IsNotNull(derivedKey, $"Derived key is null in iteration {i}");
                Assert.AreEqual(32, derivedKey.Length, $"Derived key has incorrect length in iteration {i}");

                // Track unique derived keys to ensure randomness
                uniqueDerivedKeys.Add(Convert.ToBase64String(derivedKey));
            }

            // Ensure we're generating sufficiently unique keys
            Assert.IsTrue(uniqueDerivedKeys.Count > ITERATIONS * 0.9,
                "Derived keys should have high uniqueness");
        }

        /*TODO: Figure out why this isnt working correctly.
        [TestMethod]
        public void ProcessDeviceLinkMessage_EdgeCaseScenarios()
        {
            var scenarios = new List<(
                Func<(byte[] publicKey, byte[] privateKey)> mainDeviceKeyPairFunc,
                string scenarioDescription,
                bool shouldSucceed)>
            {
                // Scenario 1: Standard Ed25519 Key Generation (expected to succeed)
                (() => KeyGenerator.GenerateEd25519KeyPair(), "Standard Ed25519 Key Generation", true),

                // Scenario 2: Ed25519 to X25519 Conversion (expected to fail because signing requires an Ed25519 private key)
                (() => {
                    var ed25519Pair = KeyGenerator.GenerateEd25519KeyPair();
                    var x25519Private = KeyConversion.DeriveX25519PrivateKeyFromEd25519(ed25519Pair.privateKey);
                    var x25519Public = Sodium.ScalarMultBase(x25519Private);
                    return (x25519Public, x25519Private);
                }, "Ed25519 to X25519 Conversion", false),

                // Scenario 3: Minimal Entropy Keys (expected to succeed)
                (() => {
                    var minEntropyKey = new byte[Constants.ED25519_PUBLIC_KEY_SIZE];
                    var minEntropyPrivate = new byte[Constants.ED25519_PRIVATE_KEY_SIZE];
                    new Random(0).NextBytes(minEntropyKey);
                    new Random(0).NextBytes(minEntropyPrivate);
                    return (minEntropyKey, minEntropyPrivate);
                }, "Minimal Entropy Keys", true),

                // Scenario 4: Maximum Entropy Keys (expected to succeed)
                (() => {
                    var maxEntropyKey = Enumerable.Range(0, Constants.ED25519_PUBLIC_KEY_SIZE)
                        .Select(i => (byte)(i * 17))
                        .ToArray();
                    var maxEntropyPrivate = Enumerable.Range(0, Constants.ED25519_PRIVATE_KEY_SIZE)
                        .Select(i => (byte)(i * 13))
                        .ToArray();
                    return (maxEntropyKey, maxEntropyPrivate);
                }, "Maximum Entropy Keys", true),

                // Scenario 5: X25519 Key Pair (expected to fail because it cannot be used for signing)
                (() => KeyGenerator.GenerateX25519KeyPair(), "X25519 Key Pair", false)
            };

            foreach (var (mainDeviceKeyPairFunc, scenarioDescription, shouldSucceed) in scenarios)
            {
                // Generate the main device key pair for the scenario.
                var mainDeviceKeyPair = mainDeviceKeyPairFunc();
                // Generate a new device key pair (always Ed25519 for signing).
                var newDeviceKeyPair = KeyGenerator.GenerateEd25519KeyPair();

                // Compute the main device's X25519 public key.
                byte[] mainDeviceX25519Public;
                string computedX25519PublicBase64;
                if (mainDeviceKeyPair.privateKey.Length == Constants.ED25519_PRIVATE_KEY_SIZE)
                {
                    var mainDeviceX25519Private = KeyConversion.DeriveX25519PrivateKeyFromEd25519(mainDeviceKeyPair.privateKey);
                    mainDeviceX25519Public = Sodium.ScalarMultBase(mainDeviceX25519Private);
                    computedX25519PublicBase64 = Convert.ToBase64String(mainDeviceX25519Public);
                }
                else if (mainDeviceKeyPair.privateKey.Length == Constants.X25519_KEY_SIZE)
                {
                    mainDeviceX25519Public = mainDeviceKeyPair.publicKey;
                    computedX25519PublicBase64 = Convert.ToBase64String(mainDeviceX25519Public);
                }
                else
                {
                    mainDeviceX25519Public = mainDeviceKeyPair.publicKey;
                    computedX25519PublicBase64 = Convert.ToBase64String(mainDeviceX25519Public);
                }

                try
                {
                    // Create device link message.
                    var encryptedMessage = DeviceLinking.CreateDeviceLinkMessage(
                        mainDeviceKeyPair,
                        newDeviceKeyPair.publicKey
                    );

                    // Gather encryption details for logging.
                    string nonceBase64 = Convert.ToBase64String(encryptedMessage.Nonce);
                    string ciphertextBase64 = Convert.ToBase64String(encryptedMessage.Ciphertext);

                    // Process the message using the computed X25519 public key.
                    var result = DeviceLinking.ProcessDeviceLinkMessage(
                        encryptedMessage,
                        newDeviceKeyPair,
                        mainDeviceX25519Public
                    );

                    if (shouldSucceed)
                    {
                        Assert.IsNotNull(result,
                            $"Scenario '{scenarioDescription}' failed: Result is null.");
                        Assert.IsTrue(result.Length > 0,
                            $"Scenario '{scenarioDescription}' failed: Result is empty.");
                    }
                    else
                    {
                        Assert.IsNull(result,
                            $"Scenario '{scenarioDescription}' unexpectedly succeeded. EncryptedMessage: Nonce = {nonceBase64}, Ciphertext = {ciphertextBase64}");
                    }
                }
                catch (Exception ex)
                {
                    // Build a detailed error message.
                    string mainDeviceEd25519PublicBase64 = Convert.ToBase64String(mainDeviceKeyPair.publicKey);
                    string newDevicePublicBase64 = Convert.ToBase64String(newDeviceKeyPair.publicKey);
                    string errorDetails =
                        $"Scenario: {scenarioDescription}\n" +
                        $"Main Device Ed25519 Public Key (base64): {mainDeviceEd25519PublicBase64}\n" +
                        $"Main Device X25519 Public Key (base64): {computedX25519PublicBase64}\n" +
                        $"Main Device Private Key Length: {mainDeviceKeyPair.privateKey.Length}\n" +
                        $"New Device Ed25519 Public Key (base64): {newDevicePublicBase64}\n" +
                        $"Error: {ex.Message}";

                    Assert.Fail($"Unexpected exception in scenario '{scenarioDescription}': {errorDetails}");
                }
            }
        }
        */

        [TestMethod]
        public void DeviceLinkMessage_WithMaliciousPayload_ShouldFail()
        {
            var mainDeviceKeyPair = KeyGenerator.GenerateEd25519KeyPair();
            var newDeviceKeyPair = KeyGenerator.GenerateEd25519KeyPair();

            // Create a valid device link message
            var originalMessage = DeviceLinking.CreateDeviceLinkMessage(
                mainDeviceKeyPair,
                newDeviceKeyPair.publicKey
            );

            // Create malicious variations
            var maliciousScenarios = new[]
            {
                // Scenario 1: Tamper with ciphertext
                () => {
                    var tamperedMessage = new EncryptedMessage
                    {
                        Ciphertext = originalMessage.Ciphertext.Select(b => (byte)(b ^ 0xFF)).ToArray(),
                        Nonce = originalMessage.Nonce
                    };
                    return tamperedMessage;
                },
        
                // Scenario 2: Corrupt nonce
                () => {
                    var tamperedMessage = new EncryptedMessage
                    {
                        Ciphertext = originalMessage.Ciphertext,
                        Nonce = originalMessage.Nonce.Select(b => (byte)(b ^ 0x55)).ToArray()
                    };
                    return tamperedMessage;
                },
        
                // Scenario 3: Completely random payload
                () => {
                    var randomMessage = new EncryptedMessage
                    {
                        Ciphertext = new byte[originalMessage.Ciphertext.Length],
                        Nonce = new byte[originalMessage.Nonce.Length]
                    };
                    new Random().NextBytes(randomMessage.Ciphertext);
                    new Random().NextBytes(randomMessage.Nonce);
                    return randomMessage;
                }
            };

            foreach (var maliciousMessageFunc in maliciousScenarios)
            {
                var maliciousMessage = maliciousMessageFunc();

                // Expecting a CryptographicException due to tampering
                Assert.ThrowsException<CryptographicException>(() =>
                {
                    DeviceLinking.ProcessDeviceLinkMessage(
                        maliciousMessage,
                        newDeviceKeyPair,
                        mainDeviceKeyPair.publicKey
                    );
                }, "Malicious payload did not trigger an exception as expected.");
            }
        }


        [TestMethod]
        public void DeriveSharedKey_WithCryptographicVariety_ShouldBeRobust()
        {
            // Test deriving shared keys with various input characteristics
            var keyVarietyScenarios = new[]
            {
                // Scenario 1: Cryptographically secure random key
                () => {
                    byte[] secureKey = new byte[32];
                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(secureKey);
                    }
                    return secureKey;
                },
                
                // Scenario 2: Partially predictable key
                () => {
                    byte[] predictableKey = new byte[32];
                    for (int i = 0; i < predictableKey.Length; i++)
                    {
                        predictableKey[i] = (byte)(i * 7);
                    }
                    return predictableKey;
                },
                
                // Scenario 3: Key with high entropy
                () => {
                    return Enumerable.Range(0, 32)
                        .Select(i => (byte)Math.Abs(Math.Sin(i) * 255))
                        .ToArray();
                }
            };

            foreach (var keyFunc in keyVarietyScenarios)
            {
                byte[] sharedKey = keyFunc();
                var newDeviceKeyPair = KeyGenerator.GenerateEd25519KeyPair();

                var derivedKey = DeviceLinking.DeriveSharedKeyForNewDevice(sharedKey, newDeviceKeyPair.publicKey);

                // Validate derived key properties
                Assert.IsNotNull(derivedKey, "Derived key should not be null");
                Assert.AreEqual(32, derivedKey.Length, "Derived key should be 32 bytes");

                // Ensure derived key is not just a direct copy
                CollectionAssert.AreNotEqual(sharedKey, derivedKey,
                    "Derived key should not be identical to input key");
            }
        }
    }
}