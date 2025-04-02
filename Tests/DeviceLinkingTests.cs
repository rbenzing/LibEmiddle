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
                var x25519NewDeviceKey = KeyConversion.DeriveX25519PublicKeyFromEd25519(newDeviceKeyPair.publicKey);

                // Derive keys using different input types
                byte[] keyFromEd25519 = DeviceLinking.DeriveSharedKeyForNewDevice(existingSharedKey, newDeviceKeyPair.publicKey);
                byte[] keyFromX25519 = DeviceLinking.DeriveSharedKeyForNewDevice(existingSharedKey, x25519NewDeviceKey);

                // Validate key consistency
                CollectionAssert.AreEqual(keyFromEd25519, keyFromX25519,
                    $"Shared key derivation inconsistent in iteration {i}");

                // Track unique derived keys to ensure randomness
                uniqueDerivedKeys.Add(Convert.ToBase64String(keyFromEd25519));
            }

            // Ensure we're generating sufficiently unique keys
            Assert.IsTrue(uniqueDerivedKeys.Count > ITERATIONS * 0.9,
                "Derived keys should have high uniqueness");
        }

        [TestMethod]
        public void ProcessDeviceLinkMessage_EdgeCaseScenarios()
        {
            var scenarios = new List<(
                Func<(byte[] publicKey, byte[] privateKey)> mainDeviceKeyPairFunc,
                string scenarioDescription)>
            {
                // Scenario 1: Standard Ed25519 Key Generation
                (() => KeyGenerator.GenerateEd25519KeyPair(), "Standard Ed25519 Key Generation"),

                // Scenario 2: Ed25519 to X25519 Conversion
                (() => {
                    var ed25519Pair = KeyGenerator.GenerateEd25519KeyPair();
                    var x25519Private = KeyConversion.DeriveX25519PrivateKeyFromEd25519(ed25519Pair.privateKey);
                    var x25519Public = Sodium.ScalarMultBase(x25519Private);
                    return (x25519Public, x25519Private);
                }, "Ed25519 to X25519 Conversion"),

                // Scenario 3: Minimal Entropy Keys
                (() => {
                    var minEntropyKey = new byte[Constants.ED25519_PUBLIC_KEY_SIZE];
                    var minEntropyPrivate = new byte[Constants.ED25519_PRIVATE_KEY_SIZE];
                    new Random(0).NextBytes(minEntropyKey);
                    new Random(0).NextBytes(minEntropyPrivate);
                    return (minEntropyKey, minEntropyPrivate);
                }, "Minimal Entropy Keys"),

                // Scenario 4: Maximum Entropy Keys
                (() => {
                    var maxEntropyKey = Enumerable.Range(0, Constants.ED25519_PUBLIC_KEY_SIZE)
                        .Select(i => (byte)(i * 17))
                        .ToArray();
                    var maxEntropyPrivate = Enumerable.Range(0, Constants.ED25519_PRIVATE_KEY_SIZE)
                        .Select(i => (byte)(i * 13))
                        .ToArray();
                    return (maxEntropyKey, maxEntropyPrivate);
                }, "Maximum Entropy Keys"),

                // Scenario 5: X25519 Key Pair
                (() => KeyGenerator.GenerateX25519KeyPair(), "X25519 Key Pair")
            };

            foreach (var (mainDeviceKeyPairFunc, scenarioDescription) in scenarios)
            {
                // Generate main device key pair for the scenario
                var mainDeviceKeyPair = mainDeviceKeyPairFunc();

                // Generate a new device key pair
                var newDeviceKeyPair = KeyGenerator.GenerateEd25519KeyPair();

                try
                {
                    // Create device link message
                    var encryptedMessage = DeviceLinking.CreateDeviceLinkMessage(
                        mainDeviceKeyPair,
                        newDeviceKeyPair.publicKey
                    );

                    // Process the message
                    var result = DeviceLinking.ProcessDeviceLinkMessage(
                        encryptedMessage,
                        newDeviceKeyPair,
                        mainDeviceKeyPair.publicKey
                    );

                    // Validation
                    Assert.IsNotNull(result,
                        $"Device link message processing failed for scenario: {scenarioDescription}");
                    Assert.IsTrue(result.Length > 0,
                        $"Processed result should not be empty for scenario: {scenarioDescription}");
                }
                catch (Exception ex)
                {
                    // Detailed failure reporting
                    Assert.Fail(
                        $"Unexpected exception in scenario {scenarioDescription}: {ex.Message}\n" +
                        $"Main Device Key Length: {mainDeviceKeyPair.publicKey.Length}\n" +
                        $"Main Device Private Key Length: {mainDeviceKeyPair.privateKey.Length}\n" +
                        $"New Device Key Length: {newDeviceKeyPair.publicKey.Length}"
                    );
                }
            }
        }

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

                var result = DeviceLinking.ProcessDeviceLinkMessage(
                    maliciousMessage,
                    newDeviceKeyPair,
                    mainDeviceKeyPair.publicKey
                );

                Assert.IsNull(result, "Malicious message should not be processed");
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