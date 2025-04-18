using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using LibEmiddle.Core;
using LibEmiddle.Domain;
using LibEmiddle.MultiDevice;
using LibEmiddle.Abstractions;
using LibEmiddle.Crypto;

namespace LibEmiddle.Tests.Unit
{
    [TestClass]
    public class DeviceLinkingTests
    {
        private CryptoProvider _cryptoProvider;

        [TestInitialize]
        public void Setup()
        {
            _cryptoProvider = new CryptoProvider();
        }

        [TestMethod]
        public void CreateDeviceLinkMessage_MultipleKeyTypes_ShouldWork()
        {
            // Test scenarios: valid key pairs should succeed; invalid ones should throw.
            var testScenarios = new (Func<KeyPair> keyPairFunc, bool shouldSucceed, string description)[]
            {
                // Scenario 1: Standard Ed25519 Key Pair (should succeed)
                ( () => _cryptoProvider.GenerateKeyPair(KeyType.Ed25519), true, "Standard Ed25519 Key Pair" ),
        
                // Scenario 2: X25519 Key Pair (should fail, because signing requires Ed25519)
                ( () => _cryptoProvider.GenerateKeyPair(KeyType.X25519), false, "X25519 Key Pair" ),
        
                // Scenario 3: Ed25519 public key with X25519 private key (should fail)
                ( () => {
                    var ed25519Pair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);
                    return new KeyPair(ed25519Pair.PublicKey, _cryptoProvider.DeriveX25519PrivateKeyFromEd25519(ed25519Pair.PrivateKey));
                }, false, "Ed25519 to X25519 Hybrid Key Pair" )
            };

            foreach (var (keyPairFunc, shouldSucceed, description) in testScenarios)
            {
                var mainDeviceKeyPair = keyPairFunc();
                var newDeviceKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);

                if (shouldSucceed)
                {
                    // Expect successful creation.
                    var encryptedMessage = DeviceLinking.CreateDeviceLinkMessage(
                        mainDeviceKeyPair,
                        newDeviceKeyPair.PublicKey
                    );

                    Assert.IsNotNull(encryptedMessage, $"Device link message should be created for {description}");
                    Assert.IsNotNull(encryptedMessage.Ciphertext, $"Ciphertext should not be null for {description}");
                    Assert.IsNotNull(encryptedMessage.Nonce, $"Nonce should not be null for {description}");
                }
                else
                {
                    // Expect an exception due to invalid main device key pair format.
                    Assert.ThrowsException<ArgumentException>(() =>
                    {
                        DeviceLinking.CreateDeviceLinkMessage(mainDeviceKeyPair, newDeviceKeyPair.PublicKey);
                    }, $"Scenario {description} should throw an exception due to invalid main device key pair format.");
                }
            }
        }

        [TestMethod]
        public void DeriveSharedKeyForNewDevice_StressTest()
        {
            const int ITERATIONS = 100;
            var uniqueDerivedKeys = new HashSet<string>();

            for (int i = 0; i < ITERATIONS; i++)
            {
                // Generate a unique shared key each iteration.
                byte[] existingSharedKey = new byte[32];
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(existingSharedKey);
                }

                // Generate a new device key pair (Ed25519).
                var newDeviceKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);

                // Convert the Ed25519 public key to its X25519 representation.
                var x25519NewDeviceKey = _cryptoProvider.ConvertEd25519PublicKeyToX25519(newDeviceKeyPair.PublicKey);

                // Derive the shared key using the Ed25519 public key overload.
                byte[] keyFromEd25519 = DeviceLinking.DeriveSharedKeyForNewDevice(existingSharedKey, newDeviceKeyPair.PublicKey);

                // Derive the shared key using the X25519 public key overload.
                byte[] keyFromX25519 = DeviceLinking.DeriveSharedKeyForNewDeviceX25519(existingSharedKey, x25519NewDeviceKey);

                // Both derivations should yield the same shared key.
                CollectionAssert.AreEqual(keyFromEd25519, keyFromX25519,
                    $"Shared key derivation inconsistent in iteration {i}");

                // Track unique derived keys to verify randomness.
                uniqueDerivedKeys.Add(Convert.ToBase64String(keyFromEd25519));
            }

            // Ensure that a high degree of uniqueness is maintained across iterations.
            Assert.IsTrue(uniqueDerivedKeys.Count > ITERATIONS * 0.9,
                "Derived keys should have high uniqueness");
        }

        [TestMethod]
        public void ProcessDeviceLinkMessage_EdgeCaseScenarios()
        {
            var scenarios = new List<(Func<KeyPair> mainDeviceKeyPairFunc, string scenarioDescription)>
            {
                // Scenario 1: Standard Ed25519 Key Generation
                (() => _cryptoProvider.GenerateKeyPair(KeyType.Ed25519), "Standard Ed25519 Key Generation"),

                // Scenario 2: Ed25519 to X25519 Conversion
                // (This returns a key pair that is already converted and should be rejected.)
                (() => {
                    KeyPair ed25519Pair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);
                    var x25519Private = _cryptoProvider.DeriveX25519PrivateKeyFromEd25519(ed25519Pair.PrivateKey);
                    var x25519Public = SecureMemory.CreateSecureBuffer(Constants.X25519_KEY_SIZE);
                    Sodium.ComputePublicKey(x25519Public, x25519Private);
                    return new KeyPair(x25519Public, x25519Private);
                }, "Ed25519 to X25519 Conversion"),

                // Scenario 3: Minimal Entropy Keys – valid key pair derived from an all-zero seed.
                (() => {
                    var seed = new byte[32]; // 32 zero bytes
                    return _cryptoProvider.GenerateEd25519KeyPairFromSeed(seed);
                }, "Minimal Entropy Keys"),

                // Scenario 4: Maximum Entropy Keys – valid key pair derived from a fixed high-entropy seed.
                (() => {
                    var seed = Enumerable.Range(0, 32).Select(i => (byte)(i * 17)).ToArray();
                    return _cryptoProvider.GenerateEd25519KeyPairFromSeed(seed);
                }, "Maximum Entropy Keys"),

                // Scenario 5: X25519 Key Pair
                // (This scenario uses a pure X25519 key pair and should be rejected.)
                (() => _cryptoProvider.GenerateKeyPair(KeyType.X25519), "X25519 Key Pair")
            };

            foreach (var (mainDeviceKeyPairFunc, scenarioDescription) in scenarios)
            {
                // Generate main device key pair for the scenario.
                var mainDeviceKeyPair = mainDeviceKeyPairFunc();

                // Generate a new device key pair (always standard Ed25519).
                var newDeviceKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);

                if (scenarioDescription == "Ed25519 to X25519 Conversion" ||
                    scenarioDescription == "X25519 Key Pair")
                {
                    // For these scenarios, we expect an exception when creating the device link message.
                    Assert.ThrowsException<ArgumentException>(() =>
                    {
                        DeviceLinking.CreateDeviceLinkMessage(mainDeviceKeyPair, newDeviceKeyPair.PublicKey);
                    }, $"Scenario {scenarioDescription} should throw an exception due to invalid main device key pair format.");
                }
                else
                {
                    // For valid Ed25519 key pairs, proceed normally.
                    try
                    {
                        // Create device link message.
                        var encryptedMessage = DeviceLinking.CreateDeviceLinkMessage(
                            mainDeviceKeyPair,
                            newDeviceKeyPair.PublicKey
                        );

                        // Process the message.
                        var result = DeviceLinking.ProcessDeviceLinkMessage(
                            encryptedMessage,
                            newDeviceKeyPair,
                            mainDeviceKeyPair.PublicKey
                        );

                        // Validation.
                        Assert.IsNotNull(result,
                            $"Device link message processing failed for scenario: {scenarioDescription}");
                        Assert.IsTrue(result.Length > 0,
                            $"Processed result should not be empty for scenario: {scenarioDescription}");
                    }
                    catch (Exception ex)
                    {
                        // Detailed failure reporting.
                        Assert.Fail(
                            $"Unexpected exception in scenario {scenarioDescription}: {ex.Message}\n" +
                            $"Main Device Key Length: {mainDeviceKeyPair.PublicKey.Length}\n" +
                            $"Main Device Private Key Length: {mainDeviceKeyPair.PrivateKey.Length}\n" +
                            $"New Device Key Length: {newDeviceKeyPair.PublicKey.Length}"
                        );
                    }
                }
            }
        }

        [TestMethod]
        public void DeviceLinkMessage_WithMaliciousPayload_ShouldFail()
        {
            var mainDeviceKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);
            var newDeviceKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);

            // Create a valid device link message
            var originalMessage = DeviceLinking.CreateDeviceLinkMessage(
                mainDeviceKeyPair,
                newDeviceKeyPair.PublicKey
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
                        Ciphertext = SecureMemory.CreateSecureBuffer((uint)originalMessage.Ciphertext.Length),
                        Nonce = SecureMemory.CreateSecureBuffer((uint) originalMessage.Nonce.Length)
                    };
                    return randomMessage;
                }
            };

            foreach (var maliciousMessageFunc in maliciousScenarios)
            {
                var maliciousMessage = maliciousMessageFunc();

                var result = DeviceLinking.ProcessDeviceLinkMessage(
                    maliciousMessage,
                    newDeviceKeyPair,
                    mainDeviceKeyPair.PublicKey
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
                var newDeviceKeyPair = _cryptoProvider.GenerateKeyPair(KeyType.Ed25519);

                var derivedKey = DeviceLinking.DeriveSharedKeyForNewDevice(sharedKey, newDeviceKeyPair.PublicKey);

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