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
using System.Diagnostics;

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
        ( () => {
            return Sodium.GenerateEd25519KeyPair();
        }, true, "Standard Ed25519 Key Pair" ),
        // Scenario 2: X25519 Key Pair (should fail, because signing requires Ed25519)
        ( () => {
            return Sodium.GenerateX25519KeyPair();
        }, false, "X25519 Key Pair" ),
        // Scenario 3: Ed25519 public key with X25519 private key (should fail)
        ( () => {
            var ed25519Pair = Sodium.GenerateEd25519KeyPair();
            var x25519Private = _cryptoProvider.DeriveX25519PrivateKeyFromEd25519(ed25519Pair.PrivateKey);
            return new KeyPair(ed25519Pair.PublicKey, x25519Private);
        }, false, "Ed25519 to X25519 Hybrid Key Pair" )
            };
            foreach (var (keyPairFunc, shouldSucceed, description) in testScenarios)
            {
                var mainDeviceKeyPair = keyPairFunc();
                var newDeviceKeyPair = Sodium.GenerateEd25519KeyPair();
                if (shouldSucceed)
                {
                    // Expect successful creation.
                    var encryptedMessage = DeviceLinkingService.CreateDeviceLinkMessage(
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
                    Exception caughtException = null;
                    try
                    {
                        DeviceLinkingService.CreateDeviceLinkMessage(mainDeviceKeyPair, newDeviceKeyPair.PublicKey);
                    }
                    catch (Exception ex)
                    {
                        caughtException = ex;
                    }

                    Assert.IsNotNull(caughtException, $"Scenario {description} should throw an exception");
                    Assert.IsTrue(caughtException is ArgumentException || caughtException is CryptographicException,
                                 $"Expected ArgumentException or CryptographicException for {description}, but got {caughtException?.GetType().Name}");
                }
            }
        }

        [TestMethod]
        public void DeriveSharedKeyForNewDevice_StressTest()
        {
            const int ITERATIONS = 20;
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
                var newDeviceKeyPair = Sodium.GenerateEd25519KeyPair();
                Trace.TraceInformation($"Generated KeyPair({Convert.ToBase64String(newDeviceKeyPair.PublicKey)}, {Convert.ToBase64String(newDeviceKeyPair.PrivateKey)})");

                // Convert the Ed25519 public key to its X25519 representation.
                var x25519NewDeviceKey = Sodium.ConvertEd25519PublicKeyToX25519(newDeviceKeyPair.PublicKey);
                Trace.TraceInformation($"Converted public to X25519 - {Convert.ToBase64String(x25519NewDeviceKey)}");

                // Derive the shared key using the Ed25519 public key.
                byte[] keyFromEd25519 = DeviceLinkingService.DeriveSharedKeyForNewDevice(existingSharedKey, newDeviceKeyPair.PublicKey);
                Trace.TraceInformation($"Derived Ed25519 public shared key - {Convert.ToBase64String(keyFromEd25519)}");

                // Verify the derived key has the expected length
                Assert.AreEqual(Constants.AES_KEY_SIZE, keyFromEd25519.Length,
                    $"Derived key should be {Constants.AES_KEY_SIZE} bytes in iteration {i}");

                // Since the method should internally convert Ed25519 to X25519, passing an already
                // converted key should produce a different result. We're not testing equivalence here,
                // but rather that the keys are properly derived in both cases.
                byte[] keyFromX25519 = DeviceLinkingService.DeriveSharedKeyForNewDevice(existingSharedKey, x25519NewDeviceKey);
                Trace.TraceInformation($"Derived X25519 public shared key - {Convert.ToBase64String(keyFromX25519)}");

                // Both derived keys should have the correct length
                Assert.AreEqual(Constants.AES_KEY_SIZE, keyFromX25519.Length,
                    $"Derived key should be {Constants.AES_KEY_SIZE} bytes in iteration {i}");

                // Verify the methods produce different results with different inputs
                Assert.IsFalse(keyFromEd25519.SequenceEqual(keyFromX25519),
                    $"Keys derived from Ed25519 and X25519 should be different in iteration {i}");

                // Track unique derived keys to verify randomness.
                uniqueDerivedKeys.Add(Convert.ToBase64String(keyFromEd25519));
                uniqueDerivedKeys.Add(Convert.ToBase64String(keyFromX25519));
            }

            // Ensure that a high degree of uniqueness is maintained across iterations.
            // With 2 keys per iteration, we should expect close to 2*ITERATIONS unique keys
            Assert.IsTrue(uniqueDerivedKeys.Count > ITERATIONS * 1.8,
                $"Derived keys should have high uniqueness. Got {uniqueDerivedKeys.Count} unique keys from {ITERATIONS * 2} total keys.");
        }

        [TestMethod]
        public void ProcessDeviceLinkMessage_EdgeCaseScenarios()
        {
            var scenarios = new List<(Func<KeyPair> mainDeviceKeyPairFunc, string scenarioDescription)>
    {
        // Scenario 1: Standard Ed25519 Key Generation
        (() => Sodium.GenerateEd25519KeyPair(), "Standard Ed25519 Key Generation"),

        // Scenario 2: Ed25519 to X25519 Conversion
        // (This returns a key pair that is already converted and should be rejected.)
        (() => {
            KeyPair ed25519Pair = Sodium.GenerateEd25519KeyPair();
            var x25519Private = Sodium.ConvertEd25519PrivateKeyToX25519(ed25519Pair.PrivateKey);
            var x25519Public = SecureMemory.CreateSecureBuffer(Constants.X25519_KEY_SIZE);
            Sodium.ComputePublicKey(x25519Public, x25519Private);
            return new KeyPair(x25519Public, x25519Private);
        }, "Ed25519 to X25519 Conversion"),

        // Scenario 3: Minimal Entropy Keys – valid key pair derived from an all-zero seed.
        (() => {
            var seed = new byte[32]; // 32 zero bytes
            return Sodium.GenerateEd25519KeyPairFromSeed(seed);
        }, "Minimal Entropy Keys"),

        // Scenario 4: Maximum Entropy Keys – valid key pair derived from a fixed high-entropy seed.
        (() => {
            var seed = Enumerable.Range(0, 32).Select(i => (byte)(i * 17)).ToArray();
            return Sodium.GenerateEd25519KeyPairFromSeed(seed);
        }, "Maximum Entropy Keys"),

        // Scenario 5: X25519 Key Pair
        // (This scenario uses a pure X25519 key pair and should be rejected.)
        (() => Sodium.GenerateX25519KeyPair(), "X25519 Key Pair")
    };

            foreach (var (mainDeviceKeyPairFunc, scenarioDescription) in scenarios)
            {
                // Generate main device key pair for the scenario.
                var mainDeviceKeyPair = mainDeviceKeyPairFunc();

                // Generate a new device key pair (always standard Ed25519).
                var newDeviceKeyPair = Sodium.GenerateEd25519KeyPair();

                if (scenarioDescription == "Ed25519 to X25519 Conversion" ||
                    scenarioDescription == "X25519 Key Pair")
                {
                    // For these scenarios, we expect an exception when creating the device link message.
                    Assert.ThrowsException<ArgumentException>(() =>
                    {
                        DeviceLinkingService.CreateDeviceLinkMessage(mainDeviceKeyPair, newDeviceKeyPair.PublicKey);
                    }, $"Scenario {scenarioDescription} should throw an exception due to invalid main device key pair format.");
                }
                else
                {
                    // For valid Ed25519 key pairs, proceed normally.
                    try
                    {
                        // Create device link message.
                        var encryptedMessage = DeviceLinkingService.CreateDeviceLinkMessage(
                            mainDeviceKeyPair,
                            newDeviceKeyPair.PublicKey
                        );

                        // Make sure to convert Ed25519 public key to X25519 for SenderDHKey before processing
                        // This simulates what would happen in the real system where SenderDHKey comes from a network message
                        var mainDeviceX25519Public = Sodium.ConvertEd25519PublicKeyToX25519(mainDeviceKeyPair.PublicKey);
                        encryptedMessage.SenderDHKey = mainDeviceX25519Public;

                        // Process the message.
                        var result = DeviceLinkingService.ProcessDeviceLinkMessage(
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
            var mainDeviceKeyPair = Sodium.GenerateEd25519KeyPair();
            var newDeviceKeyPair = Sodium.GenerateEd25519KeyPair();

            // Create a valid device link message
            var originalMessage = DeviceLinkingService.CreateDeviceLinkMessage(
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

                var result = DeviceLinkingService.ProcessDeviceLinkMessage(
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
                var newDeviceKeyPair = Sodium.GenerateEd25519KeyPair();

                var derivedKey = DeviceLinkingService.DeriveSharedKeyForNewDevice(sharedKey, newDeviceKeyPair.PublicKey);

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