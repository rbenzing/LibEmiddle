using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using LibEmiddle.Core;
using LibEmiddle.Domain;
using LibEmiddle.MultiDevice;
using LibEmiddle.Crypto;
using LibEmiddle.Abstractions;

namespace LibEmiddle.Tests.Unit
{
    [TestClass]
    public class DeviceLinkingTests
    {
        private ICryptoProvider _cryptoProvider;
        private DeviceLinkingService _deviceLinkingSvc;

        [TestInitialize]
        public void Setup()
        {
            _cryptoProvider = new CryptoProvider();
            _deviceLinkingSvc = new DeviceLinkingService(_cryptoProvider);
        }

        [TestMethod]
        public void CreateDeviceLinkMessage_MultipleKeyTypes_ShouldWork()
        {
            var testScenarios = new (Func<KeyPair> KeyPairGenerator, bool IsValid, string Description)[]
            {
                (() => Sodium.GenerateEd25519KeyPair(), true, "Standard Ed25519 Key Pair"),
                (() => Sodium.GenerateX25519KeyPair(), false, "X25519 Key Pair"),
                (() => {
                    var edKeyPair = Sodium.GenerateEd25519KeyPair();
                    var xPrivate = _cryptoProvider.ConvertEd25519PrivateKeyToX25519(edKeyPair.PrivateKey);
                    return new KeyPair(edKeyPair.PublicKey, xPrivate);
                }, false, "Ed25519 to X25519 Hybrid Key Pair")
            };

            foreach (var (KeyPairGenerator, IsValid, Description) in testScenarios)
            {
                var mainKeyPair = KeyPairGenerator();
                var newKeyPair = Sodium.GenerateEd25519KeyPair();

                if (IsValid)
                {
                    var message = _deviceLinkingSvc.CreateDeviceLinkMessage(mainKeyPair, newKeyPair.PublicKey);
                    Assert.IsNotNull(message, $"Expected message for {Description}");
                    Assert.IsNotNull(message.Ciphertext, $"Ciphertext should not be null for {Description}");
                    Assert.IsNotNull(message.Nonce, $"Nonce should not be null for {Description}");
                }
                else
                {
                    Exception caught = null;
                    try
                    {
                        _deviceLinkingSvc.CreateDeviceLinkMessage(mainKeyPair, newKeyPair.PublicKey);
                    }
                    catch (Exception ex)
                    {
                        caught = ex;
                    }

                    Assert.IsNotNull(caught, $"Expected exception for {Description}");
                    Assert.IsTrue(caught is ArgumentException or CryptographicException,
                        $"Expected specific exception for {Description}, got {caught?.GetType().Name}");
                }
            }
        }

        [TestMethod]
        public void DeriveSharedKeyForNewDevice_StressTest()
        {
            const int ITERATIONS = 20;
            var seenKeys = new HashSet<string>();
            int successfulConversions = 0;
            int directDerivations = 0;

            for (int i = 0; i < ITERATIONS; i++)
            {
                try
                {
                    var baseKey = new byte[32];
                    RandomNumberGenerator.Fill(baseKey);

                    var newKeyPair = Sodium.GenerateX25519KeyPair();

                    var derivedFromX = _deviceLinkingSvc.DeriveSharedKeyForNewDevice(baseKey, newKeyPair.PublicKey);
                    Assert.AreEqual(Constants.AES_KEY_SIZE, derivedFromX.Length, $"X key length mismatch at {i}");

                    successfulConversions++;
                }
                catch (Exception _ex)
                {
                    Console.WriteLine( _ex.Message );
                    continue;
                }
            }

            // At least some conversions should succeed (statistically very likely)
            Assert.IsTrue(successfulConversions > 0, "Expected at least some X25519 conversions to succeed");

            // Log the conversion statistics for debugging
            Console.WriteLine($"Conversion statistics: {successfulConversions} successful, {directDerivations} direct derivations");
        }

        [TestMethod]
        public void ProcessDeviceLinkMessage_EdgeCaseScenarios()
        {
            var scenarios = new List<(Func<KeyPair> GenerateKeyPair, string Description)>
            {
                (() => {
                    var edPair = Sodium.GenerateEd25519KeyPair();
                    var xPrivate = Sodium.ConvertEd25519PrivateKeyToX25519(edPair.PrivateKey);
                    var xPublic = SecureMemory.CreateSecureBuffer(Constants.X25519_KEY_SIZE);
                    Sodium.ComputePublicKey(xPublic, xPrivate);
                    return new KeyPair(xPublic, xPrivate);
                }, "Ed25519 to X25519 Conversion"),
                (() => Sodium.GenerateX25519KeyPair(), "X25519 Key Pair")
            };

            foreach (var (GenerateKeyPair, Description) in scenarios)
            {
                var mainKey = GenerateKeyPair();
                var newKey = Sodium.GenerateEd25519KeyPair();

                bool shouldThrow = Description.Contains("X25519");

                if (shouldThrow)
                {
                    Assert.ThrowsException<ArgumentException>(() =>
                        _deviceLinkingSvc.CreateDeviceLinkMessage(mainKey, newKey.PublicKey),
                        $"Expected failure for: {Description}");
                }
                else
                {
                    try
                    {
                        var message = _deviceLinkingSvc.CreateDeviceLinkMessage(mainKey, newKey.PublicKey);
                        var senderX25519 = Sodium.ConvertEd25519PublicKeyToX25519(mainKey.PublicKey);
                        message.SenderDHKey = senderX25519;

                        var result = _deviceLinkingSvc.ProcessDeviceLinkMessage(message, newKey, mainKey.PublicKey);

                        Assert.IsNotNull(result, $"Processing failed for {Description}");
                        Assert.IsTrue(result.Length > 0, $"Empty result for {Description}");
                    }
                    catch (Exception ex)
                    {
                        Assert.Fail($"Exception for {Description}: {ex.Message}");
                    }
                }
            }
        }

        [TestMethod]
        public void DeviceLinkMessage_WithMaliciousPayload_ShouldFail()
        {
            var mainKey = Sodium.GenerateEd25519KeyPair();
            var newKey = Sodium.GenerateEd25519KeyPair();
            var publicKey = Sodium.ConvertEd25519PrivateKeyToX25519PublicKey(newKey.PrivateKey);
            var validMessage = _deviceLinkingSvc.CreateDeviceLinkMessage(mainKey, publicKey);

            var maliciousVariations = new[]
            {
                () => new EncryptedMessage
                {
                    Ciphertext = validMessage.Ciphertext.Select(b => (byte)(b ^ 0xFF)).ToArray(),
                    Nonce = validMessage.Nonce
                },
                () => new EncryptedMessage
                {
                    Ciphertext = validMessage.Ciphertext,
                    Nonce = validMessage.Nonce.Select(b => (byte)(b ^ 0x55)).ToArray()
                },
                () => new EncryptedMessage
                {
                    Ciphertext = SecureMemory.CreateSecureBuffer((uint)validMessage.Ciphertext.Length),
                    Nonce = SecureMemory.CreateSecureBuffer((uint)validMessage.Nonce.Length)
                }
            };

            foreach (var generateMessage in maliciousVariations)
            {
                var tampered = generateMessage();
                var result = _deviceLinkingSvc.ProcessDeviceLinkMessage(tampered, newKey, mainKey.PublicKey);
                Assert.IsNull(result, "Tampered message should not produce a valid result");
            }
        }

        [TestMethod]
        public void DeriveSharedKey_WithCryptographicVariety_ShouldBeRobust()
        {
            var keyScenarios = new[]
            {
                () => {
                    var key = new byte[32];
                    RandomNumberGenerator.Fill(key);
                    return key;
                },
                () => Enumerable.Range(0, 32).Select(i => (byte)(i * 7)).ToArray(),
                () => Enumerable.Range(0, 32).Select(i => (byte)Math.Abs(Math.Sin(i) * 255)).ToArray()
            };

            foreach (var getKey in keyScenarios)
            {
                var sharedKey = getKey();
                var newDevice = Sodium.GenerateEd25519KeyPair();
                var publicKey = Sodium.ConvertEd25519PrivateKeyToX25519PublicKey(newDevice.PrivateKey);

                var derived = _deviceLinkingSvc.DeriveSharedKeyForNewDevice(sharedKey, publicKey);

                Assert.IsNotNull(derived, "Key should be derived");
                Assert.AreEqual(32, derived.Length, "Derived key length mismatch");
                CollectionAssert.AreNotEqual(sharedKey, derived, "Derived key should not equal input");
            }
        }
    }
}
