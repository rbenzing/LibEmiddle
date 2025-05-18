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

            for (int i = 0; i < ITERATIONS; i++)
            {
                var baseKey = new byte[32];
                RandomNumberGenerator.Fill(baseKey);

                var newKeyPair = Sodium.GenerateEd25519KeyPair();
                var x25519PubKey = Sodium.ConvertEd25519PublicKeyToX25519(newKeyPair.PublicKey);

                var derivedFromEd = _deviceLinkingSvc.DeriveSharedKeyForNewDevice(baseKey, newKeyPair.PublicKey);
                var derivedFromX = _deviceLinkingSvc.DeriveSharedKeyForNewDevice(baseKey, x25519PubKey.ToArray());

                Assert.AreEqual(Constants.AES_KEY_SIZE, derivedFromEd.Length, $"Ed key length mismatch at {i}");
                Assert.AreEqual(Constants.AES_KEY_SIZE, derivedFromX.Length, $"X key length mismatch at {i}");
                Assert.IsFalse(derivedFromEd.SequenceEqual(derivedFromX), $"Derived keys should differ at {i}");

                seenKeys.Add(Convert.ToBase64String(derivedFromEd));
                seenKeys.Add(Convert.ToBase64String(derivedFromX));
            }

            Assert.IsTrue(seenKeys.Count > ITERATIONS * 1.8, "Expected high key uniqueness");
        }

        [TestMethod]
        public void ProcessDeviceLinkMessage_EdgeCaseScenarios()
        {
            var scenarios = new List<(Func<KeyPair> GenerateKeyPair, string Description)>
            {
                (() => Sodium.GenerateEd25519KeyPair(), "Standard Ed25519 Key Generation"),
                (() => {
                    var edPair = Sodium.GenerateEd25519KeyPair();
                    var xPrivate = Sodium.ConvertEd25519PrivateKeyToX25519(edPair.PrivateKey);
                    var xPublic = SecureMemory.CreateSecureBuffer(Constants.X25519_KEY_SIZE);
                    Sodium.ComputePublicKey(xPublic, xPrivate);
                    return new KeyPair(xPublic.ToArray(), xPrivate.ToArray());
                }, "Ed25519 to X25519 Conversion"),
                (() => {
                    var seed = new byte[32]; // All zeros
                    return Sodium.GenerateEd25519KeyPairFromSeed(seed);
                }, "Minimal Entropy Keys"),
                (() => {
                    var seed = Enumerable.Range(0, 32).Select(i => (byte)(i * 17)).ToArray();
                    return Sodium.GenerateEd25519KeyPairFromSeed(seed);
                }, "Maximum Entropy Keys"),
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
                        message.SenderDHKey = senderX25519.ToArray();

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
            var validMessage = _deviceLinkingSvc.CreateDeviceLinkMessage(mainKey, newKey.PublicKey);

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

                var derived = _deviceLinkingSvc.DeriveSharedKeyForNewDevice(sharedKey, newDevice.PublicKey);

                Assert.IsNotNull(derived, "Key should be derived");
                Assert.AreEqual(32, derived.Length, "Derived key length mismatch");
                CollectionAssert.AreNotEqual(sharedKey, derived, "Derived key should not equal input");
            }
        }
    }
}
