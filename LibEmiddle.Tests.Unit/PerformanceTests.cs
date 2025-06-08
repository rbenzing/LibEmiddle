using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Text;
using System.Security.Cryptography;
using System.Threading.Tasks;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;
using LibEmiddle.Messaging.Group;
using LibEmiddle.Protocol;

namespace LibEmiddle.Tests.Unit
{
    [TestClass]
    public class PerformanceTests
    {
        private CryptoProvider _cryptoProvider;
        private X3DHProtocol _x3dhProtocol;
        private DoubleRatchetProtocol _doubleRatchetProtocol;
        private ProtocolAdapter _protocolAdapter;

        [TestInitialize]
        public void Setup()
        {
            _cryptoProvider = new CryptoProvider();
            _x3dhProtocol = new X3DHProtocol(_cryptoProvider);
            _doubleRatchetProtocol = new DoubleRatchetProtocol();
            _protocolAdapter = new ProtocolAdapter(_x3dhProtocol, _doubleRatchetProtocol, _cryptoProvider);
        }

        [TestMethod]
        public void Performance_EncryptionAndDecryptionSpeedTest()
        {
            // Arrange
            byte[] key = new byte[32];
            RandomNumberGenerator.Fill(key);

            // Create messages of different sizes
            string smallMessage = "Small message for testing";

            StringBuilder mediumMessageBuilder = new(10 * 1024);
            for (int i = 0; i < 500; i++)
            {
                mediumMessageBuilder.Append("Medium sized message for performance testing. ");
            }
            string mediumMessage = mediumMessageBuilder.ToString();

            StringBuilder largeMessageBuilder = new(100 * 1024);
            for (int i = 0; i < 5000; i++)
            {
                largeMessageBuilder.Append("Large message for comprehensive performance testing across different message sizes. ");
            }
            string largeMessage = largeMessageBuilder.ToString();

            // Act - Measure encryption time
            System.Diagnostics.Stopwatch stopwatch = new System.Diagnostics.Stopwatch();

            // Small message
            stopwatch.Restart();
            byte[] smallPlaintext = System.Text.Encoding.UTF8.GetBytes(smallMessage);
            byte[] smallNonce = _cryptoProvider.GenerateRandomBytes(Constants.NONCE_SIZE);
            var smallEncrypted = _cryptoProvider.Encrypt(smallPlaintext, key, smallNonce, null);
            stopwatch.Stop();
            long smallEncryptTime = stopwatch.ElapsedMilliseconds;

            // Medium message
            stopwatch.Restart();
            byte[] mediumPlaintext = System.Text.Encoding.UTF8.GetBytes(mediumMessage);
            byte[] mediumNonce = _cryptoProvider.GenerateRandomBytes(Constants.NONCE_SIZE);
            var mediumEncrypted = _cryptoProvider.Encrypt(mediumPlaintext, key, mediumNonce, null);
            stopwatch.Stop();
            long mediumEncryptTime = stopwatch.ElapsedMilliseconds;

            // Large message
            stopwatch.Restart();
            byte[] largePlaintext = System.Text.Encoding.UTF8.GetBytes(largeMessage);
            byte[] largeNonce = _cryptoProvider.GenerateRandomBytes(Constants.NONCE_SIZE);
            var largeEncrypted = _cryptoProvider.Encrypt(largePlaintext, key, largeNonce, null);
            stopwatch.Stop();
            long largeEncryptTime = stopwatch.ElapsedMilliseconds;

            // Measure decryption time
            // Small message
            stopwatch.Restart();
            byte[] smallDecryptedBytes = _cryptoProvider.Decrypt(smallEncrypted, key, smallNonce, null);
            string smallDecrypted = System.Text.Encoding.UTF8.GetString(smallDecryptedBytes);
            stopwatch.Stop();
            long smallDecryptTime = stopwatch.ElapsedMilliseconds;

            // Medium message
            stopwatch.Restart();
            byte[] mediumDecryptedBytes = _cryptoProvider.Decrypt(mediumEncrypted, key, mediumNonce, null);
            string mediumDecrypted = System.Text.Encoding.UTF8.GetString(mediumDecryptedBytes);
            stopwatch.Stop();
            long mediumDecryptTime = stopwatch.ElapsedMilliseconds;

            // Large message
            stopwatch.Restart();
            byte[] largeDecryptedBytes = _cryptoProvider.Decrypt(largeEncrypted, key, largeNonce, null);
            string largeDecrypted = System.Text.Encoding.UTF8.GetString(largeDecryptedBytes);
            stopwatch.Stop();
            long largeDecryptTime = stopwatch.ElapsedMilliseconds;

            // Assert
            // Verify correctness
            Assert.AreEqual(smallMessage, smallDecrypted);
            Assert.AreEqual(mediumMessage, mediumDecrypted);
            Assert.AreEqual(largeMessage, largeDecrypted);

            // Check that performance is reasonable - these thresholds should be adjusted based on your system
            // Small messages should encrypt/decrypt quickly, but we're just checking for gross performance issues
            Assert.IsTrue(smallEncryptTime < 100, $"Small message encryption took {smallEncryptTime}ms");
            Assert.IsTrue(smallDecryptTime < 100, $"Small message decryption took {smallDecryptTime}ms");

            // Medium messages should be reasonably fast
            Assert.IsTrue(mediumEncryptTime < 500, $"Medium message encryption took {mediumEncryptTime}ms");
            Assert.IsTrue(mediumDecryptTime < 500, $"Medium message decryption took {mediumDecryptTime}ms");

            // Verify that performance scales roughly linearly with message size (with some margin)
            double smallToMediumRatio = (double)mediumMessage.Length / smallMessage.Length;
            double encryptTimeRatio = (double)mediumEncryptTime / (smallEncryptTime > 0 ? smallEncryptTime : 1);

            // Allow for some overhead, but if encryption time grows much faster than message size, there may be an issue
            Assert.IsTrue(encryptTimeRatio < smallToMediumRatio * 2,
                $"Encryption time doesn't scale linearly with message size. Message size ratio: {smallToMediumRatio}, time ratio: {encryptTimeRatio}");
        }

        [TestMethod]
        public void Performance_KeyGenerationSpeedTest()
        {
            // Arrange
            System.Diagnostics.Stopwatch stopwatch = new System.Diagnostics.Stopwatch();
            const int iterations = 100;

            // Act - Measure Ed25519 key generation
            stopwatch.Start();
            for (int i = 0; i < iterations; i++)
            {
                var keyPair = Sodium.GenerateEd25519KeyPair();
            }
            stopwatch.Stop();

            double avgEd25519Time = (double)stopwatch.ElapsedMilliseconds / iterations;

            // Measure X25519 key generation
            stopwatch.Restart();
            for (int i = 0; i < iterations; i++)
            {
                var keyPair = Sodium.GenerateX25519KeyPair();
            }
            stopwatch.Stop();

            double avgX25519Time = (double)stopwatch.ElapsedMilliseconds / iterations;

            // Assert - Just verifying performance is in a reasonable range
            Assert.IsTrue(avgEd25519Time < 50, $"Ed25519 key generation took average {avgEd25519Time}ms per key");
            Assert.IsTrue(avgX25519Time < 50, $"X25519 key generation took average {avgX25519Time}ms per key");
        }

        [TestMethod]
        public async Task Performance_GroupMessageEncryptionTest()
        {
            // Arrange
            var aliceKeyPair = Sodium.GenerateEd25519KeyPair();
            string groupId = "performance-test-group";
            string groupName = "Performance Test Group";
            var groupSession = new GroupSession(groupId, groupName, aliceKeyPair);
            await groupSession.ActivateAsync();

            // Create a message of moderate size
            StringBuilder messageBuilder = new(50 * 1024);
            for (int i = 0; i < 1000; i++)
            {
                messageBuilder.Append("Group message performance test with moderate sized content. ");
            }
            string message = messageBuilder.ToString();

            // Act
            System.Diagnostics.Stopwatch stopwatch = new System.Diagnostics.Stopwatch();
            stopwatch.Start();

            // Measure time to encrypt 10 messages
            for (int i = 0; i < 10; i++)
            {
                var encryptedMessage = await groupSession.EncryptMessageAsync(message);
            }

            stopwatch.Stop();
            double avgEncryptionTime = stopwatch.ElapsedMilliseconds / 10.0;

            // Assert
            Assert.IsTrue(avgEncryptionTime < 200,
                $"Group message encryption took an average of {avgEncryptionTime}ms per message");

            groupSession.Dispose();
        }

        [TestMethod]
        public async Task Performance_DoubleRatchetMessageExchangeTest()
        {
            // Arrange - Set up X3DH and Double Ratchet sessions using the working pattern from IntegrationTests
            // 1. Generate identity key pairs for Alice and Bob
            var aliceIdentityKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var bobIdentityKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);

            // 2. Create Bob's key bundle (recipient)
            var bobKeyBundle = await _x3dhProtocol.CreateKeyBundleAsync(bobIdentityKeyPair, numOneTimeKeys: 1);
            var bobPublicBundle = bobKeyBundle.ToPublicBundle();

            // 3. Perform X3DH key exchange (Alice initiating with Bob) - same as IntegrationTests
            var x3dhResult = await _x3dhProtocol.InitiateSessionAsSenderAsync(
                bobPublicBundle,
                aliceIdentityKeyPair);

            // Create a unique session ID
            string sessionId = $"test-session-{Guid.NewGuid():N}";

            // 4. Initialize Double Ratchet for Alice (sender) - same as IntegrationTests
            var aliceSession = _doubleRatchetProtocol.InitializeSessionAsSender(
                x3dhResult.SharedKey,
                bobPublicBundle.SignedPreKey,
                sessionId);

            // 5. Initialize Double Ratchet for Bob (receiver) - same as IntegrationTests
            var bobSignedPreKeyPrivate = bobKeyBundle.GetSignedPreKeyPrivate();
            var bobSignedPreKeyPair = new KeyPair(
                bobPublicBundle.SignedPreKey,
                bobSignedPreKeyPrivate);

            var bobSession = _doubleRatchetProtocol.InitializeSessionAsReceiver(
                x3dhResult.SharedKey,
                bobSignedPreKeyPair,
                x3dhResult.MessageDataToSend.SenderEphemeralKeyPublic,
                sessionId);

            // Create a test message
            string message = "Performance test message for Double Ratchet";

            // Act - Measure performance of 50 message exchanges
            System.Diagnostics.Stopwatch stopwatch = new System.Diagnostics.Stopwatch();
            stopwatch.Start();

            var currentAliceSession = aliceSession;
            var currentBobSession = bobSession;

            for (int i = 0; i < 50; i++)
            {
                // Alice to Bob
                (DoubleRatchetSession aliceUpdatedSession, EncryptedMessage encryptedMessage) =
                    _doubleRatchetProtocol.EncryptAsync(currentAliceSession, message);

                // Bob decrypts Alice's message
                (DoubleRatchetSession bobUpdatedSession, string decryptedMessage) =
                    _doubleRatchetProtocol.DecryptAsync(currentBobSession, encryptedMessage);

                // Ensure everything worked correctly
                Assert.IsNotNull(aliceUpdatedSession, $"Alice's updated session should not be null at iteration {i}");
                Assert.IsNotNull(bobUpdatedSession, $"Bob's updated session should not be null at iteration {i}");
                Assert.IsNotNull(decryptedMessage, $"Decrypted message should not be null at iteration {i}");
                Assert.AreEqual(message, decryptedMessage, $"Decrypted message should match original at iteration {i}");

                // Update sessions for next iteration
                currentAliceSession = aliceUpdatedSession;
                currentBobSession = bobUpdatedSession;
            }

            stopwatch.Stop();
            double avgMessageExchangeTime = stopwatch.ElapsedMilliseconds / 50.0;

            // Assert
            Assert.IsTrue(avgMessageExchangeTime < 20,
                $"Double Ratchet message exchange took an average of {avgMessageExchangeTime}ms per exchange");
        }
    }
}