using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Text;
using System.Security.Cryptography;
using System.Threading.Tasks;
using LibEmiddle.API;
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

        [TestInitialize]
        public void Setup()
        {
            _cryptoProvider = new CryptoProvider();
            _x3dhProtocol = new X3DHProtocol(_cryptoProvider);
            _doubleRatchetProtocol = new DoubleRatchetProtocol();
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
            var smallEncrypted = LibEmiddleClient.EncryptMessage(smallMessage, key);
            stopwatch.Stop();
            long smallEncryptTime = stopwatch.ElapsedMilliseconds;

            // Medium message
            stopwatch.Restart();
            var mediumEncrypted = LibEmiddleClient.EncryptMessage(mediumMessage, key);
            stopwatch.Stop();
            long mediumEncryptTime = stopwatch.ElapsedMilliseconds;

            // Large message
            stopwatch.Restart();
            var largeEncrypted = LibEmiddleClient.EncryptMessage(largeMessage, key);
            stopwatch.Stop();
            long largeEncryptTime = stopwatch.ElapsedMilliseconds;

            // Measure decryption time
            // Small message
            stopwatch.Restart();
            string smallDecrypted = LibEmiddleClient.DecryptMessage(smallEncrypted, key);
            stopwatch.Stop();
            long smallDecryptTime = stopwatch.ElapsedMilliseconds;

            // Medium message
            stopwatch.Restart();
            string mediumDecrypted = LibEmiddleClient.DecryptMessage(mediumEncrypted, key);
            stopwatch.Stop();
            long mediumDecryptTime = stopwatch.ElapsedMilliseconds;

            // Large message
            stopwatch.Restart();
            string largeDecrypted = LibEmiddleClient.DecryptMessage(largeEncrypted, key);
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
        public void Performance_GroupMessageEncryptionTest()
        {
            // Arrange
            var aliceKeyPair = Sodium.GenerateEd25519KeyPair();
            var groupChatManager = new GroupChatManager(aliceKeyPair);
            string groupId = "performance-test-group";
            string groupName = "Performance Test Group";
            groupChatManager.CreateGroupAsync(groupId, groupName).GetAwaiter().GetResult();

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
                var encryptedMessage = groupChatManager.SendMessageAsync(groupId, message).GetAwaiter().GetResult();
            }

            stopwatch.Stop();
            double avgEncryptionTime = stopwatch.ElapsedMilliseconds / 10.0;

            // Assert
            Assert.IsTrue(avgEncryptionTime < 200,
                $"Group message encryption took an average of {avgEncryptionTime}ms per message");
        }

        [TestMethod]
        public async Task Performance_DoubleRatchetMessageExchangeTest()
        {
            // Arrange - Set up X3DH and Double Ratchet sessions
            // 1. Generate identity key pairs for Alice and Bob
            var aliceIdentityKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var bobIdentityKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);

            // 2. Create Bob's key bundle (recipient)
            var bobKeyBundle = await _x3dhProtocol.CreateKeyBundleAsync(bobIdentityKeyPair, numOneTimeKeys: 1);

            // 3. Alice initiates session with Bob's bundle (Alice is the sender)
            string sessionId = $"test-session-{Guid.NewGuid():N}";
            var x3dhResult = await _x3dhProtocol.InitiateSessionAsSenderAsync(bobKeyBundle.ToPublicBundle(), aliceIdentityKeyPair);

            // 4. Initialize Alice's Double Ratchet session with the shared key from X3DH
            var aliceSession = _doubleRatchetProtocol.InitializeSessionAsSenderAsync(
                x3dhResult.SharedKey,
                bobKeyBundle.SignedPreKey,
                sessionId);

            // 5. Bob processes the initial message and establishes his session
            var bobSharedKey = await _x3dhProtocol.EstablishSessionAsReceiverAsync(
                x3dhResult.MessageDataToSend,
                bobKeyBundle);

            // 6. Create a signed prekey pair for Bob's Double Ratchet initialization
            var bobSignedPreKeyPair = new KeyPair
            {
                PublicKey = bobKeyBundle.SignedPreKey,
                PrivateKey = bobKeyBundle.GetSignedPreKeyPrivate()
            };

            // 7. Initialize Bob's Double Ratchet session
            var bobSession = _doubleRatchetProtocol.InitializeSessionAsReceiverAsync(
                bobSharedKey,
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