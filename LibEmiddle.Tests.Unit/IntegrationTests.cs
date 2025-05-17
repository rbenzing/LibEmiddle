using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using LibEmiddle.API;
using LibEmiddle.Abstractions;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;
using LibEmiddle.Messaging.Chat;
using LibEmiddle.Messaging.Group;
using LibEmiddle.Protocol;
using LibEmiddle.Sessions;
using System;

namespace LibEmiddle.Tests.Unit
{
    [TestClass]
    public class IntegrationTests
    {
        private ICryptoProvider _cryptoProvider;
        private IX3DHProtocol _x3dhProtocol;
        private IDoubleRatchetProtocol _doubleRatchetProtocol;

        [TestInitialize]
        public void Setup()
        {
            // Initialize the core components
            _cryptoProvider = new CryptoProvider();
            _x3dhProtocol = new X3DHProtocol(_cryptoProvider);
            _doubleRatchetProtocol = new DoubleRatchetProtocol(_cryptoProvider);
        }

        [TestMethod]
        public async Task FullE2EEFlow_ShouldWorkEndToEnd()
        {
            // Step 1: Generate identity keys for Alice and Bob
            var aliceIdentityKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var bobIdentityKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);

            // Step 2: Create Bob's key bundle with the proper identity key
            var bobKeyBundle = await _x3dhProtocol.CreateKeyBundleAsync(bobIdentityKeyPair);
            var bobPublicBundle = bobKeyBundle.ToPublicBundle();

            // Step 3: Perform X3DH key exchange (Alice initiating with Bob)
            var x3dhResult = await _x3dhProtocol.InitiateSessionAsSenderAsync(
                bobPublicBundle,
                aliceIdentityKeyPair);

            Assert.IsNotNull(x3dhResult, "X3DH exchange should produce a result");
            Assert.IsNotNull(x3dhResult.SharedKey, "X3DH exchange should produce a shared key");
            Assert.IsNotNull(x3dhResult.MessageDataToSend, "X3DH exchange should produce initial message data");

            // Create a unique session ID
            string sessionId = $"test-session-{System.Guid.NewGuid()}";

            // Step 4: Initialize Double Ratchet for Alice (sender)
            var aliceSession = await _doubleRatchetProtocol.InitializeSessionAsSenderAsync(
                x3dhResult.SharedKey,
                bobPublicBundle.SignedPreKey,
                sessionId);

            Assert.IsNotNull(aliceSession, "Alice's Double Ratchet session should be initialized");
            Assert.IsNotNull(aliceSession.RootKey, "Alice's root key should be initialized");
            Assert.IsNotNull(aliceSession.SenderChainKey, "Alice's sending chain key should be initialized");

            // Step 5: Initialize Double Ratchet for Bob (receiver)
            var bobSignedPreKeyPair = new KeyPair(
                bobPublicBundle.SignedPreKey,
                bobKeyBundle.GetSignedPreKeyPrivate()
            );

            var bobSession = await _doubleRatchetProtocol.InitializeSessionAsReceiverAsync(
                x3dhResult.SharedKey,
                bobSignedPreKeyPair,
                x3dhResult.MessageDataToSend.SenderEphemeralKeyPublic,
                sessionId);

            Assert.IsNotNull(bobSession, "Bob's Double Ratchet session should be initialized");
            Assert.IsNotNull(bobSession.RootKey, "Bob's root key should be initialized");

            // Step 6: Alice encrypts a message to Bob
            string initialMessage = "Hello Bob, this is Alice!";
            var (aliceUpdatedSession, encryptedMessage) = await _doubleRatchetProtocol.EncryptAsync(
                aliceSession,
                initialMessage);

            Assert.IsNotNull(aliceUpdatedSession, "Alice's session should be updated after encryption");
            Assert.IsNotNull(encryptedMessage, "Encrypted message should not be null");
            Assert.IsNotNull(encryptedMessage.Ciphertext, "Ciphertext should not be null");
            Assert.IsNotNull(encryptedMessage.Nonce, "Nonce should not be null");
            Assert.IsNotNull(encryptedMessage.SenderDHKey, "Sender DH key should not be null");

            // Step 7: Bob decrypts Alice's message
            var (bobUpdatedSession, decryptedMessage) = await _doubleRatchetProtocol.DecryptAsync(
                bobSession,
                encryptedMessage);

            Assert.IsNotNull(bobUpdatedSession, "Bob's session should be updated after decryption");
            Assert.IsNotNull(decryptedMessage, "Decrypted message should not be null");
            Assert.AreEqual(initialMessage, decryptedMessage, "Bob should see Alice's original message");

            // Step 8: Bob replies to Alice
            string replyMessage = "Hi Alice, Bob here!";
            var (bobRepliedSession, bobReplyEncrypted) = await _doubleRatchetProtocol.EncryptAsync(
                bobUpdatedSession,
                replyMessage);

            Assert.IsNotNull(bobRepliedSession, "Bob's session should be updated after encryption");
            Assert.IsNotNull(bobReplyEncrypted, "Bob's encrypted reply should not be null");

            // Step 9: Alice decrypts Bob's reply
            var (aliceFinalSession, aliceDecryptedReply) = await _doubleRatchetProtocol.DecryptAsync(
                aliceUpdatedSession,
                bobReplyEncrypted);

            Assert.IsNotNull(aliceFinalSession, "Alice's session should be updated after decryption");
            Assert.IsNotNull(aliceDecryptedReply, "Alice should successfully decrypt Bob's message");
            Assert.AreEqual(replyMessage, aliceDecryptedReply, "Alice should see Bob's original message");

            // Verify session properties were correctly updated
            Assert.AreEqual(1, aliceUpdatedSession.SendMessageNumber, "Alice's message number should be incremented");
            Assert.AreEqual(1, bobUpdatedSession.ReceiveMessageNumber, "Bob's message number should be incremented");
        }

        [TestMethod]
        public async Task FullGroupMessageFlow_ShouldWorkEndToEnd()
        {
            // Step 1: Generate identity keys for the participants
            var aliceKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var bobKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var charlieKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);

            // Step 2: Create group chat managers for each participant
            var aliceGroupChatManager = new GroupChatManager(_cryptoProvider, aliceKeyPair);
            var bobGroupChatManager = new GroupChatManager(_cryptoProvider, bobKeyPair);
            var charlieGroupChatManager = new GroupChatManager(_cryptoProvider, charlieKeyPair);

            // Step 3: Create a group
            string groupId = "test-group-" + System.Guid.NewGuid().ToString("N");
            string groupName = "Test Group";

            // Alice creates the group
            var aliceGroupSession = await aliceGroupChatManager.CreateGroupAsync(
                groupId,
                groupName,
                new List<byte[]> { bobKeyPair.PublicKey, charlieKeyPair.PublicKey });

            Assert.IsNotNull(aliceGroupSession, "Alice should have a valid group session");

            // Bob and Charlie join the group
            var bobGroupSession = await bobGroupChatManager.JoinGroupAsync(
                aliceGroupSession.CreateDistributionMessage());

            var charlieGroupSession = await charlieGroupChatManager.JoinGroupAsync(
                aliceGroupSession.CreateDistributionMessage());

            Assert.IsNotNull(bobGroupSession, "Bob should have a valid group session");
            Assert.IsNotNull(charlieGroupSession, "Charlie should have a valid group session");

            // Bob and Charlie need to share their distribution messages too
            var bobDistribution = bobGroupSession.CreateDistributionMessage();
            var charlieDistribution = charlieGroupSession.CreateDistributionMessage();

            // Everyone processes everyone else's distribution messages
            bool aliceProcessBobResult = bobGroupSession.ProcessDistributionMessage(bobDistribution);
            bool aliceProcessCharlieResult = charlieGroupSession.ProcessDistributionMessage(charlieDistribution);
            bool bobProcessCharlieResult = charlieGroupSession.ProcessDistributionMessage(charlieDistribution);
            bool charlieProcessBobResult = bobGroupSession.ProcessDistributionMessage(bobDistribution);

            Assert.IsTrue(aliceProcessBobResult, "Alice should process Bob's distribution message");
            Assert.IsTrue(aliceProcessCharlieResult, "Alice should process Charlie's distribution message");
            Assert.IsTrue(bobProcessCharlieResult, "Bob should process Charlie's distribution message");
            Assert.IsTrue(charlieProcessBobResult, "Charlie should process Bob's distribution message");

            // Step 4: Alice sends a message to the group
            string aliceMessage = "Hello everyone, this is Alice!";
            var aliceEncryptedMessage = await aliceGroupSession.EncryptMessageAsync(aliceMessage);

            Assert.IsNotNull(aliceEncryptedMessage, "Alice should encrypt a message successfully");

            // Bob and Charlie decrypt Alice's message
            string bobDecryptedAliceMessage = await bobGroupSession.DecryptMessageAsync(aliceEncryptedMessage);
            string charlieDecryptedAliceMessage = await charlieGroupSession.DecryptMessageAsync(aliceEncryptedMessage);

            Assert.AreEqual(aliceMessage, bobDecryptedAliceMessage, "Bob should decrypt Alice's message correctly");
            Assert.AreEqual(aliceMessage, charlieDecryptedAliceMessage, "Charlie should decrypt Alice's message correctly");

            // Step 5: Bob replies to the group
            string bobMessage = "Hi Alice and Charlie, Bob here!";
            var bobEncryptedMessage = await bobGroupSession.EncryptMessageAsync(bobMessage);

            Assert.IsNotNull(bobEncryptedMessage, "Bob should encrypt a message successfully");

            // Alice and Charlie decrypt Bob's message
            string aliceDecryptedBobMessage = await aliceGroupSession.DecryptMessageAsync(bobEncryptedMessage);
            string charlieDecryptedBobMessage = await charlieGroupSession.DecryptMessageAsync(bobEncryptedMessage);

            Assert.AreEqual(bobMessage, aliceDecryptedBobMessage, "Alice should decrypt Bob's message correctly");
            Assert.AreEqual(bobMessage, charlieDecryptedBobMessage, "Charlie should decrypt Bob's message correctly");

            // Step 6: Test a more complete messaging flow with Charlie
            string charlieMessage = "Hey everyone, Charlie joining the conversation!";
            var charlieEncryptedMessage = await charlieGroupSession.EncryptMessageAsync(charlieMessage);

            string aliceDecryptedCharlieMessage = await aliceGroupSession.DecryptMessageAsync(charlieEncryptedMessage);
            string bobDecryptedCharlieMessage = await bobGroupSession.DecryptMessageAsync(charlieEncryptedMessage);

            Assert.AreEqual(charlieMessage, aliceDecryptedCharlieMessage, "Alice should decrypt Charlie's message correctly");
            Assert.AreEqual(charlieMessage, bobDecryptedCharlieMessage, "Bob should decrypt Charlie's message correctly");
        }

        [TestMethod]
        public async Task FullSessionManagerFlow_ShouldWorkEndToEnd()
        {
            // This test demonstrates the high-level SessionManager API for end-to-end messaging

            // Step 1: Create session manager for each user with their identity keys
            var aliceIdentityKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var bobIdentityKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);

            var aliceSessionManager = new SessionManager(
                _cryptoProvider,
                _x3dhProtocol,
                _doubleRatchetProtocol,
                aliceIdentityKeyPair);

            var bobSessionManager = new SessionManager(
                _cryptoProvider,
                _x3dhProtocol,
                _doubleRatchetProtocol,
                bobIdentityKeyPair);

            // Step 2: Generate key bundles for both users
            var aliceKeyBundle = await _x3dhProtocol.CreateKeyBundleAsync(aliceIdentityKeyPair);
            var bobKeyBundle = await _x3dhProtocol.CreateKeyBundleAsync(bobIdentityKeyPair);

            // Step 3: Alice initiates a chat with Bob
            // In a real app, Alice would have fetched Bob's bundle from a server
            var aliceSession = await aliceSessionManager.CreateDirectMessageSessionAsync(
                bobIdentityKeyPair.PublicKey,
                "bob@example.com");

            Assert.IsNotNull(aliceSession, "Alice should have a valid chat session");
            Assert.AreEqual(SessionState.Active, aliceSession.State, "Alice's session should be active");

            // Step 4: Create a message exchange simulation
            // In a real app, this would go through a transport layer

            // Create a mock mailbox message from Alice's initial message data
            var initialMessageData = ((ChatSession)aliceSession).InitialMessageData;
            Assert.IsNotNull(initialMessageData, "Alice should have initial message data to send to Bob");

            var keyExchangeMessage = new MailboxMessage(
                bobIdentityKeyPair.PublicKey,
                aliceIdentityKeyPair.PublicKey,
                new EncryptedMessage())
            {
                Type = MessageType.KeyExchange,
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                Metadata = new Dictionary<string, string>
                {
                    ["SenderIdentityKey"] = Convert.ToBase64String(initialMessageData.SenderIdentityKeyPublic),
                    ["SenderEphemeralKey"] = Convert.ToBase64String(initialMessageData.SenderEphemeralKeyPublic),
                    ["SignedPreKeyId"] = initialMessageData.RecipientSignedPreKeyId.ToString()
                }
            };

            if (initialMessageData.RecipientOneTimePreKeyId.HasValue)
            {
                keyExchangeMessage.Metadata["OneTimePreKeyId"] = initialMessageData.RecipientOneTimePreKeyId.Value.ToString();
            }

            // Step 5: Bob processes the key exchange and establishes a session
            var bobSession = await bobSessionManager.ProcessKeyExchangeMessageAsync(
                keyExchangeMessage,
                bobKeyBundle);

            Assert.IsNotNull(bobSession, "Bob should establish a session from Alice's key exchange");
            Assert.AreEqual(SessionState.Active, bobSession.State, "Bob's session should be active");

            // Step 6: Alice sends a message to Bob
            string aliceMessage = "Hello Bob, this is Alice via SessionManager!";
            var encryptedAliceMessage = await aliceSession.EncryptAsync(aliceMessage);

            Assert.IsNotNull(encryptedAliceMessage, "Alice should encrypt a message successfully");

            // Step 7: Bob receives and decrypts Alice's message
            string bobDecryptedMessage = await bobSession.ProcessIncomingMessageAsync(encryptedAliceMessage);

            Assert.AreEqual(aliceMessage, bobDecryptedMessage, "Bob should decrypt Alice's message correctly");

            // Step 8: Bob replies to Alice
            string bobMessage = "Hello Alice, got your message through SessionManager!";
            var encryptedBobMessage = await bobSession.EncryptAsync(bobMessage);

            Assert.IsNotNull(encryptedBobMessage, "Bob should encrypt a message successfully");

            // Step 9: Alice receives and decrypts Bob's message
            string aliceDecryptedMessage = await aliceSession.ProcessIncomingMessageAsync(encryptedBobMessage);

            Assert.AreEqual(bobMessage, aliceDecryptedMessage, "Alice should decrypt Bob's message correctly");

            // Step 10: Persistence test - save and load sessions
            await aliceSessionManager.SaveSessionAsync(aliceSession);
            await bobSessionManager.SaveSessionAsync(bobSession);

            // List and verify sessions
            var aliceSessions = await aliceSessionManager.ListSessionsAsync();
            var bobSessions = await bobSessionManager.ListSessionsAsync();

            Assert.IsTrue(aliceSessions.Length > 0, "Alice should have at least one saved session");
            Assert.IsTrue(bobSessions.Length > 0, "Bob should have at least one saved session");

            // Clean up
            await aliceSessionManager.DeleteSessionAsync(aliceSession.SessionId);
            await bobSessionManager.DeleteSessionAsync(bobSession.SessionId);

            aliceSessionManager.Dispose();
            bobSessionManager.Dispose();
        }
    }
}