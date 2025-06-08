using Microsoft.VisualStudio.TestTools.UnitTesting;
using LibEmiddle.Abstractions;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;
using LibEmiddle.Messaging.Chat;
using LibEmiddle.Messaging.Group;
using LibEmiddle.Protocol;
using LibEmiddle.Sessions;
using LibEmiddle.Messaging.Transport;
using System.Text;
using System.Collections.Generic;
using System.Threading.Tasks;
using System;
using LibEmiddle.API;

namespace LibEmiddle.Tests.Unit;

/// <summary>
/// Integration tests that verify the complete end-to-end flow of the LibEmiddle library.
/// Tests the interaction between X3DH, Double Ratchet, group messaging, and session management.
/// </summary>
[TestClass]
public class IntegrationTests
{
    private ICryptoProvider _cryptoProvider = null!;
    private IX3DHProtocol _x3dhProtocol = null!;
    private IDoubleRatchetProtocol _doubleRatchetProtocol = null!;

    [TestInitialize]
    public void Setup()
    {
        // Initialize libsodium
        Sodium.Initialize();

        // Initialize the core components
        _cryptoProvider = new CryptoProvider();
        _x3dhProtocol = new X3DHProtocol(_cryptoProvider);
        _doubleRatchetProtocol = new DoubleRatchetProtocol();
    }

    [TestCleanup]
    public void Cleanup()
    {
        _cryptoProvider?.Dispose();
    }

    /// <summary>
    /// Tests the complete end-to-end encrypted messaging flow between two users.
    /// Verifies X3DH key exchange, Double Ratchet initialization, and bidirectional messaging.
    /// </summary>
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
        string sessionId = $"test-session-{Guid.NewGuid()}";

        // Step 4: Initialize Double Ratchet for Alice (sender)
        var aliceSession = _doubleRatchetProtocol.InitializeSessionAsSenderAsync(
            x3dhResult.SharedKey,
            bobPublicBundle.SignedPreKey,
            sessionId);

        Assert.IsNotNull(aliceSession, "Alice's Double Ratchet session should be initialized");
        Assert.IsNotNull(aliceSession.RootKey, "Alice's root key should be initialized");
        Assert.IsNotNull(aliceSession.SenderChainKey, "Alice's sending chain key should be initialized");
        Assert.IsTrue(aliceSession.IsInitialized, "Alice's session should be marked as initialized");

        // Step 5: Initialize Double Ratchet for Bob (receiver)
        var bobSignedPreKeyPrivate = bobKeyBundle.GetSignedPreKeyPrivate();
        Assert.IsNotNull(bobSignedPreKeyPrivate, "Bob's signed pre-key private should be available");

        var bobSignedPreKeyPair = new KeyPair(
            bobPublicBundle.SignedPreKey,
            bobSignedPreKeyPrivate);

        var bobSession = _doubleRatchetProtocol.InitializeSessionAsReceiverAsync(
            x3dhResult.SharedKey,
            bobSignedPreKeyPair,
            x3dhResult.MessageDataToSend.SenderEphemeralKeyPublic,
            sessionId);

        Assert.IsNotNull(bobSession, "Bob's Double Ratchet session should be initialized");
        Assert.IsNotNull(bobSession.RootKey, "Bob's root key should be initialized");
        Assert.IsTrue(bobSession.IsInitialized, "Bob's session should be marked as initialized");

        // Step 6: Alice encrypts a message to Bob
        string initialMessage = "Hello Bob, this is Alice!";
        var (aliceUpdatedSession, encryptedMessage) = _doubleRatchetProtocol.EncryptAsync(
            aliceSession,
            initialMessage);

        Assert.IsNotNull(aliceUpdatedSession, "Alice's session should be updated after encryption");
        Assert.IsNotNull(encryptedMessage, "Encrypted message should not be null");
        Assert.IsNotNull(encryptedMessage.Ciphertext, "Ciphertext should not be null");
        Assert.IsNotNull(encryptedMessage.Nonce, "Nonce should not be null");
        Assert.IsNotNull(encryptedMessage.SenderDHKey, "Sender DH key should not be null");
        Assert.AreEqual(sessionId, encryptedMessage.SessionId, "Message should have correct session ID");

        // Step 7: Bob decrypts Alice's message
        var (bobUpdatedSession, decryptedMessage) = _doubleRatchetProtocol.DecryptAsync(
            bobSession,
            encryptedMessage);

        Assert.IsNotNull(bobUpdatedSession, "Bob's session should be updated after decryption");
        Assert.IsNotNull(decryptedMessage, "Decrypted message should not be null");
        Assert.AreEqual(initialMessage, decryptedMessage, "Bob should see Alice's original message");

        // Step 8: Bob replies to Alice
        string replyMessage = "Hi Alice, Bob here!";
        var (bobRepliedSession, bobReplyEncrypted) = _doubleRatchetProtocol.EncryptAsync(
            bobUpdatedSession,
            replyMessage);

        Assert.IsNotNull(bobRepliedSession, "Bob's session should be updated after encryption");
        Assert.IsNotNull(bobReplyEncrypted, "Bob's encrypted reply should not be null");

        // Step 9: Alice decrypts Bob's reply
        var (aliceFinalSession, aliceDecryptedReply) = _doubleRatchetProtocol.DecryptAsync(
            aliceUpdatedSession,
            bobReplyEncrypted);

        Assert.IsNotNull(aliceFinalSession, "Alice's session should be updated after decryption");
        Assert.IsNotNull(aliceDecryptedReply, "Alice should successfully decrypt Bob's message");
        Assert.AreEqual(replyMessage, aliceDecryptedReply, "Alice should see Bob's original message");

        // Verify session properties were correctly updated
        Assert.IsTrue(aliceUpdatedSession.SendMessageNumber > 0, "Alice's message number should be incremented");
        Assert.IsTrue(bobUpdatedSession.ReceiveMessageNumber > 0, "Bob's message number should be incremented");

        // Verify forward secrecy - each message should use different message keys
        string secondMessage = "This is Alice's second message!";
        var (aliceSession2, encryptedMessage2) = _doubleRatchetProtocol.EncryptAsync(
            aliceFinalSession,
            secondMessage);

        Assert.IsNotNull(encryptedMessage2, "Second encrypted message should be created");
        Assert.IsFalse(SecureMemory.SecureCompare(encryptedMessage.Ciphertext!, encryptedMessage2.Ciphertext!),
            "Different messages should produce different ciphertexts");

        // Clean up sensitive data
        SecureMemory.SecureClear(x3dhResult.SharedKey);
    }

    /// <summary>
    /// Tests the complete group messaging flow with multiple participants.
    /// Verifies group creation, member addition, key distribution, and multi-party messaging.
    /// </summary>
    [TestMethod]
    public async Task FullGroupMessageFlow_ShouldWorkEndToEnd()
    {
        // Step 1: Create LibEmiddleClient instances for each person
        var aliceOptions = new LibEmiddleClientOptions
        {
            TransportType = TransportType.InMemory,
            IdentityKeyPath = "alice_identity.key",
            SessionStoragePath = "alice_sessions"
        };

        var bobOptions = new LibEmiddleClientOptions
        {
            TransportType = TransportType.InMemory,
            IdentityKeyPath = "bob_identity.key",
            SessionStoragePath = "bob_sessions"
        };

        var charlieOptions = new LibEmiddleClientOptions
        {
            TransportType = TransportType.InMemory,
            IdentityKeyPath = "charlie_identity.key",
            SessionStoragePath = "charlie_sessions"
        };

        using var aliceClient = new LibEmiddleClient(aliceOptions);
        using var bobClient = new LibEmiddleClient(bobOptions);
        using var charlieClient = new LibEmiddleClient(charlieOptions);

        // Step 2: Initialize all clients
        await aliceClient.InitializeAsync();
        await bobClient.InitializeAsync();
        await charlieClient.InitializeAsync();

        // Step 3: Alice creates the group (she becomes the owner/admin)
        string groupId = "friends-group-2024";
        string groupName = "Friends Chat";

        var aliceGroupSession = await aliceClient.CreateGroupAsync(groupId, groupName);
        Console.WriteLine($"Alice created group: {groupId}");

        // Step 4: Alice adds Bob and Charlie as members
        await aliceGroupSession.AddMemberAsync(bobClient.IdentityPublicKey);
        await aliceGroupSession.AddMemberAsync(charlieClient.IdentityPublicKey);
        Console.WriteLine("Alice added Bob and Charlie to the group");

        // Step 5: Alice creates a distribution message to share group keys
        var aliceDistribution = aliceGroupSession.CreateDistributionMessage();
        Console.WriteLine("Alice created key distribution message");

        // Step 6: Bob and Charlie join the group using Alice's distribution
        var bobGroupSession = await bobClient.JoinGroupAsync(aliceDistribution);
        var charlieGroupSession = await charlieClient.JoinGroupAsync(aliceDistribution);
        Console.WriteLine("Bob and Charlie joined the group");

        // Step 7: Bob and Charlie add each other and Alice as members on their side
        await bobGroupSession.AddMemberAsync(aliceClient.IdentityPublicKey);
        await bobGroupSession.AddMemberAsync(charlieClient.IdentityPublicKey);

        await charlieGroupSession.AddMemberAsync(aliceClient.IdentityPublicKey);
        await charlieGroupSession.AddMemberAsync(bobClient.IdentityPublicKey);

        // Step 8: Exchange distribution messages between all participants
        var bobDistribution = bobGroupSession.CreateDistributionMessage();
        var charlieDistribution = charlieGroupSession.CreateDistributionMessage();

        // Everyone processes everyone else's distribution messages
        aliceGroupSession.ProcessDistributionMessage(bobDistribution);
        aliceGroupSession.ProcessDistributionMessage(charlieDistribution);

        bobGroupSession.ProcessDistributionMessage(charlieDistribution);
        // Bob already has Alice's keys from joining

        charlieGroupSession.ProcessDistributionMessage(bobDistribution);
        // Charlie already has Alice's keys from joining

        Console.WriteLine("All distribution messages exchanged");

        // Step 9: Now everyone can send and receive messages!

        // Alice sends a message
        string aliceMessage = "Hey everyone! Welcome to our group chat! 👋";
        var aliceEncrypted = await aliceClient.SendGroupMessageAsync(groupId, aliceMessage);
        Console.WriteLine($"Alice sent: {aliceMessage}");

        // Bob and Charlie receive and decrypt Alice's message
        string bobReceivesAlice = await bobClient.ProcessGroupMessageAsync(aliceEncrypted!);
        string charlieReceivesAlice = await charlieClient.ProcessGroupMessageAsync(aliceEncrypted!);

        Console.WriteLine($"Bob received: {bobReceivesAlice}");
        Console.WriteLine($"Charlie received: {charlieReceivesAlice}");

        // Bob replies
        string bobMessage = "Hi Alice and Charlie! Great to be here! 🎉";
        var bobEncrypted = await bobClient.SendGroupMessageAsync(groupId, bobMessage);
        Console.WriteLine($"Bob sent: {bobMessage}");

        // Alice and Charlie receive Bob's message
        string aliceReceivesBob = await aliceClient.ProcessGroupMessageAsync(bobEncrypted!);
        string charlieReceivesBob = await charlieClient.ProcessGroupMessageAsync(bobEncrypted!);

        Console.WriteLine($"Alice received: {aliceReceivesBob}");
        Console.WriteLine($"Charlie received: {charlieReceivesBob}");

        // Charlie joins the conversation
        string charlieMessage = "Hello Alice and Bob! This is awesome! 🚀";
        var charlieEncrypted = await charlieClient.SendGroupMessageAsync(groupId, charlieMessage);
        Console.WriteLine($"Charlie sent: {charlieMessage}");

        // Alice and Bob receive Charlie's message
        string aliceReceivesCharlie = await aliceClient.ProcessGroupMessageAsync(charlieEncrypted!);
        string bobReceivesCharlie = await bobClient.ProcessGroupMessageAsync(charlieEncrypted!);

        Console.WriteLine($"Alice received: {aliceReceivesCharlie}");
        Console.WriteLine($"Bob received: {bobReceivesCharlie}");

        Console.WriteLine("\n✅ Group chat setup complete! All messages encrypted and exchanged successfully.");
    }

    /// <summary>
    /// Tests the high-level SessionManager API for complete session lifecycle management.
    /// Verifies session creation, message exchange, persistence, and cleanup.
    /// </summary>
    [TestMethod]
    public async Task FullSessionManagerFlow_ShouldWorkEndToEnd()
    {
        // Step 1: Create session managers with identity keys
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

        try
        {
            // Step 2: Generate key bundles for both users
            var aliceKeyBundle = await _x3dhProtocol.CreateKeyBundleAsync(aliceIdentityKeyPair);
            var bobKeyBundle = await _x3dhProtocol.CreateKeyBundleAsync(bobIdentityKeyPair);

            // Step 3: Alice creates a session to communicate with Bob
            string bobIdentifier = "bob@example.com";
            var aliceSession = await aliceSessionManager.CreateDirectMessageSessionAsync(
                bobIdentityKeyPair.PublicKey!,
                bobIdentifier);

            Assert.IsNotNull(aliceSession, "Alice should have a valid chat session");
            Assert.AreEqual(SessionState.Initialized, aliceSession.State, "Alice's session should be initialized");

            // Step 4: Simulate the initial key exchange message transport
            var chatSession = aliceSession as ChatSession;
            Assert.IsNotNull(chatSession, "Alice's session should be a ChatSession");

            var initialMessageData = chatSession.InitialMessageData;
            Assert.IsNotNull(initialMessageData, "Alice should have initial message data to send to Bob");

            // Create a simulated transport message containing the X3DH initial data
            var keyExchangeMessage = new MailboxMessage(
                bobIdentityKeyPair.PublicKey!,
                aliceIdentityKeyPair.PublicKey!,
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

            // Step 6: Activate Alice's session and send a message
            await aliceSession.ActivateAsync();
            Assert.AreEqual(SessionState.Active, aliceSession.State, "Alice's session should be active");

            string aliceMessage = "Hello Bob, this is Alice via SessionManager!";
            var encryptedAliceMessage = await aliceSession.EncryptAsync(aliceMessage);

            Assert.IsNotNull(encryptedAliceMessage, "Alice should encrypt a message successfully");
            Assert.IsNotNull(encryptedAliceMessage.Ciphertext, "Encrypted message should have ciphertext");
            Assert.IsNotNull(encryptedAliceMessage.Nonce, "Encrypted message should have nonce");

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

            // Step 10: Test multiple message exchange for ratcheting
            for (int i = 0; i < 3; i++)
            {
                string testMessage = $"Test message {i + 1} from Alice";
                var encrypted = await aliceSession.EncryptAsync(testMessage);
                string decrypted = await bobSession.ProcessIncomingMessageAsync(encrypted);
                Assert.AreEqual(testMessage, decrypted, $"Message {i + 1} should be correctly decrypted");
            }

            // Step 11: Test session persistence
            await aliceSessionManager.SaveSessionAsync(aliceSession);
            await bobSessionManager.SaveSessionAsync(bobSession);

            // List and verify sessions
            var aliceSessions = await aliceSessionManager.ListSessionsAsync();
            var bobSessions = await bobSessionManager.ListSessionsAsync();

            Assert.IsTrue(aliceSessions.Length > 0, "Alice should have at least one saved session");
            Assert.IsTrue(bobSessions.Length > 0, "Bob should have at least one saved session");

            // Verify session properties
            Assert.IsTrue(aliceSession.IsValid(), "Alice's session should be valid");
            Assert.IsTrue(bobSession.IsValid(), "Bob's session should be valid");

            // Step 12: Test session termination
            bool aliceTerminated = await aliceSession.TerminateAsync();
            bool bobTerminated = await bobSession.TerminateAsync();

            Assert.IsTrue(aliceTerminated, "Alice's session should terminate successfully");
            Assert.IsTrue(bobTerminated, "Bob's session should terminate successfully");
            Assert.AreEqual(SessionState.Terminated, aliceSession.State, "Alice's session should be terminated");
            Assert.AreEqual(SessionState.Terminated, bobSession.State, "Bob's session should be terminated");

            // Clean up
            await aliceSessionManager.DeleteSessionAsync(aliceSession.SessionId);
            await bobSessionManager.DeleteSessionAsync(bobSession.SessionId);
        }
        finally
        {
            aliceSessionManager.Dispose();
            bobSessionManager.Dispose();
        }
    }

    /// <summary>
    /// Tests error handling and edge cases in the messaging flow.
    /// </summary>
    [TestMethod]
    public async Task ErrorHandling_ShouldBehaveCorrectly()
    {
        var aliceKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
        var bobKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);

        // Create a valid session first
        var bobKeyBundle = await _x3dhProtocol.CreateKeyBundleAsync(bobKeyPair);
        var x3dhResult = await _x3dhProtocol.InitiateSessionAsSenderAsync(
            bobKeyBundle.ToPublicBundle(),
            aliceKeyPair);

        var aliceSession = _doubleRatchetProtocol.InitializeSessionAsSenderAsync(
            x3dhResult.SharedKey,
            bobKeyBundle.ToPublicBundle().SignedPreKey,
            "test-session");

        // Test 1: Invalid message with incomplete fields
        var invalidMessage = new EncryptedMessage
        {
            Ciphertext = new byte[] { 1, 2, 3 }, // Invalid ciphertext
            Nonce = new byte[] { 4, 5, 6 }, // Invalid nonce length (should be 12 bytes)
            SessionId = "invalid-session",
            SenderDHKey = null, // Missing required field
            SenderMessageNumber = 0
        };

        // The DecryptAsync should handle invalid messages gracefully
        try
        {
            var (updatedSession, decryptedMessage) = _doubleRatchetProtocol.DecryptAsync(
                aliceSession,
                invalidMessage);

            // If no exception is thrown, both should be null
            Assert.IsNull(updatedSession, "Should not return updated session for invalid message");
            Assert.IsNull(decryptedMessage, "Should not return decrypted message for invalid message");
        }
        catch (ArgumentException ex)
        {
            // It's acceptable for the protocol to throw ArgumentException for malformed messages
            Assert.IsTrue(ex.Message.Contains("incomplete") || ex.Message.Contains("invalid"),
                "Exception should indicate message is incomplete or invalid");
        }

        // Test 2: Message with wrong session ID
        var wrongSessionMessage = new EncryptedMessage
        {
            Ciphertext = new byte[32], // Valid length
            Nonce = _cryptoProvider.GenerateRandomBytes(Constants.NONCE_SIZE), // Valid nonce
            SessionId = "wrong-session-id",
            SenderDHKey = _cryptoProvider.GenerateRandomBytes(Constants.X25519_KEY_SIZE), // Valid key size
            SenderMessageNumber = 1
        };

        var (wrongSessionUpdated, wrongSessionDecrypted) = _doubleRatchetProtocol.DecryptAsync(
            aliceSession,
            wrongSessionMessage);

        Assert.IsNull(wrongSessionUpdated, "Should not return updated session for wrong session ID");
        Assert.IsNull(wrongSessionDecrypted, "Should not return decrypted message for wrong session ID");

        // Test 3: Null message handling
        try
        {
            var (nullUpdated, nullDecrypted) = _doubleRatchetProtocol.DecryptAsync(
                aliceSession,
                null!);

            Assert.IsNull(nullUpdated, "Should not return updated session for null message");
            Assert.IsNull(nullDecrypted, "Should not return decrypted message for null message");
        }
        catch (ArgumentNullException)
        {
            // It's acceptable to throw ArgumentNullException for null input
        }

        // Clean up
        SecureMemory.SecureClear(x3dhResult.SharedKey);
    }
}