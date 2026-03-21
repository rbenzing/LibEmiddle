using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.Messaging.Chat;
using LibEmiddle.Protocol;
using LibEmiddle.Sessions;

namespace LibEmiddle.Tests.Unit
{
    /// <summary>
    /// Tests for STORY-002: SenderIdentityKey field on EncryptedMessage and O(1) session routing.
    /// Covers:
    ///   - SenderIdentityKey property on EncryptedMessage (nullable, backwards compatible)
    ///   - Clone() preserves SenderIdentityKey
    ///   - ToDictionary() / FromDictionary() round-trip with SenderIdentityKey
    ///   - ToJson() / FromJson() round-trip with SenderIdentityKey
    ///   - GetEstimatedSize() accounts for SenderIdentityKey
    ///   - ChatSession.EncryptAsync() populates SenderIdentityKey with LocalPublicKey
    ///   - SessionManager sender-key index: TryGetSessionIdBySenderKey
    ///   - Index is populated on session create and cleared on session delete
    ///   - Performance: routing 100 messages to correct session is fast (O(1) path)
    /// </summary>
    [TestClass]
    public class SenderIdentityKeyRoutingTests
    {
        private CryptoProvider _cryptoProvider = null!;
        private DoubleRatchetProtocol _doubleRatchetProtocol = null!;
        private X3DHProtocol _x3DHProtocol = null!;
        private ProtocolAdapter _protocolAdapter = null!;

        [TestInitialize]
        public void Setup()
        {
            _cryptoProvider = new CryptoProvider();
            _doubleRatchetProtocol = new DoubleRatchetProtocol();
            _x3DHProtocol = new X3DHProtocol(_cryptoProvider);
            _protocolAdapter = new ProtocolAdapter(_x3DHProtocol, _doubleRatchetProtocol, _cryptoProvider);
        }

        [TestCleanup]
        public void Cleanup()
        {
            _cryptoProvider?.Dispose();
        }

        // -------------------------------------------------------------------------
        // EncryptedMessage property and serialization tests
        // -------------------------------------------------------------------------

        [TestMethod]
        public void EncryptedMessage_SenderIdentityKey_DefaultsToNull()
        {
            var msg = new EncryptedMessage();
            Assert.IsNull(msg.SenderIdentityKey, "SenderIdentityKey should default to null for backwards compatibility");
        }

        [TestMethod]
        public void EncryptedMessage_Clone_PreservesSenderIdentityKey()
        {
            var identityKey = new byte[] { 1, 2, 3, 4, 5 };
            var original = new EncryptedMessage
            {
                Ciphertext = new byte[] { 10, 11 },
                Nonce = new byte[] { 20, 21 },
                SenderDHKey = new byte[] { 30, 31 },
                SenderIdentityKey = identityKey,
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                SessionId = "test-session"
            };

            var clone = original.Clone();

            Assert.IsNotNull(clone.SenderIdentityKey, "Clone should carry SenderIdentityKey");
            CollectionAssert.AreEqual(identityKey, clone.SenderIdentityKey, "Cloned SenderIdentityKey must equal original");
            Assert.AreNotSame(original.SenderIdentityKey, clone.SenderIdentityKey, "Clone must be a deep copy, not the same array reference");
        }

        [TestMethod]
        public void EncryptedMessage_Clone_WhenSenderIdentityKeyNull_PreservesNull()
        {
            var original = new EncryptedMessage
            {
                Ciphertext = new byte[] { 10, 11 },
                Nonce = new byte[] { 20, 21 },
                SenderDHKey = new byte[] { 30, 31 },
                SenderIdentityKey = null,
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                SessionId = "test-session"
            };

            var clone = original.Clone();

            Assert.IsNull(clone.SenderIdentityKey, "Null SenderIdentityKey should remain null after clone");
        }

        [TestMethod]
        public void EncryptedMessage_ToDictionary_IncludesSenderIdentityKey_WhenSet()
        {
            var identityKey = new byte[] { 0xAB, 0xCD, 0xEF };
            var msg = new EncryptedMessage
            {
                Ciphertext = new byte[] { 1 },
                Nonce = new byte[] { 2 },
                SenderDHKey = new byte[] { 3 },
                SenderIdentityKey = identityKey,
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                SessionId = "test-session"
            };

            var dict = msg.ToDictionary();

            Assert.IsTrue(dict.ContainsKey("SenderIdentityKey"), "Dictionary should contain SenderIdentityKey when set");
            Assert.AreEqual(Convert.ToBase64String(identityKey), dict["SenderIdentityKey"]);
        }

        [TestMethod]
        public void EncryptedMessage_ToDictionary_OmitsSenderIdentityKey_WhenNull()
        {
            var msg = new EncryptedMessage
            {
                Ciphertext = new byte[] { 1 },
                Nonce = new byte[] { 2 },
                SenderDHKey = new byte[] { 3 },
                SenderIdentityKey = null,
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                SessionId = "test-session"
            };

            var dict = msg.ToDictionary();

            Assert.IsFalse(dict.ContainsKey("SenderIdentityKey"), "Dictionary should NOT contain SenderIdentityKey when null");
        }

        [TestMethod]
        public void EncryptedMessage_FromDictionary_RoundTrip_WithSenderIdentityKey()
        {
            var identityKey = new byte[] { 0x11, 0x22, 0x33, 0x44 };
            var original = new EncryptedMessage
            {
                Ciphertext = new byte[] { 1, 2, 3 },
                Nonce = new byte[] { 4, 5, 6 },
                SenderDHKey = new byte[] { 7, 8, 9 },
                SenderIdentityKey = identityKey,
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                SessionId = "round-trip-test",
                MessageId = Guid.NewGuid().ToString()
            };

            var dict = original.ToDictionary();
            var restored = EncryptedMessage.FromDictionary(dict);

            Assert.IsNotNull(restored.SenderIdentityKey, "Restored message should have SenderIdentityKey");
            CollectionAssert.AreEqual(identityKey, restored.SenderIdentityKey, "Restored SenderIdentityKey must equal original");
        }

        [TestMethod]
        public void EncryptedMessage_FromDictionary_RoundTrip_WithoutSenderIdentityKey()
        {
            // Simulates a legacy message that has no SenderIdentityKey in the dictionary
            var dict = new Dictionary<string, object>
            {
                ["Ciphertext"] = Convert.ToBase64String(new byte[] { 1, 2, 3 }),
                ["Nonce"] = Convert.ToBase64String(new byte[] { 4, 5, 6 }),
                ["SenderDHKey"] = Convert.ToBase64String(new byte[] { 7, 8, 9 }),
                ["SenderMessageNumber"] = 0,
                ["Timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
            };

            var restored = EncryptedMessage.FromDictionary(dict);

            Assert.IsNull(restored.SenderIdentityKey, "Legacy messages without SenderIdentityKey should restore to null");
        }

        [TestMethod]
        public void EncryptedMessage_ToJson_FromJson_RoundTrip_WithSenderIdentityKey()
        {
            var identityKey = new byte[32];
            System.Security.Cryptography.RandomNumberGenerator.Fill(identityKey);

            var original = new EncryptedMessage
            {
                Ciphertext = new byte[] { 1, 2, 3 },
                Nonce = new byte[] { 4, 5, 6 },
                SenderDHKey = new byte[] { 7, 8, 9 },
                SenderIdentityKey = identityKey,
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                SessionId = "json-test",
                MessageId = Guid.NewGuid().ToString()
            };

            var json = original.ToJson();
            var restored = EncryptedMessage.FromJson(json);

            Assert.IsNotNull(restored.SenderIdentityKey, "JSON round-trip should preserve SenderIdentityKey");
            CollectionAssert.AreEqual(identityKey, restored.SenderIdentityKey, "JSON round-trip SenderIdentityKey must equal original");
        }

        [TestMethod]
        public void EncryptedMessage_ToJson_FromJson_RoundTrip_WithoutSenderIdentityKey()
        {
            // Legacy message without SenderIdentityKey — JSON should not include the field
            var original = new EncryptedMessage
            {
                Ciphertext = new byte[] { 1, 2, 3 },
                Nonce = new byte[] { 4, 5, 6 },
                SenderDHKey = new byte[] { 7, 8, 9 },
                SenderIdentityKey = null,
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                SessionId = "json-legacy-test"
            };

            var json = original.ToJson();

            // SenderIdentityKey should not appear in the JSON for legacy messages
            Assert.IsFalse(json.Contains("SenderIdentityKey"), "JSON should not contain SenderIdentityKey when null");

            var restored = EncryptedMessage.FromJson(json);
            Assert.IsNull(restored.SenderIdentityKey, "Legacy JSON without SenderIdentityKey should restore to null");
        }

        [TestMethod]
        public void EncryptedMessage_GetEstimatedSize_AccountsForSenderIdentityKey()
        {
            var msgWithout = new EncryptedMessage
            {
                Ciphertext = new byte[32],
                Nonce = new byte[12],
                SenderDHKey = new byte[32],
                SenderIdentityKey = null,
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                SessionId = "test"
            };

            var msgWith = new EncryptedMessage
            {
                Ciphertext = new byte[32],
                Nonce = new byte[12],
                SenderDHKey = new byte[32],
                SenderIdentityKey = new byte[32],
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                SessionId = "test"
            };

            int sizeWithout = msgWithout.GetEstimatedSize();
            int sizeWith = msgWith.GetEstimatedSize();

            Assert.AreEqual(sizeWithout + 32, sizeWith,
                "GetEstimatedSize() should account for the 32-byte SenderIdentityKey");
        }

        // -------------------------------------------------------------------------
        // ChatSession.EncryptAsync populates SenderIdentityKey
        // -------------------------------------------------------------------------

        [TestMethod]
        public async Task ChatSession_EncryptAsync_PopulatesSenderIdentityKey()
        {
            // Arrange: set up a minimal Alice→Bob session
            var aliceKeyPair = Sodium.GenerateEd25519KeyPair();
            var bobKeyPair = Sodium.GenerateEd25519KeyPair();
            string sessionId = Guid.NewGuid().ToString();

            var bobBundle = await _x3DHProtocol.CreateKeyBundleAsync(bobKeyPair);
            var (aliceDR, initialMsg) = await _protocolAdapter.PrepareSenderSessionAsync(
                bobBundle.ToPublicBundle(), aliceKeyPair, sessionId);

            var aliceSession = new ChatSession(aliceDR, bobKeyPair.PublicKey, aliceKeyPair.PublicKey, _doubleRatchetProtocol);
            aliceSession.SetInitialMessageData(initialMsg);

            try
            {
                // Act
                var encrypted = await aliceSession.EncryptAsync("hello");

                // Assert
                Assert.IsNotNull(encrypted, "Encryption should succeed");
                Assert.IsNotNull(encrypted.SenderIdentityKey, "SenderIdentityKey should be set after encryption");
                CollectionAssert.AreEqual(aliceKeyPair.PublicKey, encrypted.SenderIdentityKey,
                    "SenderIdentityKey should equal Alice's LocalPublicKey");
            }
            finally
            {
                aliceSession.Dispose();
            }
        }

        // -------------------------------------------------------------------------
        // SessionManager sender-key index tests
        // -------------------------------------------------------------------------

        [TestMethod]
        public async Task SessionManager_AfterSaveSession_TryGetSessionIdBySenderKey_ReturnsCorrectSessionId()
        {
            // Arrange
            var aliceKeyPair = Sodium.GenerateEd25519KeyPair();
            var bobKeyPair = Sodium.GenerateEd25519KeyPair();
            string sessionId = $"chat-{Guid.NewGuid():N}";

            var bobBundle = await _x3DHProtocol.CreateKeyBundleAsync(bobKeyPair);
            var (aliceDR, initialMsg) = await _protocolAdapter.PrepareSenderSessionAsync(
                bobBundle.ToPublicBundle(), aliceKeyPair, sessionId);

            var sessionManager = new SessionManager(
                _cryptoProvider, _x3DHProtocol, _doubleRatchetProtocol, aliceKeyPair);

            var chatSession = new ChatSession(
                aliceDR, bobKeyPair.PublicKey, aliceKeyPair.PublicKey, _doubleRatchetProtocol);
            chatSession.SetInitialMessageData(initialMsg);

            try
            {
                // Act: save the session so it is indexed
                await sessionManager.SaveSessionAsync(chatSession);

                // Assert: Bob's identity key should now map to this session
                bool found = sessionManager.TryGetSessionIdBySenderKey(bobKeyPair.PublicKey, out var indexedSessionId);

                Assert.IsTrue(found, "Sender-key index should have an entry after session is saved");
                Assert.AreEqual(chatSession.SessionId, indexedSessionId,
                    "Indexed session ID should match the saved session");
            }
            finally
            {
                chatSession.Dispose();
                sessionManager.Dispose();
            }
        }

        [TestMethod]
        public async Task SessionManager_AfterDeleteSession_TryGetSessionIdBySenderKey_ReturnsFalse()
        {
            // Arrange
            var aliceKeyPair = Sodium.GenerateEd25519KeyPair();
            var bobKeyPair = Sodium.GenerateEd25519KeyPair();
            string sessionId = $"chat-{Guid.NewGuid():N}";

            var bobBundle = await _x3DHProtocol.CreateKeyBundleAsync(bobKeyPair);
            var (aliceDR, initialMsg) = await _protocolAdapter.PrepareSenderSessionAsync(
                bobBundle.ToPublicBundle(), aliceKeyPair, sessionId);

            var sessionManager = new SessionManager(
                _cryptoProvider, _x3DHProtocol, _doubleRatchetProtocol, aliceKeyPair);

            var chatSession = new ChatSession(
                aliceDR, bobKeyPair.PublicKey, aliceKeyPair.PublicKey, _doubleRatchetProtocol);
            chatSession.SetInitialMessageData(initialMsg);

            try
            {
                await sessionManager.SaveSessionAsync(chatSession);
                string savedId = chatSession.SessionId;

                // Verify it was indexed
                Assert.IsTrue(sessionManager.TryGetSessionIdBySenderKey(bobKeyPair.PublicKey, out _),
                    "Should be indexed after save");

                // Dispose before deleting (session manager will dispose cached copy)
                // Act: delete the session
                await sessionManager.DeleteSessionAsync(savedId);

                // Assert: index entry should be removed
                bool found = sessionManager.TryGetSessionIdBySenderKey(bobKeyPair.PublicKey, out _);
                Assert.IsFalse(found, "Sender-key index entry should be removed after session deletion");
            }
            finally
            {
                try { chatSession.Dispose(); } catch { }
                sessionManager.Dispose();
            }
        }

        [TestMethod]
        public void SessionManager_TryGetSessionIdBySenderKey_NullKey_ReturnsFalse()
        {
            var aliceKeyPair = Sodium.GenerateEd25519KeyPair();
            var sessionManager = new SessionManager(
                _cryptoProvider, _x3DHProtocol, _doubleRatchetProtocol, aliceKeyPair);

            try
            {
                bool found = sessionManager.TryGetSessionIdBySenderKey(null!, out var sid);
                Assert.IsFalse(found, "TryGetSessionIdBySenderKey with null key should return false");
                Assert.IsNull(sid);
            }
            finally
            {
                sessionManager.Dispose();
            }
        }

        [TestMethod]
        public void SessionManager_TryGetSessionIdBySenderKey_UnknownKey_ReturnsFalse()
        {
            var aliceKeyPair = Sodium.GenerateEd25519KeyPair();
            var unknownKey = Sodium.GenerateEd25519KeyPair().PublicKey;

            var sessionManager = new SessionManager(
                _cryptoProvider, _x3DHProtocol, _doubleRatchetProtocol, aliceKeyPair);

            try
            {
                bool found = sessionManager.TryGetSessionIdBySenderKey(unknownKey, out _);
                Assert.IsFalse(found, "Unknown sender key should not be found in the index");
            }
            finally
            {
                sessionManager.Dispose();
            }
        }

        // -------------------------------------------------------------------------
        // Performance test: routing 100 messages O(1)
        // -------------------------------------------------------------------------

        [TestMethod]
        public async Task Performance_RoutingHundredMessages_UsesO1Lookup_IsFast()
        {
            // Arrange: create 5 sessions (Alice talking to 5 different Bobs)
            // Then send 20 messages per session = 100 total, all routed via SenderIdentityKey
            const int SessionCount = 5;
            const int MessagesPerSession = 20;

            var aliceKeyPair = Sodium.GenerateEd25519KeyPair();
            var sessionManager = new SessionManager(
                _cryptoProvider, _x3DHProtocol, _doubleRatchetProtocol, aliceKeyPair);

            var encryptedMessages = new List<(byte[] senderKey, EncryptedMessage msg)>();

            try
            {
                // Create sessions and encrypt messages
                for (int s = 0; s < SessionCount; s++)
                {
                    var remoteKeyPair = Sodium.GenerateEd25519KeyPair();
                    var remoteBundle = await _x3DHProtocol.CreateKeyBundleAsync(remoteKeyPair);
                    var bundleJson = System.Text.Json.JsonSerializer.Serialize(remoteBundle.ToPublicBundle());
                    var bundleBytes = System.Text.Encoding.UTF8.GetBytes(bundleJson);

                    // Create a session from the remote side so we can encrypt "incoming" messages
                    // from that remote peer.  The remote peer's session has LocalPublicKey = remoteKeyPair.PublicKey
                    string sessionId = $"chat-test-{Guid.NewGuid():N}";
                    var (remoteDR, initialMsg) = await _protocolAdapter.PrepareSenderSessionAsync(
                        remoteBundle.ToPublicBundle(), remoteKeyPair, sessionId);

                    // Build the corresponding receiver session for Alice
                    var aliceDR = await _protocolAdapter.PrepareReceiverSessionAsync(
                        initialMsg, remoteBundle, sessionId);

                    // Register Alice's receiver session in the session manager so it can be found
                    var aliceChatSession = new ChatSession(
                        aliceDR, remoteKeyPair.PublicKey, aliceKeyPair.PublicKey, _doubleRatchetProtocol);

                    await sessionManager.SaveSessionAsync(aliceChatSession);

                    // Encrypt messages from the remote peer's side
                    var remoteChatSession = new ChatSession(
                        remoteDR, aliceKeyPair.PublicKey, remoteKeyPair.PublicKey, _doubleRatchetProtocol);
                    remoteChatSession.SetInitialMessageData(initialMsg);

                    for (int m = 0; m < MessagesPerSession; m++)
                    {
                        var encrypted = await remoteChatSession.EncryptAsync($"msg {m} from session {s}");
                        Assert.IsNotNull(encrypted?.SenderIdentityKey, "Each encrypted message must carry SenderIdentityKey");
                        encryptedMessages.Add((remoteKeyPair.PublicKey, encrypted!));
                    }

                    remoteChatSession.Dispose();
                }

                // Act: measure time to route 100 messages using the index
                var sw = Stopwatch.StartNew();
                int routed = 0;

                foreach (var (senderKey, msg) in encryptedMessages)
                {
                    bool found = sessionManager.TryGetSessionIdBySenderKey(msg.SenderIdentityKey!, out var sid);
                    if (found && sid != null)
                        routed++;
                }

                sw.Stop();

                // Assert
                Assert.AreEqual(SessionCount * MessagesPerSession, routed,
                    $"All {SessionCount * MessagesPerSession} messages should be routable via the index");

                // O(1) lookup for 100 messages should complete well under 100ms on any hardware
                Assert.IsTrue(sw.ElapsedMilliseconds < 100,
                    $"100 O(1) lookups took {sw.ElapsedMilliseconds}ms; expected < 100ms");
            }
            finally
            {
                sessionManager.Dispose();
            }
        }
    }
}
