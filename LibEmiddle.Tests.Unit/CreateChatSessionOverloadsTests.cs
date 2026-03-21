using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using LibEmiddle.Abstractions;
using LibEmiddle.API;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;
using LibEmiddle.Domain.Exceptions;
using LibEmiddle.Messaging.Chat;
using LibEmiddle.Protocol;
using LibEmiddle.Sessions;

namespace LibEmiddle.Tests.Unit
{
    /// <summary>
    /// STORY-010: Tests for the two explicit CreateChatSessionAsync overloads added to
    /// ILibEmiddleClient and LibEmiddleClient:
    ///   - Overload 1: CreateChatSessionAsync(byte[] recipientIdentityKey, ...)
    ///   - Overload 2: CreateChatSessionAsync(X3DHPublicBundle recipientBundle, ...)
    /// </summary>
    [TestClass]
    public class CreateChatSessionOverloadsTests
    {
        // ── helpers ─────────────────────────────────────────────────────────────

        private static async Task<X3DHPublicBundle> BuildValidPublicBundleAsync()
        {
            Sodium.Initialize();
            var crypto = new CryptoProvider();
            var x3dh = new X3DHProtocol(crypto);
            var identityKeyPair = Sodium.GenerateEd25519KeyPair();
            var bundle = await x3dh.CreateKeyBundleAsync(identityKeyPair, 5);
            return bundle.ToPublicBundle();
        }

        // ── Interface surface ────────────────────────────────────────────────────

        [TestMethod]
        public void ILibEmiddleClient_HasBothCreateChatSessionOverloads()
        {
            var methods = typeof(ILibEmiddleClient).GetMethods();

            bool hasIdentityKeyOverload = false;
            bool hasBundleOverload = false;

            foreach (var m in methods)
            {
                if (m.Name != "CreateChatSessionAsync")
                    continue;

                var parameters = m.GetParameters();
                if (parameters.Length >= 1 && parameters[0].ParameterType == typeof(byte[]))
                    hasIdentityKeyOverload = true;
                if (parameters.Length >= 1 && parameters[0].ParameterType == typeof(X3DHPublicBundle))
                    hasBundleOverload = true;
            }

            Assert.IsTrue(hasIdentityKeyOverload,
                "ILibEmiddleClient must expose CreateChatSessionAsync(byte[], ...)");
            Assert.IsTrue(hasBundleOverload,
                "ILibEmiddleClient must expose CreateChatSessionAsync(X3DHPublicBundle, ...)");
        }

        // ── Overload 2 (bundle overload): success path ───────────────────────────

        [TestMethod]
        public async Task CreateChatSessionAsync_BundleOverload_ReturnsChatSession()
        {
            Sodium.Initialize();
            var bundle = await BuildValidPublicBundleAsync();

            using var client = new LibEmiddleClient(new LibEmiddleClientOptions
            {
                TransportType = TransportType.InMemory
            });
            await client.InitializeAsync();

            var session = await client.CreateChatSessionAsync(bundle);

            Assert.IsNotNull(session, "Session must not be null");
            Assert.IsTrue(session.SessionId.StartsWith("chat-"),
                "Session ID should start with 'chat-'");
        }

        // ── Overload 2 (bundle overload): recipientUserId is propagated ──────────

        [TestMethod]
        public async Task CreateChatSessionAsync_BundleOverload_SetsRecipientUserId()
        {
            Sodium.Initialize();
            var bundle = await BuildValidPublicBundleAsync();
            const string userId = "bob@example.com";

            using var client = new LibEmiddleClient(new LibEmiddleClientOptions
            {
                TransportType = TransportType.InMemory
            });
            await client.InitializeAsync();

            var session = await client.CreateChatSessionAsync(bundle, userId);

            Assert.IsNotNull(session, "Session must not be null");
            // Cast to the concrete ChatSession to read back the Metadata dictionary.
            var chatSession = session as ChatSession;
            Assert.IsNotNull(chatSession, "Returned session should be a ChatSession");
            Assert.IsTrue(chatSession.Metadata.ContainsKey("RemoteUserId"),
                "Session metadata should contain RemoteUserId");
            Assert.AreEqual(userId, chatSession.Metadata["RemoteUserId"],
                "RemoteUserId in metadata should match the supplied recipientUserId");
        }

        // ── Overload 2 (bundle overload): null bundle throws ─────────────────────

        [TestMethod]
        public async Task CreateChatSessionAsync_BundleOverload_NullBundle_Throws()
        {
            using var client = new LibEmiddleClient(new LibEmiddleClientOptions
            {
                TransportType = TransportType.InMemory
            });
            await client.InitializeAsync();

            X3DHPublicBundle nullBundle = null;

            await Assert.ThrowsExceptionAsync<ArgumentNullException>(
                () => client.CreateChatSessionAsync(nullBundle),
                "Passing a null bundle must throw ArgumentNullException");
        }

        // ── Overload 1 (identity-key overload): cached bundle path ───────────────

        [TestMethod]
        public async Task CreateChatSessionAsync_IdentityKeyOverload_WithCachedBundle_ReturnsChatSession()
        {
            Sodium.Initialize();
            var crypto = new CryptoProvider();
            var x3dh = new X3DHProtocol(crypto);
            var dr = new DoubleRatchetProtocol();
            var aliceKeyPair = Sodium.GenerateEd25519KeyPair();

            string tempDir = Path.Combine(
                Path.GetTempPath(),
                "LibEmiddle_STORY010_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);

            try
            {
                using var sessionManager = new SessionManager(crypto, x3dh, dr, aliceKeyPair, tempDir);

                // Build Bob's bundle and pre-cache it so the identity-key overload can
                // find it without needing a transport fetch.
                var bobBundle = await BuildValidPublicBundleAsync();
                await sessionManager.CacheRecipientBundleAsync(bobBundle);

                // CreateSessionAsync(byte[]) is the direct SessionManager API that the
                // client delegates to; verify it succeeds with the pre-cached bundle.
                var session = await sessionManager.CreateSessionAsync(bobBundle.IdentityKey);

                Assert.IsNotNull(session, "Session must not be null");
                Assert.IsTrue(session.SessionId.StartsWith("chat-"),
                    "Session ID should start with 'chat-'");
                Assert.IsInstanceOfType(session, typeof(IChatSession),
                    "Session must implement IChatSession");
            }
            finally
            {
                try { Directory.Delete(tempDir, recursive: true); }
                catch { /* best-effort */ }
            }
        }

        // ── Overload 1 (identity-key overload): no bundle + non-bundle transport ──

        [TestMethod]
        public async Task CreateChatSessionAsync_IdentityKeyOverload_NoBundleAndNoTransportSupport_ThrowsLibEmiddleException()
        {
            Sodium.Initialize();

            using var client = new LibEmiddleClient(new LibEmiddleClientOptions
            {
                TransportType = TransportType.InMemory   // InMemory does NOT implement IKeyBundleTransport
            });
            await client.InitializeAsync();

            // Unknown 32-byte identity key — no bundle in local cache, transport cannot fetch
            var unknownKey = RandomNumberGenerator.GetBytes(32);

            var ex = await Assert.ThrowsExceptionAsync<LibEmiddleException>(
                () => client.CreateChatSessionAsync(unknownKey),
                "Must throw LibEmiddleException when no bundle is available");

            Assert.AreEqual(LibEmiddleErrorCode.KeyNotFound, ex.ErrorCode,
                "Error code must be KeyNotFound");
        }
    }
}
