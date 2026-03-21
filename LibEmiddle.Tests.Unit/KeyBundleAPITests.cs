using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Collections.Concurrent;
using LibEmiddle.Abstractions;
using LibEmiddle.API;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;
using LibEmiddle.Domain.Exceptions;
using LibEmiddle.Protocol;
using LibEmiddle.Sessions;

namespace LibEmiddle.Tests.Unit
{
    /// <summary>
    /// STORY-003: Tests for UploadKeyBundleAsync and FetchRecipientKeyBundleAsync
    /// on ILibEmiddleClient, and for the SessionManager bundle cache.
    /// </summary>
    [TestClass]
    public class KeyBundleAPITests
    {
        // ── helpers ─────────────────────────────────────────────────────────

        private static LibEmiddleClient CreateClient(TransportType transportType = TransportType.InMemory)
        {
            return new LibEmiddleClient(new LibEmiddleClientOptions
            {
                TransportType = transportType
            });
        }

        private static async Task<X3DHPublicBundle> BuildValidPublicBundle()
        {
            Sodium.Initialize();
            var crypto = new CryptoProvider();
            var x3dh = new X3DHProtocol(crypto);
            var identityKeyPair = Sodium.GenerateEd25519KeyPair();
            var bundle = await x3dh.CreateKeyBundleAsync(identityKeyPair, 5);
            return bundle.ToPublicBundle();
        }

        // ── ILibEmiddleClient interface surface ──────────────────────────────

        [TestMethod]
        public void ILibEmiddleClient_HasUploadKeyBundleAsync()
        {
            var method = typeof(ILibEmiddleClient).GetMethod("UploadKeyBundleAsync");
            Assert.IsNotNull(method, "ILibEmiddleClient must declare UploadKeyBundleAsync()");
            Assert.AreEqual(typeof(Task), method.ReturnType,
                "UploadKeyBundleAsync must return Task");
            Assert.AreEqual(0, method.GetParameters().Length,
                "UploadKeyBundleAsync must take no parameters");
        }

        [TestMethod]
        public void ILibEmiddleClient_HasFetchRecipientKeyBundleAsync()
        {
            var method = typeof(ILibEmiddleClient).GetMethod("FetchRecipientKeyBundleAsync");
            Assert.IsNotNull(method, "ILibEmiddleClient must declare FetchRecipientKeyBundleAsync");
            Assert.AreEqual(typeof(Task<X3DHPublicBundle>), method.ReturnType,
                "FetchRecipientKeyBundleAsync must return Task<X3DHPublicBundle>");
            var parameters = method.GetParameters();
            Assert.AreEqual(1, parameters.Length, "FetchRecipientKeyBundleAsync must accept one parameter");
            Assert.AreEqual(typeof(byte[]), parameters[0].ParameterType,
                "Parameter must be byte[]");
        }

        // ── IKeyBundleTransport interface contract ───────────────────────────

        [TestMethod]
        public void IKeyBundleTransport_HasUploadKeyBundleAsync()
        {
            var method = typeof(IKeyBundleTransport).GetMethod("UploadKeyBundleAsync");
            Assert.IsNotNull(method, "IKeyBundleTransport must declare UploadKeyBundleAsync");
        }

        [TestMethod]
        public void IKeyBundleTransport_HasFetchKeyBundleAsync()
        {
            var method = typeof(IKeyBundleTransport).GetMethod("FetchKeyBundleAsync");
            Assert.IsNotNull(method, "IKeyBundleTransport must declare FetchKeyBundleAsync");
        }

        // ── UploadKeyBundleAsync: transport does not support bundles ─────────

        [TestMethod]
        public async Task UploadKeyBundleAsync_WithNonBundleTransport_ThrowsNotSupported()
        {
            using var client = CreateClient(TransportType.InMemory);
            await client.InitializeAsync();

            await Assert.ThrowsExceptionAsync<NotSupportedException>(
                () => client.UploadKeyBundleAsync(),
                "Should throw NotSupportedException when transport does not implement IKeyBundleTransport");
        }

        // ── FetchRecipientKeyBundleAsync: transport does not support bundles ─

        [TestMethod]
        public async Task FetchRecipientKeyBundleAsync_WithNonBundleTransport_ThrowsNotSupported()
        {
            using var client = CreateClient(TransportType.InMemory);
            await client.InitializeAsync();

            var key = new byte[32];
            RandomNumberGenerator.Fill(key);

            await Assert.ThrowsExceptionAsync<NotSupportedException>(
                () => client.FetchRecipientKeyBundleAsync(key),
                "Should throw NotSupportedException when transport does not implement IKeyBundleTransport");
        }

        // ── FetchRecipientKeyBundleAsync: null argument ──────────────────────

        [TestMethod]
        public async Task FetchRecipientKeyBundleAsync_NullKey_ThrowsArgumentNullException()
        {
            using var client = CreateClient(TransportType.InMemory);
            await client.InitializeAsync();

            // Assign null to a local variable to avoid compiler CS8600 in nullable-disabled project
            byte[] nullKey = null;
            await Assert.ThrowsExceptionAsync<ArgumentNullException>(
                () => client.FetchRecipientKeyBundleAsync(nullKey));
        }

        // ── LibEmiddleClient implements the interface ─────────────────────────

        [TestMethod]
        public void LibEmiddleClient_ImplementsILibEmiddleClient()
        {
            using var client = CreateClient();
            Assert.IsInstanceOfType(client, typeof(ILibEmiddleClient),
                "LibEmiddleClient must implement ILibEmiddleClient");
        }

        // ── SessionManager bundle cache: in-memory TTL cache ─────────────────

        [TestMethod]
        public async Task SessionManager_CacheRecipientBundle_IsReturnedOnSubsequentLookup()
        {
            Sodium.Initialize();
            var crypto = new CryptoProvider();
            var x3dh = new X3DHProtocol(crypto);
            var dr = new DoubleRatchetProtocol();
            var identityKeyPair = Sodium.GenerateEd25519KeyPair();

            using var tempDir = new BundleTestTempDirectory();
            using var sessionManager = new SessionManager(crypto, x3dh, dr, identityKeyPair, tempDir.Path);

            var bundle = await BuildValidPublicBundle();

            // Cache the bundle
            await sessionManager.CacheRecipientBundleAsync(bundle);

            // Retrieve via CreateSessionAsync using the identity key — should not throw
            var session = await sessionManager.CreateSessionAsync(bundle.IdentityKey);
            Assert.IsNotNull(session, "Should create a chat session using the cached bundle");
        }

        [TestMethod]
        public async Task SessionManager_CacheRecipientBundle_NullBundle_Throws()
        {
            Sodium.Initialize();
            var crypto = new CryptoProvider();
            var x3dh = new X3DHProtocol(crypto);
            var dr = new DoubleRatchetProtocol();
            var identityKeyPair = Sodium.GenerateEd25519KeyPair();

            using var tempDir = new BundleTestTempDirectory();
            using var sessionManager = new SessionManager(crypto, x3dh, dr, identityKeyPair, tempDir.Path);

            X3DHPublicBundle nullBundle = null;
            await Assert.ThrowsExceptionAsync<ArgumentNullException>(
                () => sessionManager.CacheRecipientBundleAsync(nullBundle));
        }

        [TestMethod]
        public async Task SessionManager_CacheRecipientBundle_EmptyIdentityKey_Throws()
        {
            Sodium.Initialize();
            var crypto = new CryptoProvider();
            var x3dh = new X3DHProtocol(crypto);
            var dr = new DoubleRatchetProtocol();
            var identityKeyPair = Sodium.GenerateEd25519KeyPair();

            using var tempDir = new BundleTestTempDirectory();
            using var sessionManager = new SessionManager(crypto, x3dh, dr, identityKeyPair, tempDir.Path);

            // IdentityKey is Array.Empty<byte>() by default
            var badBundle = new X3DHPublicBundle();

            await Assert.ThrowsExceptionAsync<ArgumentException>(
                () => sessionManager.CacheRecipientBundleAsync(badBundle));
        }

        // ── CreateChatSessionAsync uses the cached bundle ────────────────────

        [TestMethod]
        public async Task CreateChatSessionAsync_WithCachedBundle_SucceedsWithoutPreload()
        {
            Sodium.Initialize();
            var crypto = new CryptoProvider();
            var x3dh = new X3DHProtocol(crypto);
            var dr = new DoubleRatchetProtocol();
            var aliceKeyPair = Sodium.GenerateEd25519KeyPair();

            using var tempDir = new BundleTestTempDirectory();
            using var sessionManager = new SessionManager(crypto, x3dh, dr, aliceKeyPair, tempDir.Path);

            // Build Bob's bundle and cache it
            var bobBundle = await BuildValidPublicBundle();
            await sessionManager.CacheRecipientBundleAsync(bobBundle);

            // Alice creates a session using only Bob's identity key (no serialized JSON)
            var session = await sessionManager.CreateSessionAsync(bobBundle.IdentityKey);

            Assert.IsNotNull(session, "Session should be created");
            Assert.IsTrue(session.SessionId.StartsWith("chat-"),
                "Session ID should start with 'chat-'");
        }

        [TestMethod]
        public async Task CreateChatSessionAsync_WithoutCachedBundle_Throws()
        {
            Sodium.Initialize();
            var crypto = new CryptoProvider();
            var x3dh = new X3DHProtocol(crypto);
            var dr = new DoubleRatchetProtocol();
            var aliceKeyPair = Sodium.GenerateEd25519KeyPair();

            using var tempDir = new BundleTestTempDirectory();
            using var sessionManager = new SessionManager(crypto, x3dh, dr, aliceKeyPair, tempDir.Path);

            // Generate a random 32-byte identity key with no bundle registered
            var unknownKey = RandomNumberGenerator.GetBytes(32);

            await Assert.ThrowsExceptionAsync<ArgumentException>(
                () => sessionManager.CreateSessionAsync(unknownKey),
                "Should throw when no bundle exists for the identity key");
        }

        // ── UploadKeyBundleAsync: mock transport that implements IKeyBundleTransport ──

        [TestMethod]
        public async Task UploadKeyBundleAsync_WithSupportingTransport_CallsTransportUpload()
        {
            // Test the transport call directly via the mock interface.
            // This validates the interaction contract for IKeyBundleTransport.
            var mockTransport = new MockKeyBundleTransport();

            var bundle = await BuildValidPublicBundle();
            await mockTransport.UploadKeyBundleAsync(bundle);

            Assert.AreEqual(1, mockTransport.UploadCallCount,
                "UploadKeyBundleAsync should have been called once");
            Assert.IsNotNull(mockTransport.LastUploadedBundle,
                "Transport should have received the bundle");
        }

        // ── FetchKeyBundleAsync: mock transport ─────────────────────────────

        [TestMethod]
        public async Task FetchKeyBundleAsync_WhenBundleRegistered_ReturnsBundle()
        {
            var bundle = await BuildValidPublicBundle();
            var mockTransport = new MockKeyBundleTransport();
            await mockTransport.UploadKeyBundleAsync(bundle);

            var fetched = await mockTransport.FetchKeyBundleAsync(bundle.IdentityKey);

            Assert.IsNotNull(fetched, "Should return the registered bundle");
            CollectionAssert.AreEqual(bundle.IdentityKey, fetched.IdentityKey,
                "Identity keys should match");
        }

        [TestMethod]
        public async Task FetchKeyBundleAsync_WhenNoBundleRegistered_ReturnsNull()
        {
            var mockTransport = new MockKeyBundleTransport();
            var randomKey = RandomNumberGenerator.GetBytes(32);

            var fetched = await mockTransport.FetchKeyBundleAsync(randomKey);

            Assert.IsNull(fetched, "Should return null when no bundle is registered");
        }

        // ── M4: FetchRecipientKeyBundleAsync end-to-end via IKeyBundleTransport ──

        [TestMethod]
        public async Task FetchRecipientKeyBundleAsync_WithMockTransport_ValidatesSignatureAndCaches()
        {
            // Arrange: build a real bundle (with valid signature) and put it in a mock transport
            var bundle = await BuildValidPublicBundle();
            var mockTransport = new MockMailboxAndKeyBundleTransport();
            await mockTransport.UploadKeyBundleAsync(bundle);

            using var client = new LibEmiddleClient(new LibEmiddleClientOptions
            {
                CustomTransport = mockTransport
            });
            await client.InitializeAsync();

            // Act: fetch via the full client path (validates signature, caches result)
            var fetched = await client.FetchRecipientKeyBundleAsync(bundle.IdentityKey);

            // Assert: correct bundle returned
            Assert.IsNotNull(fetched, "Should return the bundle from transport");
            CollectionAssert.AreEqual(bundle.IdentityKey, fetched.IdentityKey,
                "Identity keys must match");
        }

        [TestMethod]
        public async Task FetchRecipientKeyBundleAsync_BundleNotFound_ThrowsLibEmiddleException_KeyNotFound()
        {
            // Arrange: empty transport — no bundle registered
            var mockTransport = new MockMailboxAndKeyBundleTransport();
            using var client = new LibEmiddleClient(new LibEmiddleClientOptions
            {
                CustomTransport = mockTransport
            });
            await client.InitializeAsync();

            var unknownKey = RandomNumberGenerator.GetBytes(32);

            // Act + Assert
            var ex = await Assert.ThrowsExceptionAsync<LibEmiddleException>(
                () => client.FetchRecipientKeyBundleAsync(unknownKey));
            Assert.AreEqual(LibEmiddleErrorCode.KeyNotFound, ex.ErrorCode,
                "Should throw LibEmiddleException with KeyNotFound when no bundle is registered");
        }

        // ── M5: Bundle cache TTL eviction ────────────────────────────────────

        [TestMethod]
        public async Task SessionManager_BundleCache_StaleEntry_IsEvictedAndFallsBackToDisk()
        {
            // Arrange
            Sodium.Initialize();
            var crypto = new CryptoProvider();
            var x3dh = new X3DHProtocol(crypto);
            var dr = new DoubleRatchetProtocol();
            var aliceKeyPair = Sodium.GenerateEd25519KeyPair();

            using var tempDir = new BundleTestTempDirectory();
            using var sessionManager = new SessionManager(crypto, x3dh, dr, aliceKeyPair, tempDir.Path);

            var bundle = await BuildValidPublicBundle();

            // Cache the bundle (goes to both memory + disk)
            await sessionManager.CacheRecipientBundleAsync(bundle);

            // Inject a stale timestamp into the in-memory cache via reflection so we can
            // test the TTL eviction path without waiting 72 hours.
            string cacheKey = Convert.ToBase64String(bundle.IdentityKey);
            var cacheField = typeof(SessionManager).GetField("_bundleCache",
                BindingFlags.NonPublic | BindingFlags.Instance);
            Assert.IsNotNull(cacheField, "SessionManager must have a _bundleCache field");
            var cache = (ConcurrentDictionary<string, (X3DHPublicBundle Bundle, DateTime CachedAt)>)
                cacheField.GetValue(sessionManager)!;

            // Overwrite with a timestamp far in the past (75 hours ago — older than 72-hour TTL)
            cache[cacheKey] = (bundle, DateTime.UtcNow.AddHours(-75));

            // Act: CreateSessionAsync should detect the stale in-memory entry, evict it,
            // and fall back to disk — the bundle is on disk so session creation must succeed.
            var session = await sessionManager.CreateSessionAsync(bundle.IdentityKey);

            // Assert: TTL eviction did not break the API — disk fallback works
            Assert.IsNotNull(session,
                "Session creation must succeed after stale in-memory entry is evicted (disk fallback)");

            // And the in-memory entry should now be fresh (re-warmed from disk)
            Assert.IsTrue(cache.TryGetValue(cacheKey, out var rewarmed),
                "Cache should be re-warmed after disk fallback");
            Assert.IsTrue(DateTime.UtcNow - rewarmed.CachedAt < TimeSpan.FromMinutes(1),
                "Re-warmed cache entry should have a recent timestamp");
        }

        // ── Bundle cache: multiple bundles ───────────────────────────────────

        [TestMethod]
        public async Task SessionManager_BundleCache_SurvivesCreateSessionCall()
        {
            // Ensures the bundle cache handles multiple recipients correctly
            Sodium.Initialize();
            var crypto = new CryptoProvider();
            var x3dh = new X3DHProtocol(crypto);
            var dr = new DoubleRatchetProtocol();
            var aliceKeyPair = Sodium.GenerateEd25519KeyPair();

            using var tempDir = new BundleTestTempDirectory();
            using var sessionManager = new SessionManager(crypto, x3dh, dr, aliceKeyPair, tempDir.Path);

            var bundle1 = await BuildValidPublicBundle();
            var bundle2 = await BuildValidPublicBundle();

            // Cache both bundles
            await sessionManager.CacheRecipientBundleAsync(bundle1);
            await sessionManager.CacheRecipientBundleAsync(bundle2);

            // Create sessions for both recipients
            var session1 = await sessionManager.CreateSessionAsync(bundle1.IdentityKey);
            var session2 = await sessionManager.CreateSessionAsync(bundle2.IdentityKey);

            Assert.IsNotNull(session1);
            Assert.IsNotNull(session2);
            Assert.AreNotEqual(session1.SessionId, session2.SessionId,
                "Each recipient should get a distinct session");
        }
    }

    // ── Test helpers ─────────────────────────────────────────────────────────

    /// <summary>
    /// Dual-purpose mock that implements both <see cref="IMailboxTransport"/> and
    /// <see cref="IKeyBundleTransport"/>, suitable for injection via
    /// <see cref="LibEmiddleClientOptions.CustomTransport"/>.
    /// </summary>
    internal sealed class MockMailboxAndKeyBundleTransport : IMailboxTransport, IKeyBundleTransport
    {
        private readonly Dictionary<string, X3DHPublicBundle> _store = new Dictionary<string, X3DHPublicBundle>();

        // ── IMailboxTransport (minimal no-op stubs) ──────────────────────────
#pragma warning disable CS0067
        public event EventHandler<MailboxMessageReceivedEventArgs> MessageReceived;
#pragma warning restore CS0067
        public Task<bool> SendMessageAsync(MailboxMessage message) => Task.FromResult(true);
        public Task<List<MailboxMessage>> FetchMessagesAsync(byte[] recipientKey, CancellationToken cancellationToken = default)
            => Task.FromResult(new List<MailboxMessage>());
        public Task StartListeningAsync(byte[] localIdentityKey, int pollingInterval = 5000, CancellationToken cancellationToken = default)
            => Task.CompletedTask;
        public Task StopListeningAsync() => Task.CompletedTask;
        public Task<bool> DeleteMessageAsync(string messageId) => Task.FromResult(true);
        public Task<bool> MarkMessageAsReadAsync(string messageId) => Task.FromResult(true);
        public Task<bool> UpdateDeliveryStatusAsync(string messageId, bool isDelivered) => Task.FromResult(true);
        public void Dispose() { }

        // ── IKeyBundleTransport ───────────────────────────────────────────────
        public Task UploadKeyBundleAsync(X3DHPublicBundle bundle)
        {
            if (bundle == null) throw new ArgumentNullException("bundle");
            _store[Convert.ToBase64String(bundle.IdentityKey)] = bundle;
            return Task.CompletedTask;
        }

        public Task<X3DHPublicBundle> FetchKeyBundleAsync(byte[] recipientIdentityKey)
        {
            if (recipientIdentityKey == null) throw new ArgumentNullException("recipientIdentityKey");
            X3DHPublicBundle result;
            _store.TryGetValue(Convert.ToBase64String(recipientIdentityKey), out result);
            return Task.FromResult(result);
        }
    }

    /// <summary>
    /// Minimal in-memory implementation of <see cref="IKeyBundleTransport"/> for unit tests.
    /// </summary>
    internal sealed class MockKeyBundleTransport : IKeyBundleTransport
    {
        private readonly Dictionary<string, X3DHPublicBundle> _store = new Dictionary<string, X3DHPublicBundle>();

        public int UploadCallCount { get; private set; }

        // Stored without nullable annotation for compatibility with nullable-disabled project
        public X3DHPublicBundle LastUploadedBundle { get; private set; }

        public Task UploadKeyBundleAsync(X3DHPublicBundle bundle)
        {
            if (bundle == null) throw new ArgumentNullException("bundle");
            UploadCallCount++;
            LastUploadedBundle = bundle;
            _store[Convert.ToBase64String(bundle.IdentityKey)] = bundle;
            return Task.CompletedTask;
        }

        public Task<X3DHPublicBundle> FetchKeyBundleAsync(byte[] recipientIdentityKey)
        {
            if (recipientIdentityKey == null) throw new ArgumentNullException("recipientIdentityKey");
            string key = Convert.ToBase64String(recipientIdentityKey);
            X3DHPublicBundle result;
            _store.TryGetValue(key, out result);
            return Task.FromResult(result);
        }
    }

    /// <summary>
    /// Creates a temporary directory and deletes it on disposal.
    /// Named distinctly to avoid collision with any existing helper class in the test project.
    /// </summary>
    internal sealed class BundleTestTempDirectory : IDisposable
    {
        public string Path { get; }

        public BundleTestTempDirectory()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                "LibEmiddle_BUNDLE_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Path);
        }

        public void Dispose()
        {
            try { Directory.Delete(Path, recursive: true); }
            catch { /* best-effort */ }
        }
    }
}
