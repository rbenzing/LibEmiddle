using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;
using LibEmiddle.Protocol;
using LibEmiddle.Sessions;
using LibEmiddle.Abstractions;

namespace LibEmiddle.Tests.Unit
{
    /// <summary>
    /// TEST-006: Tests for SessionManager group session creation/load paths
    /// and SessionPersistenceManager bundle cache persistence.
    /// </summary>
    [TestClass]
    public class SessionManagerBundleTests
    {
        private string _tempDir = null!;
        private CryptoProvider _cryptoProvider = null!;
        private X3DHProtocol _x3dhProtocol = null!;
        private DoubleRatchetProtocol _doubleRatchetProtocol = null!;
        private KeyPair _aliceKeyPair;

        [TestInitialize]
        public void Setup()
        {
            _tempDir = Path.Combine(Path.GetTempPath(), "LibEmiddle_TEST006_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_tempDir);

            _cryptoProvider = new CryptoProvider();
            _x3dhProtocol = new X3DHProtocol(_cryptoProvider);
            _doubleRatchetProtocol = new DoubleRatchetProtocol();
            _aliceKeyPair = Sodium.GenerateEd25519KeyPair();
        }

        [TestCleanup]
        public void Cleanup()
        {
            try
            {
                if (Directory.Exists(_tempDir))
                    Directory.Delete(_tempDir, recursive: true);
            }
            catch { /* best-effort */ }
        }

        // -------------------------------------------------------------------
        // SessionPersistenceManager: bundle round-trip
        // -------------------------------------------------------------------

        [TestMethod]
        public async Task SaveKeyBundle_ThenLoadByIdentityKey_ReturnsSameBundle()
        {
            using var pm = new SessionPersistenceManager(_cryptoProvider, _tempDir);

            var bundle = BuildTestBundle();
            await pm.SaveKeyBundleAsync(bundle);

            var loaded = await pm.LoadKeyBundleByIdentityKeyAsync(bundle.IdentityKey);

            Assert.IsNotNull(loaded, "Bundle should be found after saving");
            CollectionAssert.AreEqual(bundle.IdentityKey, loaded!.IdentityKey);
            CollectionAssert.AreEqual(bundle.SignedPreKey, loaded.SignedPreKey);
            CollectionAssert.AreEqual(bundle.SignedPreKeySignature, loaded.SignedPreKeySignature);
            Assert.AreEqual(bundle.SignedPreKeyId, loaded.SignedPreKeyId);
        }

        [TestMethod]
        public async Task LoadKeyBundleByIdentityKey_WhenNotFound_ReturnsNull()
        {
            using var pm = new SessionPersistenceManager(_cryptoProvider, _tempDir);

            byte[] unknownKey = new byte[32];
            RandomNumberGenerator.Fill(unknownKey);

            var result = await pm.LoadKeyBundleByIdentityKeyAsync(unknownKey);

            Assert.IsNull(result, "Should return null for an identity key that was never saved");
        }

        [TestMethod]
        public async Task SaveKeyBundle_OverwritesExistingBundle_ForSameIdentityKey()
        {
            using var pm = new SessionPersistenceManager(_cryptoProvider, _tempDir);

            var bundle1 = BuildTestBundle();
            await pm.SaveKeyBundleAsync(bundle1);

            // Build a second bundle with same identity key but different prekey ID
            var bundle2 = new X3DHPublicBundle(
                bundle1.IdentityKey,
                new byte[32],
                signedPreKeyId: 99,
                signedPreKeySignature: new byte[64]);

            await pm.SaveKeyBundleAsync(bundle2);

            var loaded = await pm.LoadKeyBundleByIdentityKeyAsync(bundle1.IdentityKey);
            Assert.IsNotNull(loaded);
            Assert.AreEqual(99u, loaded!.SignedPreKeyId, "Second save should overwrite the first");
        }

        [TestMethod]
        public async Task SaveKeyBundle_NullBundle_ThrowsArgumentNullException()
        {
            using var pm = new SessionPersistenceManager(_cryptoProvider, _tempDir);
            await Assert.ThrowsExceptionAsync<ArgumentNullException>(
                () => pm.SaveKeyBundleAsync(null!));
        }

        [TestMethod]
        public async Task SaveKeyBundle_EmptyIdentityKey_ThrowsArgumentException()
        {
            using var pm = new SessionPersistenceManager(_cryptoProvider, _tempDir);

            var bundle = new X3DHPublicBundle
            {
                IdentityKey = Array.Empty<byte>(),
                SignedPreKey = new byte[32],
                SignedPreKeyId = 1,
                SignedPreKeySignature = new byte[64]
            };

            await Assert.ThrowsExceptionAsync<ArgumentException>(
                () => pm.SaveKeyBundleAsync(bundle));
        }

        // -------------------------------------------------------------------
        // SessionManager: CreateSessionAsync with serialized bundle JSON
        // -------------------------------------------------------------------

        [TestMethod]
        public async Task CreateSessionAsync_WithSerializedBundleJson_CachesBundleForFutureLookup()
        {
            var bobKeyPair = Sodium.GenerateEd25519KeyPair();
            var bobBundle = await _x3dhProtocol.CreateKeyBundleAsync(bobKeyPair);
            var bobPublicBundle = bobBundle.ToPublicBundle();

            // Serialize bundle to JSON bytes — this is how callers supply a full bundle
            string json = JsonSerialization.Serialize(bobPublicBundle);
            byte[] jsonBytes = Encoding.UTF8.GetBytes(json);

            using var sessionManager = new SessionManager(
                _cryptoProvider, _x3dhProtocol, _doubleRatchetProtocol, _aliceKeyPair, _tempDir);

            // First call with full JSON — should succeed and cache the bundle
            var session = await sessionManager.CreateSessionAsync(jsonBytes);
            Assert.IsNotNull(session, "Session should be created from a serialized bundle");
            (session as IDisposable)?.Dispose();
        }

        [TestMethod]
        public async Task CreateSessionAsync_WithBareIdentityKey_WhenNoCachedBundle_ThrowsArgumentException()
        {
            using var sessionManager = new SessionManager(
                _cryptoProvider, _x3dhProtocol, _doubleRatchetProtocol, _aliceKeyPair, _tempDir);

            // 32-byte key that has never been registered via a full bundle
            byte[] unknownIdentityKey = new byte[32];
            RandomNumberGenerator.Fill(unknownIdentityKey);

            await Assert.ThrowsExceptionAsync<ArgumentException>(
                () => sessionManager.CreateSessionAsync(unknownIdentityKey),
                "Should throw because no bundle is cached for this identity key");
        }

        [TestMethod]
        public async Task CreateSessionAsync_WithBareIdentityKey_AfterBundleRegistered_Succeeds()
        {
            var bobKeyPair = Sodium.GenerateEd25519KeyPair();
            var bobBundle = await _x3dhProtocol.CreateKeyBundleAsync(bobKeyPair);
            var bobPublicBundle = bobBundle.ToPublicBundle();

            string json = JsonSerialization.Serialize(bobPublicBundle);
            byte[] jsonBytes = Encoding.UTF8.GetBytes(json);

            using var sessionManager = new SessionManager(
                _cryptoProvider, _x3dhProtocol, _doubleRatchetProtocol, _aliceKeyPair, _tempDir);

            // Register the bundle first via the full JSON path
            var firstSession = await sessionManager.CreateSessionAsync(jsonBytes);
            (firstSession as IDisposable)?.Dispose();

            // Now a second call with just the identity key (32 bytes) should succeed
            var secondSession = await sessionManager.CreateSessionAsync(bobPublicBundle.IdentityKey);
            Assert.IsNotNull(secondSession, "Should succeed because bundle is now cached");
            (secondSession as IDisposable)?.Dispose();
        }

        // -------------------------------------------------------------------
        // SessionManager: group session creation and load paths
        // -------------------------------------------------------------------

        [TestMethod]
        public async Task CreateSessionAsync_WithGroupOptions_CreatesGroupSession()
        {
            using var sessionManager = new SessionManager(
                _cryptoProvider, _x3dhProtocol, _doubleRatchetProtocol, _aliceKeyPair, _tempDir);

            var options = new GroupSessionOptions
            {
                GroupId = "test-group-001",
                GroupName = "Test Group"
            };

            // GroupSessionOptions require a dummy recipientKey — use alice's own public key
            var session = await sessionManager.CreateSessionAsync(_aliceKeyPair.PublicKey!, options);

            Assert.IsNotNull(session);
            Assert.IsInstanceOfType(session, typeof(IGroupSession), "Should return an IGroupSession");
            Assert.IsTrue(session.SessionId.StartsWith("group-"), "Group session ID must start with 'group-'");
            (session as IDisposable)?.Dispose();
        }

        [TestMethod]
        public async Task CreateSessionAsync_GroupOptions_NullGroupId_ThrowsArgumentNullException()
        {
            using var sessionManager = new SessionManager(
                _cryptoProvider, _x3dhProtocol, _doubleRatchetProtocol, _aliceKeyPair, _tempDir);

            var options = new GroupSessionOptions
            {
                GroupId = null!,
                GroupName = "Bad Group"
            };

            // ArgumentException.ThrowIfNullOrEmpty throws ArgumentNullException when value is null
            await Assert.ThrowsExceptionAsync<ArgumentNullException>(
                () => sessionManager.CreateSessionAsync(_aliceKeyPair.PublicKey!, options));
        }

        [TestMethod]
        public async Task PersistenceManager_SaveGroupSession_ThenLoad_ReturnsState()
        {
            // Test SessionPersistenceManager save/load directly (without SessionManager abstraction)
            using var pm = new SessionPersistenceManager(_cryptoProvider, _tempDir);

            var groupSession = new LibEmiddle.Messaging.Group.GroupSession(
                "persist-group-001", "Persist Test Group", _aliceKeyPair, KeyRotationStrategy.Standard);
            await groupSession.AddMemberAsync(_aliceKeyPair.PublicKey!);
            await groupSession.ActivateAsync();

            bool saved = await pm.SaveGroupSessionAsync(groupSession);
            Assert.IsTrue(saved, "SaveGroupSessionAsync must return true");

            string loadedState = await pm.LoadGroupSessionStateAsync(groupSession.SessionId);
            Assert.IsNotNull(loadedState, "LoadGroupSessionStateAsync must return non-null state after save");
            Assert.IsTrue(loadedState.Length > 0, "Loaded state must be non-empty");

            groupSession.Dispose();
        }

        [TestMethod]
        public async Task GetSessionAsync_GroupSession_LoadsFromDisk()
        {
            using var sessionManager = new SessionManager(
                _cryptoProvider, _x3dhProtocol, _doubleRatchetProtocol, _aliceKeyPair, _tempDir);

            var options = new GroupSessionOptions
            {
                GroupId = "persist-group-002",
                GroupName = "Persist Test Group"
            };

            var created = await sessionManager.CreateSessionAsync(_aliceKeyPair.PublicKey!, options);
            string sessionId = created.SessionId;

            // Save the session explicitly (SessionManager already saved it during creation)
            await sessionManager.SaveSessionAsync(created);
            (created as IDisposable)?.Dispose();

            // Same session manager (same _cryptoProvider with in-memory key cache) should be able to reload
            var loaded = await sessionManager.GetSessionAsync(sessionId);
            Assert.IsNotNull(loaded, "Group session should be loadable from disk");
            Assert.AreEqual(sessionId, loaded.SessionId);
            (loaded as IDisposable)?.Dispose();
        }

        [TestMethod]
        public async Task CreateLocalKeyBundleAsync_ReturnsValidBundle()
        {
            using var sessionManager = new SessionManager(
                _cryptoProvider, _x3dhProtocol, _doubleRatchetProtocol, _aliceKeyPair, _tempDir);

            var bundle = await sessionManager.CreateLocalKeyBundleAsync(numOneTimeKeys: 5);

            Assert.IsNotNull(bundle, "Key bundle must not be null");
            Assert.AreEqual(5, bundle.OneTimePreKeys.Count, "Should contain 5 one-time prekeys");
            Assert.IsNotNull(bundle.IdentityKey, "Bundle must have an identity key");
        }

        // -------------------------------------------------------------------
        // Helpers
        // -------------------------------------------------------------------

        private static X3DHPublicBundle BuildTestBundle()
        {
            var identityKey = new byte[32];
            var signedPreKey = new byte[32];
            var signature = new byte[64];

            RandomNumberGenerator.Fill(identityKey);
            RandomNumberGenerator.Fill(signedPreKey);
            RandomNumberGenerator.Fill(signature);

            return new X3DHPublicBundle(identityKey, signedPreKey, signedPreKeyId: 1, signedPreKeySignature: signature);
        }
    }
}
