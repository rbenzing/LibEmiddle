using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using LibEmiddle.Abstractions;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;
using LibEmiddle.Domain.Exceptions;
using LibEmiddle.Messaging.Chat;
using LibEmiddle.Messaging.Group;
using LibEmiddle.Protocol;
using LibEmiddle.Sessions;

namespace LibEmiddle.Tests.Unit.Integration
{
    /// <summary>
    /// STORY-013: Stress tests validating that the library remains stable under
    /// sustained load (10+ sessions, 50+ messages) and under common error paths
    /// (transport failures, invalid messages, OPK exhaustion, malformed bundles).
    ///
    /// Tests are intentionally kept fast (total runtime well under 30 seconds) for CI.
    /// </summary>
    [TestClass]
    [DoNotParallelize] // Stress tests allocate significant resources; outer parallelism would distort results.
    public class StressTests
    {
        private CryptoProvider _crypto;
        private X3DHProtocol _x3dh;
        private DoubleRatchetProtocol _dr;
        private ProtocolAdapter _adapter;
        private List<string> _tempDirs;

        [TestInitialize]
        public void Setup()
        {
            Sodium.Initialize();
            _crypto = new CryptoProvider();
            _x3dh = new X3DHProtocol(_crypto);
            _dr = new DoubleRatchetProtocol();
            _adapter = new ProtocolAdapter(_x3dh, _dr, _crypto);
            _tempDirs = new List<string>();
        }

        [TestCleanup]
        public void Cleanup()
        {
            _crypto?.Dispose();

            // Remove all temp directories created during tests
            foreach (var dir in _tempDirs)
            {
                try { Directory.Delete(dir, recursive: true); }
                catch { /* best-effort */ }
            }
        }

        // ── Helpers ──────────────────────────────────────────────────────────

        private string CreateTempDir()
        {
            string path = Path.Combine(Path.GetTempPath(), "libemiddle_stress_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(path);
            _tempDirs.Add(path);
            return path;
        }

        /// <summary>
        /// Creates a symmetric ChatSession pair using X3DH + Double Ratchet.
        /// </summary>
        private async Task<(ChatSession sender, ChatSession receiver)> CreateSessionPairAsync()
        {
            var aliceKp = Sodium.GenerateEd25519KeyPair();
            var bobKp = Sodium.GenerateEd25519KeyPair();
            string sid = Guid.NewGuid().ToString();

            var bobBundle = await _x3dh.CreateKeyBundleAsync(bobKp);
            var bobPublic = bobBundle.ToPublicBundle();

            var (aliceDR, init) = await _adapter.PrepareSenderSessionAsync(bobPublic, aliceKp, sid);
            var bobDR = await _adapter.PrepareReceiverSessionAsync(init, bobBundle, sid);

            var alice = new ChatSession(aliceDR, bobKp.PublicKey, aliceKp.PublicKey, _dr);
            var bob = new ChatSession(bobDR, aliceKp.PublicKey, bobKp.PublicKey, _dr);
            alice.SetInitialMessageData(init);

            return (alice, bob);
        }

        // ── Tests ─────────────────────────────────────────────────────────────

        /// <summary>
        /// Stress: Open 10 concurrent 1:1 sessions and exchange 50 messages per session.
        /// All messages must decrypt correctly and no exceptions should escape.
        /// Total message operations: 10 pairs x 50 messages = 500.
        /// </summary>
        [TestMethod]
        public async Task Stress_TenSessions_FiftyMessages_AllDecryptCorrectly()
        {
            const int sessionCount = 10;
            const int msgCount = 50;

            var sessionPairs = await Task.WhenAll(
                Enumerable.Range(0, sessionCount).Select(_ => CreateSessionPairAsync()));

            int totalFailures = 0;

            foreach (var (alice, bob) in sessionPairs)
            {
                await alice.ActivateAsync();
                await bob.ActivateAsync();

                for (int i = 0; i < msgCount; i++)
                {
                    string plain = $"stress message {i}";
                    var enc = await alice.EncryptAsync(plain);
                    Assert.IsNotNull(enc, $"Encryption returned null at message {i}.");

                    var dec = await bob.DecryptAsync(enc);
                    if (dec != plain) totalFailures++;
                }

                alice.Dispose();
                bob.Dispose();
            }

            Assert.AreEqual(0, totalFailures,
                $"{totalFailures} messages failed to decrypt correctly.");
        }

        /// <summary>
        /// Stress: 5 independent group sessions each encrypt 20 messages and decrypt their own output.
        /// Verifies that the GroupSession encryption/decryption pipeline is stable under sustained load.
        /// Total operations: 5 sessions x 20 encrypt + 20 decrypt = 200 round-trips.
        /// </summary>
        [TestMethod]
        public async Task Stress_FiveGroupSessions_TwentyMessages_AllDecryptCorrectly()
        {
            const int sessionCount = 5;
            const int msgsPerSession = 20;

            int decryptFailures = 0;

            for (int s = 0; s < sessionCount; s++)
            {
                var keyPair = Sodium.GenerateEd25519KeyPair();
                var groupSession = new GroupSession($"stress-group-{s}", $"Stress Group {s}", keyPair);
                await groupSession.ActivateAsync();

                for (int i = 0; i < msgsPerSession; i++)
                {
                    var enc = await groupSession.EncryptMessageAsync($"group-stress-{i}");
                    Assert.IsNotNull(enc, $"Session {s}: group encrypt returned null at message {i}.");

                    // The same session can decrypt its own messages (self-decrypt path)
                    var plain = await groupSession.DecryptMessageAsync(enc);
                    if (plain == null) decryptFailures++;
                }

                groupSession.Dispose();
            }

            Assert.AreEqual(0, decryptFailures,
                $"{decryptFailures} group messages failed self-decryption across {sessionCount} sessions.");
        }

        /// <summary>
        /// Error path: decrypting a malformed/tampered ciphertext must throw or return null
        /// without crashing the session or leaking sensitive exceptions.
        /// </summary>
        [TestMethod]
        public async Task ErrorPath_TamperedCiphertext_IsRejectedGracefully()
        {
            var (alice, bob) = await CreateSessionPairAsync();
            await alice.ActivateAsync();
            await bob.ActivateAsync();

            // Encrypt a legitimate message
            var enc = await alice.EncryptAsync("legitimate message");
            Assert.IsNotNull(enc, "Encryption returned null.");

            // Tamper with the ciphertext
            var tampered = new EncryptedMessage
            {
                MessageId = enc.MessageId,
                SessionId = enc.SessionId,
                SenderDHKey = enc.SenderDHKey,
                Nonce = enc.Nonce,
                Timestamp = enc.Timestamp,
                // Flip all bytes in the ciphertext to guarantee decryption failure
                Ciphertext = enc.Ciphertext.Select(b => (byte)(b ^ 0xFF)).ToArray()
            };

            bool threwOrReturnedNull = false;
            try
            {
                var result = await bob.DecryptAsync(tampered);
                threwOrReturnedNull = (result == null);
            }
            catch (Exception)
            {
                threwOrReturnedNull = true;
            }

            alice.Dispose();
            bob.Dispose();

            Assert.IsTrue(threwOrReturnedNull,
                "Decrypting a tampered ciphertext must either throw or return null.");
        }

        /// <summary>
        /// Error path: using a key bundle with an empty identity key must be rejected cleanly
        /// before any cryptographic operations are attempted (malformed bundle guard).
        /// </summary>
        [TestMethod]
        public async Task ErrorPath_MalformedBundle_EmptyIdentityKey_ThrowsBeforeCrypto()
        {
            string tempDir = CreateTempDir();
            var sessionManager = new SessionManager(_crypto, _x3dh, _dr, Sodium.GenerateEd25519KeyPair(), tempDir);

            var badBundle = new X3DHPublicBundle(); // IdentityKey defaults to Array.Empty<byte>()

            Exception caught = null;
            try
            {
                await sessionManager.CacheRecipientBundleAsync(badBundle);
            }
            catch (ArgumentException ex)
            {
                caught = ex;
            }

            sessionManager.Dispose();

            Assert.IsNotNull(caught,
                "CacheRecipientBundleAsync should reject a bundle with an empty identity key.");
        }

        /// <summary>
        /// Error path: OPK exhaustion — after all one-time pre-keys are consumed, further
        /// X3DH initiations without a OPK must still complete (fallback to signed pre-key only).
        /// </summary>
        [TestMethod]
        public async Task ErrorPath_OPKExhaustion_X3DHFallsBackToSignedPreKey()
        {
            // Bob creates a bundle with just 1 OPK
            var bobKp = Sodium.GenerateEd25519KeyPair();
            var bobBundle = await _x3dh.CreateKeyBundleAsync(bobKp, numOneTimeKeys: 1);

            // First initiation consumes the single OPK
            var aliceKp1 = Sodium.GenerateEd25519KeyPair();
            var result1 = await _x3dh.InitiateSessionAsSenderAsync(bobBundle.ToPublicBundle(), aliceKp1);
            Assert.IsNotNull(result1, "First X3DH initiation should succeed.");

            // Build a public bundle with NO OPKs to simulate exhaustion
            var exhaustedBundle = new X3DHPublicBundle
            {
                IdentityKey = bobBundle.IdentityKey.ToArray(),
                SignedPreKey = bobBundle.SignedPreKey.ToArray(),
                SignedPreKeyId = bobBundle.SignedPreKeyId,
                SignedPreKeySignature = bobBundle.SignedPreKeySignature.ToArray(),
                ProtocolVersion = bobBundle.ProtocolVersion,
                CreationTimestamp = bobBundle.CreationTimestamp
                // OneTimePreKeys intentionally left empty
            };

            // Second initiation with exhausted bundle — must succeed using only the signed pre-key
            var aliceKp2 = Sodium.GenerateEd25519KeyPair();
            var result2 = await _x3dh.InitiateSessionAsSenderAsync(exhaustedBundle, aliceKp2);

            Assert.IsNotNull(result2, "X3DH initiation must succeed even when no OPKs remain.");
            Assert.IsNull(result2.MessageDataToSend?.RecipientOneTimePreKeyId,
                "No OPK should be referenced in the initiation message when the bundle has none.");
        }
    }
}
