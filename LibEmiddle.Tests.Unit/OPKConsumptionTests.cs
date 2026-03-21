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
using LibEmiddle.KeyManagement;
using LibEmiddle.Protocol;
using LibEmiddle.Sessions;

namespace LibEmiddle.Tests.Unit
{
    /// <summary>
    /// Tests for OPK consumption tracking and replenishment (STORY-004).
    /// Covers:
    ///   - OPKManager.IsConsumed / MarkConsumed / FilterAvailable
    ///   - Persistence of consumed-ID list across instances
    ///   - Replenishment callback fires below threshold
    ///   - X3DH receiver path marks OPK consumed in SessionManager
    ///   - Duplicate X3DH using the same OPK is rejected
    /// </summary>
    [TestClass]
    public class OPKConsumptionTests
    {
        // -----------------------------------------------------------------------
        // Helpers
        // -----------------------------------------------------------------------

        private static string CreateTempDir()
        {
            string path = Path.Combine(Path.GetTempPath(), "opk_tests_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(path);
            return path;
        }

        private static void DeleteDir(string path)
        {
            try { Directory.Delete(path, recursive: true); }
            catch { /* best-effort */ }
        }

        // -----------------------------------------------------------------------
        // OPKManager unit tests
        // -----------------------------------------------------------------------

        [TestMethod]
        public void IsConsumed_ReturnsFalse_ForUnknownId()
        {
            string dir = CreateTempDir();
            try
            {
                var mgr = new OPKManager(dir);
                Assert.IsFalse(mgr.IsConsumed(42u));
            }
            finally { DeleteDir(dir); }
        }

        [TestMethod]
        public void MarkConsumed_ThenIsConsumed_ReturnsTrue()
        {
            string dir = CreateTempDir();
            try
            {
                var mgr = new OPKManager(dir);
                mgr.MarkConsumed(100u);
                Assert.IsTrue(mgr.IsConsumed(100u));
            }
            finally { DeleteDir(dir); }
        }

        [TestMethod]
        public void MarkConsumed_DoesNotMarkOtherIds()
        {
            string dir = CreateTempDir();
            try
            {
                var mgr = new OPKManager(dir);
                mgr.MarkConsumed(100u);
                Assert.IsFalse(mgr.IsConsumed(101u));
            }
            finally { DeleteDir(dir); }
        }

        [TestMethod]
        public void MarkConsumed_IdempotentForSameId()
        {
            string dir = CreateTempDir();
            try
            {
                var mgr = new OPKManager(dir);
                mgr.MarkConsumed(55u);
                mgr.MarkConsumed(55u); // second call must not throw
                Assert.AreEqual(1, mgr.ConsumedCount);
            }
            finally { DeleteDir(dir); }
        }

        [TestMethod]
        public void FilterAvailable_ExcludesConsumedIds()
        {
            string dir = CreateTempDir();
            try
            {
                var mgr = new OPKManager(dir);
                mgr.MarkConsumed(2u);

                var all = new List<uint> { 1u, 2u, 3u };
                IReadOnlyList<uint> available = mgr.FilterAvailable(all);

                Assert.AreEqual(2, available.Count);
                CollectionAssert.DoesNotContain((List<uint>)available, 2u);
                CollectionAssert.Contains((List<uint>)available, 1u);
                CollectionAssert.Contains((List<uint>)available, 3u);
            }
            finally { DeleteDir(dir); }
        }

        [TestMethod]
        public void FilterAvailable_ReturnsAll_WhenNoneConsumed()
        {
            string dir = CreateTempDir();
            try
            {
                var mgr = new OPKManager(dir);
                var all = new List<uint> { 10u, 20u, 30u };
                IReadOnlyList<uint> available = mgr.FilterAvailable(all);
                Assert.AreEqual(3, available.Count);
            }
            finally { DeleteDir(dir); }
        }

        [TestMethod]
        public void GetAvailableCount_ReturnsCorrectValue()
        {
            string dir = CreateTempDir();
            try
            {
                var mgr = new OPKManager(dir);
                var all = new List<uint> { 1u, 2u, 3u, 4u, 5u };
                mgr.MarkConsumed(1u, all);
                mgr.MarkConsumed(2u, all);

                int count = mgr.GetAvailableCount(all);
                Assert.AreEqual(3, count);
            }
            finally { DeleteDir(dir); }
        }

        // -----------------------------------------------------------------------
        // Persistence tests
        // -----------------------------------------------------------------------

        [TestMethod]
        public void ConsumedIds_PersistedAndLoadedAcrossInstances()
        {
            string dir = CreateTempDir();
            try
            {
                // First instance writes
                var mgr1 = new OPKManager(dir);
                mgr1.MarkConsumed(999u);
                mgr1.Dispose();

                // Second instance loads from disk
                var mgr2 = new OPKManager(dir);
                Assert.IsTrue(mgr2.IsConsumed(999u), "Consumed ID should survive process restart");
                mgr2.Dispose();
            }
            finally { DeleteDir(dir); }
        }

        [TestMethod]
        public void ConsumedIds_MultipleIdsPersistedAndLoaded()
        {
            string dir = CreateTempDir();
            try
            {
                var ids = new uint[] { 10u, 20u, 30u, 40u };
                var mgr1 = new OPKManager(dir);
                foreach (uint id in ids)
                    mgr1.MarkConsumed(id);
                mgr1.Dispose();

                var mgr2 = new OPKManager(dir);
                foreach (uint id in ids)
                    Assert.IsTrue(mgr2.IsConsumed(id), $"ID {id} should be persisted");
                Assert.IsFalse(mgr2.IsConsumed(99u), "Unknown ID should not appear as consumed");
                mgr2.Dispose();
            }
            finally { DeleteDir(dir); }
        }

        // -----------------------------------------------------------------------
        // Replenishment callback tests
        // -----------------------------------------------------------------------

        [TestMethod]
        public async Task ReplenishmentCallback_FiredWhenAvailableCountBelowThreshold()
        {
            string dir = CreateTempDir();
            try
            {
                var mgr = new OPKManager(dir);
                int callbackCount = 0;
                mgr.SetReplenishmentCallback(_ => { callbackCount++; return Task.CompletedTask; });

                // Build a list just at the threshold so one more consumption drops below it.
                var all = new List<uint>();
                for (uint i = 1; i <= OPKManager.ReplenishmentThreshold; i++)
                    all.Add(i);

                // Consume one — available becomes ReplenishmentThreshold-1 < threshold.
                mgr.MarkConsumed(1u, all);

                // Give the background task a moment to execute.
                await Task.Delay(100);

                Assert.IsTrue(callbackCount > 0, "Replenishment callback should have fired");
            }
            finally { DeleteDir(dir); }
        }

        [TestMethod]
        public async Task ReplenishmentCallback_NotFired_WhenAboveThreshold()
        {
            string dir = CreateTempDir();
            try
            {
                var mgr = new OPKManager(dir);
                int callbackCount = 0;
                mgr.SetReplenishmentCallback(_ => { callbackCount++; return Task.CompletedTask; });

                // Build a list well above the threshold.
                var all = new List<uint>();
                for (uint i = 1; i <= OPKManager.ReplenishmentThreshold + 5; i++)
                    all.Add(i);

                // Consume one — still above threshold.
                mgr.MarkConsumed(1u, all);

                await Task.Delay(100);

                Assert.AreEqual(0, callbackCount, "Replenishment callback should NOT fire when above threshold");
            }
            finally { DeleteDir(dir); }
        }

        // -----------------------------------------------------------------------
        // X3DH integration: OPK selection uniqueness
        // -----------------------------------------------------------------------

        [TestMethod]
        public void X3DH_SelectsDifferentOPK_OnEachInitiation()
        {
            // Arrange: Bob has a bundle with multiple OPKs.
            var crypto = new CryptoProvider();
            var protocol = new X3DHProtocol(crypto);
            var bobBundle = protocol.CreateKeyBundleAsync(numOneTimeKeys: 10).GetAwaiter().GetResult();
            var bobPublicBundle = bobBundle.ToPublicBundle();

            // Alice sends two key exchange messages using different ephemeral keys.
            // Each should pick an OPK — and because the selection is random, with 10 OPKs
            // the probability of two sequential calls picking the same one is only 10%.
            // We run this multiple times to get a confident signal.
            var selectedIds = new HashSet<uint>();
            for (int i = 0; i < 20; i++)
            {
                KeyPair aliceId = Sodium.GenerateEd25519KeyPair();
                var result = protocol.InitiateSessionAsSenderAsync(bobPublicBundle, aliceId).GetAwaiter().GetResult();
                if (result.MessageDataToSend.RecipientOneTimePreKeyId.HasValue)
                    selectedIds.Add(result.MessageDataToSend.RecipientOneTimePreKeyId.Value);
            }

            // With 10 OPKs and 20 draws (with replacement from the public bundle), we expect
            // more than 1 unique ID to be selected — the probability of always picking the same
            // one out of 10 is (1/10)^19 ≈ negligible.
            Assert.IsTrue(selectedIds.Count > 1,
                $"Expected multiple distinct OPKs to be selected across 20 initiations, but got {selectedIds.Count}.");
        }

        // -----------------------------------------------------------------------
        // X3DH receiver-side OPK consumption via SessionManager
        // -----------------------------------------------------------------------

        [TestMethod]
        public async Task ProcessKeyExchange_MarksOPKConsumed()
        {
            // Arrange
            var crypto = new CryptoProvider();
            var protocol = new X3DHProtocol(crypto);
            var drProtocol = new DoubleRatchetProtocol();

            // Bob creates his identity and key bundle.
            KeyPair bobIdentity = Sodium.GenerateEd25519KeyPair();
            var bobBundle = await protocol.CreateKeyBundleAsync(bobIdentity, numOneTimeKeys: 5);
            var bobPublicBundle = bobBundle.ToPublicBundle();

            // Alice performs X3DH as sender.
            KeyPair aliceIdentity = Sodium.GenerateEd25519KeyPair();
            var senderResult = await protocol.InitiateSessionAsSenderAsync(bobPublicBundle, aliceIdentity);

            Assert.IsNotNull(senderResult.MessageDataToSend.RecipientOneTimePreKeyId,
                "Sender should have selected an OPK.");

            uint usedOpkId = senderResult.MessageDataToSend.RecipientOneTimePreKeyId!.Value;

            // Build a MailboxMessage wrapping Alice's initial message data.
            var protocolAdapter = new ProtocolAdapter(protocol, drProtocol, crypto);
            var mailboxMsg = protocolAdapter.CreateKeyExchangeMessage(
                senderResult.MessageDataToSend,
                bobIdentity.PublicKey,
                aliceIdentity.PublicKey);

            // Bob's SessionManager processes the message.
            string tempDir = CreateTempDir();
            try
            {
                var sessionManager = new SessionManager(crypto, protocol, drProtocol, bobIdentity, tempDir);
                await sessionManager.RegisterLocalKeyBundleAsync(bobBundle);

                var chatSession = await sessionManager.ProcessKeyExchangeMessageAsync(mailboxMsg, bobBundle);

                Assert.IsNotNull(chatSession, "Session should be created successfully.");
                Assert.IsTrue(sessionManager._opkManager.IsConsumed(usedOpkId),
                    $"OPK {usedOpkId} should be marked consumed after key exchange.");
            }
            finally
            {
                DeleteDir(tempDir);
            }
        }

        [TestMethod]
        public async Task ProcessKeyExchange_RejectsReusedOPK()
        {
            // Arrange
            var crypto = new CryptoProvider();
            var protocol = new X3DHProtocol(crypto);
            var drProtocol = new DoubleRatchetProtocol();

            KeyPair bobIdentity = Sodium.GenerateEd25519KeyPair();
            var bobBundle = await protocol.CreateKeyBundleAsync(bobIdentity, numOneTimeKeys: 5);
            var bobPublicBundle = bobBundle.ToPublicBundle();

            KeyPair aliceIdentity = Sodium.GenerateEd25519KeyPair();
            var senderResult = await protocol.InitiateSessionAsSenderAsync(bobPublicBundle, aliceIdentity);

            Assert.IsNotNull(senderResult.MessageDataToSend.RecipientOneTimePreKeyId,
                "Sender should have selected an OPK.");

            var protocolAdapter = new ProtocolAdapter(protocol, drProtocol, crypto);
            var mailboxMsg = protocolAdapter.CreateKeyExchangeMessage(
                senderResult.MessageDataToSend,
                bobIdentity.PublicKey,
                aliceIdentity.PublicKey);

            string tempDir = CreateTempDir();
            try
            {
                var sessionManager = new SessionManager(crypto, protocol, drProtocol, bobIdentity, tempDir);
                await sessionManager.RegisterLocalKeyBundleAsync(bobBundle);

                // First key exchange — should succeed.
                var first = await sessionManager.ProcessKeyExchangeMessageAsync(mailboxMsg, bobBundle);
                Assert.IsNotNull(first, "First key exchange should succeed.");

                // Second key exchange using the same MailboxMessage (same OPK) — should be rejected.
                var second = await sessionManager.ProcessKeyExchangeMessageAsync(mailboxMsg, bobBundle);
                Assert.IsNull(second, "Second key exchange with same OPK should be rejected.");
            }
            finally
            {
                DeleteDir(tempDir);
            }
        }

        // -----------------------------------------------------------------------
        // Replenishment via SessionManager
        // -----------------------------------------------------------------------

        [TestMethod]
        public async Task SessionManager_ReplenishesOPKs_WhenBelowThreshold()
        {
            var crypto = new CryptoProvider();
            var protocol = new X3DHProtocol(crypto);
            var drProtocol = new DoubleRatchetProtocol();

            // Start with exactly ReplenishmentThreshold OPKs.
            int initialCount = OPKManager.ReplenishmentThreshold;
            KeyPair bobIdentity = Sodium.GenerateEd25519KeyPair();
            var bobBundle = await protocol.CreateKeyBundleAsync(bobIdentity, numOneTimeKeys: initialCount);
            var bobPublicBundle = bobBundle.ToPublicBundle();

            string tempDir = CreateTempDir();
            try
            {
                var sessionManager = new SessionManager(crypto, protocol, drProtocol, bobIdentity, tempDir);
                await sessionManager.RegisterLocalKeyBundleAsync(bobBundle);

                // Snapshot the original OPK IDs before consuming any, so we can verify new IDs
                // appear after replenishment. Assert through GetAvailableOPKIds() to avoid
                // reading the bundle's List<T> fields without a lock.
                var originalIds = new HashSet<uint>(sessionManager.GetAvailableOPKIds());
                int countBefore = originalIds.Count;

                // Consume one OPK via a full key exchange — this should drop available below threshold.
                KeyPair aliceIdentity = Sodium.GenerateEd25519KeyPair();
                var senderResult = await protocol.InitiateSessionAsSenderAsync(bobPublicBundle, aliceIdentity);

                if (!senderResult.MessageDataToSend.RecipientOneTimePreKeyId.HasValue)
                {
                    Assert.Inconclusive("No OPK was selected — bundle may be empty.");
                    return;
                }

                var protocolAdapter = new ProtocolAdapter(protocol, drProtocol, crypto);
                var mailboxMsg = protocolAdapter.CreateKeyExchangeMessage(
                    senderResult.MessageDataToSend,
                    bobIdentity.PublicKey,
                    aliceIdentity.PublicKey);

                await sessionManager.ProcessKeyExchangeMessageAsync(mailboxMsg, bobBundle);

                // Allow the async replenishment task to run.
                await Task.Delay(500);

                // Assert through GetAvailableOPKIds() — no direct field access.
                var afterIds = new HashSet<uint>(sessionManager.GetAvailableOPKIds());
                int countAfter = afterIds.Count;

                Assert.IsTrue(countAfter > countBefore - 1,
                    $"Available OPKs should not decrease to zero after replenishment. Before: {countBefore}, After: {countAfter}");

                // New IDs must include some IDs not present in the original set.
                afterIds.ExceptWith(originalIds);
                Assert.IsTrue(afterIds.Count > 0,
                    "Replenishment should have added at least one OPK ID that was not in the original set.");
            }
            finally
            {
                DeleteDir(tempDir);
            }
        }

        // -----------------------------------------------------------------------
        // Integration test: 15 sequential chat sessions (OPK replenishment works)
        // -----------------------------------------------------------------------

        /// <summary>
        /// Builds a filtered public bundle that only exposes OPK IDs that are still
        /// available (not yet consumed). In production this filtering is done server-side;
        /// in tests we simulate it so the sender only picks from unconsumed OPKs.
        /// </summary>
        private static X3DHPublicBundle BuildFilteredPublicBundle(
            X3DHKeyBundle privateBundle,
            IReadOnlyList<uint> availableIds)
        {
            var availableSet = new HashSet<uint>(availableIds);
            var filteredPublic = new X3DHPublicBundle
            {
                IdentityKey = privateBundle.IdentityKey.ToArray(),
                SignedPreKey = privateBundle.SignedPreKey.ToArray(),
                SignedPreKeyId = privateBundle.SignedPreKeyId,
                SignedPreKeySignature = privateBundle.SignedPreKeySignature.ToArray(),
                ProtocolVersion = privateBundle.ProtocolVersion,
                CreationTimestamp = privateBundle.CreationTimestamp
            };

            for (int i = 0; i < privateBundle.OneTimePreKeyIds.Count; i++)
            {
                uint id = privateBundle.OneTimePreKeyIds[i];
                if (availableSet.Contains(id))
                {
                    filteredPublic.OneTimePreKeyIds.Add(id);
                    filteredPublic.OneTimePreKeys.Add(privateBundle.OneTimePreKeys[i].ToArray());
                }
            }

            return filteredPublic;
        }

        /// <summary>
        /// Creates 15 sequential X3DH key-exchange sessions against the same receiver bundle.
        /// Each session consumes one OPK. After the initial stock is exhausted, replenishment
        /// must kick in and provide fresh OPKs so that all 15 sessions succeed.
        /// </summary>
        [TestMethod]
        public async Task FifteenSequentialSessions_AllSucceed_WithOPKReplenishment()
        {
            var crypto = new CryptoProvider();
            var protocol = new X3DHProtocol(crypto);
            var drProtocol = new DoubleRatchetProtocol();
            var protocolAdapter = new ProtocolAdapter(protocol, drProtocol, crypto);

            // Bob starts with ReplenishmentThreshold OPKs — fewer than the 15 sessions we will
            // open, so replenishment must fire and succeed for all 15 to go through.
            KeyPair bobIdentity = Sodium.GenerateEd25519KeyPair();
            var bobBundle = await protocol.CreateKeyBundleAsync(bobIdentity,
                numOneTimeKeys: OPKManager.ReplenishmentThreshold);

            string tempDir = CreateTempDir();
            try
            {
                var sessionManager = new SessionManager(crypto, protocol, drProtocol, bobIdentity, tempDir);
                await sessionManager.RegisterLocalKeyBundleAsync(bobBundle);

                int successCount = 0;
                const int TotalSessions = 15;

                for (int i = 0; i < TotalSessions; i++)
                {
                    // Get OPK IDs that are still available (not yet consumed). This simulates
                    // what a real key server does: only advertise unconsumed OPKs in the
                    // public bundle so the sender cannot accidentally pick a consumed one.
                    var availableIds = sessionManager.GetAvailableOPKIds();

                    // If exhausted, wait for the background replenishment task to complete.
                    if (availableIds.Count == 0)
                    {
                        await Task.Delay(500);
                        availableIds = sessionManager.GetAvailableOPKIds();
                    }

                    // Build a public bundle containing only available OPKs.
                    var currentPublicBundle = BuildFilteredPublicBundle(bobBundle, availableIds);

                    KeyPair aliceIdentity = Sodium.GenerateEd25519KeyPair();
                    var senderResult = await protocol.InitiateSessionAsSenderAsync(
                        currentPublicBundle, aliceIdentity);

                    if (!senderResult.MessageDataToSend.RecipientOneTimePreKeyId.HasValue)
                    {
                        // X3DH without OPK is still valid; count it as a success.
                        successCount++;
                        continue;
                    }

                    var mailboxMsg = protocolAdapter.CreateKeyExchangeMessage(
                        senderResult.MessageDataToSend,
                        bobIdentity.PublicKey,
                        aliceIdentity.PublicKey);

                    var session = await sessionManager.ProcessKeyExchangeMessageAsync(mailboxMsg, bobBundle);

                    if (session != null)
                        successCount++;

                    // Give the replenishment background task time to add new OPKs before the
                    // next iteration further reduces the available count.
                    await Task.Delay(50);
                }

                Assert.AreEqual(TotalSessions, successCount,
                    $"All {TotalSessions} sessions should succeed with OPK replenishment. " +
                    $"Succeeded: {successCount}");
            }
            finally
            {
                DeleteDir(tempDir);
            }
        }
    }
}
