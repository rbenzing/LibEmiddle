using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Threading.Tasks;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;
using LibEmiddle.Messaging.Group;

namespace LibEmiddle.Tests.Unit
{
    /// <summary>
    /// The per-sender seen-message-ID set is capped. When the cap is exceeded the
    /// OLDEST entry must be evicted, so the replay window only ever reopens for the
    /// most distant messages. Evicting an arbitrary entry would reopen it for a recent
    /// message instead.
    /// </summary>
    [TestClass]
    public class GroupReplayEvictionTests
    {
        private const int Cap = 1000;
        private CryptoProvider _cryptoProvider;

        [TestInitialize]
        public void Setup()
        {
            _cryptoProvider = new CryptoProvider();
        }

        [TestCleanup]
        public void Cleanup()
        {
            try { _cryptoProvider?.Dispose(); } catch (ObjectDisposedException) { }
        }

        [TestMethod]
        public async Task DecryptMessageAsync_EvictionAtCap_RemovesOldestNotArbitrary()
        {
            var senderKey = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var receiverKey = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            string groupId = $"evict-test-{Guid.NewGuid()}";

            var sender = new GroupSession(groupId, "Eviction Test", senderKey);
            var receiver = new GroupSession(groupId, "Eviction Test", receiverKey);
            await sender.ActivateAsync();
            await receiver.ActivateAsync();
            await sender.AddMemberAsync(receiverKey.PublicKey);
            await receiver.AddMemberAsync(senderKey.PublicKey);
            receiver.ProcessDistributionMessage(sender.CreateDistributionMessage());

            // The first message is the one that must be evicted once the cap is passed.
            var first = await sender.EncryptMessageAsync("message 0");
            Assert.IsNotNull(await receiver.DecryptMessageAsync(first));

            EncryptedGroupMessage recent = null;
            for (int i = 1; i <= Cap; i++)
            {
                var m = await sender.EncryptMessageAsync($"message {i}");
                Assert.IsNotNull(await receiver.DecryptMessageAsync(m), $"message {i} should decrypt");
                if (i == Cap) recent = m;
            }

            // Oldest evicted: replaying it is accepted again.
            Assert.IsNotNull(await receiver.DecryptMessageAsync(first),
                "The oldest message ID should have been evicted at the cap, so replaying it is accepted.");

            // Most recent retained: replaying it is still rejected.
            Assert.IsNull(await receiver.DecryptMessageAsync(recent),
                "The most recent message ID must still be tracked and its replay rejected.");
        }
    }
}
