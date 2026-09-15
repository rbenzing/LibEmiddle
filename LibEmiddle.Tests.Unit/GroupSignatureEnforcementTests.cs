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
    /// Signature verification in GroupSession must be mandatory, not conditional on a
    /// signature being present. Omitting the signature must reject the message, because
    /// SenderIdentityKey is public and the transport is untrusted: an attacker who can
    /// write to the transport could otherwise impersonate any member.
    /// </summary>
    [TestClass]
    public class GroupSignatureEnforcementTests
    {
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

        internal async Task<(GroupSession sender, GroupSession receiver)> BuildPairAsync()
        {
            var senderKey = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var receiverKey = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            string groupId = $"sig-enforce-{Guid.NewGuid()}";
            const string groupName = "Signature Enforcement Group";

            var sender = new GroupSession(groupId, groupName, senderKey);
            var receiver = new GroupSession(groupId, groupName, receiverKey);

            await sender.ActivateAsync();
            await receiver.ActivateAsync();

            await sender.AddMemberAsync(receiverKey.PublicKey);
            await receiver.AddMemberAsync(senderKey.PublicKey);

            receiver.ProcessDistributionMessage(sender.CreateDistributionMessage());
            sender.ProcessDistributionMessage(receiver.CreateDistributionMessage());

            return (sender, receiver);
        }

        [TestMethod]
        public async Task DecryptMessageAsync_NullSignature_IsRejected()
        {
            var (sender, receiver) = await BuildPairAsync();
            var message = await sender.EncryptMessageAsync("unsigned payload");
            Assert.IsNotNull(message, "precondition: sender produced a message");

            message.Signature = null;

            string result = await receiver.DecryptMessageAsync(message);

            Assert.IsNull(result,
                "A group message with no signature must be rejected. Accepting it lets any " +
                "party who can write to the transport impersonate a member.");
        }

        [TestMethod]
        public async Task DecryptMessageAsync_ForgedSignature_IsRejected()
        {
            var (sender, receiver) = await BuildPairAsync();
            var message = await sender.EncryptMessageAsync("tampered payload");
            Assert.IsNotNull(message);
            Assert.IsNotNull(message.Signature, "precondition: sender signed the message");

            message.Signature[0] ^= 0xFF;

            string result = await receiver.DecryptMessageAsync(message);

            Assert.IsNull(result, "A group message with an invalid signature must be rejected.");
        }
    }
}
