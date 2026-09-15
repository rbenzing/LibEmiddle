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

        [TestMethod]
        public async Task ProcessDistributionMessage_NullSignature_IsRejected()
        {
            var (sender, receiver) = await BuildPairAsync();
            var distribution = sender.CreateDistributionMessage();
            Assert.IsNotNull(distribution.Signature, "precondition: distributions are signed");

            distribution.Signature = null;

            bool accepted = receiver.ProcessDistributionMessage(distribution);

            Assert.IsFalse(accepted,
                "An unsigned sender-key distribution must be rejected. Accepting it installs " +
                "an attacker-chosen chain key under a member's public identity key.");
        }

        [TestMethod]
        public async Task ProcessDistributionMessage_ForgedSignature_IsRejected()
        {
            var (sender, receiver) = await BuildPairAsync();
            var distribution = sender.CreateDistributionMessage();
            Assert.IsNotNull(distribution.Signature);

            distribution.Signature[0] ^= 0xFF;

            bool accepted = receiver.ProcessDistributionMessage(distribution);

            Assert.IsFalse(accepted, "A distribution with an invalid signature must be rejected.");
        }

        [TestMethod]
        public async Task DecryptMessageAsync_SignatureFromAnotherMember_IsRejected()
        {
            // A signature must bind to the sender it claims. Taking a message genuinely
            // signed by one member and relabelling it as another member's must fail, or
            // any member could be impersonated by replaying another's traffic under their
            // identity key.
            var senderKey = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var otherKey = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var receiverKey = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            string groupId = $"sig-bind-{Guid.NewGuid()}";

            var sender = new GroupSession(groupId, "Binding Test", senderKey);
            var receiver = new GroupSession(groupId, "Binding Test", receiverKey);
            await sender.ActivateAsync();
            await receiver.ActivateAsync();

            // Both sender and other are members, so the membership check passes and the
            // signature check is what must reject the message.
            await sender.AddMemberAsync(receiverKey.PublicKey);
            await receiver.AddMemberAsync(senderKey.PublicKey);
            await receiver.AddMemberAsync(otherKey.PublicKey);
            receiver.ProcessDistributionMessage(sender.CreateDistributionMessage());

            var message = await sender.EncryptMessageAsync("relabelled payload");
            Assert.IsNotNull(message);

            // Keep the genuine signature, claim a different member as the sender.
            message.SenderIdentityKey = otherKey.PublicKey;

            string result = await receiver.DecryptMessageAsync(message);

            Assert.IsNull(result,
                "A message signed by one member but labelled as another must be rejected.");
        }

        [TestMethod]
        public async Task ProcessDistributionMessage_SignatureFromAnotherMember_IsRejected()
        {
            var senderKey = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var otherKey = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var receiverKey = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            string groupId = $"dist-bind-{Guid.NewGuid()}";

            var sender = new GroupSession(groupId, "Binding Test", senderKey);
            var receiver = new GroupSession(groupId, "Binding Test", receiverKey);
            await sender.ActivateAsync();
            await receiver.ActivateAsync();
            await receiver.AddMemberAsync(senderKey.PublicKey);
            await receiver.AddMemberAsync(otherKey.PublicKey);

            var distribution = sender.CreateDistributionMessage();
            Assert.IsNotNull(distribution.Signature);

            distribution.SenderIdentityKey = otherKey.PublicKey;

            bool accepted = receiver.ProcessDistributionMessage(distribution);

            Assert.IsFalse(accepted,
                "A distribution signed by one member but claiming another must be rejected. " +
                "Accepting it would install the signer's chain key under the other member's identity.");
        }

        [TestMethod]
        public async Task DecryptMessageAsync_NullCiphertext_IsRejectedWithoutThrowing()
        {
            var (sender, receiver) = await BuildPairAsync();
            var message = await sender.EncryptMessageAsync("payload");
            Assert.IsNotNull(message);

            message.Ciphertext = null;

            string result = await receiver.DecryptMessageAsync(message);

            Assert.IsNull(result,
                "A message with null ciphertext must be rejected by validation, not reach " +
                "the signing-data serialiser where it would throw.");
        }

        [TestMethod]
        public async Task DecryptMessageAsync_EmptyCiphertext_IsRejected()
        {
            var (sender, receiver) = await BuildPairAsync();
            var message = await sender.EncryptMessageAsync("payload");
            Assert.IsNotNull(message);

            message.Ciphertext = Array.Empty<byte>();

            string result = await receiver.DecryptMessageAsync(message);

            Assert.IsNull(result, "A message with empty ciphertext must be rejected.");
        }
    }
}
