using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Buffers.Binary;
using System.IO;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using LibEmiddle.Core;
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

        /// <summary>
        /// Same as <see cref="BuildPairAsync"/> but also returns the sender's raw key pair, so
        /// a test can re-sign a message it has tampered with after the sender originally signed
        /// it (needed to isolate a guard that runs BEFORE signature verification from signature
        /// verification itself).
        /// </summary>
        private async Task<(GroupSession sender, GroupSession receiver, KeyPair senderKey)> BuildPairWithSenderKeyAsync()
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

            return (sender, receiver, senderKey);
        }

        // Mirrors the private wire format GroupSession.GetMessageDataToSign builds internally
        // (via GroupSignatureData.ForMessage), including its null-coalescing of Ciphertext to
        // Array.Empty<byte>() — see LibEmiddle/Messaging/Group/GroupSignatureData.cs. This lets
        // a test produce a signature that ValidateGroupMessage's signature check would accept
        // for a message it has tampered with, INCLUDING a message whose Ciphertext is null,
        // isolating the explicit ciphertext guard (which runs before signature verification)
        // from signature verification itself.
        private const byte MessageDomainTag = 0x01;

        private static byte[] BuildGroupMessageSigningPayload(EncryptedGroupMessage message)
        {
            using var ms = new MemoryStream();

            ms.WriteByte(MessageDomainTag);
            WriteField(ms, Encoding.UTF8.GetBytes(message.GroupId ?? string.Empty));
            WriteField(ms, message.SenderIdentityKey ?? Array.Empty<byte>());
            WriteField(ms, message.Ciphertext ?? Array.Empty<byte>());
            WriteField(ms, message.Nonce ?? Array.Empty<byte>());
            WriteInt64(ms, message.Timestamp);
            WriteInt64(ms, message.RotationEpoch);
            WriteField(ms, Encoding.UTF8.GetBytes(message.MessageId ?? string.Empty));

            return ms.ToArray();
        }

        private static void WriteField(Stream stream, byte[] value)
        {
            WriteUInt32(stream, (uint)value.Length);
            stream.Write(value, 0, value.Length);
        }

        private static void WriteUInt32(Stream stream, uint value)
        {
            Span<byte> buffer = stackalloc byte[sizeof(uint)];
            BinaryPrimitives.WriteUInt32BigEndian(buffer, value);
            stream.Write(buffer);
        }

        private static void WriteInt64(Stream stream, long value)
        {
            Span<byte> buffer = stackalloc byte[sizeof(long)];
            BinaryPrimitives.WriteInt64BigEndian(buffer, value);
            stream.Write(buffer);
        }

        // Invokes the private GroupSession.ValidateGroupMessage directly via reflection.
        //
        // This is necessary (not merely convenient) for the null/empty-ciphertext tests below:
        // DecryptMessageAsync wraps the AES-decryption step in a catch-all that returns null for
        // ANY exception, including the ArgumentNullException/CryptographicException that
        // AES.AESDecrypt throws for a null or empty ciphertext. So even with the explicit
        // ciphertext guard in ValidateGroupMessage deleted entirely, a message with null or
        // empty Ciphertext that reaches AES decryption is independently turned into a null
        // result there too -- DecryptMessageAsync's return value alone cannot distinguish
        // "rejected by the guard" from "rejected because AES threw and the exception was
        // swallowed downstream". Calling ValidateGroupMessage directly removes that confound.
        private static bool InvokeValidateGroupMessage(GroupSession session, EncryptedGroupMessage message)
        {
            var method = typeof(GroupSession).GetMethod("ValidateGroupMessage",
                BindingFlags.NonPublic | BindingFlags.Instance);
            Assert.IsNotNull(method, "GroupSession.ValidateGroupMessage was not found via reflection " +
                "(method renamed or removed) — this test needs updating to match.");
            return (bool)method!.Invoke(session, new object[] { message })!;
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
            // signed by one member and relabelling it as another member's must fail.
            //
            // WHAT THIS TEST DOES AND DOES NOT PROVE: `receiver` installs sender-key state for
            // `other` (by processing `other`'s own distribution message) before the relabelled
            // message is decrypted. This closes a trivial, unrepresentative way this test used
            // to pass: signature binding verification runs first (GroupSession.Messaging.cs:102),
            // and the `_senderKeys.TryGetValue` gate runs later (roughly :124). Under a mutation
            // that discards the signature verification result, the later _senderKeys miss supplies
            // a fallback rejection, so this test cannot distinguish a working signature check from
            // a broken one without that gate open.
            //
            // Even with that gate open, this test does NOT fully isolate signature binding from
            // AES decryption: `other`'s chain key is independently generated by `other`'s own
            // session and can never decrypt ciphertext that `sender` produced with sender's own
            // chain key, so the relabelled message is also rejected at AES decryption -- it would
            // be rejected here even if binding verification were skipped entirely. The message
            // path appears to be structurally incapable of isolating binding from decryption this
            // way. The genuine, isolated proof that a relabelled signature is rejected BY
            // SIGNATURE VERIFICATION (and not some other reason) is
            // ProcessDistributionMessage_SignatureFromAnotherMember_IsRejected below, which has
            // no analogous decryption step to confound it.
            var senderKey = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var otherKey = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var receiverKey = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            string groupId = $"sig-bind-{Guid.NewGuid()}";

            var sender = new GroupSession(groupId, "Binding Test", senderKey);
            var other = new GroupSession(groupId, "Binding Test", otherKey);
            var receiver = new GroupSession(groupId, "Binding Test", receiverKey);
            await sender.ActivateAsync();
            await other.ActivateAsync();
            await receiver.ActivateAsync();

            // Both sender and other are members, so the membership check passes and the
            // signature check is what must reject the message.
            await sender.AddMemberAsync(receiverKey.PublicKey);
            await receiver.AddMemberAsync(senderKey.PublicKey);
            await receiver.AddMemberAsync(otherKey.PublicKey);
            receiver.ProcessDistributionMessage(sender.CreateDistributionMessage());
            // Open the sender-key gate for `other` too, via other's own genuine distribution
            // message, so the relabelled message below is not rejected merely because receiver
            // has no chain-key state for `other` at all (see the comment above).
            receiver.ProcessDistributionMessage(other.CreateDistributionMessage());

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
        public async Task PositiveControl_ReSignedMessageWithUnmodifiedCiphertext_StillDecrypts()
        {
            // Proves BuildGroupMessageSigningPayload (above) still matches GroupSession's
            // actual signing format (GetMessageDataToSign / GroupSignatureData.ForMessage)
            // BEFORE it is relied on destructively below. Without this, a replica that has
            // drifted from production would make a "tampered" message fail at signature
            // verification instead of at the guard under test, and the test would still
            // report green — silently testing the wrong thing.
            var (sender, receiver, senderKey) = await BuildPairWithSenderKeyAsync();
            var message = await sender.EncryptMessageAsync("control payload");
            Assert.IsNotNull(message);

            message.Signature = Sodium.SignDetached(BuildGroupMessageSigningPayload(message), senderKey.PrivateKey);

            string result = await receiver.DecryptMessageAsync(message);

            Assert.AreEqual("control payload", result,
                "BuildGroupMessageSigningPayload (this test file) has drifted from GroupSession's " +
                "GetMessageDataToSign (GroupSession.Helpers.cs) and must be updated to match it.");
        }

        [TestMethod]
        public async Task DecryptMessageAsync_NullCiphertext_IsRejectedWithoutThrowing()
        {
            // Signature verification is mandatory, and mutating Ciphertext changes the bytes
            // that were signed, so an unmodified signature would already be rejected by
            // verification regardless of whether the explicit ciphertext guard exists. To
            // isolate the guard, re-sign the tampered message with the sender's key using a
            // replica of the production signing format that coalesces null the same way
            // GroupSignatureData.ForMessage does — so signature verification cannot be what
            // rejects the message.
            var (sender, receiver, senderKey) = await BuildPairWithSenderKeyAsync();
            var message = await sender.EncryptMessageAsync("payload");
            Assert.IsNotNull(message);

            message.Ciphertext = null;
            message.Signature = Sodium.SignDetached(BuildGroupMessageSigningPayload(message), senderKey.PrivateKey);

            // Primary, isolated assertion: ValidateGroupMessage itself must reject a null
            // ciphertext. See InvokeValidateGroupMessage for why this must be called directly
            // rather than only through DecryptMessageAsync.
            bool valid = InvokeValidateGroupMessage(receiver, message);
            Assert.IsFalse(valid,
                "A message with null ciphertext must be rejected by ValidateGroupMessage, not " +
                "reach the signing-data serialiser where it would throw.");

            // End-to-end contract: the public API must also return null, without throwing.
            string result = await receiver.DecryptMessageAsync(message);
            Assert.IsNull(result,
                "A message with null ciphertext must be rejected without throwing.");
        }

        [TestMethod]
        public async Task DecryptMessageAsync_EmptyCiphertext_IsRejected()
        {
            // Same isolation concern as the null-ciphertext test above: re-sign over the
            // tampered (empty-ciphertext) message so signature verification cannot be what
            // rejects it.
            var (sender, receiver, senderKey) = await BuildPairWithSenderKeyAsync();
            var message = await sender.EncryptMessageAsync("payload");
            Assert.IsNotNull(message);

            message.Ciphertext = Array.Empty<byte>();
            message.Signature = Sodium.SignDetached(BuildGroupMessageSigningPayload(message), senderKey.PrivateKey);

            // Primary, isolated assertion: ValidateGroupMessage itself must reject an empty
            // ciphertext. See InvokeValidateGroupMessage for why this must be called directly
            // rather than only through DecryptMessageAsync.
            bool valid = InvokeValidateGroupMessage(receiver, message);
            Assert.IsFalse(valid, "A message with empty ciphertext must be rejected by ValidateGroupMessage.");

            // End-to-end contract: the public API must also return null.
            string result = await receiver.DecryptMessageAsync(message);
            Assert.IsNull(result, "A message with empty ciphertext must be rejected.");
        }

        [TestMethod]
        public async Task DecryptMessageAsync_WrongLengthSignature_IsRejectedWithoutThrowing()
        {
            // Sodium.SignVerifyDetached throws ArgumentException for any signature whose
            // length is not exactly Constants.ED25519_SIGNATURE_SIZE (64 bytes) — it does not
            // return false. The null/empty check alone lets a non-null, non-empty,
            // wrong-length signature reach that call and escape as an unhandled exception
            // out of DecryptMessageAsync. The guard must reject the wrong length itself.
            var (sender, receiver) = await BuildPairAsync();
            var message = await sender.EncryptMessageAsync("payload");
            Assert.IsNotNull(message);
            Assert.IsNotNull(message.Signature, "precondition: sender signed the message");

            message.Signature = new byte[10]; // non-null, non-empty, wrong length

            string result = await receiver.DecryptMessageAsync(message);

            Assert.IsNull(result,
                "A group message with a wrong-length signature must be rejected by validation, " +
                "not reach Sodium.SignVerifyDetached where it would throw ArgumentException.");
        }

        [TestMethod]
        public async Task ProcessDistributionMessage_WrongLengthSignature_IsRejectedWithoutThrowing()
        {
            // Same bug class as above, for the distribution path: a wrong-length signature
            // must not reach Sodium.SignVerifyDetached, which throws rather than returning
            // false for a length other than Constants.ED25519_SIGNATURE_SIZE.
            var (sender, receiver) = await BuildPairAsync();
            var distribution = sender.CreateDistributionMessage();
            Assert.IsNotNull(distribution.Signature, "precondition: distributions are signed");

            distribution.Signature = new byte[10]; // non-null, non-empty, wrong length

            bool accepted = receiver.ProcessDistributionMessage(distribution);

            Assert.IsFalse(accepted,
                "A sender-key distribution with a wrong-length signature must be rejected by " +
                "validation, not reach Sodium.SignVerifyDetached where it would throw.");
        }
    }
}
