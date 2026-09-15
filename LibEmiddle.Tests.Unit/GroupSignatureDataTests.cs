using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Text;
using LibEmiddle.Domain;
using LibEmiddle.Messaging.Group;

namespace LibEmiddle.Tests.Unit
{
    /// <summary>
    /// The signed byte string must commit to exactly one decomposition into fields.
    /// Without length prefixes, adjacent fields can be re-split to produce identical
    /// signing input for different message content, so a signature would not uniquely
    /// bind the message it was computed over.
    /// </summary>
    [TestClass]
    public class GroupSignatureDataTests
    {
        [TestMethod]
        public void ForMessage_DifferentFieldSplit_ProducesDifferentBytes()
        {
            // These two messages differ only in where the boundary between GroupId and
            // SenderIdentityKey falls: 'x' (0x78) is the last byte of A's GroupId and the
            // first byte of B's SenderIdentityKey. Without length prefixes both serialise
            // to the identical byte string 67 78 01 02 03 09 07 ...
            var a = new EncryptedGroupMessage
            {
                GroupId = "gx",
                SenderIdentityKey = new byte[] { 0x01, 0x02, 0x03 },
                Ciphertext = new byte[] { 0x09 },
                Nonce = new byte[] { 0x07 },
                Timestamp = 100,
                RotationEpoch = 0,
                MessageId = "m"
            };

            var b = new EncryptedGroupMessage
            {
                GroupId = "g",
                SenderIdentityKey = new byte[] { 0x78, 0x01, 0x02 },
                Ciphertext = new byte[] { 0x03, 0x09 },
                Nonce = new byte[] { 0x07 },
                Timestamp = 100,
                RotationEpoch = 0,
                MessageId = "m"
            };

            byte[] bytesA = GroupSignatureData.ForMessage(a);
            byte[] bytesB = GroupSignatureData.ForMessage(b);

            CollectionAssert.AreNotEqual(bytesA, bytesB,
                "Two different field decompositions produced identical signing input, so a " +
                "signature over one is also valid over the other.");
        }

        [TestMethod]
        public void ForDistribution_NullAndEmptySenderIdentityKey_SerialiseIdentically()
        {
            // Accepted characteristic of the frozen format, not a defect: null and
            // Array.Empty<byte>() both write a zero-length length-prefixed field
            // (00 00 00 00 with no following bytes), so they are indistinguishable in the
            // signed byte string. This is safe because both group paths reject a null or empty
            // SenderIdentityKey before verifying a signature over one, so this ambiguity is
            // never reachable with a value that would otherwise need to be distinguished.
            // ValidateGroupMessage (Validation.cs) checks both null and empty explicitly.
            // ProcessDistributionMessage (Keys.cs) checks only null at line 108; an empty key is
            // rejected one line later by the membership check (GetMemberId(Array.Empty<byte>())
            // produces an empty string not in _members). This empty-key rejection is safe only
            // because nothing ever adds an empty identity key to _members.
            // See GroupSignatureData's class remarks for the general length-prefix rationale.
            var withNullKey = new SenderKeyDistributionMessage
            {
                GroupId = "g",
                ChainKey = new byte[] { 0x01, 0x02 },
                Iteration = 1,
                Timestamp = 100,
                SenderIdentityKey = null
            };

            var withEmptyKey = new SenderKeyDistributionMessage
            {
                GroupId = "g",
                ChainKey = new byte[] { 0x01, 0x02 },
                Iteration = 1,
                Timestamp = 100,
                SenderIdentityKey = Array.Empty<byte>()
            };

            byte[] a = GroupSignatureData.ForDistribution(withNullKey);
            byte[] b = GroupSignatureData.ForDistribution(withEmptyKey);

            CollectionAssert.AreEqual(a, b,
                "null and empty SenderIdentityKey are expected to serialise identically in the " +
                "frozen format.");
        }

        [TestMethod]
        public void ForDistribution_DifferentFieldSplit_ProducesDifferentBytes()
        {
            // Mirrors ForMessage_DifferentFieldSplit_ProducesDifferentBytes above: the boundary
            // between GroupId and ChainKey shifts by one byte ('x' / 0x78 moves from the end of
            // A's GroupId to the start of B's ChainKey). Under the old (pre-length-prefix)
            // format these collapsed to the identical byte string; without this test, removing
            // the length prefix from ForDistribution alone would go uncaught even though
            // ForMessage's equivalent test still passes.
            var a = new SenderKeyDistributionMessage
            {
                GroupId = "gx",
                ChainKey = new byte[] { 0x01, 0x02 },
                Iteration = 1,
                Timestamp = 100,
                SenderIdentityKey = new byte[] { 0xAA }
            };

            var b = new SenderKeyDistributionMessage
            {
                GroupId = "g",
                ChainKey = new byte[] { 0x78, 0x01, 0x02 },
                Iteration = 1,
                Timestamp = 100,
                SenderIdentityKey = new byte[] { 0xAA }
            };

            byte[] bytesA = GroupSignatureData.ForDistribution(a);
            byte[] bytesB = GroupSignatureData.ForDistribution(b);

            CollectionAssert.AreNotEqual(bytesA, bytesB,
                "Two different field decompositions produced identical signing input, so a " +
                "signature over one is also valid over the other.");
        }

        [TestMethod]
        public void ForMessageAndForDistribution_NeverProduceIdenticalBytes()
        {
            // Without a domain-separation tag, a message payload and a distribution payload
            // with compatible field widths can serialise to the identical byte string, even
            // though every field is individually length-prefixed. Both signing contexts share
            // one Ed25519 identity key, so a collision here would let a signature over one
            // payload type be reinterpreted as covering the other. This exact pair collides
            // (all 38 bytes equal) only if the leading domain tag is removed from BOTH
            // functions -- removing it from just one leaves a 38 vs. 39 byte length
            // mismatch, so the pair no longer collides.
            var message = new EncryptedGroupMessage
            {
                GroupId = "g",
                SenderIdentityKey = new byte[] { 0xAA },
                Ciphertext = Array.Empty<byte>(),
                Nonce = Array.Empty<byte>(),
                Timestamp = 12,
                RotationEpoch = 0,
                MessageId = ""
            };

            var distribution = new SenderKeyDistributionMessage
            {
                GroupId = "g",
                ChainKey = new byte[] { 0xAA },
                Iteration = 0,
                Timestamp = 0,
                SenderIdentityKey = new byte[12]
            };

            byte[] messageBytes = GroupSignatureData.ForMessage(message);
            byte[] distributionBytes = GroupSignatureData.ForDistribution(distribution);

            CollectionAssert.AreNotEqual(messageBytes, distributionBytes,
                "A group message payload and a sender-key distribution payload serialised to " +
                "identical bytes. Since both are signed with the same Ed25519 identity key, this " +
                "would let a signature over one payload type be replayed as a valid signature " +
                "over the other.");
        }
    }
}
