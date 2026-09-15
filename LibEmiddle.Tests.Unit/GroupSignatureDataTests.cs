using Microsoft.VisualStudio.TestTools.UnitTesting;
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
        public void ForDistribution_SenderIdentityKeyAlwaysContributes()
        {
            // SenderIdentityKey was written only when non-null, so its absence silently
            // changed the signed byte string rather than producing a distinct one.
            var withKey = new SenderKeyDistributionMessage
            {
                GroupId = "g",
                ChainKey = new byte[] { 0x01, 0x02 },
                Iteration = 1,
                Timestamp = 100,
                SenderIdentityKey = new byte[] { 0xAA }
            };

            var withoutKey = new SenderKeyDistributionMessage
            {
                GroupId = "g",
                ChainKey = new byte[] { 0x01, 0x02 },
                Iteration = 1,
                Timestamp = 100,
                SenderIdentityKey = null
            };

            byte[] a = GroupSignatureData.ForDistribution(withKey);
            byte[] b = GroupSignatureData.ForDistribution(withoutKey);

            CollectionAssert.AreNotEqual(a, b,
                "Presence and absence of SenderIdentityKey must produce different signing input.");
        }
    }
}
