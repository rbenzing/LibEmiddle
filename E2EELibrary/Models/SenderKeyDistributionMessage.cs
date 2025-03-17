
namespace E2EELibrary.Models
{
    /// <summary>
    /// Sender key distribution message for group messaging
    /// </summary>
    public class SenderKeyDistributionMessage
    {
        /// <summary>
        /// Group identifier
        /// </summary>
        public string? GroupId { get; set; }

        /// <summary>
        /// Sender key for the group
        /// </summary>
        public byte[]? SenderKey { get; set; }

        /// <summary>
        /// Sender's identity key
        /// </summary>
        public byte[]? SenderIdentityKey { get; set; }

        /// <summary>
        /// Signature of the sender key
        /// </summary>
        public byte[]? Signature { get; set; }
    }
}
