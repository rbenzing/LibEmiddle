
namespace E2EELibrary.Models
{
    /// <summary>
    /// X3DH session data - immutable to prevent unauthorized state changes
    /// </summary>
    public class X3DHSession
    {
        /// <summary>
        /// Creates a new X3DH session with the specified parameters
        /// </summary>
        public X3DHSession(
            byte[] recipientIdentityKey,
            byte[] senderIdentityKey,
            byte[] ephemeralKey,
            bool usedOneTimePreKey,
            byte[] rootKey,
            byte[] chainKey)
        {
            RecipientIdentityKey = recipientIdentityKey ?? throw new ArgumentNullException(nameof(recipientIdentityKey));
            SenderIdentityKey = senderIdentityKey ?? throw new ArgumentNullException(nameof(senderIdentityKey));
            EphemeralKey = ephemeralKey ?? throw new ArgumentNullException(nameof(ephemeralKey));
            UsedOneTimePreKey = usedOneTimePreKey;
            RootKey = rootKey ?? throw new ArgumentNullException(nameof(rootKey));
            ChainKey = chainKey ?? throw new ArgumentNullException(nameof(chainKey));
        }

        /// <summary>
        /// Recipient's identity key
        /// </summary>
        public byte[] RecipientIdentityKey { get; }

        /// <summary>
        /// Sender's identity key
        /// </summary>
        public byte[] SenderIdentityKey { get; }

        /// <summary>
        /// Ephemeral key used for this session
        /// </summary>
        public byte[] EphemeralKey { get; }

        /// <summary>
        /// Whether a one-time pre-key was used
        /// </summary>
        public bool UsedOneTimePreKey { get; }

        /// <summary>
        /// Root key for Double Ratchet
        /// </summary>
        public byte[] RootKey { get; }

        /// <summary>
        /// Chain key for Double Ratchet
        /// </summary>
        public byte[] ChainKey { get; }

        /// <summary>
        /// Creates a new X3DHSession with an updated chain key
        /// </summary>
        /// <param name="newChainKey">New chain key to use</param>
        /// <returns>Updated X3DHSession instance</returns>
        public X3DHSession WithUpdatedChainKey(byte[] newChainKey)
        {
            return new X3DHSession(
                RecipientIdentityKey,
                SenderIdentityKey,
                EphemeralKey,
                UsedOneTimePreKey,
                RootKey,
                newChainKey ?? throw new ArgumentNullException(nameof(newChainKey)));
        }

        /// <summary>
        /// Creates a new X3DHSession with updated root and chain keys
        /// </summary>
        /// <param name="newRootKey">New root key to use</param>
        /// <param name="newChainKey">New chain key to use</param>
        /// <returns>Updated X3DHSession instance</returns>
        public X3DHSession WithUpdatedKeys(byte[] newRootKey, byte[] newChainKey)
        {
            return new X3DHSession(
                RecipientIdentityKey,
                SenderIdentityKey,
                EphemeralKey,
                UsedOneTimePreKey,
                newRootKey ?? throw new ArgumentNullException(nameof(newRootKey)),
                newChainKey ?? throw new ArgumentNullException(nameof(newChainKey)));
        }
    }
}