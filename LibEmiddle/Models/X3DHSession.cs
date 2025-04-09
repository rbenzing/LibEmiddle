namespace E2EELibrary.Models
{
    /// <summary>
    /// X3DH session data - immutable to prevent unauthorized state changes.
    /// Contains the shared keys established through the X3DH key agreement protocol.
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
            CreationTimestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        }

        /// <summary>
        /// Extended constructor with additional metadata and tracking information
        /// </summary>
        public X3DHSession(
            byte[] recipientIdentityKey,
            byte[] senderIdentityKey,
            byte[] ephemeralKey,
            bool usedOneTimePreKey,
            uint? usedOneTimePreKeyId,
            uint usedSignedPreKeyId,
            byte[] rootKey,
            byte[] chainKey,
            long creationTimestamp)
        {
            RecipientIdentityKey = recipientIdentityKey ?? throw new ArgumentNullException(nameof(recipientIdentityKey));
            SenderIdentityKey = senderIdentityKey ?? throw new ArgumentNullException(nameof(senderIdentityKey));
            EphemeralKey = ephemeralKey ?? throw new ArgumentNullException(nameof(ephemeralKey));
            UsedOneTimePreKey = usedOneTimePreKey;
            UsedOneTimePreKeyId = usedOneTimePreKeyId;
            UsedSignedPreKeyId = usedSignedPreKeyId;
            RootKey = rootKey ?? throw new ArgumentNullException(nameof(rootKey));
            ChainKey = chainKey ?? throw new ArgumentNullException(nameof(chainKey));
            CreationTimestamp = creationTimestamp > 0 ? creationTimestamp : DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
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
        /// ID of the one-time pre-key that was used (if any)
        /// </summary>
        public uint? UsedOneTimePreKeyId { get; }

        /// <summary>
        /// ID of the signed pre-key that was used
        /// </summary>
        public uint UsedSignedPreKeyId { get; }

        /// <summary>
        /// Root key for Double Ratchet
        /// </summary>
        public byte[] RootKey { get; }

        /// <summary>
        /// Chain key for Double Ratchet
        /// </summary>
        public byte[] ChainKey { get; }

        /// <summary>
        /// When this session was created (milliseconds since Unix epoch)
        /// </summary>
        public long CreationTimestamp { get; }

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
                UsedOneTimePreKeyId,
                UsedSignedPreKeyId,
                RootKey,
                newChainKey ?? throw new ArgumentNullException(nameof(newChainKey)),
                CreationTimestamp);
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
                UsedOneTimePreKeyId,
                UsedSignedPreKeyId,
                newRootKey ?? throw new ArgumentNullException(nameof(newRootKey)),
                newChainKey ?? throw new ArgumentNullException(nameof(newChainKey)),
                CreationTimestamp);
        }

        /// <summary>
        /// Checks if this session is still valid based on age
        /// </summary>
        /// <param name="maxAgeMs">Maximum age in milliseconds</param>
        /// <returns>True if the session is still valid</returns>
        public bool IsValid(long maxAgeMs = 2592000000) // 30 days by default
        {
            long currentTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            return (currentTime - CreationTimestamp) <= maxAgeMs;
        }
    }
}