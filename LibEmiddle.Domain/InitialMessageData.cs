namespace LibEmiddle.Domain
{
    /// <summary>
    /// Contains the data sent by the initiator (Alice) to the responder (Bob)
    /// in the initial X3DH message, alongside the first encrypted payload.
    /// This data allows the responder to compute the shared secret key (SK)
    /// required to initialize the Double Ratchet session.
    /// </summary>
    public class InitialMessageData
    {
        /// <summary>
        /// Sender's (Alice's) public Identity Key (Ed25519, 32 bytes).
        /// Needed by Bob for DH calculation and potentially verification.
        /// </summary>
        public byte[] SenderIdentityKeyPublic { get; set; } = Array.Empty<byte>(); // Initialize to avoid null ref warnings

        /// <summary>
        /// Sender's (Alice's) public Ephemeral Key (X25519, 32 bytes), generated for this session initiation.
        /// Needed by Bob for DH calculation.
        /// </summary>
        public byte[] SenderEphemeralKeyPublic { get; set; } = Array.Empty<byte>(); // Initialize

        /// <summary>
        /// The ID of the recipient's (Bob's) Signed PreKey (SPK) that the sender (Alice) used
        /// for a DH calculation. Bob uses this to look up his corresponding private SPK.
        /// </summary>
        public uint RecipientSignedPreKeyId { get; set; }

        /// <summary>
        /// The ID of the recipient's (Bob's) One-Time PreKey (OPK) that the sender (Alice) used
        /// for a DH calculation (if one was available and used).
        /// This is null if no One-Time PreKey was used. Bob uses this to look up his private OPK.
        /// </summary>
        public uint? RecipientOneTimePreKeyId { get; set; } // Nullable uint

        /// <summary>
        /// Parameterless constructor for serialization frameworks or manual initialization.
        /// </summary>
        public InitialMessageData() { }

        /// <summary>
        /// Constructor for creating an instance with all required data.
        /// </summary>
        /// <param name="senderIKPub">Sender's public Identity Key (Ed25519).</param>
        /// <param name="senderEKPub">Sender's public Ephemeral Key (X25519).</param>
        /// <param name="recipientSPKId">Recipient's Signed PreKey ID used.</param>
        /// <param name="recipientOPKId">Recipient's One-Time PreKey ID used (can be null).</param>
        /// <exception cref="ArgumentNullException">If required keys are null.</exception>
        /// <exception cref="ArgumentException">If keys have incorrect length or SPK ID is zero.</exception>
        public InitialMessageData(byte[] senderIKPub, byte[] senderEKPub, uint recipientSPKId, uint? recipientOPKId)
        {
            SenderIdentityKeyPublic = senderIKPub ?? throw new ArgumentNullException(nameof(senderIKPub));
            SenderEphemeralKeyPublic = senderEKPub ?? throw new ArgumentNullException(nameof(senderEKPub));
            RecipientSignedPreKeyId = recipientSPKId;
            RecipientOneTimePreKeyId = recipientOPKId;

            // Perform validation on construction
            if (SenderIdentityKeyPublic.Length != Constants.ED25519_PUBLIC_KEY_SIZE)
                throw new ArgumentException($"Sender Identity Key must be {Constants.ED25519_PUBLIC_KEY_SIZE} bytes.", nameof(senderIKPub));

            if (SenderEphemeralKeyPublic.Length != Constants.X25519_KEY_SIZE)
                throw new ArgumentException($"Sender Ephemeral Key must be {Constants.X25519_KEY_SIZE} bytes.", nameof(senderEKPub));

            if (RecipientSignedPreKeyId == 0)
                throw new ArgumentException("Recipient Signed PreKey ID cannot be zero.", nameof(recipientSPKId));

            if (RecipientOneTimePreKeyId.HasValue && RecipientOneTimePreKeyId.Value == 0)
                throw new ArgumentException("Recipient One Time PreKey ID cannot be zero.", nameof(recipientOPKId));
        }

        /// <summary>
        /// Validates the instance properties to ensure they meet the expected criteria.
        /// </summary>
        /// <returns>True if the instance is valid; otherwise, false.</returns>
        public bool IsValid()
        {
            // Check Sender's Identity Key
            if (SenderIdentityKeyPublic == null || SenderIdentityKeyPublic.Length != Constants.ED25519_PUBLIC_KEY_SIZE)
                return false;

            // Check Sender's Ephemeral Key
            if (SenderEphemeralKeyPublic == null || SenderEphemeralKeyPublic.Length != Constants.X25519_KEY_SIZE)
                return false;

            // Check Recipient Signed PreKey ID
            if (RecipientSignedPreKeyId == 0)
                return false;

            // If present, check Recipient One-Time PreKey ID
            if (RecipientOneTimePreKeyId.HasValue && RecipientOneTimePreKeyId.Value == 0)
                return false;

            return true;
        }
    }
}
