using System.Collections.Immutable; // Required for ImmutableDictionary

namespace LibEmiddle.Domain // Adjust namespace as needed
{
    /// <summary>
    /// Represents the state of a Double Ratchet session.
    /// This class is immutable; all state changes result in a new session instance.
    /// </summary>
    public class DoubleRatchetSession
    {
        // Define a key type for the skipped message keys dictionary
        // Using Tuple<byte[], int> is possible but requires custom comparer for byte[] equality.
        // A dedicated struct might be better for clarity and correct equality.
        public readonly record struct SkippedKeyIdentifier(byte[] RemoteDhPublicKey, int MessageNumber)
        {
            // Implement custom equality based on byte array content if needed,
            // record struct provides value equality by default IF RemoteDhPublicKey was immutable (e.g. ReadOnlyMemory<byte>)
            // For byte[], we might need SequenceEqual. Let's keep Tuple for simplicity now,
            // but acknowledge a custom struct with proper equality is more robust.
        }

        // Using Tuple for simplicity - requires careful handling or a custom comparer in practice
        // Key: Tuple Item1=Remote DHR Key (Their Public Key), Item2=Message Number
        // Value: Message Key
        private readonly ImmutableDictionary<Tuple<byte[], int>, byte[]> _skippedMessageKeys;

        /// <summary>
        /// Read-only collection of recently processed message IDs for replay protection. Bounded size.
        /// </summary>
        private readonly ImmutableList<Guid> _recentlyProcessedIds;

        /// <summary>
        /// Set of processed message numbers for the current receiving chain. Used for replay/duplicate detection within a chain.
        /// </summary>
        private readonly ImmutableHashSet<int> _processedMessageNumbersReceiving;

        /// <summary>
        /// The DHRatchet KeyPair
        /// </summary>
        private readonly KeyPair _dhRatchetKeyPair;

        /// <summary>
        /// Maximum number of message IDs to keep track of for replay protection.
        /// </summary>
        private const int MaxTrackedMessageIds = 100;

        /// <summary>
        /// Initializes a new instance of the DoubleRatchetSession class.
        /// </summary>
        public DoubleRatchetSession(
            KeyPair dhRatchetKeyPair,          // Our current DH key pair (DHs)
            byte[] remoteDHRatchetKey,             // Their current public DH key (DHr)
            byte[] rootKey,                        // Current Root Key (RK)
            byte[]? sendingChainKey,               // Current Sending Chain Key (CKs), nullable for initial state
            byte[]? receivingChainKey,             // Current Receiving Chain Key (CKr), nullable for initial state
            int messageNumberSending,              // Ns: Number of messages sent in current sending chain
            int messageNumberReceiving,            // Nr: Number of messages received in current receiving chain
            string? sessionId = null,                  // Optional session ID
            ImmutableList<Guid>? recentlyProcessedIds = null, // Track recent Message Guids for replay
            ImmutableHashSet<int>? processedMessageNumbersReceiving = null, // Track received message numbers in current chain
            ImmutableDictionary<Tuple<byte[], int>, byte[]>? skippedMessageKeys = null // Store keys for out-of-order messages
        )
        {
            ArgumentNullException.ThrowIfNullOrEmpty(dhRatchetKeyPair.ToString(), nameof(dhRatchetKeyPair));

            // Validate non-nullable required arguments
            RemoteDHRatchetKey = remoteDHRatchetKey ?? throw new ArgumentNullException(nameof(remoteDHRatchetKey));
            RootKey = rootKey ?? throw new ArgumentNullException(nameof(rootKey));

            // Validate key lengths (assuming Constants class is accessible)
            if (RemoteDHRatchetKey.Length != Constants.X25519_KEY_SIZE) throw new ArgumentException("Invalid Remote DH Ratchet Key size.", nameof(remoteDHRatchetKey));
            if (RootKey.Length != Constants.AES_KEY_SIZE) throw new ArgumentException("Invalid Root Key size.", nameof(rootKey));
            if (sendingChainKey != null && sendingChainKey.Length != Constants.AES_KEY_SIZE) throw new ArgumentException("Invalid Sending Chain Key size.", nameof(sendingChainKey));
            if (receivingChainKey != null && receivingChainKey.Length != Constants.AES_KEY_SIZE) throw new ArgumentException("Invalid Receiving Chain Key size.", nameof(receivingChainKey));
            
            // TODO: Add validation for DHRatchetKeyPair keys if needed

            // Assign properties
            SendingChainKey = sendingChainKey; // Can be null initially
            ReceivingChainKey = receivingChainKey; // Can be null initially
            MessageNumberSending = messageNumberSending;
            MessageNumberReceiving = messageNumberReceiving;
            SessionId = sessionId ?? Guid.NewGuid().ToString();

            // Initialize immutable collections
            _dhRatchetKeyPair = dhRatchetKeyPair;
            _recentlyProcessedIds = recentlyProcessedIds ?? ImmutableList<Guid>.Empty;
            _processedMessageNumbersReceiving = processedMessageNumbersReceiving ?? ImmutableHashSet<int>.Empty;
            _skippedMessageKeys = skippedMessageKeys ?? ImmutableDictionary<Tuple<byte[], int>, byte[]>.Empty; // Requires custom comparer for byte[] keys usually
        }

        // --- Public Properties ---

        /// <summary>
        /// Unique session identifier.
        /// </summary>
        public string SessionId { get; }

        /// <summary>
        /// Our current DH ratchet key pair (DHs). Contains private key. Handle with care.
        /// </summary>
        public ref readonly KeyPair DHRatchetKeyPair => ref _dhRatchetKeyPair;

        /// <summary>
        /// Remote party's current public DH ratchet key (DHr).
        /// </summary>
        public byte[] RemoteDHRatchetKey { get; }

        /// <summary>
        /// Current Root Key (RK).
        /// </summary>
        public byte[] RootKey { get; }

        /// <summary>
        /// Current Sending Chain Key (CKs), if initialized. Null otherwise.
        /// </summary>
        public byte[]? SendingChainKey { get; }

        /// <summary>
        /// Current Receiving Chain Key (CKr), if initialized. Null otherwise.
        /// </summary>
        public byte[]? ReceivingChainKey { get; }

        /// <summary>
        /// Number of messages sent using the current sending chain key (Ns).
        /// </summary>
        public int MessageNumberSending { get; }

        /// <summary>
        /// Number of messages received using the current receiving chain key (Nr).
        /// </summary>
        public int MessageNumberReceiving { get; } // Tracks count within current receiving chain step

        /// <summary>
        /// Provides read-only access to the dictionary of skipped message keys.
        /// Key: Tuple(RemoteDHKeyPublicKey, MessageNumber). Value: MessageKey.
        /// Note: Using byte[] in Tuple requires custom equality logic for reliable dictionary operations.
        /// Consider a dedicated struct key with SequenceEqual implementation.
        /// </summary>
        public ImmutableDictionary<Tuple<byte[], int>, byte[]> SkippedMessageKeys => _skippedMessageKeys;

        /// <summary>
        /// Provides read-only access to recently processed message GUIDs (for replay protection).
        /// </summary>
        public ImmutableList<Guid> RecentlyProcessedIds => _recentlyProcessedIds;

        /// <summary>
        /// Provides read-only access to the set of processed message numbers in the current receiving chain.
        /// </summary>
        public ImmutableHashSet<int> ProcessedMessageNumbersReceiving => _processedMessageNumbersReceiving;

        // --- Methods ---

        /// <summary>
        /// Checks if a message GUID has been processed recently.
        /// </summary>
        public bool HasProcessedMessageId(Guid messageId)
        {
            return _recentlyProcessedIds.Contains(messageId);
        }

        /// <summary>
        /// Checks if a message number within the current receiving chain has been processed.
        /// </summary>
        public bool HasProcessedMessageNumberReceiving(int messageNumber)
        {
            return _processedMessageNumbersReceiving.Contains(messageNumber);
        }

        /// <summary>
        /// Creates a copy of this session with updated parameters. Returns a new instance.
        /// Use this method to reflect state changes after cryptographic operations.
        /// </summary>
        public DoubleRatchetSession WithUpdatedParameters(
            KeyPair? newDHRatchetKeyPair = null,
            byte[]? newRemoteDHRatchetKey = null,
            byte[]? newRootKey = null,
            byte[]? newSendingChainKey = null,       // Use null to keep existing, or provide new value
            byte[]? newReceivingChainKey = null,     // Use null to keep existing, or provide new value
            int? newMessageNumberSending = null,
            int? newMessageNumberReceiving = null,
            Guid? newProcessedMessageId = null,        // ID of the message just processed (for replay list)
            int? newProcessedMessageNumberReceiving = null, // Number of msg just processed (for received set)
            ImmutableDictionary<Tuple<byte[], int>, byte[]>? newSkippedMessageKeys = null, // Replace entire skipped key dict
            bool resetReceivingChainState = false // Flag to reset receiving message numbers upon DH ratchet
            )
        {
            // Update recently processed IDs list
            var updatedMessageIds = _recentlyProcessedIds;
            if (newProcessedMessageId.HasValue)
            {
                updatedMessageIds = updatedMessageIds.Add(newProcessedMessageId.Value);
                // Maintain bounded size
                if (updatedMessageIds.Count > MaxTrackedMessageIds)
                {
                    updatedMessageIds = updatedMessageIds.RemoveAt(0);
                }
            }

            // Update processed message numbers set for the receiving chain
            var updatedMessageNumbersReceiving = _processedMessageNumbersReceiving;
            if (resetReceivingChainState) // Usually after a DH Ratchet step for the receiving chain
            {
                updatedMessageNumbersReceiving = ImmutableHashSet<int>.Empty;
            }
            else if (newProcessedMessageNumberReceiving.HasValue)
            {
                updatedMessageNumbersReceiving = updatedMessageNumbersReceiving.Add(newProcessedMessageNumberReceiving.Value);
            }


            // Create new session with updated parameters using null-coalescing operator
            return new DoubleRatchetSession(
                dhRatchetKeyPair: newDHRatchetKeyPair ?? this.DHRatchetKeyPair,
                remoteDHRatchetKey: newRemoteDHRatchetKey ?? this.RemoteDHRatchetKey,
                rootKey: newRootKey ?? this.RootKey,
                sendingChainKey: newSendingChainKey ?? this.SendingChainKey,       // Keeps existing if new value is null
                receivingChainKey: newReceivingChainKey ?? this.ReceivingChainKey, // Keeps existing if new value is null
                messageNumberSending: newMessageNumberSending ?? this.MessageNumberSending,
                messageNumberReceiving: newMessageNumberReceiving ?? this.MessageNumberReceiving,
                sessionId: this.SessionId, // Session ID does not change
                recentlyProcessedIds: updatedMessageIds,
                processedMessageNumbersReceiving: updatedMessageNumbersReceiving,
                skippedMessageKeys: newSkippedMessageKeys ?? this.SkippedMessageKeys // Replace or keep existing dict
            );
        }

        /// <summary>
        /// Creates a copy of this session marking a message ID as processed.
        /// </summary>
        public DoubleRatchetSession WithProcessedMessageId(Guid messageId)
        {
            return WithUpdatedParameters(newProcessedMessageId: messageId);
        }

        /// <summary>
        /// Creates a copy of this session marking a receiving message number as processed.
        /// </summary>
        public DoubleRatchetSession WithProcessedMessageNumberReceiving(int messageNumber)
        {
            return WithUpdatedParameters(newProcessedMessageNumberReceiving: messageNumber);
        }

        /// <summary>
        /// Creates a copy of this session with an added skipped message key.
        /// </summary>
        public DoubleRatchetSession WithAddedSkippedKey(Tuple<byte[], int> keyIdentifier, byte[] messageKey)
        {
            // Use ImmutableDictionary.Add - creates new dictionary instance
            var updatedSkippedKeys = _skippedMessageKeys.Add(keyIdentifier, messageKey);
            return WithUpdatedParameters(newSkippedMessageKeys: updatedSkippedKeys);
        }

        /// <summary>
        /// Creates a copy of this session with a removed skipped message key.
        /// </summary>
        public DoubleRatchetSession WithRemovedSkippedKey(Tuple<byte[], int> keyIdentifier)
        {
            // Use ImmutableDictionary.Remove - creates new dictionary instance
            var updatedSkippedKeys = _skippedMessageKeys.Remove(keyIdentifier);
            return WithUpdatedParameters(newSkippedMessageKeys: updatedSkippedKeys);
        }

        // CONSIDER: Add a Dispose method or pattern if KeyPair contains sensitive
        // private key material that should be securely cleared when the session is discarded.
        // Since this class is immutable, clearing happens when instances go out of scope
        // and are garbage collected, but explicit clearing might be desired depending
        // on the KeyPair implementation and overall memory management strategy.
    }
}