using E2EELibrary.Core;

namespace E2EELibrary.Models
{
    /// <summary>
    /// Double Ratchet session data - fully immutable to prevent state corruption.
    /// All state changes result in a new session instance, ensuring thread safety
    /// and preventing unauthorized state modifications.
    /// </summary>
    public class DoubleRatchetSession
    {
        /// <summary>
        /// Creates a new Double Ratchet session
        /// </summary>
        public DoubleRatchetSession(
            (byte[] publicKey, byte[] privateKey) dhRatchetKeyPair,
            byte[] remoteDHRatchetKey,
            byte[] rootKey,
            byte[] sendingChainKey,
            byte[] receivingChainKey,
            int messageNumber,
            string? sessionId = null,
            IEnumerable<Guid>? recentlyProcessedIds = null,
            IEnumerable<int>? processedMessageNumbers = null)
        {
            DHRatchetKeyPair = dhRatchetKeyPair;
            RemoteDHRatchetKey = remoteDHRatchetKey ?? throw new ArgumentNullException(nameof(remoteDHRatchetKey));
            RootKey = rootKey ?? throw new ArgumentNullException(nameof(rootKey));
            SendingChainKey = sendingChainKey ?? throw new ArgumentNullException(nameof(sendingChainKey));
            ReceivingChainKey = receivingChainKey ?? throw new ArgumentNullException(nameof(receivingChainKey));
            MessageNumber = messageNumber;
            SessionId = sessionId ?? Guid.NewGuid().ToString();

            // Initialize message ID tracking with immutable collections
            _recentlyProcessedIds = recentlyProcessedIds != null
                ? new List<Guid>(recentlyProcessedIds).AsReadOnly()
                : new List<Guid>().AsReadOnly();

            _processedMessageNumbers = processedMessageNumbers != null
                ? new HashSet<int>(processedMessageNumbers)
                : new HashSet<int>();
        }

        /// <summary>
        /// Unique session identifier to group messages
        /// </summary>
        public string SessionId { get; }

        /// <summary>
        /// Read-only collection of recently processed message IDs for replay protection
        /// </summary>
        private readonly IReadOnlyCollection<Guid> _recentlyProcessedIds;

        /// <summary>
        /// Set of processed message numbers for replay protection (immutable)
        /// </summary>
        private readonly HashSet<int> _processedMessageNumbers;

        /// <summary>
        /// Current DH ratchet key pair
        /// </summary>
        public (byte[] publicKey, byte[] privateKey) DHRatchetKeyPair { get; }

        /// <summary>
        /// Remote party's current ratchet public key
        /// </summary>
        public byte[] RemoteDHRatchetKey { get; }

        /// <summary>
        /// Current root key
        /// </summary>
        public byte[] RootKey { get; }

        /// <summary>
        /// Current sending chain key
        /// </summary>
        public byte[] SendingChainKey { get; }

        /// <summary>
        /// Current receiving chain key
        /// </summary>
        public byte[] ReceivingChainKey { get; }

        /// <summary>
        /// Current message number
        /// </summary>
        public int MessageNumber { get; }

        /// <summary>
        /// Provides read-only access to processed message numbers
        /// </summary>
        public IReadOnlyCollection<int> ProcessedMessageNumbers => _processedMessageNumbers;

        /// <summary>
        /// Provides read-only access to processed message IDs
        /// </summary>
        public IReadOnlyCollection<Guid> RecentlyProcessedIds => _recentlyProcessedIds;

        /// <summary>
        /// Checks if a message ID has been processed already
        /// </summary>
        public bool HasProcessedMessageId(Guid messageId)
        {
            return _recentlyProcessedIds.Contains(messageId);
        }

        /// <summary>
        /// Checks if a message number has been processed already
        /// </summary>
        public bool HasProcessedMessageNumber(int messageNumber)
        {
            return _processedMessageNumbers.Contains(messageNumber);
        }

        /// <summary>
        /// Creates a copy of this session with updated parameters and tracked message IDs
        /// </summary>
        public DoubleRatchetSession WithUpdatedParameters(
            (byte[] publicKey, byte[] privateKey)? newDHRatchetKeyPair = null,
            byte[]? newRemoteDHRatchetKey = null,
            byte[]? newRootKey = null,
            byte[]? newSendingChainKey = null,
            byte[]? newReceivingChainKey = null,
            int? newMessageNumber = null,
            Guid? newProcessedMessageId = null,
            int? newProcessedMessageNumber = null,
            string? newSessionId = null)
        {
            // Create new collections for tracking IDs
            var updatedMessageIds = new List<Guid>(_recentlyProcessedIds);
            var updatedMessageNumbers = new HashSet<int>(_processedMessageNumbers);

            // Add new processed ID if provided
            if (newProcessedMessageId.HasValue)
            {
                updatedMessageIds.Add(newProcessedMessageId.Value);

                // Maintain bounded collection size
                while (updatedMessageIds.Count > Constants.MAX_TRACKED_MESSAGE_IDS)
                {
                    updatedMessageIds.RemoveAt(0);
                }
            }

            // Add new processed message number if provided
            if (newProcessedMessageNumber.HasValue)
            {
                updatedMessageNumbers.Add(newProcessedMessageNumber.Value);
            }

            // Create new session with updated parameters
            return new DoubleRatchetSession(
                newDHRatchetKeyPair ?? DHRatchetKeyPair,
                newRemoteDHRatchetKey ?? RemoteDHRatchetKey,
                newRootKey ?? RootKey,
                newSendingChainKey ?? SendingChainKey,
                newReceivingChainKey ?? ReceivingChainKey,
                newMessageNumber ?? MessageNumber,
                newSessionId ?? SessionId,
                updatedMessageIds,
                updatedMessageNumbers
            );
        }

        /// <summary>
        /// Creates a copy of this session with a newly processed message ID
        /// </summary>
        public DoubleRatchetSession WithProcessedMessageId(Guid messageId)
        {
            return WithUpdatedParameters(newProcessedMessageId: messageId);
        }

        /// <summary>
        /// Creates a copy of this session with a newly processed message number
        /// </summary>
        public DoubleRatchetSession WithProcessedMessageNumber(int messageNumber)
        {
            return WithUpdatedParameters(newProcessedMessageNumber: messageNumber);
        }
    }
}