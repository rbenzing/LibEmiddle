using System.Text.Json.Serialization;

namespace LibEmiddle.Domain
{
    /// <summary>
    /// Represents the state of a Double Ratchet session as defined in the Signal protocol.
    /// Contains all cryptographic state needed for encrypted communication with forward secrecy
    /// and break-in recovery.
    /// </summary>
    public class DoubleRatchetSession
    {
        /// <summary>
        /// Gets or sets the unique identifier for this session.
        /// </summary>
        public string SessionId { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the root key for the Double Ratchet algorithm.
        /// This key evolves with each new ratchet step.
        /// </summary>
        public byte[] RootKey { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Gets or sets the chain key for sending messages.
        /// This advances with each message sent.
        /// </summary>
        public byte[]? SenderChainKey { get; set; }

        /// <summary>
        /// Gets or sets the chain key for receiving messages.
        /// This advances with each message received.
        /// </summary>
        public byte[]? ReceiverChainKey { get; set; }

        /// <summary>
        /// Gets or sets the sender's ratchet key pair (X25519).
        /// This is rotated periodically for enhanced security.
        /// </summary>
        public KeyPair SenderRatchetKeyPair { get; set; } = new KeyPair();

        /// <summary>
        /// Gets or sets the receiver's ratchet public key (X25519).
        /// This is the public key provided by the other party.
        /// </summary>
        public byte[]? ReceiverRatchetPublicKey { get; set; }

        /// <summary>
        /// Gets or sets the previous receiver's ratchet public key.
        /// Used for handling out-of-order messages.
        /// </summary>
        public byte[]? PreviousReceiverRatchetPublicKey { get; set; }

        /// <summary>
        /// Gets or sets the current message number for sending.
        /// Incremented with each message sent in the current chain.
        /// </summary>
        public uint SendMessageNumber { get; set; }

        /// <summary>
        /// Gets or sets the current message number for receiving.
        /// Incremented with each message received in the current chain.
        /// </summary>
        public uint ReceiveMessageNumber { get; set; }

        /// <summary>
        /// Gets or sets the dictionary of message keys for sent messages.
        /// Used for handling out-of-order messages.
        /// Key is the message number, value is the message key.
        /// </summary>
        public Dictionary<uint, byte[]> SentMessages { get; set; } = new Dictionary<uint, byte[]>();

        /// <summary>
        /// Gets or sets the dictionary of skipped message keys.
        /// Used for handling out-of-order messages.
        /// Key is the SkippedMessageKey (DH public key + message number), value is the message key.
        /// </summary>
        public Dictionary<SkippedMessageKey, byte[]> SkippedMessageKeys { get; set; } =
            new Dictionary<SkippedMessageKey, byte[]>();

        /// <summary>
        /// Gets or sets whether the session is fully initialized.
        /// </summary>
        public bool IsInitialized { get; set; }

        /// <summary>
        /// Gets or sets when the session was created (milliseconds since Unix epoch).
        /// </summary>
        public long CreationTimestamp { get; set; }

        /// <summary>
        /// Gets or sets additional metadata for the session.
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public Dictionary<string, string>? Metadata { get; set; }

        /// <summary>
        /// Creates a deep clone of this Double Ratchet session.
        /// </summary>
        /// <returns>A cloned copy of this session.</returns>
        public DoubleRatchetSession Clone()
        {
            var clone = new DoubleRatchetSession
            {
                SessionId = SessionId,
                RootKey = RootKey?.ToArray() ?? Array.Empty<byte>(),
                SenderChainKey = SenderChainKey?.ToArray(),
                ReceiverChainKey = ReceiverChainKey?.ToArray(),
                SenderRatchetKeyPair = new KeyPair
                {
                    PublicKey = SenderRatchetKeyPair.PublicKey.ToArray(),
                    PrivateKey = SenderRatchetKeyPair.PrivateKey.ToArray()
                },
                ReceiverRatchetPublicKey = ReceiverRatchetPublicKey?.ToArray(),
                PreviousReceiverRatchetPublicKey = PreviousReceiverRatchetPublicKey?.ToArray(),
                SendMessageNumber = SendMessageNumber,
                ReceiveMessageNumber = ReceiveMessageNumber,
                IsInitialized = IsInitialized,
                CreationTimestamp = CreationTimestamp
            };

            // Clone dictionaries
            foreach (var kvp in SentMessages)
            {
                clone.SentMessages[kvp.Key] = kvp.Value.ToArray();
            }

            foreach (var kvp in SkippedMessageKeys)
            {
                // Create a new entry with a cloned key and value
                var key = new SkippedMessageKey(
                    kvp.Key.DhPublicKey.ToArray(),
                    kvp.Key.MessageNumber
                );
                clone.SkippedMessageKeys[key] = kvp.Value.ToArray();
            }

            // Clone metadata if present
            if (Metadata != null)
            {
                clone.Metadata = new Dictionary<string, string>(Metadata);
            }

            return clone;
        }

        /// <summary>
        /// Securely clears sensitive cryptographic material from memory.
        /// </summary>
        public void ClearSensitiveData()
        {
            // Clear root key
            if (RootKey != null && RootKey.Length > 0)
            {
                RootKey = Array.Empty<byte>();
            }

            // Clear chain keys
            if (SenderChainKey != null)
            {
                SenderChainKey = null;
            }

            if (ReceiverChainKey != null)
            {
                ReceiverChainKey = null;
            }

            // Clear sent message keys
            SentMessages.Clear();

            // Clear skipped message keys
            SkippedMessageKeys.Clear();
        }

        /// <summary>
        /// Validates that all required fields are present and properly formatted.
        /// </summary>
        /// <returns>True if the session is valid, false otherwise.</returns>
        public bool Validate()
        {
            if (string.IsNullOrEmpty(SessionId))
                return false;

            if (RootKey == null || RootKey.Length != Constants.ROOT_KEY_SIZE)
                return false;

            if (!IsInitialized)
                return false;

            if (SenderRatchetKeyPair.PublicKey == null ||
                SenderRatchetKeyPair.PrivateKey == null ||
                SenderRatchetKeyPair.PublicKey.Length != Constants.X25519_KEY_SIZE ||
                SenderRatchetKeyPair.PrivateKey.Length != Constants.X25519_KEY_SIZE)
                return false;

            // If we have a sender chain key, validate it
            if (SenderChainKey != null && SenderChainKey.Length != Constants.CHAIN_KEY_SIZE)
                return false;

            // If we have a receiver chain key, validate it
            if (ReceiverChainKey != null && ReceiverChainKey.Length != Constants.CHAIN_KEY_SIZE)
                return false;

            // If we have a receiver ratchet public key, validate it
            if (ReceiverRatchetPublicKey != null &&
                ReceiverRatchetPublicKey.Length != Constants.X25519_KEY_SIZE)
                return false;

            // If we have a previous receiver ratchet public key, validate it
            if (PreviousReceiverRatchetPublicKey != null &&
                PreviousReceiverRatchetPublicKey.Length != Constants.X25519_KEY_SIZE)
                return false;

            return true;
        }

        /// <summary>
        /// Creates a new Double Ratchet session with default values.
        /// </summary>
        /// <param name="sessionId">The session identifier to use.</param>
        /// <returns>A new session instance.</returns>
        public static DoubleRatchetSession Create(string sessionId)
        {
            return new DoubleRatchetSession
            {
                SessionId = sessionId,
                CreationTimestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                IsInitialized = false
            };
        }
    }
}