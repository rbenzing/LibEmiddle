namespace LibEmiddle.Domain
{
    /// <summary>
    /// Represents a key for looking up skipped message keys in the Double Ratchet protocol.
    /// Used to handle out-of-order message delivery.
    /// </summary>
    public readonly struct SkippedMessageKey : IEquatable<SkippedMessageKey>
    {
        /// <summary>
        /// Gets the DH public key associated with this skipped message key.
        /// </summary>
        public byte[] DhPublicKey { get; }

        /// <summary>
        /// Gets the message number associated with this skipped message key.
        /// </summary>
        public uint MessageNumber { get; }

        /// <summary>
        /// Initializes a new instance of the SkippedMessageKey struct.
        /// </summary>
        /// <param name="dhPublicKey">The DH public key.</param>
        /// <param name="messageNumber">The message number.</param>
        public SkippedMessageKey(byte[] dhPublicKey, uint messageNumber)
        {
            DhPublicKey = dhPublicKey ?? throw new ArgumentNullException(nameof(dhPublicKey));
            MessageNumber = messageNumber;
        }

        /// <summary>
        /// Determines whether the specified object is equal to the current object.
        /// </summary>
        public override bool Equals(object? obj)
        {
            return obj is SkippedMessageKey key && Equals(key);
        }

        /// <summary>
        /// Determines whether the specified SkippedMessageKey is equal to the current SkippedMessageKey.
        /// </summary>
        public bool Equals(SkippedMessageKey other)
        {
            return MessageNumber == other.MessageNumber &&
                   DhPublicKey.AsSpan().SequenceEqual(other.DhPublicKey);
        }

        /// <summary>
        /// Returns a hash code for this instance.
        /// </summary>
        public override int GetHashCode()
        {
            var hashCode = new HashCode();
            foreach (byte b in DhPublicKey)
            {
                hashCode.Add(b);
            }
            hashCode.Add(MessageNumber);
            return hashCode.ToHashCode();
        }

        /// <summary>
        /// Determines whether two specified SkippedMessageKey objects have the same value.
        /// </summary>
        public static bool operator ==(SkippedMessageKey left, SkippedMessageKey right)
        {
            return left.Equals(right);
        }

        /// <summary>
        /// Determines whether two specified SkippedMessageKey objects have different values.
        /// </summary>
        public static bool operator !=(SkippedMessageKey left, SkippedMessageKey right)
        {
            return !(left == right);
        }
    }
}
