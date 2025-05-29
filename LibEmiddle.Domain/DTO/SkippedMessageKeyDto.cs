#pragma warning disable IDE0130 // Namespace does not match folder structure
namespace LibEmiddle.Domain
#pragma warning restore IDE0130 // Namespace does not match folder structure
{
    /// <summary>
    /// DTO for serializing and deserializing a skipped message key identifier.
    /// </summary>
    public class SkippedMessageKeyDto : IEquatable<SkippedMessageKeyDto>
    {
        /// <summary>
        /// Gets or sets the Base64-encoded DH public key.
        /// </summary>
        public string DhPublicKey { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the message number.
        /// </summary>
        public uint MessageNumber { get; set; }

        /// <summary>
        /// Determines whether the specified object is equal to the current object.
        /// </summary>
        public override bool Equals(object? obj)
        {
            return obj is SkippedMessageKeyDto dto && Equals(dto);
        }

        /// <summary>
        /// Determines whether the specified SkippedMessageKeyDto is equal to the current SkippedMessageKeyDto.
        /// </summary>
        public bool Equals(SkippedMessageKeyDto? other)
        {
            return other != null &&
                   DhPublicKey == other.DhPublicKey &&
                   MessageNumber == other.MessageNumber;
        }

        /// <summary>
        /// Returns a hash code for this instance.
        /// </summary>
        public override int GetHashCode()
        {
            return HashCode.Combine(DhPublicKey, MessageNumber);
        }
    }
}