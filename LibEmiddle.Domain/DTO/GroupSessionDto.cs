#pragma warning disable IDE0130 // Namespace does not match folder structure
namespace LibEmiddle.Domain
#pragma warning restore IDE0130 // Namespace does not match folder structure
{
    /// <summary>
    /// The DTO for Group Sessions
    /// </summary>
    public sealed class GroupSessionDto
    {
        public string GroupId { get; set; } = string.Empty;
        public string ChainKeyBase64 { get; set; } = string.Empty;
        public uint Iteration { get; set; }
        public string CreatorIdentityKeyBase64 { get; set; } = string.Empty;
        public long CreationTimestamp { get; set; }
        public long KeyEstablishmentTimestamp { get; set; }
        public string? MetadataJson { get; set; }
    }
}
