#pragma warning disable IDE0130 // Namespace does not match folder structure
namespace LibEmiddle.Domain
#pragma warning restore IDE0130 // Namespace does not match folder structure
{
    /// <summary>
    /// Represents the data structure used for serializing DoubleRatchetSession state.
    /// Uses Base64 for byte arrays and simple collections for IDs/numbers.
    /// </summary>
    public class SerializableSessionData
    {
        // Use nullable strings for keys that might be null in the session
        public string? DHRatchetPublicKey { get; set; }
        public string? DHRatchetPrivateKey { get; set; } // Store private key securely!
        public string? RemoteDHRatchetKey { get; set; }
        public string? RootKey { get; set; }
        public string? SendingChainKey { get; set; }
        public string? ReceivingChainKey { get; set; }
        public int MessageNumberSending { get; set; }
        public int MessageNumberReceiving { get; set; }
        public string? SessionId { get; set; }
        public List<Guid>? RecentlyProcessedIds { get; set; } // Use List<T> for JSON simplicity
        public List<int>? ProcessedMessageNumbersReceiving { get; set; } // Use List<T> or HashSet<T>
        public List<SerializableSkippedKeyEntry>? SkippedMessageKeys { get; set; } // Custom type for dictionary
    }

    /// <summary>
    /// Helper structure for serializing the SkippedMessageKeys dictionary entries.
    /// </summary>
    public class SerializableSkippedKeyEntry
    {
        public string? RemoteDhKeyBase64 { get; set; } // Key part 1 (byte[]) as Base64
        public int MessageNumber { get; set; }        // Key part 2 (int)
        public string? MessageKeyBase64 { get; set; }  // Value (byte[]) as Base64
    }
}
