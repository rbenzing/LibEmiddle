namespace LibEmiddle.Domain
{
    /// <summary>
    /// Message indicating a device has been revoked.
    /// </summary>
    public class DeviceRevocationMessage
    {
        /// <summary>
        /// Public key of the revoked device
        /// </summary>
        public byte[] RevokedDeviceKey { get; set; }

        /// <summary>
        /// Timestamp when the device was revoked (milliseconds since Unix epoch)
        /// </summary>
        public long RevocationTimestamp { get; set; }

        /// <summary>
        /// Signature of the revoked device key and timestamp, signed by the authorizing device
        /// </summary>
        public byte[] Signature { get; set; }

        /// <summary>
        /// Protocol version information for compatibility checking
        /// </summary>
        public string Version { get; set; } = ProtocolVersion.FULL_VERSION;

        /// <summary>
        /// Creates a new device revocation message with empty non-null properties.
        /// </summary>
        public DeviceRevocationMessage()
        {
            RevokedDeviceKey = Array.Empty<byte>();
            Signature = Array.Empty<byte>();
            RevocationTimestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        }

        /// <summary>
        /// Creates a new device revocation message with the specified parameters.
        /// </summary>
        /// <param name="revokedDeviceKey">The public key of the device being revoked</param>
        /// <param name="signature">The signature of the combined device key and timestamp</param>
        /// <param name="revocationTimestamp">The revocation timestamp (defaults to current time if not specified)</param>
        /// <exception cref="ArgumentNullException">Thrown when required parameters are null</exception>
        public DeviceRevocationMessage(byte[] revokedDeviceKey, byte[] signature, long revocationTimestamp = 0)
        {
            RevokedDeviceKey = revokedDeviceKey ?? throw new ArgumentNullException(nameof(revokedDeviceKey));
            Signature = signature ?? throw new ArgumentNullException(nameof(signature));
            RevocationTimestamp = revocationTimestamp > 0 ? revocationTimestamp : DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        }

        /// <summary>
        /// Serializes this message to a dictionary for transport
        /// </summary>
        public Dictionary<string, string> ToDictionary()
        {
            var dict = new Dictionary<string, string>
            {
                ["revokedDeviceKey"] = Convert.ToBase64String(RevokedDeviceKey),
                ["revocationTimestamp"] = RevocationTimestamp.ToString(),
                ["signature"] = Convert.ToBase64String(Signature),
                ["protocolVersion"] = Version
            };

            return dict;
        }

        /// <summary>
        /// Creates a DeviceRevocationMessage from a dictionary
        /// </summary>
        public static DeviceRevocationMessage FromDictionary(Dictionary<string, string> dict)
        {
            if (!dict.TryGetValue("revokedDeviceKey", out string? keyBase64) ||
                !dict.TryGetValue("signature", out string? sigBase64) ||
                !dict.TryGetValue("revocationTimestamp", out string? timestampStr))
            {
                throw new ArgumentException("Missing required fields in dictionary", nameof(dict));
            }

            byte[] deviceKey = Convert.FromBase64String(keyBase64);
            byte[] signature = Convert.FromBase64String(sigBase64);
            long timestamp = long.Parse(timestampStr);

            var message = new DeviceRevocationMessage(deviceKey, signature, timestamp);

            // Set protocol version if present
            if (dict.TryGetValue("protocolVersion", out string? version))
            {
                message.Version = version;
            }

            return message;
        }

        /// <summary>
        /// Serializes this message to JSON
        /// </summary>
        public string ToJson()
        {
            return System.Text.Json.JsonSerializer.Serialize(ToDictionary());
        }

        /// <summary>
        /// Creates a DeviceRevocationMessage from JSON
        /// </summary>
        public static DeviceRevocationMessage FromJson(string json)
        {
            var dict = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(json)
                ?? throw new ArgumentException("Failed to deserialize JSON", nameof(json));

            return FromDictionary(dict);
        }
    }

    // Add a cryptographic validation interface to Domain project
    public interface ICryptographicValidator
    {
        /// <summary>
        /// Validates a revocation message against a trusted public key.
        /// </summary>
        bool ValidateRevocationMessage(DeviceRevocationMessage message, byte[] trustedPublicKey);
    }
}