namespace LibEmiddle.Domain
{
    /// <summary>
    /// Message indicating a device has been revoked.
    /// </summary>
    public class DeviceRevocationMessage
    {
        /// <summary>
        /// Gets or sets a unique identifier for this revocation message.
        /// </summary>
        public string Id { get; set; } = Guid.NewGuid().ToString();

        /// <summary>
        /// Gets or sets the public key of the device being revoked (in standard X25519 format).
        /// </summary>
        public byte[]? RevokedDevicePublicKey { get; set; }

        /// <summary>
        /// Gets or sets the identity public key of the user who owns the devices.
        /// Used to verify that the revocation comes from the legitimate owner.
        /// </summary>
        public byte[]? UserIdentityPublicKey { get; set; }

        /// <summary>
        /// Timestamp when the device was revoked (milliseconds since Unix epoch)
        /// Used for ordering and preventing replay attacks.
        /// </summary>
        public long Timestamp { get; set; }

        /// <summary>
        /// Signature of the revoked device key and timestamp, signed by the authorizing device
        /// </summary>
        public byte[]? Signature { get; set; }

        /// <summary>
        /// Gets or sets an optional reason for the revocation.
        /// </summary>
        public string? Reason { get; set; }

        /// <summary>
        /// Protocol version information for compatibility checking
        /// </summary>
        public string Version { get; set; } = ProtocolVersion.FULL_VERSION;

        /// <summary>
        /// Creates a new device revocation message with empty non-null properties.
        /// </summary>
        public DeviceRevocationMessage()
        {
            UserIdentityPublicKey = Array.Empty<byte>();
            RevokedDevicePublicKey = Array.Empty<byte>();
            Signature = Array.Empty<byte>();
            Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        }

        /// <summary>
        /// Creates a new device revocation message with the specified parameters.
        /// </summary>
        /// <param name="revokedDeviceKey">The public key of the device being revoked</param>
        /// <param name="identityKey">The public identity key of the device owner</param>
        /// <param name="signature">The signature of the combined device key and timestamp</param>
        /// <param name="revocationTimestamp">The revocation timestamp (defaults to current time if not specified)</param>
        /// <exception cref="ArgumentNullException">Thrown when required parameters are null</exception>
        public DeviceRevocationMessage(byte[] revokedDeviceKey, byte[] identityKey, byte[] signature, long revocationTimestamp = 0)
        {
            UserIdentityPublicKey = identityKey ?? throw new ArgumentNullException(nameof(identityKey)); ;
            RevokedDevicePublicKey = revokedDeviceKey ?? throw new ArgumentNullException(nameof(revokedDeviceKey));
            Signature = signature ?? throw new ArgumentNullException(nameof(signature));
            Timestamp = revocationTimestamp > 0 ? revocationTimestamp : DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        }

        /// <summary>
        /// Serializes this message to a dictionary for transport
        /// </summary>
        public Dictionary<string, string> ToDictionary()
        {
            if (UserIdentityPublicKey == null)
                throw new ArgumentNullException(nameof(UserIdentityPublicKey));
            if (RevokedDevicePublicKey == null)
                throw new ArgumentNullException(nameof(RevokedDevicePublicKey));
            if (Signature == null)
                throw new ArgumentNullException(nameof(Signature));

            var dict = new Dictionary<string, string>
            {
                ["id"] = Id,
                ["revokedDeviceKey"] = Convert.ToBase64String(RevokedDevicePublicKey),
                ["revocationTimestamp"] = Timestamp.ToString(),
                ["reason"] = Reason ?? "",
                ["identityPublicKey"] = Convert.ToBase64String(UserIdentityPublicKey),
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
            if (!dict.TryGetValue("identityPublicKey", out string? identityKeyBase64) ||
                !dict.TryGetValue("revokedDeviceKey", out string? keyBase64) ||
                !dict.TryGetValue("signature", out string? sigBase64) ||
                !dict.TryGetValue("revocationTimestamp", out string? timestampStr))
            {
                throw new ArgumentException("Missing required fields in dictionary", nameof(dict));
            }

            byte[] identityKey = Convert.FromBase64String(identityKeyBase64);
            byte[] deviceKey = Convert.FromBase64String(keyBase64);
            byte[] signature = Convert.FromBase64String(sigBase64);
            long timestamp = long.Parse(timestampStr);

            var message = new DeviceRevocationMessage(deviceKey, identityKey, signature, timestamp);

            // Set protocol version if present
            if (dict.TryGetValue("protocolVersion", out string? version))
            {
                message.Version = version;
            }

            if (dict.TryGetValue("id", out string? id))
            {
                message.Id = id;
            }

            if (dict.TryGetValue("reason", out string? reason))
            {
                message.Reason = reason;
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

        /// <summary>
        /// Validates that this revocation message contains all required fields.
        /// </summary>
        /// <returns>True if the message is valid, false otherwise.</returns>
        public bool IsValid()
        {
            return RevokedDevicePublicKey != null &&
                   RevokedDevicePublicKey.Length > 0 &&
                   UserIdentityPublicKey != null &&
                   UserIdentityPublicKey.Length > 0 &&
                   Signature != null &&
                   Signature.Length > 0 &&
                   Timestamp > 0;
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