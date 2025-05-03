using System.Text.Json;
using LibEmiddle.Core;
using LibEmiddle.Domain;
using LibEmiddle.Messaging.Transport;

namespace LibEmiddle.MultiDevice
{
    /// <summary>
    /// Represents a message used to synchronize data between multiple devices.
    /// Includes protection against replay attacks and protocol versioning.
    /// </summary>
    public class DeviceSyncMessage
    {
        /// <summary>
        /// Sender device's public key
        /// </summary>
        public byte[]? SenderPublicKey { get; set; }

        /// <summary>
        /// Data to sync
        /// </summary>
        public byte[]? Data { get; set; }

        /// <summary>
        /// Signature of the data
        /// </summary>
        public byte[]? Signature { get; set; }

        /// <summary>
        /// Timestamp to prevent replay attacks (milliseconds since Unix epoch)
        /// </summary>
        public long Timestamp { get; set; }

        /// <summary>
        /// Protocol version information for compatibility checking
        /// </summary>
        public string Version { get; set; } = ProtocolVersion.FULL_VERSION;

        /// <summary>
        /// Unique message identifier to prevent duplication
        /// </summary>
        public Guid MessageId { get; set; } = Guid.NewGuid();

        /// <summary>
        /// Creates a new DeviceSyncMessage
        /// </summary>
        public DeviceSyncMessage()
        {
            Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        }

        /// <summary>
        /// Creates a new DeviceSyncMessage with the specified parameters
        /// </summary>
        /// <param name="senderPublicKey">The public key of the sending device</param>
        /// <param name="data">The data to synchronize</param>
        /// <param name="signature">The signature of the data</param>
        public DeviceSyncMessage(byte[] senderPublicKey, byte[] data, byte[] signature)
        {
            SenderPublicKey = senderPublicKey ?? throw new ArgumentNullException(nameof(senderPublicKey));
            Data = data ?? throw new ArgumentNullException(nameof(data));
            Signature = signature ?? throw new ArgumentNullException(nameof(signature));
            Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            MessageId = Guid.NewGuid();
        }

        /// <summary>
        /// Validates this sync message using the provided public key
        /// </summary>
        /// <param name="trustedPublicKey">The trusted public key for verification</param>
        /// <returns>True if the message is valid</returns>
        public bool Validate(byte[] trustedPublicKey)
        {
            // Basic validations
            if (SenderPublicKey == null || SenderPublicKey.Length == 0)
                return false;

            if (Data == null || Data.Length == 0)
                return false;

            if (Signature == null || Signature.Length == 0)
                return false;

            if (Timestamp <= 0)
                return false;

            // Check message age (prevent replay)
            long currentTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            // Reject messages older than 5 minutes
            if (currentTime - Timestamp > Constants.MAX_MESSAGE_AGE_MS)
                return false;

            // Reject future messages with more than 1 minute time skew
            if (Timestamp > currentTime + 60 * 1000)
                return false;

            // Check protocol version compatibility if set
            if (!string.IsNullOrEmpty(Version))
            {
                if (!IsValidProtocolVersion(Version))
                    return false;
            }

            // Use SequenceEqual to validate the expected sender matches the trusted key
            if (!SecureMemory.SecureCompare(SenderPublicKey, trustedPublicKey))
                return false;

            // Verify the signature
            return MessageSigning.VerifySignature(Data, Signature, SenderPublicKey);
        }

        /// <summary>
        /// Validates the protocol version format and compatibility
        /// </summary>
        /// <param name="version">Protocol version string to check</param>
        /// <returns>True if the version is compatible</returns>
        private bool IsValidProtocolVersion(string version)
        {
            // Check format (e.g., "LibEmiddle/v1.0")
            string[] parts = version.Split('/');
            if (parts.Length != 2 || !parts[1].StartsWith("v"))
                return false;

            // Parse version number
            string versionNumber = parts[1].Substring(1);
            string[] versionParts = versionNumber.Split('.');
            if (versionParts.Length != 2)
                return false;

            if (!int.TryParse(versionParts[0], out int majorVersion) ||
                !int.TryParse(versionParts[1], out int minorVersion))
                return false;

            // Check compatibility
            return ProtocolVersion.IsCompatible(majorVersion, minorVersion);
        }

        /// <summary>
        /// Serializes this message to a dictionary for transport
        /// </summary>
        public Dictionary<string, object> ToDictionary()
        {
            var dict = new Dictionary<string, object>
            {
                ["senderPublicKey"] = Convert.ToBase64String(SenderPublicKey ?? Array.Empty<byte>()),
                ["data"] = Convert.ToBase64String(Data ?? Array.Empty<byte>()),
                ["signature"] = Convert.ToBase64String(Signature ?? Array.Empty<byte>()),
                ["timestamp"] = Timestamp,
                ["protocolVersion"] = Version,
                ["messageId"] = MessageId.ToString()
            };

            return dict;
        }

        /// <summary>
        /// Creates a DeviceSyncMessage from a dictionary
        /// </summary>
        public static DeviceSyncMessage FromDictionary(Dictionary<string, object> dict)
        {
            if (!dict.TryGetValue("senderPublicKey", out object? senderKeyObj) ||
                !dict.TryGetValue("data", out object? dataObj) ||
                !dict.TryGetValue("signature", out object? sigObj))
            {
                throw new ArgumentException("Missing required fields in dictionary", nameof(dict));
            }

            string senderKeyBase64 = senderKeyObj.ToString() ?? throw new ArgumentException("Sender key is null");
            string dataBase64 = dataObj.ToString() ?? throw new ArgumentException("Data is null");
            string signatureBase64 = sigObj.ToString() ?? throw new ArgumentException("Signature is null");

            var message = new DeviceSyncMessage
            {
                SenderPublicKey = Convert.FromBase64String(senderKeyBase64),
                Data = Convert.FromBase64String(dataBase64),
                Signature = Convert.FromBase64String(signatureBase64)
            };

            // Set timestamp if present
            if (dict.TryGetValue("timestamp", out object? timestampObj) &&
                timestampObj != null &&
                long.TryParse(timestampObj.ToString(), out long timestamp))
            {
                message.Timestamp = timestamp;
            }

            // Set protocol version if present
            if (dict.TryGetValue("protocolVersion", out object? versionObj) &&
                versionObj != null)
            {
                message.Version = versionObj.ToString() ?? ProtocolVersion.FULL_VERSION;
            }

            // Set message ID if present
            if (dict.TryGetValue("messageId", out object? idObj) &&
                idObj != null &&
                Guid.TryParse(idObj.ToString(), out Guid id))
            {
                message.MessageId = id;
            }

            return message;
        }

        /// <summary>
        /// Serializes this message to JSON
        /// </summary>
        public string ToJson()
        {
            return JsonSerialization.Serialize(ToDictionary());
        }

        /// <summary>
        /// Creates a DeviceSyncMessage from JSON
        /// </summary>
        public static DeviceSyncMessage FromJson(string json)
        {
            var dict = JsonSerialization.Deserialize<Dictionary<string, JsonElement>>(json)
                ?? throw new ArgumentException("Failed to deserialize JSON", nameof(json));

            // Convert JsonElement dictionary to object dictionary
            var objectDict = new Dictionary<string, object>();

            foreach (var kvp in dict)
            {
                switch (kvp.Value.ValueKind)
                {
                    case JsonValueKind.String:
                        objectDict[kvp.Key] = kvp.Value.GetString() ?? string.Empty;
                        break;
                    case JsonValueKind.Number:
                        if (kvp.Value.TryGetInt64(out long longValue))
                            objectDict[kvp.Key] = longValue;
                        else
                            objectDict[kvp.Key] = kvp.Value.GetDouble();
                        break;
                    case JsonValueKind.True:
                        objectDict[kvp.Key] = true;
                        break;
                    case JsonValueKind.False:
                        objectDict[kvp.Key] = false;
                        break;
                    default:
                        objectDict[kvp.Key] = kvp.Value.ToString() ?? string.Empty;
                        break;
                }
            }

            return FromDictionary(objectDict);
        }
    }
}