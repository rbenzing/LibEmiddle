using System.Text.Json;
using E2EELibrary.Core;

namespace E2EELibrary.Models
{
    /// <summary>
    /// Encrypted message container with enhanced security features
    /// </summary>
    public class EncryptedMessage
    {
        /// <summary>
        /// Encrypted data with authentication tag
        /// </summary>
        public byte[]? Ciphertext { get; set; }

        /// <summary>
        /// Nonce used for encryption
        /// </summary>
        public byte[]? Nonce { get; set; }

        /// <summary>
        /// Message number for Double Ratchet (required for replay protection)
        /// </summary>
        public int MessageNumber { get; set; }

        /// <summary>
        /// Sender's current ratchet public key
        /// </summary>
        public byte[]? SenderDHKey { get; set; }

        /// <summary>
        /// Timestamp to prevent replay attacks (milliseconds since Unix epoch)
        /// Always set and checked by the protocol
        /// </summary>
        public long Timestamp { get; set; }

        /// <summary>
        /// Required message identifier for tracking and replay detection
        /// </summary>
        public Guid MessageId { get; set; } = Guid.NewGuid();

        // Add a session ID to group messages by conversation
        /// <summary>
        /// Session identifier to track different conversations
        /// </summary>
        public string? SessionId { get; set; }

        /// <summary>
        /// Creates a copy of this message with new ciphertext and nonce
        /// </summary>
        /// <param name="newCiphertext">New ciphertext</param>
        /// <param name="newNonce">New nonce</param>
        /// <returns>New message instance</returns>
        public EncryptedMessage WithNewEncryption(byte[] newCiphertext, byte[] newNonce)
        {
            return new EncryptedMessage
            {
                Ciphertext = newCiphertext,
                Nonce = newNonce,
                MessageNumber = this.MessageNumber,
                SenderDHKey = this.SenderDHKey,
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                MessageId = this.MessageId
            };
        }

        /// <summary>
        /// Validates this message for security requirements
        /// </summary>
        /// <returns>True if the message is valid</returns>
        public bool Validate()
        {
            // Check for null or empty elements
            if (Ciphertext == null || Ciphertext.Length == 0)
                return false;

            if (Nonce == null || Nonce.Length == 0)
                return false;

            if (SenderDHKey == null || SenderDHKey.Length == 0)
                return false;

            // Validate timestamp - reject future timestamps (with 1 minute allowance for clock skew)
            long currentTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            if (Timestamp > currentTime + (60 * 1000))
                return false;

            return true;
        }

        /// <summary>
        /// Converts the message to a dictionary for serialization
        /// </summary>
        /// <returns>Dictionary representation</returns>
        public Dictionary<string, object> ToDictionary()
        {
            ArgumentNullException.ThrowIfNull(Ciphertext);
            ArgumentNullException.ThrowIfNull(Nonce);
            ArgumentNullException.ThrowIfNull(SenderDHKey);

            // Create a dictionary with predictable field ordering for canonicalization
            var result = new Dictionary<string, object>
            {
                ["ciphertext"] = Convert.ToBase64String(Ciphertext),
                ["nonce"] = Convert.ToBase64String(Nonce),
                ["messageNumber"] = MessageNumber,
                ["senderDHKey"] = Convert.ToBase64String(SenderDHKey),
                ["timestamp"] = Timestamp,
                ["messageId"] = MessageId.ToString()
            };

            // Add optional fields only if they have values
            if (!string.IsNullOrEmpty(SessionId))
            {
                result["sessionId"] = SessionId;
            }

            return result;
        }

        /// <summary>
        /// Creates an encrypted message from a dictionary (deserialization)
        /// </summary>
        /// <param name="dict">Dictionary representation</param>
        /// <returns>EncryptedMessage instance</returns>
        public static EncryptedMessage FromDictionary(Dictionary<string, object> dict)
        {
            ArgumentNullException.ThrowIfNull(dict);

            try
            {
                // Validate required fields
                ValidateRequiredDictionaryFields(dict);

                var message = new EncryptedMessage
                {
                    Ciphertext = ConvertToBytes(dict["ciphertext"]),
                    Nonce = ConvertToBytes(dict["nonce"]),
                    MessageNumber = GetInt32Value(dict["messageNumber"]),
                    SenderDHKey = ConvertToBytes(dict["senderDHKey"])
                };

                // Optional fields with fallbacks
                if (dict.ContainsKey("timestamp"))
                    message.Timestamp = GetInt64Value(dict["timestamp"]);
                else
                    message.Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

                if (dict.ContainsKey("messageId") &&
                    Guid.TryParse(dict["messageId"].ToString(), out var messageId))
                {
                    message.MessageId = messageId;
                }
                else
                {
                    message.MessageId = Guid.NewGuid();
                }

                // Handle session ID if present
                if (dict.ContainsKey("sessionId") && dict["sessionId"] != null)
                    message.SessionId = dict["sessionId"].ToString();

                return message;
            }
            catch (Exception ex)
            {
                throw new FormatException("Invalid message format", ex);
            }
        }

        /// <summary>
        /// Serializes the message to JSON using standardized options
        /// </summary>
        /// <returns>JSON string</returns>
        public string ToJson()
        {
            // Create a normalized dictionary representation with consistent ordering
            var orderedDict = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["ciphertext"] = Convert.ToBase64String(Ciphertext ?? Array.Empty<byte>()),
                ["nonce"] = Convert.ToBase64String(Nonce ?? Array.Empty<byte>()),
                ["messageNumber"] = MessageNumber,
                ["senderDHKey"] = Convert.ToBase64String(SenderDHKey ?? Array.Empty<byte>()),
                ["timestamp"] = Timestamp,
                ["messageId"] = MessageId.ToString()
            };

            // Add optional fields only if they have values
            if (!string.IsNullOrEmpty(SessionId))
            {
                orderedDict["sessionId"] = SessionId;
            }

            return JsonSerialization.Serialize(orderedDict);
        }

        /// <summary>
        /// Deserializes an encrypted message from JSON
        /// </summary>
        /// <param name="json">JSON string</param>
        /// <returns>EncryptedMessage instance</returns>
        public static EncryptedMessage FromJson(string json)
        {
            if (string.IsNullOrEmpty(json))
                throw new ArgumentException("JSON cannot be null or empty", nameof(json));

            try
            {
                // For backward compatibility, use case-insensitive deserialization
                var dict = JsonSerialization.DeserializeInsensitive<Dictionary<string, JsonElement>>(json);

                ArgumentNullException.ThrowIfNull(dict);

                ValidateRequiredJsonFields(dict);

                var message = new EncryptedMessage
                {
                    Ciphertext = Utils.GetBytesFromBase64(dict, "ciphertext"),
                    Nonce = Utils.GetBytesFromBase64(dict, "nonce"),
                    MessageNumber = Utils.GetInt32Value(dict["messageNumber"]),
                    SenderDHKey = Utils.GetBytesFromBase64(dict, "senderDHKey"),
                    Timestamp = Utils.GetInt64Value(dict, "timestamp", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()),
                    MessageId = Utils.GetGuidValue(dict, "messageId", Guid.NewGuid())
                };

                // Handle optional fields
                if (dict.TryGetValue("sessionId", out JsonElement sessionIdElement) &&
                    sessionIdElement.ValueKind == JsonValueKind.String)
                {
                    message.SessionId = sessionIdElement.GetString();
                }

                return message;
            }
            catch (Exception ex)
            {
                throw new FormatException("Invalid JSON format for encrypted message", ex);
            }
        }

        private static void ValidateRequiredDictionaryFields(Dictionary<string, object> dict)
        {
            // Check for required fields
            string[] requiredFields = { "ciphertext", "nonce", "messageNumber", "senderDHKey" };
            foreach (var field in requiredFields)
            {
                if (!dict.ContainsKey(field) || dict[field] == null)
                {
                    throw new FormatException($"Required field '{field}' is missing or null");
                }
            }
        }

        private static void ValidateRequiredJsonFields(Dictionary<string, JsonElement> dict)
        {
            string[] requiredFields = { "ciphertext", "nonce", "messageNumber", "senderDHKey" };

            foreach (var field in requiredFields)
            {
                if (!dict.ContainsKey(field))
                {
                    throw new FormatException($"Required field '{field}' is missing");
                }

                // Also validate that base64 fields contain valid base64 strings
                if (field is "ciphertext" or "nonce" or "senderDHKey")
                {
                    if (dict[field].ValueKind != JsonValueKind.String)
                    {
                        throw new FormatException($"Field '{field}' must be a string");
                    }

                    string? base64 = dict[field].GetString();
                    if (string.IsNullOrEmpty(base64) || !Utils.IsValidBase64(base64))
                    {
                        throw new FormatException($"Field '{field}' contains invalid Base64 data");
                    }
                }
            }
        }

        private static byte[] ConvertToBytes(object value)
        {
            if (value is byte[] byteArray)
                return byteArray;

            if (value is string base64String)
            {
                try
                {
                    return Convert.FromBase64String(base64String);
                }
                catch (FormatException)
                {
                    throw new FormatException($"Invalid Base64 encoding: {base64String}");
                }
            }

            if (value is JsonElement jsonElement && jsonElement.ValueKind == JsonValueKind.String)
            {
                try
                {
                    return Convert.FromBase64String(jsonElement.GetString() ?? "");
                }
                catch (FormatException)
                {
                    throw new FormatException($"Invalid Base64 encoding in JsonElement");
                }
            }

            throw new FormatException($"Cannot convert value of type {value.GetType().Name} to byte array");
        }

        private static int GetInt32Value(object value)
        {
            if (value is int intValue)
                return intValue;

            if (value is JsonElement jsonElement)
            {
                if (jsonElement.ValueKind == JsonValueKind.Number)
                    return jsonElement.GetInt32();

                if (jsonElement.ValueKind == JsonValueKind.String &&
                    int.TryParse(jsonElement.GetString(), out int parsedValue))
                    return parsedValue;
            }

            if (value is string stringValue && int.TryParse(stringValue, out int result))
                return result;

            if (value != null)
            {
                if (int.TryParse(value.ToString(), out int parsed))
                    return parsed;
            }

            throw new FormatException($"Cannot convert {value} to Int32");
        }

        private static long GetInt64Value(object value)
        {
            if (value is long longValue)
                return longValue;

            if (value is int intValue)
                return intValue;

            if (value is JsonElement jsonElement)
            {
                if (jsonElement.ValueKind == JsonValueKind.Number)
                    return jsonElement.GetInt64();

                if (jsonElement.ValueKind == JsonValueKind.String &&
                    long.TryParse(jsonElement.GetString(), out long parsedValue))
                    return parsedValue;
            }

            if (value is string stringValue && long.TryParse(stringValue, out long result))
                return result;

            if (value != null)
            {
                if (long.TryParse(value.ToString(), out long parsed))
                    return parsed;
            }

            throw new FormatException($"Cannot convert {value} to Int64");
        }
    }
}