using System.Text.Json;

namespace LibEmiddle.Domain
{
    /// <summary>
    /// Encrypted message container with enhanced security features and protocol versioning
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

        /// <summary>
        /// Session identifier to track different conversations
        /// </summary>
        public string? SessionId { get; set; }

        /// <summary>
        /// Major version of the protocol used to create this message
        /// </summary>
        public int ProtocolMajorVersion { get; set; } = ProtocolVersion.MAJOR_VERSION;

        /// <summary>
        /// Minor version of the protocol used to create this message
        /// </summary>
        public int ProtocolMinorVersion { get; set; } = ProtocolVersion.MINOR_VERSION;

        /// <summary>
        /// Full protocol version as a string
        /// </summary>
        public string Version => $"{ProtocolMajorVersion}.{ProtocolMinorVersion}";

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
                MessageNumber = MessageNumber,
                SenderDHKey = SenderDHKey,
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                MessageId = MessageId,
                SessionId = SessionId,
                ProtocolMajorVersion = ProtocolMajorVersion,
                ProtocolMinorVersion = ProtocolMinorVersion
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
            if (Timestamp > currentTime + 60 * 1000)
                return false;

            // Reject messages that are too old (replay protection)
            if (currentTime - Timestamp > Constants.MAX_MESSAGE_AGE_MS)
                return false;

            // Check protocol version compatibility
            if (!ProtocolVersion.IsCompatible(ProtocolMajorVersion, ProtocolMinorVersion))
                return false;

            // Validate message ID format
            if (MessageId == Guid.Empty)
                return false;

            // Check message number range
            if (MessageNumber < 0)
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
                ["messageId"] = MessageId.ToString(),
                ["protocolVersion"] = Version
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

                // Parse version if present
                if (dict.TryGetValue("protocolVersion", out var versionObj) &&
                    versionObj is string versionStr &&
                    versionStr.Split('.').Length == 2)
                {
                    string[] parts = versionStr.Split('.');
                    if (int.TryParse(parts[0], out int majorVersion) &&
                        int.TryParse(parts[1], out int minorVersion))
                    {
                        message.ProtocolMajorVersion = majorVersion;
                        message.ProtocolMinorVersion = minorVersion;

                        // Check compatibility
                        if (!ProtocolVersion.IsCompatible(majorVersion, minorVersion))
                        {
                            throw new ProtocolVersionException($"Incompatible protocol version: {versionStr}");
                        }
                    }
                }

                return message;
            }
            catch (ProtocolVersionException)
            {
                // Re-throw version exceptions directly
                throw;
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
                ["messageId"] = MessageId.ToString(),
                ["protocolVersion"] = Version
            };

            // Add optional fields only if they have values
            if (!string.IsNullOrEmpty(SessionId))
            {
                orderedDict["sessionId"] = SessionId;
            }

            // Use JsonSerializer directly with optimized options
            return JsonSerializer.Serialize(orderedDict, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                WriteIndented = false
            });
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
                // Use case-insensitive deserialization for backward compatibility
                var dict = JsonSerialization.DeserializeInsensitive<Dictionary<string, JsonElement>>(json);

                ArgumentNullException.ThrowIfNull(dict);

                // Fast validation of required fields
                string[] requiredFields = { "ciphertext", "nonce", "messageNumber", "senderDHKey" };
                foreach (var field in requiredFields)
                {
                    if (!dict.ContainsKey(field))
                        throw new FormatException($"Required field '{field}' is missing");
                }

                // Create message object with extracted data
                var message = new EncryptedMessage
                {
                    Ciphertext = Helpers.GetBytesFromBase64(dict, "ciphertext"),
                    Nonce = Helpers.GetBytesFromBase64(dict, "nonce"),
                    MessageNumber = Helpers.GetInt32Value(dict["messageNumber"]),
                    SenderDHKey = Helpers.GetBytesFromBase64(dict, "senderDHKey"),
                    Timestamp = Helpers.GetInt64Value(dict, "timestamp", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()),
                    MessageId = Helpers.GetGuidValue(dict, "messageId", Guid.NewGuid())
                };

                // Handle optional fields efficiently
                if (dict.TryGetValue("sessionId", out JsonElement sessionIdElement) &&
                    sessionIdElement.ValueKind == JsonValueKind.String)
                {
                    message.SessionId = sessionIdElement.GetString();
                }

                // Parse protocol version
                if (dict.TryGetValue("protocolVersion", out JsonElement versionElement) &&
                    versionElement.ValueKind == JsonValueKind.String)
                {
                    string? versionStr = versionElement.GetString();
                    if (!string.IsNullOrEmpty(versionStr) && versionStr.Split('.').Length == 2)
                    {
                        string[] parts = versionStr.Split('.');
                        if (int.TryParse(parts[0], out int majorVersion) &&
                            int.TryParse(parts[1], out int minorVersion))
                        {
                            message.ProtocolMajorVersion = majorVersion;
                            message.ProtocolMinorVersion = minorVersion;

                            // Check compatibility
                            if (!ProtocolVersion.IsCompatible(majorVersion, minorVersion))
                            {
                                throw new ProtocolVersionException($"Incompatible protocol version: {versionStr}");
                            }
                        }
                    }
                }

                return message;
            }
            catch (ProtocolVersionException)
            {
                // Re-throw version exceptions directly
                throw;
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
                    if (string.IsNullOrEmpty(base64) || !Helpers.IsValidBase64(base64))
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

    /// <summary>
    /// Exception thrown when incompatible protocol versions are detected
    /// </summary>
    public class ProtocolVersionException : Exception
    {
        /// <summary>
        /// Creates a new ProtocolVersionException with the specified message
        /// </summary>
        /// <param name="message">Exception message</param>
        public ProtocolVersionException(string message) : base(message) { }

        /// <summary>
        /// Creates a new ProtocolVersionException with the specified message and inner exception
        /// </summary>
        /// <param name="message">Exception message</param>
        /// <param name="innerException">Inner exception</param>
        public ProtocolVersionException(string message, Exception innerException)
            : base(message, innerException) { }
    }
}