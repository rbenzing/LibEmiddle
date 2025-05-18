using System.Text.Json;
using System.Text.Json.Serialization;

namespace LibEmiddle.Domain
{
    /// <summary>
    /// Represents an encrypted message for individual communication, containing
    /// all necessary metadata for routing, decryption, and verification.
    /// </summary>
    public class EncryptedMessage
    {
        /// <summary>
        /// Gets or sets a unique identifier for this message.
        /// </summary>
        public string? MessageId { get; set; }

        /// <summary>
        /// Gets or sets the session identifier this message belongs to.
        /// </summary>
        public string SessionId { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the sender's DH ratchet public key.
        /// Used for the Double Ratchet protocol.
        /// </summary>
        public byte[]? SenderDHKey { get; set; }

        /// <summary>
        /// Gets or sets the sender's message number.
        /// Used for ordering messages and skipped message handling.
        /// </summary>
        public uint SenderMessageNumber { get; set; }

        /// <summary>
        /// Gets or sets the encrypted message content.
        /// </summary>
        public byte[]? Ciphertext { get; set; }

        /// <summary>
        /// Gets or sets the nonce used for encryption.
        /// </summary>
        public byte[]? Nonce { get; set; }

        /// <summary>
        /// Gets or sets the timestamp when the message was created
        /// (milliseconds since Unix epoch).
        /// </summary>
        public long Timestamp { get; set; }

        /// <summary>
        /// Gets or sets additional headers for the message.
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public Dictionary<string, string>? Headers { get; set; }

        /// <summary>
        /// Creates a deep clone of this encrypted message.
        /// </summary>
        /// <returns>A cloned copy of this encrypted message.</returns>
        public EncryptedMessage Clone()
        {
            return new EncryptedMessage
            {
                MessageId = MessageId,
                SessionId = SessionId,
                SenderDHKey = SenderDHKey?.ToArray(),
                SenderMessageNumber = SenderMessageNumber,
                Ciphertext = Ciphertext?.ToArray(),
                Nonce = Nonce?.ToArray(),
                Timestamp = Timestamp,
                Headers = Headers != null ? new Dictionary<string, string>(Headers) : null
            };
        }

        /// <summary>
        /// Validates that all required fields are present and properly formatted.
        /// </summary>
        /// <returns>True if the encrypted message is valid, false otherwise.</returns>
        public bool IsValid()
        {
            if (string.IsNullOrEmpty(SessionId))
                return false;

            if (SenderDHKey == null || SenderDHKey.Length == 0)
                return false;

            if (Ciphertext == null || Ciphertext.Length == 0)
                return false;

            if (Nonce == null || Nonce.Length == 0)
                return false;

            if (Timestamp <= 0)
                return false;

            // Check timestamp (should not be in the future with some tolerance for clock skew)
            long currentTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            if (Timestamp > currentTime + 5 * 60 * 1000) // 5 minutes tolerance for clock skew
                return false;

            return true;
        }

        /// <summary>
        /// Gets the estimated size of this message in bytes.
        /// </summary>
        /// <returns>The estimated size in bytes.</returns>
        public int GetEstimatedSize()
        {
            int size = 0;

            // String sizes (assume UTF-8 encoding)
            size += (MessageId?.Length ?? 0) * sizeof(char);
            size += SessionId.Length * sizeof(char);

            // Byte arrays
            size += SenderDHKey?.Length ?? 0;
            size += Ciphertext?.Length ?? 0;
            size += Nonce?.Length ?? 0;

            // Other fields
            size += sizeof(uint); // SenderMessageNumber
            size += sizeof(long); // Timestamp

            // Headers
            if (Headers != null)
            {
                foreach (var kvp in Headers)
                {
                    size += kvp.Key.Length * sizeof(char);
                    size += kvp.Value.Length * sizeof(char);
                }
            }

            return size;
        }

        /// <summary>
        /// Creates an EncryptedMessage from a dictionary representation.
        /// </summary>
        /// <param name="dictionary">Dictionary containing the serialized message properties</param>
        /// <returns>A new EncryptedMessage instance</returns>
        /// <exception cref="ArgumentNullException">Thrown if the dictionary is null</exception>
        /// <exception cref="FormatException">Thrown if the dictionary has invalid or missing required properties</exception>
        public static EncryptedMessage FromDictionary(Dictionary<string, object>? dictionary)
        {
            if (dictionary == null)
                throw new ArgumentNullException(nameof(dictionary), "Dictionary cannot be null");

            var message = new EncryptedMessage();

            try
            {
                // Required fields
                if (dictionary.TryGetValue("Ciphertext", out var ciphertextObj) && ciphertextObj is string ciphertextBase64)
                {
                    message.Ciphertext = Convert.FromBase64String(ciphertextBase64);
                }
                else
                {
                    throw new FormatException("Missing or invalid Ciphertext property");
                }

                if (dictionary.TryGetValue("Nonce", out var nonceObj) && nonceObj is string nonceBase64)
                {
                    message.Nonce = Convert.FromBase64String(nonceBase64);
                }
                else
                {
                    throw new FormatException("Missing or invalid Nonce property");
                }

                if (dictionary.TryGetValue("SenderDHKey", out var senderDHKeyObj) && senderDHKeyObj is string senderDHKeyBase64)
                {
                    message.SenderDHKey = Convert.FromBase64String(senderDHKeyBase64);
                }
                else
                {
                    throw new FormatException("Missing or invalid SenderDHKey property");
                }

                // Handle SenderMessageNumber
                if (dictionary.TryGetValue("SenderMessageNumber", out var messageNumberObj))
                {
                    if (messageNumberObj is uint messageNumber)
                    {
                        message.SenderMessageNumber = messageNumber;
                    }
                    else if (messageNumberObj is int intMessageNumber)
                    {
                        message.SenderMessageNumber = (uint)intMessageNumber;
                    }
                    else if (messageNumberObj is long longMessageNumber)
                    {
                        message.SenderMessageNumber = (uint)longMessageNumber;
                    }
                    else if (messageNumberObj is string messageNumberStr && uint.TryParse(messageNumberStr, out uint parsedMessageNumber))
                    {
                        message.SenderMessageNumber = parsedMessageNumber;
                    }
                    else
                    {
                        throw new FormatException("Invalid SenderMessageNumber format");
                    }
                }

                // Optional fields with defaults
                if (dictionary.TryGetValue("Timestamp", out var timestampObj))
                {
                    if (timestampObj is long timestamp)
                    {
                        message.Timestamp = timestamp;
                    }
                    else if (timestampObj is int intTimestamp)
                    {
                        message.Timestamp = intTimestamp;
                    }
                    else if (timestampObj is string timestampStr && long.TryParse(timestampStr, out long parsedTimestamp))
                    {
                        message.Timestamp = parsedTimestamp;
                    }
                }
                else
                {
                    message.Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                }

                if (dictionary.TryGetValue("MessageId", out var messageIdObj) && messageIdObj is string messageId)
                {
                    message.MessageId = messageId;
                }
                else
                {
                    message.MessageId = Guid.NewGuid().ToString();
                }

                if (dictionary.TryGetValue("SessionId", out var sessionIdObj) && sessionIdObj is string sessionId)
                {
                    message.SessionId = sessionId;
                }

                return message;
            }
            catch (FormatException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new FormatException($"Error deserializing message: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Creates an EncryptedMessage from its JSON representation.
        /// </summary>
        /// <param name="json">JSON string representation of the message</param>
        /// <returns>A new EncryptedMessage instance</returns>
        /// <exception cref="ArgumentException">Thrown if the JSON string is null or empty</exception>
        /// <exception cref="FormatException">Thrown if the JSON is invalid or missing required properties</exception>
        public static EncryptedMessage FromJson(string json)
        {
            if (string.IsNullOrEmpty(json))
                throw new ArgumentException("JSON string cannot be null or empty", nameof(json));

            try
            {
                // Parse JSON to dictionary
                var options = new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                };

                var jsonDoc = JsonDocument.Parse(json);
                var dictionary = new Dictionary<string, object>();

                foreach (var property in jsonDoc.RootElement.EnumerateObject())
                {
                    switch (property.Value.ValueKind)
                    {
                        case JsonValueKind.String:
                            dictionary[property.Name] = property.Value.GetString() ?? string.Empty;
                            break;
                        case JsonValueKind.Number:
                            if (property.Value.TryGetInt64(out long longValue))
                            {
                                dictionary[property.Name] = longValue;
                            }
                            else if (property.Value.TryGetDouble(out double doubleValue))
                            {
                                dictionary[property.Name] = doubleValue;
                            }
                            break;
                        case JsonValueKind.True:
                            dictionary[property.Name] = true;
                            break;
                        case JsonValueKind.False:
                            dictionary[property.Name] = false;
                            break;
                        case JsonValueKind.Null:
                            dictionary[property.Name] = null!;
                            break;
                    }
                }

                return FromDictionary(dictionary);
            }
            catch (JsonException ex)
            {
                throw new FormatException($"Invalid JSON format: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Converts the EncryptedMessage to a dictionary representation.
        /// </summary>
        /// <returns>Dictionary containing serialized message properties</returns>
        /// <exception cref="ArgumentNullException">Thrown if required properties are null</exception>
        public Dictionary<string, object> ToDictionary()
        {
            if (Ciphertext == null)
                throw new ArgumentNullException(nameof(Ciphertext), "Ciphertext cannot be null");
            if (Nonce == null)
                throw new ArgumentNullException(nameof(Nonce), "Nonce cannot be null");
            if (SenderDHKey == null)
                throw new ArgumentNullException(nameof(SenderDHKey), "SenderDHKey cannot be null");

            var dictionary = new Dictionary<string, object>
            {
                ["Ciphertext"] = Convert.ToBase64String(Ciphertext),
                ["Nonce"] = Convert.ToBase64String(Nonce),
                ["SenderMessageNumber"] = SenderMessageNumber,
                ["SenderDHKey"] = Convert.ToBase64String(SenderDHKey),
                ["Timestamp"] = Timestamp
            };

            if (!string.IsNullOrEmpty(MessageId))
            {
                dictionary["MessageId"] = MessageId;
            }

            if (!string.IsNullOrEmpty(SessionId))
            {
                dictionary["SessionId"] = SessionId;
            }

            return dictionary;
        }

        /// <summary>
        /// Creates a JSON string representation of the EncryptedMessage.
        /// </summary>
        /// <returns>JSON string</returns>
        public string ToJson()
        {
            var dictionary = ToDictionary();
            return JsonSerializer.Serialize(dictionary);
        }
    }
}