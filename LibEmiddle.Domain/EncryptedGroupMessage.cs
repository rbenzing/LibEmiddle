using System.Text.Json;
using System.Text.Json.Serialization;

namespace LibEmiddle.Domain
{
    /// <summary>
    /// Represents an encrypted message for group communication, containing
    /// all necessary metadata for routing, decryption, and verification.
    /// </summary>
    public class EncryptedGroupMessage
    {
        /// <summary>
        /// Gets or sets a unique identifier for this message.
        /// </summary>
        public string? MessageId { get; set; }

        /// <summary>
        /// Gets or sets the group identifier this message belongs to.
        /// </summary>
        public string GroupId { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the sender's identity public key.
        /// </summary>
        public byte[] SenderIdentityKey { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Gets or sets the encrypted message content.
        /// </summary>
        public byte[] Ciphertext { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Gets or sets the nonce used for encryption.
        /// </summary>
        public byte[] Nonce { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Gets or sets the timestamp when the message was created
        /// (milliseconds since Unix epoch).
        /// </summary>
        public long Timestamp { get; set; }

        /// <summary>
        /// Gets or sets the timestamp of the key rotation epoch that was used
        /// to encrypt this message (milliseconds since Unix epoch).
        /// </summary>
        public long RotationEpoch { get; set; }

        /// <summary>
        /// Gets or sets the signature of the message for authenticity verification.
        /// </summary>
        public byte[]? Signature { get; set; }

        /// <summary>
        /// Gets or sets additional headers for the message.
        /// </summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public Dictionary<string, string>? Headers { get; set; }

        /// <summary>
        /// Creates a deep clone of this encrypted group message.
        /// </summary>
        /// <returns>A cloned copy of this encrypted group message.</returns>
        public EncryptedGroupMessage Clone()
        {
            return new EncryptedGroupMessage
            {
                MessageId = MessageId,
                GroupId = GroupId,
                SenderIdentityKey = SenderIdentityKey.ToArray(),
                Ciphertext = Ciphertext.ToArray(),
                Nonce = Nonce.ToArray(),
                Timestamp = Timestamp,
                RotationEpoch = RotationEpoch,
                Signature = Signature?.ToArray(),
                Headers = Headers != null ? new Dictionary<string, string>(Headers) : null
            };
        }

        /// <summary>
        /// Validates that all required fields are present and properly formatted.
        /// </summary>
        /// <returns>True if the encrypted message is valid, false otherwise.</returns>
        public bool IsValid()
        {
            if (string.IsNullOrEmpty(GroupId))
                return false;

            if (SenderIdentityKey == null || SenderIdentityKey.Length == 0)
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
            size += GroupId.Length * sizeof(char);

            // Byte arrays
            size += SenderIdentityKey.Length;
            size += Ciphertext.Length;
            size += Nonce.Length;
            size += Signature?.Length ?? 0;

            // Other fields
            size += sizeof(long) * 2; // Timestamp and RotationEpoch

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
        /// Creates an EncryptedGroupMessage from a dictionary representation.
        /// </summary>
        /// <param name="dictionary">Dictionary containing the serialized message properties</param>
        /// <returns>A new EncryptedGroupMessage instance</returns>
        /// <exception cref="ArgumentNullException">Thrown if the dictionary is null</exception>
        /// <exception cref="FormatException">Thrown if the dictionary has invalid or missing required properties</exception>
        public static EncryptedGroupMessage FromDictionary(Dictionary<string, object>? dictionary)
        {
            if (dictionary == null)
                throw new ArgumentNullException(nameof(dictionary), "Dictionary cannot be null");

            var message = new EncryptedGroupMessage();

            try
            {
                // Required fields
                if (dictionary.TryGetValue("GroupId", out var groupIdObj) && groupIdObj is string groupId)
                {
                    message.GroupId = groupId;
                }
                else
                {
                    throw new FormatException("Missing or invalid GroupId property");
                }

                if (dictionary.TryGetValue("SenderIdentityKey", out var senderIdentityKeyObj) && senderIdentityKeyObj is string senderIdentityKeyBase64)
                {
                    message.SenderIdentityKey = Convert.FromBase64String(senderIdentityKeyBase64);
                }
                else
                {
                    throw new FormatException("Missing or invalid SenderIdentityKey property");
                }

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

                // Handle Timestamp
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
                    else
                    {
                        throw new FormatException("Invalid Timestamp format");
                    }
                }
                else
                {
                    throw new FormatException("Missing Timestamp property");
                }

                // Optional fields
                if (dictionary.TryGetValue("MessageId", out var messageIdObj) && messageIdObj is string messageId)
                {
                    message.MessageId = messageId;
                }
                else
                {
                    message.MessageId = Guid.NewGuid().ToString();
                }

                if (dictionary.TryGetValue("RotationEpoch", out var rotationEpochObj))
                {
                    if (rotationEpochObj is long rotationEpoch)
                    {
                        message.RotationEpoch = rotationEpoch;
                    }
                    else if (rotationEpochObj is int intRotationEpoch)
                    {
                        message.RotationEpoch = intRotationEpoch;
                    }
                    else if (rotationEpochObj is string rotationEpochStr &&
                            long.TryParse(rotationEpochStr, out long parsedRotationEpoch))
                    {
                        message.RotationEpoch = parsedRotationEpoch;
                    }
                }

                if (dictionary.TryGetValue("Signature", out var signatureObj) && signatureObj is string signatureBase64)
                {
                    message.Signature = Convert.FromBase64String(signatureBase64);
                }

                // Headers
                if (dictionary.TryGetValue("Headers", out var headersObj))
                {
                    if (headersObj is Dictionary<string, string> headers)
                    {
                        message.Headers = new Dictionary<string, string>(headers);
                    }
                    else if (headersObj is JsonElement jsonHeaders && jsonHeaders.ValueKind == JsonValueKind.Object)
                    {
                        var extractedHeaders = new Dictionary<string, string>();
                        foreach (var property in jsonHeaders.EnumerateObject())
                        {
                            if (property.Value.ValueKind == JsonValueKind.String)
                            {
                                extractedHeaders[property.Name] = property.Value.GetString() ?? string.Empty;
                            }
                        }
                        message.Headers = extractedHeaders;
                    }
                }

                return message;
            }
            catch (FormatException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new FormatException($"Error deserializing group message: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Creates an EncryptedGroupMessage from its JSON representation.
        /// </summary>
        /// <param name="json">JSON string representation of the message</param>
        /// <returns>A new EncryptedGroupMessage instance</returns>
        /// <exception cref="ArgumentException">Thrown if the JSON string is null or empty</exception>
        /// <exception cref="FormatException">Thrown if the JSON is invalid or missing required properties</exception>
        public static EncryptedGroupMessage FromJson(string json)
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
                        case JsonValueKind.Object:
                            if (property.Name == "Headers")
                            {
                                dictionary[property.Name] = property.Value;
                            }
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
        /// Converts the EncryptedGroupMessage to a dictionary representation.
        /// </summary>
        /// <returns>Dictionary containing serialized message properties</returns>
        /// <exception cref="ArgumentNullException">Thrown if required properties are null</exception>
        public Dictionary<string, object> ToDictionary()
        {
            if (string.IsNullOrEmpty(GroupId))
                throw new ArgumentNullException(nameof(GroupId), "GroupId cannot be null or empty");
            if (SenderIdentityKey == null)
                throw new ArgumentNullException(nameof(SenderIdentityKey), "SenderIdentityKey cannot be null");
            if (Ciphertext == null)
                throw new ArgumentNullException(nameof(Ciphertext), "Ciphertext cannot be null");
            if (Nonce == null)
                throw new ArgumentNullException(nameof(Nonce), "Nonce cannot be null");

            var dictionary = new Dictionary<string, object>
            {
                ["GroupId"] = GroupId,
                ["SenderIdentityKey"] = Convert.ToBase64String(SenderIdentityKey),
                ["Ciphertext"] = Convert.ToBase64String(Ciphertext),
                ["Nonce"] = Convert.ToBase64String(Nonce),
                ["Timestamp"] = Timestamp
            };

            if (!string.IsNullOrEmpty(MessageId))
            {
                dictionary["MessageId"] = MessageId;
            }

            if (RotationEpoch > 0)
            {
                dictionary["RotationEpoch"] = RotationEpoch;
            }

            if (Signature != null)
            {
                dictionary["Signature"] = Convert.ToBase64String(Signature);
            }

            if (Headers != null && Headers.Count > 0)
            {
                dictionary["Headers"] = Headers;
            }

            return dictionary;
        }

        /// <summary>
        /// Creates a JSON string representation of the EncryptedGroupMessage.
        /// </summary>
        /// <returns>JSON string</returns>
        public string ToJson()
        {
            var options = new JsonSerializerOptions
            {
                WriteIndented = false,
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
            };

            var dictionary = ToDictionary();
            return JsonSerializer.Serialize(dictionary, options);
        }
    }
}