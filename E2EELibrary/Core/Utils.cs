using System.Text;
using System.Text.Json;

namespace E2EELibrary.Core
{
    /// <summary>
    /// Utility methods for cryptographic operations used across the library.
    /// </summary>
    public static class Utils
    {
        /// <summary>
        /// Validates UTF-8 encoding of a byte array
        /// </summary>
        /// <param name="data">Byte array to validate</param>
        /// <returns>True if the data is valid UTF-8</returns>
        public static bool IsValidUtf8(byte[] data)
        {
            try
            {
                // Attempt to decode
                string decoded = Encoding.UTF8.GetString(data);
                // Re-encode and check if the bytes match
                byte[] reEncoded = Encoding.UTF8.GetBytes(decoded);

                if (data.Length != reEncoded.Length)
                    return false;

                for (int i = 0; i < data.Length; i++)
                {
                    if (data[i] != reEncoded[i])
                        return false;
                }

                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Validates a message ID against recently processed IDs to prevent replay attacks
        /// </summary>
        /// <param name="messageId">Message ID to validate</param>
        /// <param name="recentlyProcessedIds">Queue of recently processed message IDs</param>
        /// <returns>True if the message ID is new and valid</returns>
        public static bool ValidateMessageId(Guid messageId, Queue<Guid> recentlyProcessedIds)
        {
            lock (recentlyProcessedIds)
            {
                // Check if we've seen this message ID before
                if (recentlyProcessedIds.Contains(messageId))
                {
                    return false;
                }

                // Add the new message ID to the queue
                recentlyProcessedIds.Enqueue(messageId);

                // If queue exceeds capacity, remove oldest ID
                if (recentlyProcessedIds.Count > Constants.MAX_TRACKED_MESSAGE_IDS)
                {
                    recentlyProcessedIds.Dequeue();
                }

                return true;
            }
        }

        /// <summary>
        /// Validates if a string is a valid Base64 encoding
        /// </summary>
        /// <param name="base64">The string to validate</param>
        /// <returns>True if the string is valid Base64</returns>
        public static bool IsValidBase64(string base64)
        {
            if (string.IsNullOrEmpty(base64))
                return false;

            try
            {
                Convert.FromBase64String(base64);
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Gets bytes from a Base64 string with error checking
        /// </summary>
        /// <param name="dict">Dictionary containing the key</param>
        /// <param name="key">Key to retrieve the Base64 value</param>
        /// <returns>Decoded byte array</returns>
        public static byte[] GetBytesFromBase64(Dictionary<string, JsonElement> dict, string key)
        {
            if (!dict.TryGetValue(key, out JsonElement element))
            {
                throw new FormatException($"Field '{key}' is missing");
            }

            if (element.ValueKind != JsonValueKind.String)
            {
                throw new FormatException($"Field '{key}' must be a string");
            }

            string? base64 = element.GetString();

            if (string.IsNullOrEmpty(base64))
            {
                throw new FormatException($"Field '{key}' contains null or empty Base64 data");
            }

            try
            {
                return Convert.FromBase64String(base64);
            }
            catch (FormatException)
            {
                throw new FormatException($"Field '{key}' contains invalid Base64 data");
            }
        }

        /// <summary>
        /// Converts a JsonElement to an Int32 value with error checking
        /// </summary>
        /// <param name="element">JsonElement to convert</param>
        /// <returns>Int32 value</returns>
        public static int GetInt32Value(JsonElement element)
        {
            return element.ValueKind switch
            {
                JsonValueKind.Number => element.GetInt32(),
                JsonValueKind.String => int.TryParse(element.GetString(), out int result) ? result :
                    throw new FormatException("Invalid string representation of an integer"),
                _ => throw new FormatException($"Cannot convert JsonValueKind.{element.ValueKind} to Int32")
            };
        }

        /// <summary>
        /// Converts an object to an Int32 value with error checking
        /// </summary>
        /// <param name="value">Object to convert</param>
        /// <returns>Int32 value</returns>
        public static int GetInt32Value(object value)
        {
            if (value is int intValue)
                return intValue;

            if (value is JsonElement jsonElement)
                return GetInt32Value(jsonElement);

            if (value is string stringValue && int.TryParse(stringValue, out int result))
                return result;

            if (value != null)
            {
                if (int.TryParse(value.ToString(), out int parsed))
                    return parsed;
            }

            throw new FormatException($"Cannot convert {value} to Int32");
        }

        /// <summary>
        /// Gets an Int64 value from a dictionary with a default fallback
        /// </summary>
        /// <param name="dict">Dictionary containing the key</param>
        /// <param name="key">Key to look up</param>
        /// <param name="defaultValue">Default value if key not found or conversion fails</param>
        /// <returns>Int64 value</returns>
        public static long GetInt64Value(Dictionary<string, JsonElement> dict, string key, long defaultValue)
        {
            if (dict.TryGetValue(key, out JsonElement element))
            {
                return GetInt64Value(element, defaultValue);
            }
            return defaultValue;
        }

        /// <summary>
        /// Converts a JsonElement to an Int64 value with a default fallback
        /// </summary>
        /// <param name="element">JsonElement to convert</param>
        /// <param name="defaultValue">Default value if conversion fails</param>
        /// <returns>Int64 value</returns>
        public static long GetInt64Value(JsonElement element, long defaultValue)
        {
            return element.ValueKind switch
            {
                JsonValueKind.Number => element.GetInt64(),
                JsonValueKind.String => long.TryParse(element.GetString(), out long result) ? result : defaultValue,
                _ => defaultValue
            };
        }

        /// <summary>
        /// Converts an object to an Int64 value with error checking
        /// </summary>
        /// <param name="value">Object to convert</param>
        /// <returns>Int64 value</returns>
        public static long GetInt64Value(object value)
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

        /// <summary>
        /// Gets a Guid value from a dictionary with a default fallback
        /// </summary>
        /// <param name="dict">Dictionary containing the key</param>
        /// <param name="key">Key to look up</param>
        /// <param name="defaultValue">Default value if key not found or conversion fails</param>
        /// <returns>Guid value</returns>
        public static Guid GetGuidValue(Dictionary<string, JsonElement> dict, string key, Guid defaultValue)
        {
            if (dict.TryGetValue(key, out JsonElement element) && element.ValueKind == JsonValueKind.String)
            {
                string? guidStr = element.GetString();
                if (!string.IsNullOrEmpty(guidStr) && Guid.TryParse(guidStr, out Guid result))
                {
                    return result;
                }
            }
            return defaultValue;
        }
    }
}