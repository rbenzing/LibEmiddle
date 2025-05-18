using System.Text;
using System.Text.Json;

#pragma warning disable IDE0130 // Namespace does not match folder structure
namespace LibEmiddle.Domain
#pragma warning restore IDE0130 // Namespace does not match folder structure
{
    /// <summary>
    /// Utility methods for cryptographic operations used across the library.
    /// </summary>
    public static class Helpers
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
                byte[] reEncoded = Encoding.Default.GetBytes(decoded);

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
    }
}