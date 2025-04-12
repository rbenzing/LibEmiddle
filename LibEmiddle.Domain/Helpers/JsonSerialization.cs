using System.Text.Json;

namespace LibEmiddle.Domain
{
    /// <summary>
    /// Provides standardized JSON serialization options to ensure consistent message formatting
    /// and protect against canonicalization attacks.
    /// </summary>
    public static class JsonSerialization
    {
        /// <summary>
        /// Standard serialization options for all library components to use
        /// </summary>
        public static readonly JsonSerializerOptions DefaultOptions = new JsonSerializerOptions
        {
            WriteIndented = false,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
            PropertyNameCaseInsensitive = false // Require exact case match for deserialization
        };

        /// <summary>
        /// Serialization options for when case-insensitive property matching is required
        /// </summary>
        public static readonly JsonSerializerOptions CaseInsensitiveOptions = new JsonSerializerOptions
        {
            WriteIndented = false,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
            PropertyNameCaseInsensitive = true
        };

        /// <summary>
        /// Serialize an object to JSON using the standard serialization options
        /// </summary>
        public static string Serialize<T>(T value)
        {
            return JsonSerializer.Serialize(value, DefaultOptions);
        }

        /// <summary>
        /// Deserialize JSON to an object using the standard serialization options
        /// </summary>
        public static T? Deserialize<T>(string json)
        {
            return JsonSerializer.Deserialize<T>(json, DefaultOptions);
        }

        /// <summary>
        /// Deserialize JSON to an object using case-insensitive options
        /// </summary>
        public static T? DeserializeInsensitive<T>(string json)
        {
            return JsonSerializer.Deserialize<T>(json, CaseInsensitiveOptions);
        }

        /// <summary>
        /// Normalizes an object by serializing and deserializing it to ensure a canonical representation
        /// </summary>
        public static T Normalize<T>(T value)
        {
            string json = Serialize(value);
            T? result = Deserialize<T>(json);
            return result ?? throw new InvalidOperationException("Normalization failed");
        }
    }
}