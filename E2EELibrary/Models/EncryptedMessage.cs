﻿
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
        public long Timestamp { get; set; } = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

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

            return new Dictionary<string, object>
            {
                ["ciphertext"] = Convert.ToBase64String(Ciphertext),
                ["nonce"] = Convert.ToBase64String(Nonce),
                ["messageNumber"] = MessageNumber,
                ["senderDHKey"] = Convert.ToBase64String(SenderDHKey),
                ["timestamp"] = Timestamp,
                ["messageId"] = MessageId.ToString()
            };
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
                var message = new EncryptedMessage
                {
                    Ciphertext = Convert.FromBase64String(dict["ciphertext"].ToString()),
                    Nonce = Convert.FromBase64String(dict["nonce"].ToString()),
                    MessageNumber = Convert.ToInt32(dict["messageNumber"]),
                    SenderDHKey = Convert.FromBase64String(dict["senderDHKey"].ToString())
                };

                // Optional fields with fallbacks
                if (dict.ContainsKey("timestamp"))
                    message.Timestamp = Convert.ToInt64(dict["timestamp"]);

                if (dict.ContainsKey("messageId") && Guid.TryParse(dict["messageId"].ToString(), out var messageId))
                    message.MessageId = messageId;

                return message;
            }
            catch (Exception ex)
            {
                throw new FormatException("Invalid message format", ex);
            }
        }

        /// <summary>
        /// Serializes the message to JSON
        /// </summary>
        /// <returns>JSON string</returns>
        public string ToJson()
        {
            return System.Text.Json.JsonSerializer.Serialize(ToDictionary());
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
                var dict = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(json);

                ArgumentNullException.ThrowIfNull(dict);

                return FromDictionary(dict);
            }
            catch (Exception ex)
            {
                throw new FormatException("Invalid JSON format for encrypted message", ex);
            }
        }
    }
}