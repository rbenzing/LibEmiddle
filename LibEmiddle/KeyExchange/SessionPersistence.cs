using System.Security.Cryptography;
using System.Text.Json;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.Models;

namespace LibEmiddle.KeyExchange
{
    /// <summary>
    /// Provides functionality for persisting and resuming encryption sessions.
    /// </summary>
    public static class SessionPersistence
    {
        /// <summary>
        /// Serializes a Double Ratchet session for persistent storage.
        /// </summary>
        /// <param name="session">The session to serialize</param>
        /// <param name="encryptionKey">Optional key to encrypt the serialized session</param>
        /// <returns>Serialized (and optionally encrypted) session data</returns>
        public static byte[] SerializeSession(DoubleRatchetSession session, byte[]? encryptionKey = null)
        {
            ArgumentNullException.ThrowIfNull(session, nameof(session));

            // Create a serializable representation
            var sessionData = new
            {
                DHRatchetPublicKey = Convert.ToBase64String(session.DHRatchetKeyPair.publicKey),
                DHRatchetPrivateKey = Convert.ToBase64String(session.DHRatchetKeyPair.privateKey),
                RemoteDHRatchetKey = Convert.ToBase64String(session.RemoteDHRatchetKey),
                RootKey = Convert.ToBase64String(session.RootKey),
                SendingChainKey = Convert.ToBase64String(session.SendingChainKey),
                ReceivingChainKey = Convert.ToBase64String(session.ReceivingChainKey),
                MessageNumber = session.MessageNumber,
                SessionId = session.SessionId,
                ProcessedMessageIds = session.RecentlyProcessedIds,
                ProcessedMessageNumbers = session.ProcessedMessageNumbers
            };

            // Serialize to JSON
            string json = JsonSerializer.Serialize(sessionData);
            byte[] serializedData = System.Text.Encoding.UTF8.GetBytes(json);

            // Encrypt if a key is provided
            if (encryptionKey != null && encryptionKey.Length == Constants.AES_KEY_SIZE)
            {
                byte[] nonce = NonceGenerator.GenerateNonce();
                byte[] encryptedData = AES.AESEncrypt(serializedData, encryptionKey, nonce);

                // Combine nonce and encrypted data using AsSpan
                byte[] result = Sodium.GenerateRandomBytes(nonce.Length + encryptedData.Length);
                nonce.AsSpan().CopyTo(result.AsSpan(0, nonce.Length));
                encryptedData.AsSpan().CopyTo(result.AsSpan(nonce.Length));

                // Securely clear serialized data
                SecureMemory.SecureClear(serializedData);

                return result;
            }

            return serializedData;
        }

        /// <summary>
        /// Deserializes a Double Ratchet session from persistent storage.
        /// </summary>
        /// <param name="serializedData">The serialized session data</param>
        /// <param name="decryptionKey">Optional key to decrypt the serialized session</param>
        /// <returns>Deserialized Double Ratchet session</returns>
        public static DoubleRatchetSession DeserializeSession(byte[] serializedData, byte[]? decryptionKey = null)
        {
            if (serializedData == null || serializedData.Length == 0)
                throw new ArgumentException("Serialized data cannot be null or empty", nameof(serializedData));

            byte[] jsonData;

            // Decrypt if a key is provided
            if (decryptionKey != null && decryptionKey.Length == Constants.AES_KEY_SIZE)
            {
                try
                {
                    // Extract nonce and encrypted data
                    byte[] nonce = Sodium.GenerateRandomBytes(Constants.NONCE_SIZE);
                    byte[] encryptedData = Sodium.GenerateRandomBytes(serializedData.Length - Constants.NONCE_SIZE);

                    serializedData.AsSpan(0, Constants.NONCE_SIZE).CopyTo(nonce.AsSpan());
                    serializedData.AsSpan(Constants.NONCE_SIZE).CopyTo(encryptedData.AsSpan());

                    jsonData = AES.AESDecrypt(encryptedData, decryptionKey, nonce);
                }
                catch (CryptographicException ex)
                {
                    throw new CryptographicException("Failed to decrypt session data", ex);
                }
            }
            else
            {
                jsonData = serializedData;
            }

            try
            {
                string json = System.Text.Encoding.UTF8.GetString(jsonData);
                using JsonDocument document = JsonDocument.Parse(json);
                JsonElement root = document.RootElement;

                ArgumentNullException.ThrowIfNull(root, nameof(root));

                // Extract properties
                byte[] dhPublicKey = Convert.FromBase64String(root.GetProperty("DHRatchetPublicKey").GetString() ?? "");
                ArgumentNullException.ThrowIfNullOrWhiteSpace(dhPublicKey.ToString(), nameof(dhPublicKey));

                byte[] dhPrivateKey = Convert.FromBase64String(root.GetProperty("DHRatchetPrivateKey").GetString() ?? "");
                ArgumentNullException.ThrowIfNullOrWhiteSpace(dhPrivateKey.ToString(), nameof(dhPrivateKey));

                byte[] remoteDHKey = Convert.FromBase64String(root.GetProperty("RemoteDHRatchetKey").GetString() ?? "");
                ArgumentNullException.ThrowIfNullOrWhiteSpace(remoteDHKey.ToString(), nameof(remoteDHKey));

                byte[] rootKey = Convert.FromBase64String(root.GetProperty("RootKey").GetString() ?? "");
                ArgumentNullException.ThrowIfNullOrWhiteSpace(rootKey.ToString(), nameof(rootKey));

                byte[] sendingChainKey = Convert.FromBase64String(root.GetProperty("SendingChainKey").GetString() ?? "");
                ArgumentNullException.ThrowIfNullOrWhiteSpace(sendingChainKey.ToString(), nameof(sendingChainKey));

                byte[] receivingChainKey = Convert.FromBase64String(root.GetProperty("ReceivingChainKey").GetString() ?? "");
                ArgumentNullException.ThrowIfNullOrWhiteSpace(receivingChainKey.ToString(), nameof(receivingChainKey));

                int messageNumber = root.GetProperty("MessageNumber").GetInt32();
                string? sessionId = root.GetProperty("SessionId").GetString();

                ArgumentNullException.ThrowIfNull(sessionId, nameof(sessionId));

                // Extract processed message IDs
                List<Guid> processedMessageIds = new List<Guid>();
                var idsElement = root.GetProperty("ProcessedMessageIds");
                foreach (JsonElement idElement in idsElement.EnumerateArray())
                {
                    string? idStr = idElement.GetString();
                    if (Guid.TryParse(idStr, out Guid id))
                    {
                        processedMessageIds.Add(id);
                    }
                }

                // Extract processed message numbers if they exist
                List<int> processedMessageNumbers = new List<int>();
                if (root.TryGetProperty("ProcessedMessageNumbers", out JsonElement processedNumbersElement))
                {
                    foreach (JsonElement numElement in processedNumbersElement.EnumerateArray())
                    {
                        processedMessageNumbers.Add(numElement.GetInt32());
                    }
                }

                // Create session
                return new DoubleRatchetSession(
                    dhRatchetKeyPair: (dhPublicKey, dhPrivateKey),
                    remoteDHRatchetKey: remoteDHKey,
                    rootKey: rootKey,
                    sendingChainKey: sendingChainKey,
                    receivingChainKey: receivingChainKey,
                    messageNumber: messageNumber,
                    sessionId: sessionId,
                    recentlyProcessedIds: processedMessageIds,
                    processedMessageNumbers: processedMessageNumbers
                );
            }
            catch (ArgumentNullException ex)
            {
                throw new ArgumentException("Failed to deserialize session data", ex);
            }
            catch (JsonException ex)
            {
                throw new InvalidDataException("Failed to deserialize session data", ex);
            }
            finally
            {
                // Securely clear the JSON data
                if (decryptionKey != null)
                {
                    SecureMemory.SecureClear(jsonData);
                }
            }
        }

        /// <summary>
        /// Save a session to a file.
        /// </summary>
        /// <param name="session">The session to save</param>
        /// <param name="filePath">The file path to save to</param>
        /// <param name="encryptionKey">Optional key to encrypt the session data</param>
        public static void SaveSessionToFile(DoubleRatchetSession session, string filePath, byte[]? encryptionKey = null)
        {
            byte[] serializedData = SerializeSession(session, encryptionKey);
            File.WriteAllBytes(filePath, serializedData);
        }

        /// <summary>
        /// Load a session from a file.
        /// </summary>
        /// <param name="filePath">The file path to load from</param>
        /// <param name="decryptionKey">Optional key to decrypt the session data</param>
        /// <returns>The loaded Double Ratchet session</returns>
        public static DoubleRatchetSession LoadSessionFromFile(string filePath, byte[]? decryptionKey = null)
        {
            if (!File.Exists(filePath))
                throw new FileNotFoundException("Session file not found", filePath);

            byte[] serializedData = File.ReadAllBytes(filePath);
            return DeserializeSession(serializedData, decryptionKey);
        }
    }
}