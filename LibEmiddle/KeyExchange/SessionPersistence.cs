using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text.Json;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;

namespace LibEmiddle.KeyExchange
{
    /// <summary>
    /// Provides functionality for persisting and resuming Double Ratchet encryption sessions.
    /// Uses JSON serialization and optional AEAD encryption.
    /// </summary>
    public sealed class SessionPersistence
    {
        /// <summary>
        /// Serializes a Double Ratchet session for persistent storage.
        /// </summary>
        /// <param name="session">The session to serialize.</param>
        /// <param name="encryptionKey">Optional 32-byte key to encrypt the serialized session using AES-GCM.</param>
        /// <returns>Serialized (and optionally encrypted) session data.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="CryptographicException"></exception>
        /// <exception cref="JsonException"></exception>
        public static byte[] SerializeSession(DoubleRatchetSession session, byte[]? encryptionKey = null)
        {
            ArgumentNullException.ThrowIfNull(session, nameof(session));
            if (encryptionKey != null && encryptionKey.Length != Constants.AES_KEY_SIZE)
                throw new ArgumentException($"Encryption key must be {Constants.AES_KEY_SIZE} bytes.", nameof(encryptionKey));

            byte[]? serializedData = null; // For clearing in finally

            try
            {
                // --- 1. Convert Session to Serializable DTO ---
                var sessionDto = new SerializableSessionData
                {
                    // Base64 encode byte arrays, handle potential nulls for chain keys
                    DHRatchetPublicKey = Convert.ToBase64String(session.DHRatchetKeyPair.PublicKey),
                    DHRatchetPrivateKey = Convert.ToBase64String(session.DHRatchetKeyPair.PrivateKey), // SECURITY: Handle with care!
                    RemoteDHRatchetKey = Convert.ToBase64String(session.RemoteDHRatchetKey),
                    RootKey = Convert.ToBase64String(session.RootKey),
                    SendingChainKey = session.SendingChainKey != null ? Convert.ToBase64String(session.SendingChainKey) : null,
                    ReceivingChainKey = session.ReceivingChainKey != null ? Convert.ToBase64String(session.ReceivingChainKey) : null,
                    MessageNumberSending = session.MessageNumberSending,
                    MessageNumberReceiving = session.MessageNumberReceiving,
                    SessionId = session.SessionId,
                    // Convert immutable collections to simple lists for JSON
                    RecentlyProcessedIds = session.RecentlyProcessedIds.ToList(),
                    ProcessedMessageNumbersReceiving = session.ProcessedMessageNumbersReceiving.ToList(),
                    // Convert SkippedMessageKeys dictionary
                    SkippedMessageKeys = session.SkippedMessageKeys.Select(kvp => new SerializableSkippedKeyEntry
                    {
                        // Key: Tuple<byte[], int> -> RemoteDhKeyBase64, MessageNumber
                        RemoteDhKeyBase64 = Convert.ToBase64String(kvp.Key.Item1),
                        MessageNumber = kvp.Key.Item2,
                        // Value: byte[] -> MessageKeyBase64
                        MessageKeyBase64 = Convert.ToBase64String(kvp.Value)
                    }).ToList()
                };

                // --- 2. Serialize DTO to JSON ---
                string json = JsonSerializer.Serialize(sessionDto, new JsonSerializerOptions { WriteIndented = false });
                serializedData = System.Text.Encoding.UTF8.GetBytes(json);

                // --- 3. Encrypt if Key Provided ---
                if (encryptionKey != null)
                {
                    byte[] nonce = NonceGenerator.GenerateNonce();
                    byte[] encryptedData = AES.AESEncrypt(serializedData, encryptionKey, nonce);

                    // Combine nonce + ciphertext in a more efficient manner
                    byte[] result = new byte[nonce.Length + encryptedData.Length];
                    nonce.AsSpan().CopyTo(result.AsSpan(0, nonce.Length));
                    encryptedData.AsSpan().CopyTo(result.AsSpan(nonce.Length));

                    return result;
                }

                return serializedData;
            }
            catch (Exception ex) when (ex is CryptographicException || ex is JsonException || ex is ArgumentException)
            {
                LoggingManager.LogError(nameof(SessionPersistence), $"Serialization failed: {ex.Message}");
                throw; // Re-throw known exception types
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(SessionPersistence), $"Unexpected serialization error: {ex.Message}");
                throw new InvalidOperationException("An unexpected error occurred during session serialization.", ex);
            }
            finally
            {
                // Securely clear the intermediate JSON bytes if they weren't returned directly
                if (serializedData != null && encryptionKey != null)
                    SecureMemory.SecureClear(serializedData);
            }
        }

        /// <summary>
        /// Deserializes a Double Ratchet session from persistent storage.
        /// </summary>
        /// <param name="data">The serialized (and potentially encrypted) session data.</param>
        /// <param name="decryptionKey">Optional 32-byte key to decrypt the session data.</param>
        /// <returns>Deserialized Double Ratchet session.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="CryptographicException">If decryption fails.</exception>
        /// <exception cref="InvalidDataException">If JSON is invalid or data is corrupt.</exception>
        public static DoubleRatchetSession DeserializeSession(byte[] data, byte[]? decryptionKey = null)
        {
            ArgumentNullException.ThrowIfNull(data, nameof(data));
            if (data.Length == 0) throw new ArgumentException("Serialized data cannot be empty.", nameof(data));
            if (decryptionKey != null && decryptionKey.Length != Constants.AES_KEY_SIZE)
                throw new ArgumentException($"Decryption key must be {Constants.AES_KEY_SIZE} bytes.", nameof(decryptionKey));

            byte[]? jsonData = null; // For clearing in finally

            try
            {
                // --- 1. Decrypt if Key Provided ---
                if (decryptionKey != null)
                {
                    if (data.Length < Constants.NONCE_SIZE)
                        throw new InvalidDataException("Encrypted data is too short to contain a nonce.");

                    byte[] nonce = new byte[Constants.NONCE_SIZE];
                    byte[] encryptedData = new byte[data.Length - Constants.NONCE_SIZE];

                    Buffer.BlockCopy(data, 0, nonce, 0, nonce.Length);
                    Buffer.BlockCopy(data, nonce.Length, encryptedData, 0, encryptedData.Length);

                    jsonData = AES.AESDecrypt(encryptedData, decryptionKey, nonce); // Assumes throws on auth failure
                    if (jsonData == null) // Should not happen if AESDecrypt throws, but check defensively
                    {
                        throw new CryptographicException("Decryption returned null, possibly due to authentication failure.");
                    }
                }
                else
                {
                    jsonData = data; // Data is not encrypted
                }

                // --- 2. Deserialize JSON to DTO ---
                string json = System.Text.Encoding.UTF8.GetString(jsonData);
                SerializableSessionData? sessionDto = JsonSerializer.Deserialize<SerializableSessionData>(json);

                if (sessionDto == null)
                    throw new InvalidDataException("Failed to deserialize JSON data into session DTO.");

                // --- 3. Validate and Convert DTO back to Domain Object ---

                // Validate required fields from DTO
                if (string.IsNullOrWhiteSpace(sessionDto.DHRatchetPublicKey) ||
                    string.IsNullOrWhiteSpace(sessionDto.DHRatchetPrivateKey) || // Private key is essential state
                    string.IsNullOrWhiteSpace(sessionDto.RemoteDHRatchetKey) ||
                    string.IsNullOrWhiteSpace(sessionDto.RootKey) ||
                    string.IsNullOrWhiteSpace(sessionDto.SessionId))
                {
                    throw new InvalidDataException("Deserialized session data is missing required fields.");
                }

                // Decode Base64 fields, handle nullable chain keys
                byte[] dhPublicKey = Convert.FromBase64String(sessionDto.DHRatchetPublicKey);
                byte[] dhPrivateKey = Convert.FromBase64String(sessionDto.DHRatchetPrivateKey);
                byte[] remoteDHKey = Convert.FromBase64String(sessionDto.RemoteDHRatchetKey);
                byte[] rootKey = Convert.FromBase64String(sessionDto.RootKey);
                byte[]? sendingChainKey = !string.IsNullOrEmpty(sessionDto.SendingChainKey) ? Convert.FromBase64String(sessionDto.SendingChainKey) : null;
                byte[]? receivingChainKey = !string.IsNullOrEmpty(sessionDto.ReceivingChainKey) ? Convert.FromBase64String(sessionDto.ReceivingChainKey) : null;

                // Reconstruct immutable collections
                var recentlyProcessedIds = (sessionDto.RecentlyProcessedIds ?? Enumerable.Empty<Guid>()).ToImmutableList();
                var processedNumbersReceiving = (sessionDto.ProcessedMessageNumbersReceiving ?? Enumerable.Empty<int>()).ToImmutableHashSet();

                // Reconstruct SkippedMessageKeys dictionary
                var skippedKeysBuilder = ImmutableDictionary.CreateBuilder<Tuple<byte[], int>, byte[]>();
                if (sessionDto.SkippedMessageKeys != null)
                {
                    foreach (var entry in sessionDto.SkippedMessageKeys)
                    {
                        if (entry.RemoteDhKeyBase64 != null && entry.MessageKeyBase64 != null)
                        {
                            try
                            {
                                var remoteDhKey = Convert.FromBase64String(entry.RemoteDhKeyBase64);
                                var msgKey = Convert.FromBase64String(entry.MessageKeyBase64);
                                // WARNING: Using Tuple<byte[], int> requires a custom comparer that handles
                                // byte[] equality correctly (SequenceEqual) for reliable dictionary lookups.
                                // ImmutableDictionary.CreateBuilder() doesn't allow passing comparer directly.
                                // Consider creating the final dictionary with a comparer or using a custom key struct.
                                skippedKeysBuilder.Add(Tuple.Create(remoteDhKey, entry.MessageNumber), msgKey);
                            }
                            catch (FormatException ex)
                            {
                                throw new InvalidDataException("Failed to decode Base64 data for skipped message keys.", ex);
                            }
                        }
                    }
                }
                var skippedMessageKeys = skippedKeysBuilder.ToImmutable();

                // --- 4. Create DoubleRatchetSession Instance ---
                var session = new DoubleRatchetSession(
                    dhRatchetKeyPair: new KeyPair { PublicKey = dhPublicKey, PrivateKey = dhPrivateKey }, // Recreate KeyPair
                    remoteDHRatchetKey: remoteDHKey,
                    rootKey: rootKey,
                    sendingChainKey: sendingChainKey,
                    receivingChainKey: receivingChainKey,
                    messageNumberSending: sessionDto.MessageNumberSending,
                    messageNumberReceiving: sessionDto.MessageNumberReceiving,
                    sessionId: sessionDto.SessionId,
                    recentlyProcessedIds: recentlyProcessedIds,
                    processedMessageNumbersReceiving: processedNumbersReceiving,
                    skippedMessageKeys: skippedMessageKeys
                );

                // Optional: Perform a basic validity check on the reconstructed session if possible

                return session;
            }
            catch (Exception ex) when (ex is JsonException || ex is FormatException || ex is KeyNotFoundException) // JsonException includes property not found if using strict options
            {
                LoggingManager.LogError(nameof(SessionPersistence), $"Deserialization failed due to invalid format or data: {ex.Message}");
                throw new InvalidDataException("Failed to deserialize session data due to invalid format.", ex);
            }
            catch (Exception ex) when (ex is CryptographicException || ex is ArgumentException || ex is InvalidDataException)
            {
                LoggingManager.LogError(nameof(SessionPersistence), $"Deserialization failed: {ex.Message}");
                throw; // Re-throw known exception types
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(SessionPersistence), $"Unexpected deserialization error: {ex.Message}");
                throw new InvalidOperationException("An unexpected error occurred during session deserialization.", ex);
            }
            finally
            {
                // Securely clear the intermediate JSON byte array
                if (jsonData  != null)
                    SecureMemory.SecureClear(jsonData);
                // Decoded keys are now held by the returned session object; caller manages its lifecycle.
            }
        }

        /// <summary>
        /// Saves a session to a file, optionally encrypting it.
        /// </summary>
        /// <param name="session">The session to save.</param>
        /// <param name="filePath">The file path to save to.</param>
        /// <param name="encryptionKey">Optional 32-byte key to encrypt the session data.</param>
        public static void SaveSessionToFile(DoubleRatchetSession session, string filePath, byte[]? encryptionKey = null)
        {
            byte[] serializedData = SerializeSession(session, encryptionKey);
            File.WriteAllBytes(filePath, serializedData);
            // Clear serializedData array after write if sensitive and unencrypted?
            SecureMemory.SecureClear(serializedData);
        }

        /// <summary>
        /// Loads a session from a file, optionally decrypting it.
        /// </summary>
        /// <param name="filePath">The file path to load from.</param>
        /// <param name="decryptionKey">Optional 32-byte key to decrypt the session data.</param>
        /// <returns>The loaded Double Ratchet session.</returns>
        /// <exception cref="FileNotFoundException"></exception>
        public static DoubleRatchetSession LoadSessionFromFile(string filePath, byte[]? decryptionKey = null)
        {
            if (!File.Exists(filePath))
                throw new FileNotFoundException("Session file not found.", filePath);

            byte[] serializedData = File.ReadAllBytes(filePath);
            try
            {
                return DeserializeSession(serializedData, decryptionKey);
            }
            finally
            {
                // Securely clear the data read from the file
                SecureMemory.SecureClear(serializedData);
            }
        }
    }
}