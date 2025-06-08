using System.Security;
using System.Text;
using LibEmiddle.Abstractions;
using LibEmiddle.Core;
using LibEmiddle.Domain.Enums;
using LibEmiddle.Domain;
using LibEmiddle.Messaging.Chat;
using LibEmiddle.Messaging.Group;
using LibEmiddle.KeyManagement;

namespace LibEmiddle.Sessions
{
    /// <summary>
    /// Provides centralized persistence for all types of cryptographic sessions.
    /// Updated to work with the consolidated GroupSession implementation.
    /// </summary>
    public class SessionPersistenceManager : IDisposable
    {
        private readonly ICryptoProvider _cryptoProvider;
        private readonly string _storagePath;
        private readonly SemaphoreSlim _ioLock = new(1, 1);
        private bool _disposed;

        public SessionPersistenceManager(ICryptoProvider cryptoProvider, string? storagePath = null)
        {
            _cryptoProvider = cryptoProvider ?? throw new ArgumentNullException(nameof(cryptoProvider));

            // Default path is in the local application data
            _storagePath = storagePath ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "LibEmiddle",
                "Sessions");

            // Ensure the storage directory exists
            Directory.CreateDirectory(_storagePath);
        }

        /// <summary>
        /// Saves a chat session to persistent storage.
        /// </summary>
        public async Task<bool> SaveChatSessionAsync(IChatSession session)
        {
            ArgumentNullException.ThrowIfNull(session, nameof(session));

            // Cast to our concrete implementation to access internal state
            if (session is not ChatSession chatSession)
                throw new ArgumentException("Unsupported session type", nameof(session));

            // Serialize the session
            var dto = new SerializedSessionData
            {
                SessionId = chatSession.SessionId,
                SessionType = SessionType.Individual,
                State = chatSession.State,
                CreatedAt = chatSession.CreatedAt,
                LastModifiedAt = DateTime.UtcNow,
                Metadata = new Dictionary<string, string>(chatSession.Metadata)
            };

            // Add specialized data for chat session
            dto.Properties["RemotePublicKey"] = Convert.ToBase64String(chatSession.RemotePublicKey);
            dto.Properties["LocalPublicKey"] = Convert.ToBase64String(chatSession.LocalPublicKey);

            // Get underlying cryptographic session state
            DoubleRatchetSession drSession = chatSession.GetCryptoSessionState();
            dto.CryptoState = SerializeDoubleRatchetSession(drSession);

            // Encrypt and save the session
            return await EncryptAndSaveSessionAsync(dto);
        }

        /// <summary>
        /// Saves a group session to persistent storage using the new consolidated GroupSession.
        /// </summary>
        public async Task<bool> SaveGroupSessionAsync(IGroupSession session)
        {
            ArgumentNullException.ThrowIfNull(session, nameof(session));

            // Cast to our concrete implementation to access internal state
            if (session is not GroupSession groupSession)
                throw new ArgumentException("Unsupported session type", nameof(session));

            try
            {
                // Get the serialized state directly from the GroupSession
                string groupState = await groupSession.GetSerializedStateAsync();

                // Create the session data container
                var dto = new SerializedSessionData
                {
                    SessionId = groupSession.SessionId,
                    SessionType = SessionType.Group,
                    State = groupSession.State,
                    CreatedAt = groupSession.CreatedAt,
                    LastModifiedAt = DateTime.UtcNow,
                    Metadata = new Dictionary<string, string>()
                };

                // Add group-specific metadata
                dto.Properties["GroupId"] = groupSession.GroupId;
                dto.Properties["CreatorPublicKey"] = Convert.ToBase64String(groupSession.CreatorPublicKey);
                dto.Properties["RotationStrategy"] = groupSession.RotationStrategy.ToString();

                // Store the complete group state
                dto.GroupState = groupState;

                // Encrypt and save the session
                return await EncryptAndSaveSessionAsync(dto);
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(SessionPersistenceManager),
                    $"Failed to save group session {session.SessionId}: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Loads a chat session from persistent storage.
        /// </summary>
        public async Task<ChatSession?> LoadChatSessionAsync(
            string sessionId,
            IDoubleRatchetProtocol doubleRatchetProtocol)
        {
            ArgumentNullException.ThrowIfNull(sessionId, nameof(sessionId));
            ArgumentNullException.ThrowIfNull(doubleRatchetProtocol, nameof(doubleRatchetProtocol));

            // Load and decrypt the session data
            var dto = await LoadAndDecryptSessionAsync(sessionId);
            if (dto == null || dto.SessionType != SessionType.Individual)
                return null;

            try
            {
                // Extract necessary data
                if (!dto.Properties.TryGetValue("RemotePublicKey", out string? remotePublicKeyBase64) ||
                    !dto.Properties.TryGetValue("LocalPublicKey", out string? localPublicKeyBase64))
                {
                    throw new InvalidOperationException("Missing required keys in session data");
                }

                byte[] remotePublicKey = Convert.FromBase64String(remotePublicKeyBase64);
                byte[] localPublicKey = Convert.FromBase64String(localPublicKeyBase64);

                // Deserialize crypto session
                var drSession = DeserializeDoubleRatchetSession(dto.CryptoState);

                // Create session
                var chatSession = new ChatSession(
                    drSession,
                    remotePublicKey,
                    localPublicKey,
                    doubleRatchetProtocol);

                // load the metadata
                foreach (var item in dto.Metadata)
                {
                    chatSession.SetMetadata(item.Key, item.Value);
                }

                // return the chat session
                return chatSession;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(SessionPersistenceManager), $"Failed to load chat session {sessionId}: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Loads group session state as a string for the new consolidated GroupSession.
        /// This method is used by SessionManager to restore GroupSession state.
        /// </summary>
        public async Task<string?> LoadGroupSessionStateAsync(string sessionId)
        {
            ArgumentNullException.ThrowIfNull(sessionId, nameof(sessionId));

            try
            {
                // Load and decrypt the session data
                var dto = await LoadAndDecryptSessionAsync(sessionId);
                if (dto?.SessionType != SessionType.Group || string.IsNullOrEmpty(dto.GroupState))
                {
                    LoggingManager.LogWarning(nameof(SessionPersistenceManager),
                        $"No valid group state found for session {sessionId}");
                    return null;
                }

                return dto.GroupState;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(SessionPersistenceManager),
                    $"Failed to load group session state {sessionId}: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Legacy method - loads a group session using the old multi-component approach.
        /// This is kept for backward compatibility but will use the new GroupSession internally.
        /// </summary>
        public async Task<IGroupSession?> LoadGroupSessionAsync(
            string sessionId,
            KeyPair identityKeyPair)
        {
            ArgumentNullException.ThrowIfNull(sessionId, nameof(sessionId));
            ArgumentNullException.ThrowIfNull(identityKeyPair, nameof(identityKeyPair));

            try
            {
                // Load the group state using the new method
                string? groupState = await LoadGroupSessionStateAsync(sessionId);
                if (string.IsNullOrEmpty(groupState))
                    return null;

                // Parse the group state to extract the group ID
                var sessionState = JsonSerialization.Deserialize<GroupSessionState>(groupState);
                if (sessionState?.GroupId == null)
                    return null;

                // Create a new consolidated GroupSession
                var groupSession = new GroupSession(
                    sessionState.GroupId,
                    sessionState.GroupInfo?.GroupName ?? "Untitled",
                    identityKeyPair,
                    sessionState.RotationStrategy);

                // Restore the session state
                bool restored = await groupSession.RestoreSerializedStateAsync(groupState);
                if (!restored)
                {
                    LoggingManager.LogError(nameof(SessionPersistenceManager),
                        $"Failed to restore group session state for {sessionId}");
                    return null;
                }

                return groupSession;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(SessionPersistenceManager),
                    $"Failed to load group session {sessionId}: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Deletes a session from persistent storage.
        /// </summary>
        public async Task<bool> DeleteSessionAsync(string sessionId)
        {
            ArgumentNullException.ThrowIfNull(sessionId, nameof(sessionId));

            string filePath = GetSessionFilePath(sessionId);

            await _ioLock.WaitAsync();
            try
            {
                if (!File.Exists(filePath))
                    return false;

                KeyStorage.SecureDeleteFile(filePath);
                return true;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(SessionPersistenceManager), $"Failed to delete session {sessionId}: {ex.Message}");
                return false;
            }
            finally
            {
                _ioLock.Release();
            }
        }

        /// <summary>
        /// Lists all available session IDs in storage.
        /// </summary>
        public async Task<string?[]> ListSessionsAsync()
        {
            await _ioLock.WaitAsync();
            try
            {
                if (!Directory.Exists(_storagePath))
                    return Array.Empty<string>();

                var files = Directory.GetFiles(_storagePath, "*.session");
                var sessionIds = files
                    .Select(Path.GetFileNameWithoutExtension)
                    .Where(id => !string.IsNullOrEmpty(id))
                    .ToArray();

                return sessionIds ?? Array.Empty<string>();
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(SessionPersistenceManager), $"Failed to list sessions: {ex.Message}");
                return Array.Empty<string>();
            }
            finally
            {
                _ioLock.Release();
            }
        }

        #region Helper Methods

        private async Task<bool> EncryptAndSaveSessionAsync(SerializedSessionData dto)
        {
            // Serialize to JSON
            string json = JsonSerialization.Serialize(dto);
            byte[] data = Encoding.UTF8.GetBytes(json);

            // Generate a key for encryption
            byte[] key = _cryptoProvider.GenerateRandomBytes(32);
            byte[] nonce = _cryptoProvider.GenerateRandomBytes(Constants.NONCE_SIZE);

            try
            {
                // Encrypt the data
                byte[] encryptedData = _cryptoProvider.Encrypt(data, key, nonce, null);

                // Generate file metadata
                var metadata = new KeyFileMetadata
                {
                    KeyId = dto.SessionId,
                    Nonce = nonce,
                    CreatedAt = dto.CreatedAt,
                    UpdatedAt = dto.LastModifiedAt,
                    Version = $"{ProtocolVersion.MAJOR_VERSION}.{ProtocolVersion.MINOR_VERSION}"
                };

                string metadataJson = JsonSerialization.Serialize(metadata);

                // Write to file
                string filePath = GetSessionFilePath(dto.SessionId);

                await _ioLock.WaitAsync();
                try
                {
                    // Write metadata and encrypted data using binary approach
                    using (var fs = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.None))
                    using (var writer = new BinaryWriter(fs))
                    {
                        // Write metadata length and metadata
                        byte[] metadataBytes = Encoding.UTF8.GetBytes(metadataJson);
                        writer.Write(metadataBytes.Length);
                        writer.Write(metadataBytes);

                        // Write encrypted data
                        writer.Write(encryptedData);
                    }

                    // Store the encryption key in secure storage
                    await _cryptoProvider.StoreKeyAsync($"session:{dto.SessionId}", key);

                    return true;
                }
                finally
                {
                    _ioLock.Release();
                }
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(SessionPersistenceManager), $"Failed to save session {dto.SessionId}: {ex.Message}");
                return false;
            }
            finally
            {
                // Clear sensitive data
                SecureMemory.SecureClear(key);
            }
        }

        private async Task<SerializedSessionData?> LoadAndDecryptSessionAsync(string sessionId)
        {
            string filePath = GetSessionFilePath(sessionId);

            await _ioLock.WaitAsync();
            try
            {
                if (!File.Exists(filePath))
                    return null;

                // Read the file using binary approach
                string metadataJson;
                byte[] encryptedData;

                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                using (var reader = new BinaryReader(fs))
                {
                    // Read metadata length and metadata
                    int metadataLength = reader.ReadInt32();
                    byte[] metadataBytes = reader.ReadBytes(metadataLength);
                    metadataJson = Encoding.UTF8.GetString(metadataBytes);

                    if (string.IsNullOrEmpty(metadataJson))
                        throw new InvalidDataException("Session file is corrupted");

                    // Read encrypted data
                    encryptedData = reader.ReadBytes((int)(fs.Length - fs.Position));
                }

                // Parse metadata
                var metadata = JsonSerialization.Deserialize<KeyFileMetadata>(metadataJson);
                if (metadata == null)
                    throw new InvalidDataException("Failed to parse session metadata");

                // Retrieve the encryption key
                byte[]? key = await _cryptoProvider.RetrieveKeyAsync($"session:{sessionId}");
                if (key == null)
                    throw new SecurityException($"Session key not found for {sessionId}");

                try
                {
                    // Decrypt the data
                    byte[] decryptedData = _cryptoProvider.Decrypt(encryptedData, key, metadata.Nonce, null);

                    // Deserialize the session data
                    string json = Encoding.UTF8.GetString(decryptedData);
                    var dto = JsonSerialization.Deserialize<SerializedSessionData>(json);

                    return dto;
                }
                finally
                {
                    // Clear sensitive data
                    SecureMemory.SecureClear(key);
                }
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(SessionPersistenceManager), $"Failed to load session {sessionId}: {ex.Message}");
                return null;
            }
            finally
            {
                _ioLock.Release();
            }
        }

        private string GetSessionFilePath(string sessionId)
        {
            // Sanitize the session ID to make it safe for use as a filename
            string safeSessionId = new string(sessionId.Select(c => Path.GetInvalidFileNameChars().Contains(c) ? '_' : c).ToArray());
            return Path.Combine(_storagePath, $"{safeSessionId}.session");
        }

        private string SerializeDoubleRatchetSession(DoubleRatchetSession session)
        {
            // Convert sensitive byte arrays to Base64 for serialization
            var dto = new DoubleRatchetSessionDto
            {
                SessionId = session.SessionId,
                RootKey = Convert.ToBase64String(session.RootKey),
                SenderChainKey = session.SenderChainKey != null ? Convert.ToBase64String(session.SenderChainKey) : null,
                ReceiverChainKey = session.ReceiverChainKey != null ? Convert.ToBase64String(session.ReceiverChainKey) : null,
                SenderRatchetKeyPair = new KeyPairDto
                {
                    PublicKey = Convert.ToBase64String(session.SenderRatchetKeyPair.PublicKey),
                    PrivateKey = Convert.ToBase64String(session.SenderRatchetKeyPair.PrivateKey)
                },
                ReceiverRatchetPublicKey = session.ReceiverRatchetPublicKey != null ?
                    Convert.ToBase64String(session.ReceiverRatchetPublicKey) : null,
                PreviousReceiverRatchetPublicKey = session.PreviousReceiverRatchetPublicKey != null ?
                    Convert.ToBase64String(session.PreviousReceiverRatchetPublicKey) : null,
                SendMessageNumber = session.SendMessageNumber,
                ReceiveMessageNumber = session.ReceiveMessageNumber,
                SentMessages = session.SentMessages.ToDictionary(
                    kvp => kvp.Key,
                    kvp => Convert.ToBase64String(kvp.Value)
                ),
                // Convert SkippedMessageKeys to a list to avoid JSON serialization issues with complex dictionary keys
                SkippedMessageKeys = new Dictionary<SkippedMessageKeyDto, string>(),
                SkippedMessageKeysList = session.SkippedMessageKeys.Select(kvp => new SkippedMessageKeyEntryDto
                {
                    Key = new SkippedMessageKeyDto
                    {
                        DhPublicKey = Convert.ToBase64String(kvp.Key.DhPublicKey),
                        MessageNumber = kvp.Key.MessageNumber
                    },
                    Value = Convert.ToBase64String(kvp.Value)
                }).ToList(),
                IsInitialized = session.IsInitialized,
                CreationTimestamp = session.CreationTimestamp
            };

            return JsonSerialization.Serialize(dto);
        }

        private DoubleRatchetSession DeserializeDoubleRatchetSession(string json)
        {
            var dto = JsonSerialization.Deserialize<DoubleRatchetSessionDto>(json);
            if (dto == null)
                throw new InvalidDataException("Failed to deserialize Double Ratchet session");

            // Convert Base64 strings back to byte arrays
            var session = new DoubleRatchetSession
            {
                SessionId = dto.SessionId,
                RootKey = Convert.FromBase64String(dto.RootKey),
                SenderChainKey = dto.SenderChainKey != null ? Convert.FromBase64String(dto.SenderChainKey) : null,
                ReceiverChainKey = dto.ReceiverChainKey != null ? Convert.FromBase64String(dto.ReceiverChainKey) : null,
                SenderRatchetKeyPair = new KeyPair
                {
                    PublicKey = Convert.FromBase64String(dto.SenderRatchetKeyPair.PublicKey),
                    PrivateKey = Convert.FromBase64String(dto.SenderRatchetKeyPair.PrivateKey)
                },
                ReceiverRatchetPublicKey = dto.ReceiverRatchetPublicKey != null ?
                    Convert.FromBase64String(dto.ReceiverRatchetPublicKey) : null,
                PreviousReceiverRatchetPublicKey = dto.PreviousReceiverRatchetPublicKey != null ?
                    Convert.FromBase64String(dto.PreviousReceiverRatchetPublicKey) : null,
                SendMessageNumber = dto.SendMessageNumber,
                ReceiveMessageNumber = dto.ReceiveMessageNumber,
                SentMessages = new Dictionary<uint, byte[]>(),
                SkippedMessageKeys = new Dictionary<SkippedMessageKey, byte[]>(),
                IsInitialized = dto.IsInitialized,
                CreationTimestamp = dto.CreationTimestamp
            };

            // Reconstruct the dictionaries
            foreach (var kvp in dto.SentMessages)
            {
                session.SentMessages[kvp.Key] = Convert.FromBase64String(kvp.Value);
            }

            // Handle skipped message keys - prefer the list format, fall back to dictionary
            if (dto.SkippedMessageKeysList != null && dto.SkippedMessageKeysList.Count > 0)
            {
                foreach (var entry in dto.SkippedMessageKeysList)
                {
                    var key = new SkippedMessageKey(
                        Convert.FromBase64String(entry.Key.DhPublicKey),
                        entry.Key.MessageNumber
                    );
                    session.SkippedMessageKeys[key] = Convert.FromBase64String(entry.Value);
                }
            }
            else
            {
                // Fallback to dictionary format for backward compatibility
                foreach (var kvp in dto.SkippedMessageKeys)
                {
                    var key = new SkippedMessageKey(
                        Convert.FromBase64String(kvp.Key.DhPublicKey),
                        kvp.Key.MessageNumber
                    );
                    session.SkippedMessageKeys[key] = Convert.FromBase64String(kvp.Value);
                }
            }

            return session;
        }

        #endregion

        // IDisposable implementation
        protected virtual void Dispose(bool disposing)
        {
            if (_disposed) return;

            if (disposing)
            {
                _ioLock?.Dispose();
            }

            _disposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}