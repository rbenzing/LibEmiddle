using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Collections.Immutable;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;

namespace LibEmiddle.Messaging.Group
{
    /// <summary>
    /// Manages the persistence of group session information
    /// </summary>
    public class GroupSessionPersistence
    {
        // Dictionary to store group sessions
        private readonly Dictionary<string, GroupSession> _groupSessions = new();

        // Lock object for thread safety
        private readonly object _sessionsLock = new();

        /// <summary>
        /// Gets a group session by ID
        /// </summary>
        /// <param name="groupId">Group identifier</param>
        /// <returns>Group session if found, otherwise null</returns>
        public GroupSession? GetGroupSession(string groupId)
        {
            ArgumentNullException.ThrowIfNull(groupId, nameof(groupId));

            lock (_sessionsLock)
            {
                if (_groupSessions.TryGetValue(groupId, out var session))
                {
                    // Sessions are immutable so we don't need to clone
                    return session;
                }

                return null;
            }
        }

        /// <summary>
        /// Stores a group session
        /// </summary>
        /// <param name="session">Group session to store</param>
        public void StoreGroupSession(GroupSession session)
        {
            ArgumentNullException.ThrowIfNull(session, nameof(session));
            ArgumentNullException.ThrowIfNull(session.GroupId, nameof(session.GroupId));

            lock (_sessionsLock)
            {
                // Store the session directly (it's already immutable)
                _groupSessions[session.GroupId] = session;
            }
        }

        /// <summary>
        /// Deletes a group session
        /// </summary>
        /// <param name="groupId">Group identifier</param>
        /// <returns>True if the session was deleted</returns>
        public bool DeleteGroupSession(string groupId)
        {
            ArgumentNullException.ThrowIfNull(groupId, nameof(groupId));

            lock (_sessionsLock)
            {
                if (_groupSessions.TryGetValue(groupId, out var session))
                {
                    // Sessions are immutable, so no need to clear data
                    return _groupSessions.Remove(groupId);
                }

                return false;
            }
        }

        /// <summary>
        /// Gets all group sessions
        /// </summary>
        /// <returns>List of group sessions</returns>
        public List<GroupSession> GetAllSessions()
        {
            lock (_sessionsLock)
            {
                // Return direct references since sessions are immutable
                return _groupSessions.Values.ToList();
            }
        }

        /// <summary>
        /// Saves all group sessions to a file
        /// </summary>
        /// <param name="filePath">File path to save to</param>
        /// <param name="password">Optional password for encryption</param>
        public void SaveToFile(string filePath, string? password = null)
        {
            // Create a serializable representation of sessions
            List<GroupSessionDto> sessionDtos;

            lock (_sessionsLock)
            {
                sessionDtos = _groupSessions.Values.Select(s => new GroupSessionDto
                {
                    GroupId = s.GroupId,
                    ChainKeyBase64 = Convert.ToBase64String(s.ChainKey),
                    Iteration = s.Iteration,
                    CreatorIdentityKeyBase64 = Convert.ToBase64String(s.CreatorIdentityKey),
                    CreationTimestamp = s.CreationTimestamp,
                    KeyEstablishmentTimestamp = s.KeyEstablishmentTimestamp,
                    MetadataJson = s.Metadata.Count > 0 ?
                        JsonSerializer.Serialize(s.Metadata) :
                        null
                }).ToList();
            }

            // Serialize to JSON
            string json = JsonSerializer.Serialize(sessionDtos, new JsonSerializerOptions
            {
                WriteIndented = true
            });

            byte[] data = Encoding.UTF8.GetBytes(json);

            // Encrypt if password is provided
            if (!string.IsNullOrEmpty(password))
            {
                // Generate salt and nonce
                byte[] salt = SecureMemory.CreateSecureBuffer(Constants.DEFAULT_SALT_SIZE);
                byte[] nonce = Nonce.GenerateNonce();

                // Derive key from password
                using var deriveBytes = new Rfc2898DeriveBytes(
                    password,
                    salt,
                    Constants.PBKDF2_ITERATIONS,
                    HashAlgorithmName.SHA256);

                byte[] key = deriveBytes.GetBytes(Constants.AES_KEY_SIZE);

                // Encrypt data
                byte[] encryptedData = AES.AESEncrypt(data, key, nonce);

                // Combine salt, nonce, and encrypted data
                using var ms = new MemoryStream();
                ms.Write(salt, 0, salt.Length);
                ms.Write(nonce, 0, nonce.Length);
                ms.Write(encryptedData, 0, encryptedData.Length);

                data = ms.ToArray();

                // Clean up sensitive data
                SecureMemory.SecureClear(key);
            }

            // Write to file
            File.WriteAllBytes(filePath, data);
        }

        /// <summary>
        /// Loads group sessions from a file
        /// </summary>
        /// <param name="filePath">File path to load from</param>
        /// <param name="password">Optional password for decryption</param>
        public void LoadFromFile(string filePath, string? password = null)
        {
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException("Group sessions file not found", filePath);
            }

            byte[] fileData = File.ReadAllBytes(filePath);
            byte[] jsonData;

            // Decrypt if password is provided
            if (!string.IsNullOrEmpty(password))
            {
                // Generate buffers with appropriate sizes
                byte[] salt = new byte[Constants.DEFAULT_SALT_SIZE];
                byte[] nonce = new byte[Constants.NONCE_SIZE];

                // Use Span<T> to copy data without Buffer.BlockCopy
                fileData.AsSpan(0, salt.Length).CopyTo(salt.AsSpan());
                fileData.AsSpan(salt.Length, nonce.Length).CopyTo(nonce.AsSpan());

                // Extract encrypted data
                int encryptedDataOffset = salt.Length + nonce.Length;
                byte[] encryptedData = new byte[fileData.Length - encryptedDataOffset];
                fileData.AsSpan(encryptedDataOffset, encryptedData.Length).CopyTo(encryptedData.AsSpan());

                // Derive key from password
                using var deriveBytes = new Rfc2898DeriveBytes(
                    password,
                    salt,
                    Constants.PBKDF2_ITERATIONS,
                    HashAlgorithmName.SHA256);

                byte[] key = deriveBytes.GetBytes(Constants.AES_KEY_SIZE);

                // Decrypt data
                try
                {
                    jsonData = AES.AESDecrypt(encryptedData, key, nonce);

                    // Clean up sensitive data
                    SecureMemory.SecureClear(key);
                }
                catch (Exception ex)
                {
                    throw new InvalidDataException("Failed to decrypt group sessions file", ex);
                }
            }
            else
            {
                jsonData = fileData;
            }

            // Deserialize JSON
            string json = Encoding.UTF8.GetString(jsonData);
            var sessionDtos = JsonSerializer.Deserialize<List<GroupSessionDto>>(json);

            if (sessionDtos == null)
            {
                throw new InvalidDataException("Failed to deserialize group sessions");
            }

            // Convert DTOs to group sessions
            var loadedSessions = new Dictionary<string, GroupSession>();

            foreach (var dto in sessionDtos)
            {
                try
                {
                    // Parse metadata dictionary if present
                    ImmutableDictionary<string, string>? metadata = null;
                    if (!string.IsNullOrEmpty(dto.MetadataJson))
                    {
                        var metadataDict = JsonSerializer.Deserialize<Dictionary<string, string>>(dto.MetadataJson);
                        if (metadataDict != null)
                        {
                            metadata = metadataDict.ToImmutableDictionary();
                        }
                    }

                    // Use the constructor pattern to create immutable sessions
                    var session = new GroupSession(
                        groupId: dto.GroupId,
                        chainKey: Convert.FromBase64String(dto.ChainKeyBase64),
                        iteration: dto.Iteration,
                        creatorIdentityKey: Convert.FromBase64String(dto.CreatorIdentityKeyBase64),
                        creationTimestamp: dto.CreationTimestamp,
                        keyEstablishmentTimestamp: dto.KeyEstablishmentTimestamp,
                        metadata: metadata ?? ImmutableDictionary<string, string>.Empty
                    );

                    loadedSessions[dto.GroupId] = session;
                }
                catch (Exception ex)
                {
                    // Log the error but continue processing other sessions
                    LoggingManager.LogError(nameof(GroupSessionPersistence),
                        $"Error loading session for group {dto.GroupId}: {ex.Message}");
                }
            }

            // Update sessions dictionary
            lock (_sessionsLock)
            {
                _groupSessions.Clear();

                // Add loaded sessions
                foreach (var (groupId, session) in loadedSessions)
                {
                    _groupSessions[groupId] = session;
                }
            }
        }

        /// <summary>
        /// Updates a specific field in a group session
        /// </summary>
        /// <param name="groupId">Group identifier</param>
        /// <param name="updateAction">Action to perform on the session</param>
        /// <returns>True if the session was updated</returns>
        public bool UpdateGroupSession(string groupId, Func<GroupSession, GroupSession> updateAction)
        {
            ArgumentNullException.ThrowIfNull(groupId, nameof(groupId));
            ArgumentNullException.ThrowIfNull(updateAction, nameof(updateAction));

            lock (_sessionsLock)
            {
                if (_groupSessions.TryGetValue(groupId, out var session))
                {
                    // Apply the update function to get a new session instance
                    var updatedSession = updateAction(session);

                    // Store the updated session
                    _groupSessions[groupId] = updatedSession;
                    return true;
                }

                return false;
            }
        }

        /// <summary>
        /// Exports a group session to a serialized format
        /// </summary>
        /// <param name="groupId">Group identifier</param>
        /// <param name="encryptionKey">Optional key to encrypt the session</param>
        /// <returns>Serialized session data</returns>
        public byte[] ExportGroupSession(string groupId, byte[]? encryptionKey = null)
        {
            GroupSession? session = GetGroupSession(groupId);
            if (session == null)
            {
                throw new ArgumentException($"Group {groupId} not found", nameof(groupId));
            }

            // Create DTO
            var sessionDto = new GroupSessionDto
            {
                GroupId = session.GroupId,
                ChainKeyBase64 = Convert.ToBase64String(session.ChainKey),
                Iteration = session.Iteration,
                CreatorIdentityKeyBase64 = Convert.ToBase64String(session.CreatorIdentityKey),
                CreationTimestamp = session.CreationTimestamp,
                KeyEstablishmentTimestamp = session.KeyEstablishmentTimestamp,
                MetadataJson = session.Metadata.Count > 0 ?
                    JsonSerializer.Serialize(session.Metadata) : null
            };

            // Serialize to JSON
            string json = JsonSerializer.Serialize(sessionDto);
            byte[] data = Encoding.UTF8.GetBytes(json);

            // Encrypt if a key is provided
            if (encryptionKey != null && encryptionKey.Length == Constants.AES_KEY_SIZE)
            {
                byte[] nonce = Nonce.GenerateNonce();
                byte[] encryptedData = AES.AESEncrypt(data, encryptionKey, nonce);

                // Combine nonce and encrypted data
                byte[] result = new byte[nonce.Length + encryptedData.Length];
                nonce.AsSpan().CopyTo(result.AsSpan(0, nonce.Length));
                encryptedData.AsSpan().CopyTo(result.AsSpan(nonce.Length, encryptedData.Length));

                return result;
            }

            return data;
        }

        /// <summary>
        /// Imports a group session from serialized data
        /// </summary>
        /// <param name="serializedData">Serialized session data</param>
        /// <param name="decryptionKey">Optional key for decryption</param>
        /// <returns>The imported group session</returns>
        public GroupSession ImportGroupSession(byte[] serializedData, byte[]? decryptionKey = null)
        {
            byte[] jsonData;

            // Decrypt if a key is provided
            if (decryptionKey != null && decryptionKey.Length == Constants.AES_KEY_SIZE)
            {
                // Extract nonce and encrypted data
                byte[] nonce = new byte[Constants.NONCE_SIZE];
                byte[] encryptedData = new byte[serializedData.Length - Constants.NONCE_SIZE];

                serializedData.AsSpan(0, nonce.Length).CopyTo(nonce.AsSpan());
                serializedData.AsSpan(nonce.Length).CopyTo(encryptedData.AsSpan());

                jsonData = AES.AESDecrypt(encryptedData, decryptionKey, nonce);
            }
            else
            {
                jsonData = serializedData;
            }

            // Deserialize
            string json = Encoding.UTF8.GetString(jsonData);
            var dto = JsonSerializer.Deserialize<GroupSessionDto>(json);

            if (dto == null)
            {
                throw new InvalidDataException("Failed to deserialize group session");
            }

            // Parse metadata if present
            ImmutableDictionary<string, string>? metadata = null;
            if (!string.IsNullOrEmpty(dto.MetadataJson))
            {
                var metadataDict = JsonSerializer.Deserialize<Dictionary<string, string>>(dto.MetadataJson);
                if (metadataDict != null)
                {
                    metadata = metadataDict.ToImmutableDictionary();
                }
            }

            // Create new session from the DTO
            var session = new GroupSession(
                groupId: dto.GroupId,
                chainKey: Convert.FromBase64String(dto.ChainKeyBase64),
                iteration: dto.Iteration,
                creatorIdentityKey: Convert.FromBase64String(dto.CreatorIdentityKeyBase64),
                creationTimestamp: dto.CreationTimestamp,
                keyEstablishmentTimestamp: dto.KeyEstablishmentTimestamp,
                metadata: metadata ?? ImmutableDictionary<string, string>.Empty
            );

            // Store the session
            StoreGroupSession(session);

            return session;
        }
    }
}