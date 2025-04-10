using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using E2EELibrary.Core;
using E2EELibrary.Encryption;
using E2EELibrary.Models;
using E2EELibrary.KeyExchange;

namespace E2EELibrary.GroupMessaging
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
                    // Return a deep copy to prevent external modification
                    return session.Clone();
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
                // Store a deep copy to prevent external modification
                _groupSessions[session.GroupId] = session.Clone();
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
                    // Securely clear sensitive data
                    SecureMemory.SecureClear(session.SenderKey);

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
                // Return deep copies of all sessions
                return _groupSessions.Values.Select(s => s.Clone()).ToList();
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
            List<GroupSession> sessionDtos;

            lock (_sessionsLock)
            {
                sessionDtos = _groupSessions.Values.Select(s => new GroupSession
                {
                    GroupId = s.GroupId,
                    SenderKeyBase64 = Convert.ToBase64String(s.SenderKey),
                    CreatorIdentityKeyBase64 = Convert.ToBase64String(s.CreatorIdentityKey),
                    CreationTimestamp = s.CreationTimestamp,
                    LastKeyRotation = s.LastKeyRotation,
                    Metadata = s.Metadata
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
                byte[] salt = Sodium.GenerateRandomBytes(Constants.DEFAULT_SALT_SIZE);
                RandomNumberGenerator.Fill(salt);

                byte[] nonce = NonceGenerator.GenerateNonce();

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
                byte[] salt = Sodium.GenerateRandomBytes(Constants.DEFAULT_SALT_SIZE);
                byte[] nonce = Sodium.GenerateRandomBytes(Constants.NONCE_SIZE);

                // Use Span<T> to copy data without Buffer.BlockCopy
                fileData.AsSpan(0, salt.Length).CopyTo(salt.AsSpan());
                fileData.AsSpan(salt.Length, nonce.Length).CopyTo(nonce.AsSpan());

                // Extract encrypted data
                int encryptedDataOffset = salt.Length + nonce.Length;
                byte[] encryptedData = Sodium.GenerateRandomBytes(fileData.Length - encryptedDataOffset);
                fileData.AsSpan(encryptedDataOffset, encryptedData.Length).CopyTo(encryptedData.AsSpan());
                
                // Derive key from password
                using var deriveBytes = new Rfc2898DeriveBytes(
                    password,
                    salt,
                    Constants.PBKDF2_ITERATIONS,
                    HashAlgorithmName.SHA256);

                byte[] key = deriveBytes.GetBytes(Constants.AES_KEY_SIZE);

                // Decrypt data
                jsonData = AES.AESDecrypt(encryptedData, key, nonce);
            }
            else
            {
                jsonData = fileData;
            }

            // Deserialize JSON
            string json = Encoding.UTF8.GetString(jsonData);
            var sessionDtos = JsonSerializer.Deserialize<List<GroupSession>>(json);

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
                    var session = new GroupSession
                    {
                        GroupId = dto.GroupId,
                        SenderKey = Convert.FromBase64String(dto.SenderKeyBase64),
                        CreatorIdentityKey = Convert.FromBase64String(dto.CreatorIdentityKeyBase64),
                        CreationTimestamp = dto.CreationTimestamp,
                        LastKeyRotation = dto.LastKeyRotation,
                        Metadata = dto.Metadata
                    };

                    loadedSessions[dto.GroupId] = session;
                }
                catch (Exception ex)
                {
                    // Log the error but continue processing other sessions
                    LoggingManager.LogError(nameof(GroupSessionPersistence), $"Error loading session for group {dto.GroupId}: {ex.Message}");
                }
            }

            // Update sessions dictionary
            lock (_sessionsLock)
            {
                // First, clear any sensitive data in existing sessions
                foreach (var session in _groupSessions.Values)
                {
                    SecureMemory.SecureClear(session.SenderKey);
                }

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
        public bool UpdateGroupSession(string groupId, Action<GroupSession> updateAction)
        {
            ArgumentNullException.ThrowIfNull(groupId, nameof(groupId));
            ArgumentNullException.ThrowIfNull(updateAction, nameof(updateAction));

            lock (_sessionsLock)
            {
                if (_groupSessions.TryGetValue(groupId, out var session))
                {
                    updateAction(session);
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
            var sessionDto = new GroupSession
            {
                GroupId = session.GroupId,
                SenderKeyBase64 = Convert.ToBase64String(session.SenderKey),
                CreatorIdentityKeyBase64 = Convert.ToBase64String(session.CreatorIdentityKey),
                CreationTimestamp = session.CreationTimestamp,
                LastKeyRotation = session.LastKeyRotation,
                Metadata = session.Metadata
            };

            // Serialize to JSON
            string json = JsonSerializer.Serialize(sessionDto);
            byte[] data = Encoding.UTF8.GetBytes(json);

            // Encrypt if a key is provided
            if (encryptionKey != null && encryptionKey.Length == Constants.AES_KEY_SIZE)
            {
                byte[] nonce = NonceGenerator.GenerateNonce();
                byte[] encryptedData = AES.AESEncrypt(data, encryptionKey, nonce);

                // Combine nonce and encrypted data
                byte[] result = Sodium.GenerateRandomBytes(nonce.Length + encryptedData.Length);
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
                byte[] nonce = Sodium.GenerateRandomBytes(Constants.NONCE_SIZE);
                byte[] encryptedData = Sodium.GenerateRandomBytes(serializedData.Length - Constants.NONCE_SIZE);

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
            var dto = JsonSerializer.Deserialize<GroupSession>(json);

            if (dto == null)
            {
                throw new InvalidDataException("Failed to deserialize group session");
            }

            // Convert to session object
            var session = new GroupSession
            {
                GroupId = dto.GroupId,
                SenderKey = Convert.FromBase64String(dto.SenderKeyBase64),
                CreatorIdentityKey = Convert.FromBase64String(dto.CreatorIdentityKeyBase64),
                CreationTimestamp = dto.CreationTimestamp,
                LastKeyRotation = dto.LastKeyRotation,
                Metadata = dto.Metadata
            };

            // Store the session
            StoreGroupSession(session);

            return session;
        }

        /// <summary>
        /// Leverages the existing SessionPersistence class for more advanced serialization
        /// and secure storage of group sessions
        /// </summary>
        /// <param name="groupId">Group identifier</param>
        /// <param name="filePath">File path to save to</param>
        /// <param name="encryptionKey">Optional encryption key</param>
        public void SaveGroupSessionAdvanced(string groupId, string filePath, byte[]? encryptionKey = null)
        {
            // Get the group session
            GroupSession? session = GetGroupSession(groupId);
            if (session == null)
            {
                throw new ArgumentException($"Group {groupId} not found", nameof(groupId));
            }

            // Convert to a DoubleRatchetSession for storage
            // This is a way to leverage existing SessionPersistence functionality
            // We're using the DoubleRatchetSession as a container for our group session data

            // Create a minimal DH key pair for the session
            var dummyKeyPair = (_identityKeyToSessionKey(session.CreatorIdentityKey), session.SenderKey);

            // Create a session with our group data
            var doubleRatchetSession = new DoubleRatchetSession(
                dhRatchetKeyPair: dummyKeyPair,
                remoteDHRatchetKey: _identityKeyToSessionKey(session.CreatorIdentityKey), // Use creator key
                rootKey: session.SenderKey, // Store sender key as root key
                sendingChainKey: session.SenderKey, // Reuse sender key
                receivingChainKey: session.SenderKey, // Reuse sender key
                messageNumber: 0,
                sessionId: session.GroupId // Use group ID as session ID
            );

            // Use SessionPersistence to save
            SessionPersistence.SaveSessionToFile(doubleRatchetSession, filePath, encryptionKey);
        }

        /// <summary>
        /// Loads a group session using the advanced serialization from SessionPersistence
        /// </summary>
        /// <param name="filePath">File path to load from</param>
        /// <param name="decryptionKey">Optional decryption key</param>
        /// <returns>The loaded group session</returns>
        public GroupSession LoadGroupSessionAdvanced(string filePath, byte[]? decryptionKey = null)
        {
            // Load using SessionPersistence
            var doubleRatchetSession = SessionPersistence.LoadSessionFromFile(filePath, decryptionKey);

            // Convert back to GroupSession
            var groupSession = new GroupSession
            {
                GroupId = doubleRatchetSession.SessionId,
                SenderKey = doubleRatchetSession.RootKey, // Stored in root key
                CreatorIdentityKey = _sessionKeyToIdentityKey(doubleRatchetSession.RemoteDHRatchetKey),
                CreationTimestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), // Not stored, using current time
                LastKeyRotation = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() // Not stored, using current time
            };

            // Store in memory
            StoreGroupSession(groupSession);

            return groupSession;
        }

        /// <summary>
        /// Helper method to convert identity key to session key format
        /// </summary>
        private byte[] _identityKeyToSessionKey(byte[] identityKey)
        {
            // If key is already the right size, return a copy
            if (identityKey.Length == Constants.X25519_KEY_SIZE)
            {
                byte[] copy = Sodium.GenerateRandomBytes(identityKey.Length);
                identityKey.AsSpan().CopyTo(copy);
                return copy;
            }

            // Otherwise hash it down to the right size
            using var sha256 = SHA256.Create();
            return sha256.ComputeHash(identityKey);
        }

        /// <summary>
        /// Helper method to convert session key to identity key format
        /// </summary>
        private byte[] _sessionKeyToIdentityKey(byte[] sessionKey)
        {
            // Just return a copy since we can't recover the original identity key
            byte[] copy = Sodium.GenerateRandomBytes(sessionKey.Length);
            sessionKey.AsSpan().CopyTo(copy);
            return copy;
        }
    }
}