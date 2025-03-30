using System.Security.Cryptography;
using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using E2EELibrary.Communication;
using E2EELibrary.Core;
using E2EELibrary.Encryption;
using E2EELibrary.KeyManagement;
using E2EELibrary.Models;

namespace E2EELibrary.GroupMessaging
{
    /// <summary>
    /// Group chat manager for handling multiple participants with enhanced security features
    /// to prevent unauthorized group access and ensure forward secrecy.
    /// </summary>
    public class GroupChatManager
    {
        private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, byte[]>> _groupSenderKeys =
            new ConcurrentDictionary<string, ConcurrentDictionary<string, byte[]>>();
        private readonly (byte[] publicKey, byte[] privateKey) _identityKeyPair;
        private readonly ConcurrentDictionary<string, byte[]> _myGroupSenderKeys =
            new ConcurrentDictionary<string, byte[]>();
        private readonly object _encryptionLock = new object();

        // Track when a user joined each group for message timing verification
        private readonly ConcurrentDictionary<string, long> _joinTimestamps =
            new ConcurrentDictionary<string, long>();

        // Mark members who created groups (admin tracking)
        private readonly ConcurrentDictionary<string, bool> _createdGroups =
            new ConcurrentDictionary<string, bool>(StringComparer.OrdinalIgnoreCase);

        // Group-specific fine-grained locks to improve concurrency
        private readonly ConcurrentDictionary<string, object> _groupLocks =
            new ConcurrentDictionary<string, object>();

        // Track authorized members for each group (explicit ACL)
        private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, bool>> _authorizedMembers =
            new ConcurrentDictionary<string, ConcurrentDictionary<string, bool>>();

        // Track processed message IDs to prevent replay attacks
        private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, long>> _processedMessageIds =
            new ConcurrentDictionary<string, ConcurrentDictionary<string, long>>();

        // Track group epochs for key rotation and forward secrecy
        private readonly ConcurrentDictionary<string, int> _groupEpochs =
            new ConcurrentDictionary<string, int>();

        /// <summary>
        /// Creates a new group chat manager
        /// </summary>
        /// <param name="identityKeyPair">Identity key pair for this client</param>
        public GroupChatManager((byte[] publicKey, byte[] privateKey) identityKeyPair)
        {
            _identityKeyPair = identityKeyPair;
        }

        /// <summary>
        /// Get or create a lock object for a specific group
        /// </summary>
        /// <param name="groupId">Group identifier</param>
        /// <returns>Lock object for the group</returns>
        private object GetGroupLock(string groupId)
        {
            return _groupLocks.GetOrAdd(groupId, _ => new object());
        }

        /// <summary>
        /// Creates a new group
        /// </summary>
        /// <param name="groupId">Group identifier</param>
        /// <returns>Sender key for this group</returns>
        public byte[] CreateGroup(string groupId)
        {
            if (string.IsNullOrEmpty(groupId))
                throw new ArgumentException("Group ID cannot be null or empty", nameof(groupId));

            // Record that we created this group - thread-safe with ConcurrentDictionary
            _createdGroups[groupId] = true;

            // Record our join timestamp - thread-safe with ConcurrentDictionary
            long currentTimestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            _joinTimestamps[groupId] = currentTimestamp;

            // Initialize group epoch to 1
            _groupEpochs[groupId] = 1;

            // Use GetOrAdd to ensure atomic operation for generating and storing the key
            return _myGroupSenderKeys.GetOrAdd(groupId, _ => {
                byte[] senderKey = KeyGenerator.GenerateSenderKey();

                // Thread-safe dictionary access - will create if not exists
                _groupSenderKeys.GetOrAdd(groupId, _ => new ConcurrentDictionary<string, byte[]>());

                // Initialize authorized members for this group with ourselves as the first member
                string myIdBase64 = Convert.ToBase64String(_identityKeyPair.publicKey);
                var membersDict = _authorizedMembers.GetOrAdd(groupId, _ => new ConcurrentDictionary<string, bool>());
                membersDict[myIdBase64] = true; // We're authorized as the creator

                // Initialize message ID tracking for replay protection
                _processedMessageIds.GetOrAdd(groupId, _ => new ConcurrentDictionary<string, long>());

                return senderKey;
            });
        }

        /// <summary>
        /// Creates a distribution message for sharing the sender key
        /// </summary>
        /// <param name="groupId">Group identifier</param>
        /// <returns>Distribution message to share with group members</returns>
        public SenderKeyDistributionMessage CreateDistributionMessage(string groupId)
        {
            if (string.IsNullOrEmpty(groupId))
                throw new ArgumentException("Group ID cannot be null or empty", nameof(groupId));

            // Thread-safe read from ConcurrentDictionary
            if (!_myGroupSenderKeys.TryGetValue(groupId, out byte[]? senderKey))
            {
                throw new ArgumentException($"Group {groupId} not created yet", nameof(groupId));
            }

            // Get current epoch to include in the signature context
            int currentEpoch = _groupEpochs.GetOrAdd(groupId, 1);

            return CreateSenderKeyDistributionMessageInternal(groupId, senderKey, _identityKeyPair, currentEpoch);
        }

        /// <summary>
        /// Internal method to create a sender key distribution message with enhanced security
        /// </summary>
        private static SenderKeyDistributionMessage CreateSenderKeyDistributionMessageInternal(
            string groupId, byte[] senderKey, (byte[] publicKey, byte[] privateKey) senderKeyPair, int epoch)
        {
            // Create signature context that includes the epoch for replay protection
            byte[] dataToSign;
            using (var ms = new MemoryStream())
            {
                // Start with the sender key
                ms.Write(senderKey, 0, senderKey.Length);

                // Add the epoch number to prevent replays across epochs
                ms.Write(BitConverter.GetBytes(epoch), 0, 4);

                // Add the group ID
                byte[] groupIdBytes = Encoding.UTF8.GetBytes(groupId);
                ms.Write(groupIdBytes, 0, groupIdBytes.Length);

                dataToSign = ms.ToArray();
            }

            // Sign the enhanced context
            byte[] signature;
            if (senderKeyPair.privateKey.Length == Constants.X25519_KEY_SIZE)
            {
                // For 32-byte keys, convert to appropriate format for signing
                byte[] expandedKey = new byte[Constants.ED25519_PRIVATE_KEY_SIZE];
                senderKeyPair.privateKey.AsSpan(0, Constants.X25519_KEY_SIZE).CopyTo(expandedKey.AsSpan(0, Constants.X25519_KEY_SIZE));

                using (var sha256 = SHA256.Create())
                {
                    byte[] secondHalf = sha256.ComputeHash(senderKeyPair.privateKey);
                    secondHalf.AsSpan(0, Constants.X25519_KEY_SIZE).CopyTo(expandedKey.AsSpan(Constants.X25519_KEY_SIZE, Constants.X25519_KEY_SIZE));
                }

                signature = MessageSigning.SignMessage(dataToSign, expandedKey);
            }
            else if (senderKeyPair.privateKey.Length == Constants.ED25519_PRIVATE_KEY_SIZE)
            {
                // Use the full key directly if it's already Ed25519 format
                signature = MessageSigning.SignMessage(dataToSign, senderKeyPair.privateKey);
            }
            else
            {
                throw new ArgumentException($"Unexpected private key length: {senderKeyPair.privateKey.Length}");
            }

            // Store epoch and timestamp in the existing properties - they'll be 
            // accessible via extra properties extension
            var extraProperties = new Dictionary<string, object>
            {
                ["epoch"] = epoch,
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
            };

            // Convert to base64 json for transport in existing property
            string extraPropertiesJson = System.Text.Json.JsonSerializer.Serialize(extraProperties);
            byte[] extraPropertiesBytes = Encoding.UTF8.GetBytes(extraPropertiesJson);
            string extraPropertiesBase64 = Convert.ToBase64String(extraPropertiesBytes);

            // Create distribution message with as much security info as possible
            // using existing fields so we don't need to modify the model
            return new SenderKeyDistributionMessage
            {
                GroupId = groupId,
                SenderKey = senderKey,
                SenderIdentityKey = senderKeyPair.publicKey,
                Signature = signature,
                // Store extra properties in MessageId field (since it's a string and not used in this message type)
                // This is a bit of a hack but allows us to extend the protocol without changing the models
                MessageId = extraPropertiesBase64
            };
        }

        /// <summary>
        /// Extracts epoch and timestamp from a distribution message
        /// </summary>
        private (int epoch, long timestamp) ExtractDistributionMessageProperties(SenderKeyDistributionMessage message)
        {
            // Default values
            int epoch = 1;
            long timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            // Try to extract from MessageId field
            if (!string.IsNullOrEmpty(message.MessageId))
            {
                try
                {
                    byte[] extraPropertiesBytes = Convert.FromBase64String(message.MessageId);
                    string extraPropertiesJson = Encoding.UTF8.GetString(extraPropertiesBytes);
                    var extraProperties = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(extraPropertiesJson);

                    if (extraProperties != null)
                    {
                        // Extract epoch
                        if (extraProperties.TryGetValue("epoch", out var epochObj) &&
                            epochObj.ValueKind == JsonValueKind.Number)
                        {
                            epoch = epochObj.GetInt32();
                        }

                        // Extract timestamp
                        if (extraProperties.TryGetValue("timestamp", out var timestampObj) &&
                            timestampObj.ValueKind == JsonValueKind.Number)
                        {
                            timestamp = timestampObj.GetInt64();
                        }
                    }
                }
                catch
                {
                    // Ignore parse errors - use defaults
                }
            }

            return (epoch, timestamp);
        }

        /// <summary>
        /// Processes a received sender key distribution message with enhanced security checks
        /// </summary>
        /// <param name="distribution">Distribution message</param>
        /// <returns>True if the distribution was valid and processed</returns>
        public bool ProcessSenderKeyDistribution(SenderKeyDistributionMessage distribution)
        {
            if (distribution == null)
                throw new ArgumentNullException(nameof(distribution));
            if (distribution.SenderKey == null)
                throw new ArgumentException("Sender key cannot be null", nameof(distribution));
            if (distribution.Signature == null)
                throw new ArgumentException("Signature cannot be null", nameof(distribution));
            if (distribution.SenderIdentityKey == null)
                throw new ArgumentException("Sender identity key cannot be null", nameof(distribution));

            string? groupId = distribution.GroupId;
            if (string.IsNullOrEmpty(groupId))
            {
                return false;
            }

            // Extract epoch and timestamp
            var (messageEpoch, messageTimestamp) = ExtractDistributionMessageProperties(distribution);

            // Get current time for freshness check
            long currentTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            // Validate time - reject too old or future messages
            if (Math.Abs(currentTime - messageTimestamp) > Constants.MAX_MESSAGE_AGE_MS)
            {
                return false; // Message too old or from the future
            }

            // Lock for thread safety during processing
            lock (GetGroupLock(groupId))
            {
                // Check if sender is authorized to be in this group if we're already a member
                string senderIdBase64 = Convert.ToBase64String(distribution.SenderIdentityKey);

                // If we're already in the group, check if sender is authorized
                if (_joinTimestamps.TryGetValue(groupId, out _))
                {
                    // Get authorized members dictionary
                    var authorized = _authorizedMembers.GetOrAdd(groupId, _ => new ConcurrentDictionary<string, bool>());

                    // If sender is not authorized, reject the distribution
                    if (!authorized.ContainsKey(senderIdBase64))
                    {
                        // This is the key security feature - we do NOT auto-authorize
                        Console.WriteLine($"Warning: Rejecting distribution from unauthorized sender {senderIdBase64}");
                        return false;
                    }

                    // Verify the current group epoch
                    int currentEpoch = _groupEpochs.GetOrAdd(groupId, 1);

                    // Check for temporal attacks - using old epochs to bypass forward secrecy
                    if (messageEpoch < currentEpoch)
                    {
                        // This is an old epoch distribution message - reject it
                        // to maintain forward secrecy
                        return false;
                    }

                    // Update to newer epoch if needed
                    if (messageEpoch > currentEpoch)
                    {
                        _groupEpochs[groupId] = messageEpoch;
                    }
                }

                // Recreate the signature context for verification
                byte[] dataToVerify;
                using (var ms = new MemoryStream())
                {
                    // Start with the sender key
                    ms.Write(distribution.SenderKey, 0, distribution.SenderKey.Length);

                    // Add the epoch number
                    ms.Write(BitConverter.GetBytes(messageEpoch), 0, 4);

                    // Add the group ID
                    byte[] groupIdBytes = Encoding.UTF8.GetBytes(groupId);
                    ms.Write(groupIdBytes, 0, groupIdBytes.Length);

                    dataToVerify = ms.ToArray();
                }

                // Verify the signature using our enhanced context
                bool validSignature = MessageSigning.VerifySignature(
                    dataToVerify,
                    distribution.Signature,
                    distribution.SenderIdentityKey);

                if (!validSignature)
                {
                    // Signature verification failed - reject distribution
                    return false;
                }

                // IMPORTANT: Record join timestamp if not already set
                // This ensures we track when we first joined the group
                _joinTimestamps.GetOrAdd(groupId, _ => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());

                // Generate our sender key if needed - thread-safe with ConcurrentDictionary
                _myGroupSenderKeys.GetOrAdd(groupId, _ => KeyGenerator.GenerateSenderKey());

                // Set authorized members as we join
                var authorizedMembers = _authorizedMembers.GetOrAdd(groupId, _ => new ConcurrentDictionary<string, bool>());

                // Check if this is our own distribution message
                string myIdBase64 = Convert.ToBase64String(_identityKeyPair.publicKey);
                bool isOwnMessage = SecureMemory.SecureCompare(distribution.SenderIdentityKey, _identityKeyPair.publicKey);

                if (isOwnMessage)
                {
                    // Mark ourselves as authorized
                    authorizedMembers[myIdBase64] = true;
                    return true;
                }

                // Mark this sender as authorized
                authorizedMembers[senderIdBase64] = true;

                // Store the sender key - thread-safe with nested ConcurrentDictionary
                var groupDict = _groupSenderKeys.GetOrAdd(groupId, _ => new ConcurrentDictionary<string, byte[]>());

                // Make a copy of the key before storing it (to avoid any shared references)
                byte[] keyCopy = new byte[distribution.SenderKey.Length];
                distribution.SenderKey.AsSpan().CopyTo(keyCopy.AsSpan());

                groupDict[senderIdBase64] = keyCopy;

                return true;
            }
        }

        /// <summary>
        /// Adds an authorized member to a group
        /// </summary>
        /// <param name="groupId">Group identifier</param>
        /// <param name="memberPublicKey">Member's public key</param>
        /// <returns>True if the member was successfully authorized</returns>
        public bool AuthorizeMember(string groupId, byte[] memberPublicKey)
        {
            if (string.IsNullOrEmpty(groupId))
                throw new ArgumentException("Group ID cannot be null or empty", nameof(groupId));
            if (memberPublicKey == null || memberPublicKey.Length == 0)
                throw new ArgumentException("Member public key cannot be null or empty", nameof(memberPublicKey));

            // Check if we're an admin - only admins can authorize new members
            if (!_createdGroups.TryGetValue(groupId, out bool isAdmin) || !isAdmin)
            {
                return false; // Not an admin of this group
            }

            // Get authorized members dictionary
            var authorized = _authorizedMembers.GetOrAdd(groupId, _ => new ConcurrentDictionary<string, bool>());

            // Add the member
            string memberIdBase64 = Convert.ToBase64String(memberPublicKey);
            authorized[memberIdBase64] = true;

            return true;
        }

        /// <summary>
        /// Removes an authorized member from a group
        /// </summary>
        /// <param name="groupId">Group identifier</param>
        /// <param name="memberPublicKey">Member's public key</param>
        /// <returns>True if the member was successfully removed</returns>
        public bool RevokeMember(string groupId, byte[] memberPublicKey)
        {
            if (string.IsNullOrEmpty(groupId))
                throw new ArgumentException("Group ID cannot be null or empty", nameof(groupId));
            if (memberPublicKey == null || memberPublicKey.Length == 0)
                throw new ArgumentException("Member public key cannot be null or empty", nameof(memberPublicKey));

            // Check if we're an admin - only admins can revoke members
            if (!_createdGroups.TryGetValue(groupId, out bool isAdmin) || !isAdmin)
            {
                return false; // Not an admin of this group
            }

            // Get authorized members dictionary
            if (!_authorizedMembers.TryGetValue(groupId, out var authorized))
            {
                return false; // Group not found
            }

            // Remove the member
            string memberIdBase64 = Convert.ToBase64String(memberPublicKey);
            bool memberRemoved = authorized.TryRemove(memberIdBase64, out _);

            if (memberRemoved)
            {
                // Also remove their sender key
                if (_groupSenderKeys.TryGetValue(groupId, out var senderKeys))
                {
                    senderKeys.TryRemove(memberIdBase64, out _);
                }

                // Rotate the group epoch to ensure forward secrecy
                RotateGroupEpoch(groupId);

                return true;
            }

            return false;
        }

        /// <summary>
        /// Rotates the group epoch to ensure forward secrecy when members are removed
        /// </summary>
        /// <param name="groupId">Group identifier</param>
        /// <returns>The new epoch number</returns>
        public int RotateGroupEpoch(string groupId)
        {
            if (string.IsNullOrEmpty(groupId))
                throw new ArgumentException("Group ID cannot be null or empty", nameof(groupId));

            lock (GetGroupLock(groupId))
            {
                // Increment the epoch
                int newEpoch = _groupEpochs.AddOrUpdate(
                    groupId,
                    1, // Default if not exists
                    (_, oldEpoch) => oldEpoch + 1
                );

                // Generate new sender key for this epoch
                _myGroupSenderKeys[groupId] = KeyGenerator.GenerateSenderKey();

                return newEpoch;
            }
        }

        /// <summary>
        /// Records a processed message ID to prevent replay attacks
        /// </summary>
        /// <param name="groupId">Group identifier</param>
        /// <param name="messageId">Message ID</param>
        private void RecordProcessedMessageId(string groupId, string messageId)
        {
            if (string.IsNullOrEmpty(groupId) || string.IsNullOrEmpty(messageId))
                return;

            var messageIds = _processedMessageIds.GetOrAdd(groupId, _ =>
                new ConcurrentDictionary<string, long>());

            // Record with timestamp
            messageIds[messageId] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            // Cleanup old entries periodically
            if (messageIds.Count > 1000) // Arbitrary cleanup threshold
            {
                CleanupOldMessageIds(messageIds);
            }
        }

        /// <summary>
        /// Removes old message IDs from the tracking dictionary
        /// </summary>
        private void CleanupOldMessageIds(ConcurrentDictionary<string, long> messageIds)
        {
            // Define expiration time (e.g., 30 minutes)
            long expirationTimeMs = 30 * 60 * 1000;
            long currentTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            // Find old entries
            var oldEntries = messageIds.Where(pair => currentTime - pair.Value > expirationTimeMs)
                                      .Select(pair => pair.Key)
                                      .ToList();

            // Remove old entries
            foreach (var key in oldEntries)
            {
                messageIds.TryRemove(key, out _);
            }
        }

        /// <summary>
        /// Checks if a message ID has already been processed (replay detection)
        /// </summary>
        /// <param name="groupId">Group identifier</param>
        /// <param name="messageId">Message ID</param>
        /// <returns>True if message has been processed before</returns>
        private bool HasProcessedMessageId(string groupId, string messageId)
        {
            if (string.IsNullOrEmpty(groupId) || string.IsNullOrEmpty(messageId))
                return false;

            if (!_processedMessageIds.TryGetValue(groupId, out var messageIds))
                return false;

            return messageIds.ContainsKey(messageId);
        }

        /// <summary>
        /// Encrypts a message for a group with enhanced security
        /// </summary>
        /// <param name="groupId">Group identifier</param>
        /// <param name="message">Message to encrypt</param>
        /// <returns>Encrypted group message</returns>
        public EncryptedGroupMessage EncryptGroupMessage(string groupId, string message)
        {
            if (string.IsNullOrEmpty(groupId))
                throw new ArgumentException("Group ID cannot be null or empty", nameof(groupId));
            if (string.IsNullOrEmpty(message))
                throw new ArgumentException("Message cannot be null or empty", nameof(message));

            // Thread-safe read from ConcurrentDictionary
            if (!_myGroupSenderKeys.TryGetValue(groupId, out byte[]? senderKey))
            {
                throw new InvalidOperationException($"Group {groupId} not created yet");
            }

            // Create a deep copy of the sender key to avoid any thread issues
            byte[] senderKeyCopy = new byte[senderKey.Length];
            senderKey.AsSpan().CopyTo(senderKeyCopy.AsSpan());

            // Use a lock for the encryption process to maintain thread safety
            lock (_encryptionLock)
            {
                // Basic encryption
                EncryptedMessage encryptedMessage = GroupMessage.EncryptGroupMessage(message, senderKeyCopy);

                // Validate encrypted message contents
                ArgumentNullException.ThrowIfNull(encryptedMessage.Ciphertext, nameof(encryptedMessage.Ciphertext));
                ArgumentNullException.ThrowIfNull(encryptedMessage.Nonce, nameof(encryptedMessage.Nonce));

                // ENSURE we have a valid join timestamp before setting message timestamp
                if (!_joinTimestamps.TryGetValue(groupId, out long joinTime))
                {
                    // If we somehow don't have a join timestamp, set it now
                    joinTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                    _joinTimestamps[groupId] = joinTime;
                }

                // Set current timestamp
                long currentTimestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

                // Make sure the timestamps have some separation when close together
                if (currentTimestamp - joinTime < 10)
                {
                    currentTimestamp = joinTime + 10; // Ensure at least 10ms difference
                }

                // Generate a message ID for replay protection
                string messageId = Guid.NewGuid().ToString();

                // Get current epoch
                int currentEpoch = _groupEpochs.GetOrAdd(groupId, 1);

                // Create signature context (for extra verification)
                byte[] signatureData;
                using (var ms = new MemoryStream())
                {
                    ms.Write(encryptedMessage.Ciphertext, 0, encryptedMessage.Ciphertext.Length);
                    ms.Write(encryptedMessage.Nonce, 0, encryptedMessage.Nonce.Length);
                    ms.Write(Encoding.UTF8.GetBytes(messageId), 0, Encoding.UTF8.GetBytes(messageId).Length);
                    ms.Write(BitConverter.GetBytes(currentTimestamp), 0, 8);
                    ms.Write(BitConverter.GetBytes(currentEpoch), 0, 4);
                    ms.Write(Encoding.UTF8.GetBytes(groupId), 0, Encoding.UTF8.GetBytes(groupId).Length);
                    signatureData = ms.ToArray();
                }

                // Sign the message with our identity key
                byte[] signature = MessageSigning.SignMessage(signatureData, _identityKeyPair.privateKey);

                // Pack extra security properties into the message ID field
                // Format: [Original Message ID]|[Epoch]|[Signature Base64]
                string enhancedMessageId = $"{messageId}|{currentEpoch}|{Convert.ToBase64String(signature)}";

                // Record this message ID to prevent replay of our own messages
                RecordProcessedMessageId(groupId, messageId);

                return new EncryptedGroupMessage
                {
                    GroupId = groupId,
                    SenderIdentityKey = _identityKeyPair.publicKey,
                    Ciphertext = encryptedMessage.Ciphertext,
                    Nonce = encryptedMessage.Nonce,
                    Timestamp = currentTimestamp,
                    MessageId = enhancedMessageId
                };
            }
        }

        /// <summary>
        /// Extracts enhanced security data from a message ID field
        /// </summary>
        private (string originalMessageId, int epoch, byte[] signature) ExtractMessageProperties(string messageId)
        {
            string originalMessageId = messageId;
            int epoch = 1;
            byte[] signature = Array.Empty<byte>();

            // Try to parse enhanced format
            if (!string.IsNullOrEmpty(messageId) && messageId.Contains('|'))
            {
                string[] parts = messageId.Split('|');
                if (parts.Length >= 3)
                {
                    originalMessageId = parts[0];

                    // Parse epoch
                    if (int.TryParse(parts[1], out int parsedEpoch))
                    {
                        epoch = parsedEpoch;
                    }

                    // Parse signature
                    try
                    {
                        signature = Convert.FromBase64String(parts[2]);
                    }
                    catch
                    {
                        // Ignore parse errors
                    }
                }
            }

            return (originalMessageId, epoch, signature);
        }

        /// <summary>
        /// Decrypts a group message with enhanced security validations
        /// </summary>
        /// <param name="encryptedMessage">Encrypted group message</param>
        /// <returns>Decrypted message if successful, null otherwise</returns>
        public string? DecryptGroupMessage(EncryptedGroupMessage encryptedMessage)
        {
            if (encryptedMessage == null)
                throw new ArgumentNullException(nameof(encryptedMessage));

            if (encryptedMessage.GroupId == null)
                throw new ArgumentNullException(nameof(encryptedMessage.GroupId));
            if (encryptedMessage.SenderIdentityKey == null)
                throw new ArgumentNullException(nameof(encryptedMessage.SenderIdentityKey));
            if (encryptedMessage.Ciphertext == null)
                throw new ArgumentNullException(nameof(encryptedMessage.Ciphertext));
            if (encryptedMessage.Nonce == null)
                throw new ArgumentNullException(nameof(encryptedMessage.Nonce));

            string groupId = encryptedMessage.GroupId;
            string senderId = Convert.ToBase64String(encryptedMessage.SenderIdentityKey);

            // Check if we've joined this group
            if (!_joinTimestamps.TryGetValue(groupId, out var joinTimestamp))
            {
                return null; // We haven't joined this group
            }

            // IMPORTANT: Forward secrecy check - reject messages sent before joining
            // Only do this if both timestamps are valid (greater than zero)
            if (encryptedMessage.Timestamp > 0 && joinTimestamp > 0 && encryptedMessage.Timestamp < joinTimestamp)
            {
                // Message was sent before we joined - reject it to maintain forward secrecy
                return null;
            }

            // Generate a unique message identifier for replay protection
            string messageIdentifier = GetMessageIdentifier(encryptedMessage);

            // Check for replay attacks using the full message context
            if (!string.IsNullOrEmpty(messageIdentifier) && HasProcessedMessageId(groupId, messageIdentifier))
            {
                return null; // Message was already processed - possible replay attack
            }

            // Extract security properties from messageId
            var (originalMessageId, messageEpoch, signature) =
                ExtractMessageProperties(encryptedMessage.MessageId ?? string.Empty);

            // Validate timestamp to prevent replay attacks
            long currentTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            if (Math.Abs(currentTime - encryptedMessage.Timestamp) > Constants.MAX_MESSAGE_AGE_MS)
            {
                // Message is too old or from future - possible replay attack
                return null;
            }

            // Verify sender is authorized if we're maintaining an ACL
            if (_authorizedMembers.TryGetValue(groupId, out var authorizedMembers))
            {
                // If sender isn't in the authorized members list, reject the message
                if (!authorizedMembers.ContainsKey(senderId))
                {
                    // Log potential unauthorized message attempt
                    Console.WriteLine($"Rejecting message from unauthorized sender: {senderId}");
                    return null;
                }
            }

            // Verify signature if available
            if (signature.Length > 0)
            {
                // Recreate signature context for verification
                byte[] signatureData;
                using (var ms = new MemoryStream())
                {
                    ms.Write(encryptedMessage.Ciphertext, 0, encryptedMessage.Ciphertext.Length);
                    ms.Write(encryptedMessage.Nonce, 0, encryptedMessage.Nonce.Length);
                    ms.Write(Encoding.UTF8.GetBytes(originalMessageId), 0, Encoding.UTF8.GetBytes(originalMessageId).Length);
                    ms.Write(BitConverter.GetBytes(encryptedMessage.Timestamp), 0, 8);
                    ms.Write(BitConverter.GetBytes(messageEpoch), 0, 4);
                    ms.Write(Encoding.UTF8.GetBytes(groupId), 0, Encoding.UTF8.GetBytes(groupId).Length);
                    signatureData = ms.ToArray();
                }

                // Verify the signature
                bool validSignature = MessageSigning.VerifySignature(
                    signatureData,
                    signature,
                    encryptedMessage.SenderIdentityKey);

                if (!validSignature)
                {
                    // Signature verification failed
                    return null;
                }
            }

            // Verify the epoch is valid
            int currentEpoch = _groupEpochs.GetOrAdd(groupId, 1);
            if (messageEpoch < currentEpoch)
            {
                // Message from an old epoch - reject for forward secrecy
                // This prevents decrypting messages after a member has been removed
                return null;
            }

            byte[]? senderKey = null;

            // Thread-safe reads from ConcurrentDictionary
            if (_groupSenderKeys.TryGetValue(groupId, out var senderKeys))
            {
                // If you're decrypting your own message, use your sender key - use constant time comparison
                bool isOwnMessage = SecureMemory.SecureCompare(
                    encryptedMessage.SenderIdentityKey,
                    _identityKeyPair.publicKey);

                if (isOwnMessage && _myGroupSenderKeys.TryGetValue(groupId, out var mySenderKey))
                {
                    senderKey = mySenderKey;
                }
                else if (senderKeys.TryGetValue(senderId, out var otherSenderKey))
                {
                    senderKey = otherSenderKey;
                }
            }

            if (senderKey == null)
            {
                return null;
            }

            // Create a deep copy of the sender key to avoid thread issues
            byte[] senderKeyCopy = new byte[senderKey.Length];
            senderKey.AsSpan().CopyTo(senderKeyCopy.AsSpan());

            // Create the parameters for decryption
            var message = new EncryptedMessage
            {
                Ciphertext = encryptedMessage.Ciphertext,
                Nonce = encryptedMessage.Nonce
            };

            try
            {
                // Thread safety for decryption
                lock (_encryptionLock)
                {
                    string? decryptedMessage = GroupMessage.DecryptGroupMessage(message, senderKeyCopy);

                    // Only record message as processed if decryption succeeded
                    if (decryptedMessage != null && !string.IsNullOrEmpty(messageIdentifier))
                    {
                        // Record this message context to prevent replays
                        RecordProcessedMessageId(groupId, messageIdentifier);
                    }

                    return decryptedMessage;
                }
            }
            catch (Exception ex)
            {
                // Log the exception but don't expose details
                Console.WriteLine($"Error decrypting group message: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Creates a unique message identifier from the full message context for replay protection
        /// </summary>
        private string GetMessageIdentifier(EncryptedGroupMessage message)
        {
            if (message == null || message.Ciphertext == null || message.Nonce == null)
                return string.Empty;

            // Create a unique identifier combining group, sender, ciphertext, and nonce
            using (var sha = System.Security.Cryptography.SHA256.Create())
            {
                using (var ms = new MemoryStream())
                {
                    // Write group ID
                    if (!string.IsNullOrEmpty(message.GroupId))
                    {
                        byte[] groupIdBytes = Encoding.UTF8.GetBytes(message.GroupId);
                        ms.Write(groupIdBytes, 0, groupIdBytes.Length);
                    }

                    // Write sender identity key
                    if (message.SenderIdentityKey != null)
                    {
                        ms.Write(message.SenderIdentityKey, 0, message.SenderIdentityKey.Length);
                    }

                    // Write ciphertext
                    ms.Write(message.Ciphertext, 0, message.Ciphertext.Length);

                    // Write nonce
                    ms.Write(message.Nonce, 0, message.Nonce.Length);

                    // Hash the combined data to create a unique identifier
                    return Convert.ToBase64String(sha.ComputeHash(ms.ToArray()));
                }
            }
        }

        /// <summary>
        /// Checks if user is a member of a group
        /// </summary>
        /// <param name="groupId">Group identifier</param>
        /// <returns>True if the user is a member of the group</returns>
        public bool IsMemberOfGroup(string groupId)
        {
            if (string.IsNullOrEmpty(groupId))
                return false;

            return _joinTimestamps.ContainsKey(groupId);
        }

        /// <summary>
        /// Checks if the current user is an admin of the group
        /// </summary>
        /// <param name="groupId">Group identifier</param>
        /// <returns>True if the user is a group admin</returns>
        public bool IsGroupAdmin(string groupId)
        {
            if (string.IsNullOrEmpty(groupId))
                return false;

            return _createdGroups.TryGetValue(groupId, out bool isAdmin) && isAdmin;
        }

        /// <summary>
        /// Gets a list of all group members
        /// </summary>
        /// <param name="groupId">Group identifier</param>
        /// <returns>List of member public keys</returns>
        public List<byte[]> GetGroupMembers(string groupId)
        {
            if (string.IsNullOrEmpty(groupId))
                throw new ArgumentException("Group ID cannot be null or empty", nameof(groupId));

            var members = new List<byte[]>();

            // Add ourselves if we're a member
            if (_joinTimestamps.ContainsKey(groupId))
            {
                members.Add(_identityKeyPair.publicKey);
            }

            // Add other members from authorized list
            if (_authorizedMembers.TryGetValue(groupId, out var authorizedMembers))
            {
                foreach (var memberId in authorizedMembers.Keys)
                {
                    try
                    {
                        // Convert from Base64 ID back to byte[]
                        byte[] memberKey = Convert.FromBase64String(memberId);

                        // Skip our own key (already added)
                        if (!SecureMemory.SecureCompare(memberKey, _identityKeyPair.publicKey))
                        {
                            members.Add(memberKey);
                        }
                    }
                    catch
                    {
                        // Skip invalid member IDs
                    }
                }
            }

            return members;
        }

        /// <summary>
        /// Leaves a group, cleaning up all associated resources
        /// </summary>
        /// <param name="groupId">Group identifier</param>
        /// <returns>True if the group was successfully left</returns>
        public bool LeaveGroup(string groupId)
        {
            if (string.IsNullOrEmpty(groupId))
                throw new ArgumentException("Group ID cannot be null or empty", nameof(groupId));

            // Remove our sender key
            _myGroupSenderKeys.TryRemove(groupId, out _);

            // Remove our join timestamp
            _joinTimestamps.TryRemove(groupId, out _);

            // If we were an admin, relinquish that status
            _createdGroups.TryRemove(groupId, out _);

            // Remove ourselves from the authorized members list
            if (_authorizedMembers.TryGetValue(groupId, out var authorizedMembers))
            {
                string myIdBase64 = Convert.ToBase64String(_identityKeyPair.publicKey);
                authorizedMembers.TryRemove(myIdBase64, out _);
            }

            return true;
        }

        /// <summary>
        /// Gets a list of all groups the user is a member of
        /// </summary>
        /// <returns>List of group IDs</returns>
        public List<string> GetJoinedGroups()
        {
            return _joinTimestamps.Keys.ToList();
        }
    }
}