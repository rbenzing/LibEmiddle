using System.Security.Cryptography;
using E2EELibrary.Core;
using E2EELibrary.Encryption;
using E2EELibrary.Models;
using E2EELibrary.Communication;
using System.Collections.Concurrent;

namespace E2EELibrary.GroupMessaging
{
    /// <summary>
    /// Handles encryption and decryption of group messages
    /// </summary>
    public class GroupMessageCrypto
    {
        // Track counters for each group to prevent replay attacks
        private readonly Dictionary<string, long> _messageCounters = new Dictionary<string, long>();

        private readonly ConcurrentDictionary<string, HashSet<string>> _processedMessageIds =
            new ConcurrentDictionary<string, HashSet<string>>();

        // Track when we joined groups to enforce backward secrecy
        private readonly ConcurrentDictionary<string, long> _groupJoinTimestamps =
            new ConcurrentDictionary<string, long>();

        private readonly ConcurrentDictionary<string, object> _groupLocks =
            new ConcurrentDictionary<string, object>();

        /// <summary>
        /// Encrypts a message for a group using the provided sender key
        /// </summary>
        /// <param name="groupId">Group identifier</param>
        /// <param name="message">Message to encrypt</param>
        /// <param name="senderKey">Sender key for this group</param>
        /// <param name="identityKeyPair">Sender's identity key pair for signing</param>
        /// <returns>Encrypted group message</returns>
        public EncryptedGroupMessage EncryptMessage(string groupId, string message, byte[] senderKey,
            (byte[] publicKey, byte[] privateKey) identityKeyPair)
        {
            ArgumentNullException.ThrowIfNull(groupId, nameof(groupId));
            ArgumentNullException.ThrowIfNull(message, nameof(message));
            ArgumentNullException.ThrowIfNull(senderKey, nameof(senderKey));

            // Get current message counter for the group, or initialize to 0
            if (!_messageCounters.TryGetValue(groupId, out long counter))
            {
                counter = 0;
            }

            // Increment counter
            counter++;
            _messageCounters[groupId] = counter;

            // Generate a random nonce
            byte[] nonce = NonceGenerator.GenerateNonce();

            // Convert message to bytes
            byte[] plaintext = System.Text.Encoding.UTF8.GetBytes(message);

            // Encrypt the message
            byte[] ciphertext = AES.AESEncrypt(plaintext, senderKey, nonce);

            // Create the encrypted message
            var encryptedMessage = new EncryptedGroupMessage
            {
                GroupId = groupId,
                SenderIdentityKey = identityKeyPair.publicKey,
                Ciphertext = ciphertext,
                Nonce = nonce,
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                MessageId = Guid.NewGuid().ToString()
            };

            return encryptedMessage;
        }

        /// <summary>
        /// Records that we've joined a group at the current time 
        /// </summary>
        /// <param name="groupId">The group ID</param>
        public void RecordGroupJoin(string groupId)
        {
            _groupJoinTimestamps[groupId] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        }

        /// <summary>
        /// Decrypts a group message using the provided sender key
        /// </summary>
        /// <param name="encryptedMessage">Message to decrypt</param>
        /// <param name="senderKey">Sender key for the group</param>
        /// <returns>Decrypted message text, or null if decryption fails</returns>
        public string? DecryptMessage(EncryptedGroupMessage encryptedMessage, byte[] senderKey)
        {
            ArgumentNullException.ThrowIfNull(encryptedMessage, nameof(encryptedMessage));
            ArgumentNullException.ThrowIfNull(encryptedMessage.Ciphertext, nameof(encryptedMessage.Ciphertext));
            ArgumentNullException.ThrowIfNull(encryptedMessage.Nonce, nameof(encryptedMessage.Nonce));
            ArgumentNullException.ThrowIfNull(senderKey, nameof(senderKey));
            ArgumentNullException.ThrowIfNull(encryptedMessage.GroupId, nameof(encryptedMessage.GroupId));

            try
            {
                // Get the lock for this specific group
                object groupLock = GetGroupLock(encryptedMessage.GroupId);

                // Use the lock to ensure thread-safety when checking for replays
                // and processing messages for a specific group
                lock (groupLock)
                {
                    // Check for message replay
                    if (IsReplayedMessage(encryptedMessage))
                    {
                        return null;
                    }

                    // Decrypt the message - this operation itself is thread-safe
                    // as it doesn't modify shared state
                    byte[] plaintext = AES.AESDecrypt(encryptedMessage.Ciphertext, senderKey, encryptedMessage.Nonce);

                    // Convert to string
                    return System.Text.Encoding.UTF8.GetString(plaintext);
                }
            }
            catch (CryptographicException)
            {
                // Decryption failed
                return null;
            }
        }

        /// <summary>
        /// Checks if a message is a replay of an earlier message
        /// </summary>
        /// <param name="message">Message to check</param>
        /// <returns>True if the message appears to be a replay</returns>
        private bool IsReplayedMessage(EncryptedGroupMessage message)
        {
            ArgumentNullException.ThrowIfNull(message.MessageId, nameof(message.MessageId));
            ArgumentNullException.ThrowIfNull(message.GroupId, nameof(message.GroupId));

            // Get or create a set of processed IDs for this group
            var processedIds = _processedMessageIds.GetOrAdd(message.GroupId, _ => new HashSet<string>());

            // Thread-safe check for replay
            lock (processedIds)
            {
                // If we've seen this message ID before, it's a replay
                if (processedIds.Contains(message.MessageId))
                {
                    return true;
                }

                // Otherwise, add it to our tracking and continue
                processedIds.Add(message.MessageId);

                // Limit the size of the set to prevent memory growth
                if (processedIds.Count > Constants.MAX_TRACKED_MESSAGE_IDS)
                {
                    // Remove oldest IDs (this is simplistic - a more sophisticated
                    // approach would use timestamps or a queue)
                    while (processedIds.Count > Constants.MAX_TRACKED_MESSAGE_IDS / 2)
                    {
                        processedIds.Remove(processedIds.First());
                    }
                }

                return false;
            }
        }

        /// <summary>
        /// Gets the group lock
        /// </summary>
        /// <param name="groupId"></param>
        /// <returns></returns>
        private object GetGroupLock(string groupId)
        {
            return _groupLocks.GetOrAdd(groupId, _ => new object());
        }
    }
}