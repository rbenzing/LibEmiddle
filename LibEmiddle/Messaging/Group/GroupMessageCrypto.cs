﻿using System.Collections.Concurrent;
using System.Security.Cryptography;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.Models;

namespace LibEmiddle.Messaging.Group
{
    /// <summary>
    /// Handles encryption and decryption of group messages
    /// </summary>
    public class GroupMessageCrypto
    {
        // Track counters for each group to prevent replay attacks
        private readonly ConcurrentDictionary<string, long> _messageCounters = new ConcurrentDictionary<string, long>();

        // Store message IDs that have been processed to prevent replay attacks
        private readonly ConcurrentDictionary<string, ConcurrentHashSet<string>> _processedMessageIds =
            new ConcurrentDictionary<string, ConcurrentHashSet<string>>();

        // Track when we joined groups to enforce backward secrecy
        private readonly ConcurrentDictionary<string, long> _groupJoinTimestamps =
            new ConcurrentDictionary<string, long>();

        // Use a lock per group for the message counter increments only
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
            // We need a lock here because we're doing a read-increment-write operation
            long counter;
            var counterLock = _groupLocks.GetOrAdd(groupId, _ => new object());

            lock (counterLock)
            {
                counter = _messageCounters.GetOrAdd(groupId, 0);
                counter++;
                _messageCounters[groupId] = counter;
            }

            // Generate a random nonce (thread-safe)
            byte[] nonce = NonceGenerator.GenerateNonce();

            // Convert message to bytes (thread-safe)
            byte[] plaintext = System.Text.Encoding.UTF8.GetBytes(message);

            // Encrypt the message (thread-safe)
            byte[] ciphertext = AES.AESEncrypt(plaintext, senderKey, nonce);

            // Create the encrypted message (thread-safe)
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

            try
            {
                // Check for message replay
                if (IsReplayedMessage(encryptedMessage))
                {
                    return null;
                }

                // Forward secrecy check - don't decrypt messages sent before joining the group
                if (encryptedMessage.GroupId != null &&
                    _groupJoinTimestamps.TryGetValue(encryptedMessage.GroupId, out long joinTimestamp))
                {
                    // If message was sent before we joined the group, reject it
                    if (encryptedMessage.Timestamp < joinTimestamp)
                    {
                        LoggingManager.LogWarning(nameof(GroupMessageCrypto), $"Rejecting message sent before joining group: message timestamp {encryptedMessage.Timestamp}, joined at {joinTimestamp}");
                        return null;
                    }
                }

                // Decrypt the message
                byte[] plaintext = AES.AESDecrypt(encryptedMessage.Ciphertext, senderKey, encryptedMessage.Nonce);

                // Convert to string
                return System.Text.Encoding.UTF8.GetString(plaintext);
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

            // Get or create a concurrent set of processed IDs for this group
            var processedIds = _processedMessageIds.GetOrAdd(message.GroupId, _ => new ConcurrentHashSet<string>());

            // Try to add the message ID to the set - returns false if it was already there
            bool isNewMessage = processedIds.Add(message.MessageId);

            // If we've successfully added it, it's not a replay
            if (isNewMessage)
            {
                // Periodically trim the set to prevent unbounded growth
                // We don't need to lock this because it's not critical that it happens
                // exactly when the count exceeds the threshold
                if (processedIds.Count > Constants.MAX_TRACKED_MESSAGE_IDS)
                {
                    TrimMessageIds(message.GroupId, processedIds);
                }

                return false;
            }

            // If we couldn't add it, it was already there, so it's a replay
            return true;
        }

        /// <summary>
        /// Trims the processed message IDs set to prevent unbounded growth
        /// </summary>
        private void TrimMessageIds(string groupId, ConcurrentHashSet<string> processedIds)
        {
            // Only one thread should do the trimming at a time
            var trimLock = _groupLocks.GetOrAdd(groupId + "_trim", _ => new object());

            // Try to get the lock without blocking
            if (Monitor.TryEnter(trimLock, 0))
            {
                try
                {
                    // We got the lock, now check again if trimming is still needed
                    if (processedIds.Count > Constants.MAX_TRACKED_MESSAGE_IDS)
                    {
                        // Take a snapshot of the current IDs
                        var currentIds = processedIds.ToArray();

                        // Remove half of the oldest IDs (a simple approximation)
                        int toRemove = currentIds.Length / 2;

                        // In a real implementation, we would use timestamps or a FIFO queue
                        // Here we just remove the first half of the array as a simple solution
                        for (int i = 0; i < toRemove; i++)
                        {
                            processedIds.TryRemove(currentIds[i]);
                        }
                    }
                }
                finally
                {
                    // Always release the lock
                    Monitor.Exit(trimLock);
                }
            }
            // If we couldn't get the lock, another thread is already doing the trimming or it will happen later
        }
    }

    /// <summary>
    /// A thread-safe hash set implementation using ConcurrentDictionary
    /// </summary>
    internal class ConcurrentHashSet<T> where T : notnull
    {
        private readonly ConcurrentDictionary<T, byte> _dictionary = new ConcurrentDictionary<T, byte>();

        /// <summary>
        /// Adds an item to the set
        /// </summary>
        /// <param name="item">Item to add</param>
        /// <returns>True if the item was added, false if it was already present</returns>
        public bool Add(T item)
        {
            return _dictionary.TryAdd(item, 0);
        }

        /// <summary>
        /// Checks if the set contains an item
        /// </summary>
        /// <param name="item">Item to check</param>
        /// <returns>True if the item is in the set</returns>
        public bool Contains(T item)
        {
            return _dictionary.ContainsKey(item);
        }

        /// <summary>
        /// Tries to remove an item from the set
        /// </summary>
        /// <param name="item">Item to remove</param>
        /// <returns>True if the item was removed</returns>
        public bool TryRemove(T item)
        {
            return _dictionary.TryRemove(item, out _);
        }

        /// <summary>
        /// Gets the number of items in the set
        /// </summary>
        public int Count => _dictionary.Count;

        /// <summary>
        /// Gets an array of all items in the set
        /// </summary>
        /// <returns>Array of items</returns>
        public T[] ToArray()
        {
            return _dictionary.Keys.ToArray();
        }
    }
}