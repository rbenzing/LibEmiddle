using System.Security.Cryptography;
using E2EELibrary.Core;
using E2EELibrary.Encryption;
using E2EELibrary.Models;
using E2EELibrary.Communication;

namespace E2EELibrary.GroupMessaging
{
    /// <summary>
    /// Handles encryption and decryption of group messages
    /// </summary>
    public class GroupMessageCrypto
    {
        // Track counters for each group to prevent replay attacks
        private readonly Dictionary<string, long> _messageCounters = new Dictionary<string, long>();

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
            // For simplicity, we just check the timestamp
            // In a production system, you would maintain a set of recently received message IDs

            // Reject messages older than 5 minutes
            long currentTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            long fiveMinutesAgo = currentTime - (5 * 60 * 1000);

            return message.Timestamp < fiveMinutesAgo;
        }

        /// <summary>
        /// Encrypts a file for a group
        /// </summary>
        /// <param name="groupId">Group identifier</param>
        /// <param name="fileData">File data to encrypt</param>
        /// <param name="senderKey">Sender key for this group</param>
        /// <param name="identityKeyPair">Sender's identity key pair for signing</param>
        /// <returns>Encrypted file message</returns>
        public EncryptedGroupMessage EncryptFile(string groupId, byte[] fileData, byte[] senderKey,
            (byte[] publicKey, byte[] privateKey) identityKeyPair)
        {
            ArgumentNullException.ThrowIfNull(groupId, nameof(groupId));
            ArgumentNullException.ThrowIfNull(fileData, nameof(fileData));
            ArgumentNullException.ThrowIfNull(senderKey, nameof(senderKey));

            // Generate a random nonce
            byte[] nonce = NonceGenerator.GenerateNonce();

            // Encrypt the file data
            byte[] ciphertext = AES.AESEncrypt(fileData, senderKey, nonce);

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
        /// Decrypts a file from an encrypted group message
        /// </summary>
        /// <param name="encryptedMessage">Encrypted file message</param>
        /// <param name="senderKey">Sender key for the group</param>
        /// <returns>Decrypted file data, or null if decryption fails</returns>
        public byte[]? DecryptFile(EncryptedGroupMessage encryptedMessage, byte[] senderKey)
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

                // Decrypt the file data
                return AES.AESDecrypt(encryptedMessage.Ciphertext, senderKey, encryptedMessage.Nonce);
            }
            catch (CryptographicException)
            {
                // Decryption failed
                return null;
            }
        }

        /// <summary>
        /// Signs a message for authenticity verification
        /// </summary>
        /// <param name="message">Message to sign</param>
        /// <param name="privateKey">Private key for signing</param>
        /// <returns>Signature bytes</returns>
        public byte[] SignMessage(byte[] message, byte[] privateKey)
        {
            return MessageSigning.SignMessage(message, privateKey);
        }

        /// <summary>
        /// Verifies the signature of a message
        /// </summary>
        /// <param name="message">Original message</param>
        /// <param name="signature">Signature to verify</param>
        /// <param name="publicKey">Public key of the signer</param>
        /// <returns>True if signature is valid</returns>
        public bool VerifySignature(byte[] message, byte[] signature, byte[] publicKey)
        {
            return MessageSigning.VerifySignature(message, signature, publicKey);
        }
    }
}