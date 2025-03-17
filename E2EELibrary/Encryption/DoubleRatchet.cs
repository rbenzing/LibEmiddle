﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using E2EELibrary.Core;
using E2EELibrary.KeyExchange;
using E2EELibrary.KeyManagement;
using E2EELibrary.Models;

namespace E2EELibrary.Encryption
{
    public static class DoubleRatchet
    {
        /// <summary>
        /// Encrypts a message using the Double Ratchet algorithm
        /// </summary>
        /// <param name="session">Current Double Ratchet session</param>
        /// <param name="message">Message to encrypt</param>
        /// <returns>Updated session and encrypted message</returns>
        public static (DoubleRatchetSession updatedSession, EncryptedMessage encryptedMessage)
            DoubleRatchetEncrypt(DoubleRatchetSession session, string message)
        {
            if (session == null)
                throw new ArgumentNullException(nameof(session));
            if (string.IsNullOrEmpty(message))
                throw new ArgumentException("Message cannot be null or empty", nameof(message));
            if (session.SendingChainKey == null || session.SendingChainKey.Length != Constants.AES_KEY_SIZE)
                throw new ArgumentException("Invalid sending chain key in session", nameof(session));

            try
            {
                // Get next message key and update chain key
                var (newChainKey, messageKey) = DoubleRatchetExchange.RatchetStep(session.SendingChainKey);

                // Encrypt message
                byte[] plaintext = Encoding.UTF8.GetBytes(message);
                byte[] nonce = NonceGenerator.GenerateNonce();
                byte[] ciphertext = AES.AESEncrypt(plaintext, messageKey, nonce);

                // Create encrypted message object
                var encryptedMessage = new EncryptedMessage
                {
                    Ciphertext = ciphertext,
                    Nonce = nonce,
                    MessageNumber = session.MessageNumber,
                    SenderDHKey = session.DHRatchetKeyPair.publicKey,
                    Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    MessageId = Guid.NewGuid(),
                    SessionId = session.SessionId
                };

                // Create updated session with new chain key and incremented message number
                // Using the immutable pattern
                var updatedSession = session.WithUpdatedParameters(
                    newSendingChainKey: newChainKey,
                    newMessageNumber: session.MessageNumber + 1
                );

                // Securely clear the message key when done
                SecureMemory.SecureClear(messageKey);

                return (updatedSession, encryptedMessage);
            }
            catch (Exception ex)
            {
                throw new CryptographicException("Failed to encrypt message with Double Ratchet", ex);
            }
        }

        /// <summary>
        /// Decrypts a message using the Double Ratchet algorithm with enhanced security and defensive programming
        /// </summary>
        /// <param name="session">Current Double Ratchet session</param>
        /// <param name="encryptedMessage">Encrypted message</param>
        /// <returns>Updated session and decrypted message, or null values if decryption fails</returns>
        public static (DoubleRatchetSession? updatedSession, string? decryptedMessage)
    DoubleRatchetDecrypt(DoubleRatchetSession session, EncryptedMessage encryptedMessage)
        {
            // Basic parameter validation
            if (session == null)
                throw new ArgumentNullException(nameof(session));
            if (encryptedMessage == null)
                throw new ArgumentNullException(nameof(encryptedMessage));
            if (encryptedMessage.Ciphertext == null || encryptedMessage.Nonce == null || encryptedMessage.SenderDHKey == null)
                throw new ArgumentException("Message is missing required fields");

            try
            {
                // Validate session ID
                if (string.IsNullOrEmpty(encryptedMessage.SessionId))
                    return (null, null);
                if (session.SessionId != encryptedMessage.SessionId)
                    return (null, null);

                // Check for replay
                if (session.HasProcessedMessageId(encryptedMessage.MessageId))
                    return (null, null);

                // Validate timestamp
                long currentTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                if (Math.Abs(currentTime - encryptedMessage.Timestamp) > 5 * 60 * 1000)
                    return (null, null);

                // Derive the message key
                byte[] messageKey;
                DoubleRatchetSession updatedSession = session;

                // Check if we need to perform a DH ratchet step
                bool dhRatchetNeeded = !SecureMemory.SecureCompare(encryptedMessage.SenderDHKey, session.RemoteDHRatchetKey);

                if (dhRatchetNeeded)
                {
                    // Perform DH ratchet step
                    byte[] dhOutput = X3DHExchange.X3DHKeyExchange(
                        encryptedMessage.SenderDHKey, session.DHRatchetKeyPair.privateKey);

                    var (newRootKey, newChainKey) = DoubleRatchetExchange.DHRatchetStep(
                        session.RootKey, dhOutput);

                    // Generate new key pair for next ratchet
                    var newKeyPair = KeyGenerator.GenerateX25519KeyPair();

                    // Update session with new keys
                    updatedSession = new DoubleRatchetSession(
                        dhRatchetKeyPair: newKeyPair,
                        remoteDHRatchetKey: encryptedMessage.SenderDHKey,
                        rootKey: newRootKey,
                        sendingChainKey: session.SendingChainKey,
                        receivingChainKey: newChainKey,
                        messageNumber: session.MessageNumber,
                        sessionId: session.SessionId,
                        recentlyProcessedIds: session.RecentlyProcessedIds
                    );

                    // Derive message key from new chain
                    var (updatedChainKey, derivedMessageKey) = DoubleRatchetExchange.RatchetStep(newChainKey);
                    messageKey = derivedMessageKey;

                    // Update the receiving chain key
                    updatedSession = updatedSession.WithUpdatedParameters(
                        newReceivingChainKey: updatedChainKey
                    );
                }
                else
                {
                    // Standard chain key ratchet
                    var (updatedChainKey, derivedMessageKey) = DoubleRatchetExchange.RatchetStep(
                        session.ReceivingChainKey);
                    messageKey = derivedMessageKey;

                    // Update the receiving chain key
                    updatedSession = updatedSession.WithUpdatedParameters(
                        newReceivingChainKey: updatedChainKey
                    );
                }

                // Decrypt the message
                try
                {
                    byte[] plaintext = AES.AESDecrypt(
                        encryptedMessage.Ciphertext, messageKey, encryptedMessage.Nonce);

                    // Convert to string
                    string decryptedMessage = Encoding.UTF8.GetString(plaintext);

                    // Update the session with processed message ID
                    updatedSession = updatedSession.WithProcessedMessageId(encryptedMessage.MessageId);

                    return (updatedSession, decryptedMessage);
                }
                catch
                {
                    // Decryption failed
                    return (null, null);
                }
                finally
                {
                    // Clean up sensitive data
                    if (messageKey != null)
                        SecureMemory.SecureClear(messageKey);
                }
            }
            catch (Exception)
            {
                // Any other exception
                return (null, null);
            }
        }
    }
}
