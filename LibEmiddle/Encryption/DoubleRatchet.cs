using System.Collections.Concurrent;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using E2EELibrary.Core;
using E2EELibrary.KeyExchange;
using E2EELibrary.KeyManagement;
using E2EELibrary.Models;
using static E2EELibrary.Core.Enums;

namespace E2EELibrary.Encryption
{
    /// <summary>
    /// Provides encryption and decryption using the Double Ratchet algorithm with forward secrecy and DH ratcheting.
    /// </summary>
    public static class DoubleRatchet
    {
        private static readonly ConcurrentDictionary<string, SemaphoreSlim> _sessionLocks = new();
        private static readonly ConcurrentDictionary<string, long> _lockLastUsed = new();

        /// <summary>
        /// Encrypts a message using the Double Ratchet algorithm.
        /// </summary>
        /// <param name="session">The current session state.</param>
        /// <param name="message">Plaintext message to encrypt.</param>
        /// <param name="rotationStrategy">Key rotation policy.</param>
        /// <returns>Updated session and encrypted message.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="CryptographicException"></exception>
        public static (DoubleRatchetSession updatedSession, EncryptedMessage encryptedMessage)
            DoubleRatchetEncrypt(DoubleRatchetSession session, string message, KeyRotationStrategy rotationStrategy = KeyRotationStrategy.Standard)
        {
            ArgumentNullException.ThrowIfNull(session);
            if (string.IsNullOrEmpty(message))
                throw new ArgumentException("Message cannot be null or empty", nameof(message));
            if (session.SendingChainKey == null || session.SendingChainKey.Length != Constants.AES_KEY_SIZE)
                throw new ArgumentException("Invalid sending chain key in session", nameof(session));

            try
            {
                // Get next message key and update chain key
                var (newChainKey, messageKey) = DoubleRatchetExchange.RatchetStep(session.SendingChainKey, session.SessionId, rotationStrategy);

                using var secureMessageKey = new SecureMemory.SecureArray<byte>(messageKey);

                // Encrypt message
                byte[] plaintext = Encoding.UTF8.GetBytes(message);
                byte[] nonce = NonceGenerator.GenerateNonce();
                byte[] ciphertext = AES.AESEncrypt(plaintext, secureMessageKey.Value, nonce);

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
        /// Asynchronously encrypts a message using the Double Ratchet algorithm with session locking.
        /// </summary>
        /// <param name="session">Current Double Ratchet session</param>
        /// <param name="message">Message to encrypt</param>
        /// <param name="rotationStrategy">The key rotation strategy to use.</param>
        /// <returns>Updated session and encrypted message</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentException"></exception>
        public static async Task<(DoubleRatchetSession updatedSession, EncryptedMessage encryptedMessage)>
            DoubleRatchetEncryptAsync(DoubleRatchetSession session, string message, KeyRotationStrategy rotationStrategy = KeyRotationStrategy.Standard)
        {
            ArgumentNullException.ThrowIfNull(session);
            if (string.IsNullOrEmpty(message))
                throw new ArgumentException("Message cannot be null or empty", nameof(message));
            var sessionLock = GetSessionLock(session.SessionId);

            try
            {
                await sessionLock.WaitAsync();
                // Use the existing synchronous implementation
                return DoubleRatchetEncrypt(session, message, rotationStrategy);
            }
            finally
            {
                sessionLock.Release();
            }
        }

        /// <summary>
        /// Decrypts a message using the Double Ratchet algorithm.
        /// </summary>
        /// <param name="session">Current Double Ratchet session</param>
        /// <param name="encryptedMessage">Encrypted message</param>
        /// <returns>Updated session and decrypted message, or null values if decryption fails</returns>
        public static (DoubleRatchetSession? updatedSession, string? decryptedMessage)
            DoubleRatchetDecrypt(DoubleRatchetSession session, EncryptedMessage encryptedMessage)
        {
            // Basic parameter validation
            ArgumentNullException.ThrowIfNull(session);
            ArgumentNullException.ThrowIfNull(encryptedMessage);

            if (encryptedMessage.Ciphertext == null || encryptedMessage.Nonce == null || encryptedMessage.SenderDHKey == null)
                throw new ArgumentException("Message is missing required fields", nameof(encryptedMessage));

            try
            {
                // Validate session ID
                if (string.IsNullOrEmpty(encryptedMessage.SessionId) ||
                    session.SessionId != encryptedMessage.SessionId)
                {
                    LoggingManager.LogWarning(nameof(DoubleRatchet), $"Session ID mismatch: expected {session.SessionId}, got {encryptedMessage.SessionId}");
                    return (null, null);
                }

                // Check for replay
                if (session.HasProcessedMessageId(encryptedMessage.MessageId))
                {
                    LoggingManager.LogWarning(nameof(DoubleRatchet), $"Message replay detected: {encryptedMessage.MessageId}");
                    return (null, null);
                }

                // Validate timestamp
                long currentTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                if (encryptedMessage.Timestamp <= 0 ||
                    Math.Abs(currentTime - encryptedMessage.Timestamp) > Constants.MAX_MESSAGE_AGE_MS)
                {
                    LoggingManager.LogWarning(nameof(DoubleRatchet), $"Message timestamp validation failed: current={currentTime}, message={encryptedMessage.Timestamp}");
                    return (null, null);
                }

                // Derive the message key
                byte[] messageKey;
                DoubleRatchetSession updatedSession = session;

                // Check if we need to perform a DH ratchet step
                bool dhRatchetNeeded = !SecureMemory.SecureCompare(encryptedMessage.SenderDHKey, session.RemoteDHRatchetKey);

                if (dhRatchetNeeded)
                {
                    LoggingManager.LogInformation(nameof(DoubleRatchet), "DH ratchet step needed");

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
                        recentlyProcessedIds: session.RecentlyProcessedIds,
                        processedMessageNumbers: session.ProcessedMessageNumbers
                    );

                    // Derive message key from new chain
                    var (updatedChainKey, derivedMessageKey) = DoubleRatchetExchange.RatchetStep(newChainKey);
                    messageKey = derivedMessageKey;

                    // Update the receiving chain key
                    updatedSession = updatedSession.WithUpdatedParameters(
                        newReceivingChainKey: updatedChainKey,
                        newProcessedMessageNumber: encryptedMessage.MessageNumber
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
                        newReceivingChainKey: updatedChainKey,
                        newProcessedMessageNumber: encryptedMessage.MessageNumber
                    );
                }

                using var secureMessageKey = new SecureMemory.SecureArray<byte>(messageKey);

                // Decrypt the message
                try
                {
                    byte[] plaintext = AES.AESDecrypt(
                        encryptedMessage.Ciphertext, secureMessageKey.Value, encryptedMessage.Nonce);

                    if (plaintext == null || plaintext.Length == 0)
                    {
                        LoggingManager.LogWarning(nameof(DoubleRatchet), "Decryption produced empty result");
                        return (null, null);
                    }

                    if (!Helpers.IsValidUtf8(plaintext))
                    {
                        LoggingManager.LogWarning(nameof(DoubleRatchet), "Decrypted message is not valid UTF-8");
                        return (null, null);
                    }

                    // Convert to string
                    string decryptedMessage = Encoding.UTF8.GetString(plaintext);

                    // Update the session with processed message ID
                    updatedSession = updatedSession.WithProcessedMessageId(encryptedMessage.MessageId);

                    return (updatedSession, decryptedMessage);
                }
                catch (CryptographicException ex)
                {
                    // Log the specific cryptographic error
                    LoggingManager.LogError(nameof(DoubleRatchet), $"Decryption failed: {ex.Message}");
                    return (null, null);
                }
                finally
                {
                    // Clean up sensitive data
                    SecureMemory.SecureClear(messageKey);
                }
            }
            catch (Exception ex)
            {
                // Log the error but don't expose exception details to caller
                LoggingManager.LogError(nameof(DoubleRatchet), $"Error during decryption: {ex.Message}");
                return (null, null);
            }
        }

        /// <summary>
        /// Asynchronously decrypts a message using the Double Ratchet algorithm.
        /// </summary>
        /// <param name="session">Current Double Ratchet session</param>
        /// <param name="encryptedMessage">Encrypted message</param>
        /// <returns>Updated session and decrypted message, or null values if decryption fails</returns>
        public static async Task<(DoubleRatchetSession? updatedSession, string? decryptedMessage)>
            DoubleRatchetDecryptAsync(DoubleRatchetSession session, EncryptedMessage encryptedMessage)
        {
            // Basic parameter validation
            ArgumentNullException.ThrowIfNull(session);
            ArgumentNullException.ThrowIfNull(encryptedMessage);

            if (encryptedMessage.Ciphertext == null || encryptedMessage.Nonce == null || encryptedMessage.SenderDHKey == null)
                throw new ArgumentException("Message is missing required fields", nameof(encryptedMessage));

            // Get a lock for this specific session to ensure thread safety
            var sessionLock = GetSessionLock(session.SessionId);

            try
            {
                // Acquire the lock before performing any session operations
                await sessionLock.WaitAsync();

                // Use the existing synchronous implementation
                return DoubleRatchetDecrypt(session, encryptedMessage);
            }
            catch (Exception ex)
            {
                // Log all unexpected exceptions
                LoggingManager.LogError(nameof(DoubleRatchet), $"Error in DoubleRatchetDecryptAsync: {ex.Message}");
                return (null, null);
            }
            finally
            {
                // Always release the lock
                sessionLock.Release();

                // Consider cleaning up locks that haven't been used for a while
                if (_sessionLocks.Count > 1000)
                {
                    CleanupUnusedLocks();
                }
            }
        }

        /// <summary>
        /// Frees session locks that haven't been used in over 10 minutes.
        /// </summary>
        private static void CleanupUnusedLocks()
        {
            try
            {
                // Get current time for age calculation
                long currentTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

                // Find locks that haven't been used in the last 10 minutes
                long cutoff = currentTime - (long)TimeSpan.FromMinutes(10).TotalMilliseconds;

                // Find inactive locks (limited to 100 at a time to avoid long operations)
                var expired = _lockLastUsed
                    .Where(e => e.Value < cutoff)
                    .Select(e => e.Key)
                    .Take(100)
                    .ToList();

                int removed = 0;

                // Remove each inactive lock
                foreach (var sessionId in expired)
                {
                    // First try to remove the tracking timestamp
                    if (_lockLastUsed.TryRemove(sessionId, out _) &&
                        _sessionLocks.TryRemove(sessionId, out var semaphore))
                    {
                        semaphore.Dispose();
                        removed++;
                    }
                }

                // Log cleanup results if any locks were removed
                if (removed > 0)
                    LoggingManager.LogInformation(
                        nameof(DoubleRatchet),
                        $"Cleaned {removed} expired session locks.");
            }
            catch (Exception ex)
            {
                // Log but don't throw - this is a best-effort cleanup
                LoggingManager.LogWarning(nameof(DoubleRatchet), $"Error during lock cleanup: {ex.Message}");
            }
        }

        /// <summary>
        /// Gets or creates a per-session semaphore lock.
        /// </summary>
        /// <param name="sessionId"></param>
        /// <returns></returns>
        private static SemaphoreSlim GetSessionLock(string sessionId)
        {
            // Update the last used timestamp whenever a lock is accessed
            _lockLastUsed[sessionId] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            return _sessionLocks.GetOrAdd(sessionId, _ => new SemaphoreSlim(1, 1));
        }
    }
}