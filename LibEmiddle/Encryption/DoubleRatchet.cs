using System.Collections.Concurrent;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using E2EELibrary.Core;
using E2EELibrary.KeyExchange;
using E2EELibrary.KeyManagement;
using E2EELibrary.Models;

namespace E2EELibrary.Encryption
{
    /// <summary>
    /// Implements the Double Ratchet algorithm for end-to-end encrypted communications.
    /// The Double Ratchet algorithm provides secure messaging with forward secrecy and break-in recovery
    /// properties, continuously refreshing encryption keys as messages are exchanged.
    /// </summary>
    public static class DoubleRatchet
    {

        private static readonly ConcurrentDictionary<string, SemaphoreSlim> _sessionLocks =
    new ConcurrentDictionary<string, SemaphoreSlim>();

        private static readonly ConcurrentDictionary<string, long> _lockLastUsed =
    new ConcurrentDictionary<string, long>();

        /// <summary>
        /// Encrypts a message using the Double Ratchet algorithm
        /// </summary>
        /// <param name="session">Current Double Ratchet session</param>
        /// <param name="message">Message to encrypt</param>
        /// <returns>Updated session and encrypted message</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="CryptographicException"></exception>
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
                SecureMemory.SecureClear(secureMessageKey.Value);

                return (updatedSession, encryptedMessage);
            }
            catch (Exception ex)
            {
                throw new CryptographicException("Failed to encrypt message with Double Ratchet", ex);
            }
        }

        /// <summary>
        /// Encrypts a message using the Double Ratchet algorithm
        /// </summary>
        /// <param name="session">Current Double Ratchet session</param>
        /// <param name="message">Message to encrypt</param>
        /// <returns>Updated session and encrypted message</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentException"></exception>
        public static async Task<(DoubleRatchetSession updatedSession, EncryptedMessage encryptedMessage)>
    DoubleRatchetEncryptAsync(DoubleRatchetSession session, string message)
        {
            if (session == null)
                throw new ArgumentNullException(nameof(session));
            if (string.IsNullOrEmpty(message))
                throw new ArgumentException("Message cannot be null or empty", nameof(message));

            // Get a lock for this specific session
            var sessionLock = GetSessionLock(session.SessionId);

            try
            {
                await sessionLock.WaitAsync();

                // Use the existing synchronous implementation
                return DoubleRatchetEncrypt(session, message);
            }
            finally
            {
                sessionLock.Release();
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
                {
                    // Define specific error for replay detection rather than silent failure
                    throw new CryptographicException("Message already processed (possible replay attack)");
                }

                // Validate timestamp
                long currentTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                if (Math.Abs(currentTime - encryptedMessage.Timestamp) > Constants.MAX_MESSAGE_AGE_MS)
                {
                    // Define specific error for timestamp validation rather than silent failure
                    throw new SecurityException("Message timestamp outside acceptable range");
                }

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

                using var secureMessageKey = new SecureMemory.SecureArray<byte>(messageKey);

                // Decrypt the message
                try
                {
                    byte[] plaintext = AES.AESDecrypt(
                        encryptedMessage.Ciphertext, secureMessageKey.Value, encryptedMessage.Nonce);

                    // Convert to string
                    string decryptedMessage = Encoding.UTF8.GetString(plaintext);

                    // Update the session with processed message ID
                    updatedSession = updatedSession.WithProcessedMessageId(encryptedMessage.MessageId);

                    return (updatedSession, decryptedMessage);
                }
                catch (CryptographicException ex)
                {
                    // Specific handling for decryption failures
                    throw new CryptographicException("Message decryption failed: authentication tag verification failed", ex);
                }
                finally
                {
                    // Clean up sensitive data
                    if (secureMessageKey.Value != null)
                        SecureMemory.SecureClear(secureMessageKey.Value);
                }
            }
            catch (CryptographicException ex)
            {
                // Log specific cryptographic failures with details but return generic result
                // In a production environment, this should use a proper logging framework
                LoggingManager.LogError(nameof(DoubleRatchet), $"Cryptographic failure during message decryption: {ex.Message}");
                return (null, null);
            }
            catch (SecurityException ex)
            {
                // Log security violations separately
                LoggingManager.LogWarning(nameof(DoubleRatchet), $"Security violation during message processing: {ex.Message}");
                return (null, null);
            }
            catch (Exception ex)
            {
                // Generic exception handler as last resort
                LoggingManager.LogError(nameof(DoubleRatchet), $"Unexpected error in Double Ratchet decryption: {ex.Message}");
                return (null, null);
            }
        }

        /// <summary>
        /// Asynchronously decrypts a message using the Double Ratchet algorithm with enhanced security and thread safety
        /// </summary>
        /// <param name="session">Current Double Ratchet session</param>
        /// <param name="encryptedMessage">Encrypted message</param>
        /// <returns>Updated session and decrypted message, or null values if decryption fails</returns>
        public static async Task<(DoubleRatchetSession? updatedSession, string? decryptedMessage)>
            DoubleRatchetDecryptAsync(DoubleRatchetSession session, EncryptedMessage encryptedMessage)
        {
            // Basic parameter validation
            if (session == null)
                throw new ArgumentNullException(nameof(session));
            if (encryptedMessage == null)
                throw new ArgumentNullException(nameof(encryptedMessage));
            if (encryptedMessage.Ciphertext == null || encryptedMessage.Nonce == null || encryptedMessage.SenderDHKey == null)
                throw new ArgumentException("Message is missing required fields");

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
        /// Removes session locks that haven't been used recently to prevent memory leaks
        /// </summary>
        private static void CleanupUnusedLocks()
        {
            try
            {
                // Get current time for age calculation
                long currentTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

                // Find locks that haven't been used in the last 10 minutes
                TimeSpan inactivityThreshold = TimeSpan.FromMinutes(10);
                long oldestAllowedTimestamp = currentTime - (long)inactivityThreshold.TotalMilliseconds;

                // Find inactive locks (limited to 100 at a time to avoid long operations)
                var inactiveLockIds = _lockLastUsed
                    .Where(pair => pair.Value < oldestAllowedTimestamp)
                    .Select(pair => pair.Key)
                    .Take(100)
                    .ToList();

                int removedCount = 0;

                // Remove each inactive lock
                foreach (var sessionId in inactiveLockIds)
                {
                    // First try to remove the tracking timestamp
                    if (_lockLastUsed.TryRemove(sessionId, out _))
                    {
                        // Then try to remove and dispose the actual lock
                        if (_sessionLocks.TryRemove(sessionId, out var semaphore))
                        {
                            semaphore.Dispose();
                            removedCount++;
                        }
                    }
                }

                // Log cleanup results if any locks were removed
                if (removedCount > 0)
                {
                    LoggingManager.LogInformation(
                        nameof(DoubleRatchet),
                        $"Cleaned up {removedCount} unused session locks. {_sessionLocks.Count} active locks remain.");
                }
            }
            catch (Exception ex)
            {
                // Log but don't throw - this is a best-effort cleanup
                LoggingManager.LogWarning(
                    nameof(DoubleRatchet),
                    $"Error cleaning up session locks: {ex.Message}");
            }
        }

        /// <summary>
        /// Schedule cleanup for locks
        /// </summary>
        private static void ScheduleCleanupIfNeeded()
        {
            // Only run cleanup if we have a significant number of locks
            if (_sessionLocks.Count > 500)
            {
                // Run cleanup on a background thread to avoid blocking
                Task.Run(CleanupUnusedLocks);
            }
        }

        /// <summary>
        /// Gets the session lock semaphore
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
