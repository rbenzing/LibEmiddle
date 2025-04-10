using System.Collections.Concurrent;
using E2EELibrary.Core;
using E2EELibrary.Models;
using E2EELibrary.Encryption;
using E2EELibrary.KeyExchange;

namespace E2EELibrary.Messaging
{
    /// <summary>
    /// Represents an active chat session between two parties with enhanced 
    /// tracking and management capabilities.
    /// </summary>
    public class ChatSession : IDisposable
    {
        // Underlying cryptographic session
        private DoubleRatchetSession? _cryptoSession;
        private readonly object _sessionLock = new object();
        private bool _disposed;

        // Conversation metadata
        /// <summary>
        /// Unique identifier for this session
        /// </summary>
        public string SessionId { get; }

        /// <summary>
        /// Remote identity public key
        /// </summary>
        public byte[] RemotePublicKey { get; }

        /// <summary>
        /// Local identity public key
        /// </summary>
        public byte[] LocalPublicKey { get; }

        // Message tracking
        private readonly ConcurrentQueue<MessageRecord> _messageHistory =
            new ConcurrentQueue<MessageRecord>();

        // Session state tracking
        /// <summary>
        /// When this session was created
        /// </summary>
        public DateTime CreatedAt { get; }

        /// <summary>
        /// When the last message was sent
        /// </summary>
        public DateTime? LastMessageSentAt { get; private set; }

        /// <summary>
        /// When the last message was received
        /// </summary>
        public DateTime? LastMessageReceivedAt { get; private set; }

        /// <summary>
        /// Key rotation strategy for this session
        /// </summary>
        public Enums.KeyRotationStrategy RotationStrategy { get; set; } =
            Enums.KeyRotationStrategy.Standard;

        /// <summary>
        /// Optional metadata for rich context
        /// </summary>
        public Dictionary<string, string> Metadata { get; } = new Dictionary<string, string>();

        /// <summary>
        /// Creates a new chat session
        /// </summary>
        /// <param name="cryptoSession">The Double Ratchet session for encryption</param>
        /// <param name="remotePublicKey">Remote party's public key</param>
        /// <param name="localPublicKey">Local public key</param>
        /// <exception cref="ArgumentNullException">Thrown when any parameter is null</exception>
        public ChatSession(
            DoubleRatchetSession cryptoSession,
            byte[] remotePublicKey,
            byte[] localPublicKey)
        {
            _cryptoSession = cryptoSession ??
                throw new ArgumentNullException(nameof(cryptoSession));

            RemotePublicKey = remotePublicKey ??
                throw new ArgumentNullException(nameof(remotePublicKey));

            LocalPublicKey = localPublicKey ??
                throw new ArgumentNullException(nameof(localPublicKey));

            SessionId = cryptoSession.SessionId;
            CreatedAt = DateTime.UtcNow;
        }

        /// <summary>
        /// Encrypts a message using the current session
        /// </summary>
        /// <param name="message">Message to encrypt</param>
        /// <returns>Encrypted message</returns>
        /// <exception cref="ArgumentException">Thrown when message is null or empty</exception>
        /// <exception cref="InvalidOperationException">Thrown when session is invalid or disposed</exception>
        public EncryptedMessage EncryptMessage(string message)
        {
            ThrowIfDisposed();

            if (string.IsNullOrEmpty(message))
                throw new ArgumentException("Message cannot be null or empty", nameof(message));

            lock (_sessionLock)
            {
                if (_cryptoSession == null)
                    throw new InvalidOperationException("Session is not initialized");

                var (updatedSession, encryptedMessage) =
                    DoubleRatchet.DoubleRatchetEncrypt(_cryptoSession, message, RotationStrategy);

                if (updatedSession == null)
                    throw new InvalidOperationException("Encryption failed: session update was null");

                if (encryptedMessage == null)
                    throw new InvalidOperationException("Encryption failed: encrypted message is null");

                // Update the session
                _cryptoSession = updatedSession;

                // Track message send time
                LastMessageSentAt = DateTime.UtcNow;

                // Add to message history
                _messageHistory.Enqueue(new MessageRecord
                {
                    IsOutgoing = true,
                    Timestamp = DateTime.UtcNow,
                    Content = message,
                    EncryptedMessage = encryptedMessage
                });

                return encryptedMessage;
            }
        }

        /// <summary>
        /// Decrypts a message using the current session
        /// </summary>
        /// <param name="encryptedMessage">Message to decrypt</param>
        /// <returns>Decrypted message or null if decryption failed</returns>
        /// <exception cref="ArgumentNullException">Thrown when encryptedMessage is null</exception>
        /// <exception cref="InvalidOperationException">Thrown when session is disposed</exception>
        public string? DecryptMessage(EncryptedMessage encryptedMessage)
        {
            ThrowIfDisposed();

            if (encryptedMessage == null)
                throw new ArgumentNullException(nameof(encryptedMessage));

            lock (_sessionLock)
            {
                if (_cryptoSession == null)
                    throw new InvalidOperationException("Session is not initialized");

                var (updatedSession, decryptedMessage) =
                    DoubleRatchet.DoubleRatchetDecrypt(_cryptoSession, encryptedMessage);

                if (updatedSession != null)
                {
                    _cryptoSession = updatedSession;

                    if (decryptedMessage != null)
                    {
                        LastMessageReceivedAt = DateTime.UtcNow;

                        // Add to message history
                        _messageHistory.Enqueue(new MessageRecord
                        {
                            IsOutgoing = false,
                            Timestamp = DateTime.UtcNow,
                            Content = decryptedMessage,
                            EncryptedMessage = encryptedMessage
                        });
                    }
                }

                return decryptedMessage;
            }
        }

        /// <summary>
        /// Gets the underlying Double Ratchet session
        /// </summary>
        /// <returns>Double Ratchet session</returns>
        /// <exception cref="InvalidOperationException">Thrown when session is invalid or disposed</exception>
        public DoubleRatchetSession GetCryptoSession()
        {
            ThrowIfDisposed();

            lock (_sessionLock)
            {
                if (_cryptoSession == null)
                    throw new InvalidOperationException("Session is not initialized");

                return _cryptoSession;
            }
        }

        /// <summary>
        /// Retrieves message history
        /// </summary>
        /// <param name="limit">Maximum number of messages to retrieve</param>
        /// <returns>Message history</returns>
        public IReadOnlyCollection<MessageRecord> GetMessageHistory(int limit = 100)
        {
            limit = Math.Max(0, limit); // Ensure non-negative
            return _messageHistory.Take(limit).ToArray();
        }

        /// <summary>
        /// Checks if the session is still valid
        /// </summary>
        /// <returns>True if the session is valid</returns>
        public bool IsValid()
        {
            if (_disposed)
                return false;

            lock (_sessionLock)
            {
                return _cryptoSession != null && DoubleRatchetExchange.ValidateSession(_cryptoSession);
            }
        }

        /// <summary>
        /// Adds custom metadata to the session
        /// </summary>
        /// <param name="key">Metadata key</param>
        /// <param name="value">Metadata value</param>
        /// <exception cref="ArgumentException">Thrown when key is null or empty</exception>
        /// <exception cref="InvalidOperationException">Thrown when session is disposed</exception>
        public void SetMetadata(string key, string value)
        {
            ThrowIfDisposed();

            if (string.IsNullOrEmpty(key))
                throw new ArgumentException("Metadata key cannot be null or empty", nameof(key));

            Metadata[key] = value;
        }

        /// <summary>
        /// Checks if this instance has been disposed
        /// </summary>
        /// <exception cref="ObjectDisposedException">Thrown when the object is disposed</exception>
        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(ChatSession), "This chat session has been disposed");
            }
        }

        /// <summary>
        /// Cleans up sensitive session data
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Cleans up sensitive session data
        /// </summary>
        /// <param name="disposing">True when called from Dispose(), false when called from finalizer</param>
        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                lock (_sessionLock)
                {
                    // Clear sensitive data
                    _cryptoSession = null;

                    // Clear message history that contains sensitive information
                    while (_messageHistory.TryDequeue(out _)) { }
                }
            }

            _disposed = true;
        }

        /// <summary>
        /// Finalizer
        /// </summary>
        ~ChatSession()
        {
            Dispose(false);
        }
    }

    /// <summary>
    /// Represents a message in the chat history
    /// </summary>
    public class MessageRecord
    {
        /// <summary>
        /// Whether this message was sent by the local user
        /// </summary>
        public bool IsOutgoing { get; set; }

        /// <summary>
        /// When the message was sent or received
        /// </summary>
        public DateTime Timestamp { get; set; }

        /// <summary>
        /// Plaintext content of the message
        /// </summary>
        public string? Content { get; set; }

        /// <summary>
        /// Encrypted form of the message
        /// </summary>
        public EncryptedMessage? EncryptedMessage { get; set; }
    }
}