using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.KeyExchange;
using LibEmiddle.Models;
using System.Collections.Concurrent;

namespace LibEmiddle.Messaging.Chat 
{ 
    /// <summary>
    /// Chat Session
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

        /// <summary>
        /// Current state of the chat session
        /// </summary>
        public Enums.ChatSessionState State { get; private set; }

        /// <summary>
        /// Event raised when the session state changes
        /// </summary>
        public event EventHandler<ChatSessionStateChangedEventArgs>? StateChanged;

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
        /// When the session was last activated
        /// </summary>
        public DateTime? LastActivatedAt { get; private set; }

        /// <summary>
        /// When the session was last suspended
        /// </summary>
        public DateTime? LastSuspendedAt { get; private set; }

        /// <summary>
        /// The reason for the last suspension, if any
        /// </summary>
        public string? SuspensionReason { get; private set; }

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
            State = Enums.ChatSessionState.Initialized;
        }

        /// <summary>
        /// Activates the session, transitioning it to the Active state
        /// </summary>
        /// <returns>True if the session was activated, false if it was already active</returns>
        /// <exception cref="InvalidOperationException">Thrown when trying to activate a terminated session</exception>
        public bool Activate()
        {
            ThrowIfDisposed();

            lock (_sessionLock)
            {
                if (State == Enums.ChatSessionState.Terminated)
                    throw new InvalidOperationException("Cannot activate a terminated session");

                if (State == Enums.ChatSessionState.Active)
                    return false;

                var previousState = State;
                State = Enums.ChatSessionState.Active;
                LastActivatedAt = DateTime.UtcNow;

                OnStateChanged(previousState, State);
                return true;
            }
        }

        /// <summary>
        /// Suspends the session, transitioning it to the Suspended state
        /// </summary>
        /// <param name="reason">Optional reason for suspension</param>
        /// <returns>True if the session was suspended, false if it was already suspended</returns>
        /// <exception cref="InvalidOperationException">Thrown when trying to suspend a terminated session</exception>
        public bool Suspend(string? reason = null)
        {
            ThrowIfDisposed();

            lock (_sessionLock)
            {
                if (State == Enums.ChatSessionState.Terminated)
                    throw new InvalidOperationException("Cannot suspend a terminated session");

                if (State == Enums.ChatSessionState.Suspended)
                    return false;

                var previousState = State;
                State = Enums.ChatSessionState.Suspended;
                LastSuspendedAt = DateTime.UtcNow;
                SuspensionReason = reason;

                OnStateChanged(previousState, State);
                return true;
            }
        }

        /// <summary>
        /// Terminates the session, after which it cannot be used
        /// </summary>
        /// <returns>True if the session was terminated, false if it was already terminated</returns>
        public bool Terminate()
        {
            ThrowIfDisposed();

            lock (_sessionLock)
            {
                if (State == Enums.ChatSessionState.Terminated)
                    return false;

                var previousState = State;
                State = Enums.ChatSessionState.Terminated;

                // Clear sensitive data on termination for security
                _cryptoSession = null;

                OnStateChanged(previousState, State);
                return true;
            }
        }

        /// <summary>
        /// Encrypts a message using the current session
        /// </summary>
        /// <param name="message">Message to encrypt</param>
        /// <param name="autoActivate">Whether to automatically activate the session if initialized</param>
        /// <returns>Encrypted message</returns>
        /// <exception cref="ArgumentException">Thrown when message is null or empty</exception>
        /// <exception cref="InvalidOperationException">Thrown when session is invalid, suspended, or terminated</exception>
        public EncryptedMessage EncryptMessage(string message, bool autoActivate = true)
        {
            ThrowIfDisposed();

            if (string.IsNullOrEmpty(message))
                throw new ArgumentException("Message cannot be null or empty", nameof(message));

            lock (_sessionLock)
            {
                if (State == Enums.ChatSessionState.Terminated)
                    throw new InvalidOperationException("Cannot encrypt messages in a terminated session");

                if (State == Enums.ChatSessionState.Suspended)
                    throw new InvalidOperationException($"Cannot encrypt messages while session is suspended. Reason: {SuspensionReason ?? "Unknown"}");

                // Auto-activate if requested
                if (State == Enums.ChatSessionState.Initialized && autoActivate)
                    Activate();

                if (State == Enums.ChatSessionState.Initialized && !autoActivate)
                    throw new InvalidOperationException("Session must be activated before encrypting messages");

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
        /// <param name="autoActivate">Whether to automatically activate the session if initialized</param>
        /// <returns>Decrypted message or null if decryption failed</returns>
        /// <exception cref="ArgumentNullException">Thrown when encryptedMessage is null</exception>
        /// <exception cref="InvalidOperationException">Thrown when session is disposed or terminated</exception>
        public string? DecryptMessage(EncryptedMessage encryptedMessage, bool autoActivate = true)
        {
            ThrowIfDisposed();

            if (encryptedMessage == null)
                throw new ArgumentNullException(nameof(encryptedMessage));

            lock (_sessionLock)
            {
                if (State == Enums.ChatSessionState.Terminated)
                    throw new InvalidOperationException("Cannot decrypt messages in a terminated session");

                // Auto-activate if requested and not suspended
                if (State == Enums.ChatSessionState.Initialized && autoActivate)
                    Activate();

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
        /// <param name="startIndex">Starting index for pagination</param>
        /// <returns>Message history</returns>
        public IReadOnlyCollection<MessageRecord> GetMessageHistory(int limit = 100, int startIndex = 0)
        {
            ThrowIfDisposed();

            limit = Math.Max(0, limit);
            startIndex = Math.Max(0, startIndex);

            // Use Skip for pagination and Take for limiting the result
            return _messageHistory.Skip(startIndex).Take(limit).ToArray();
        }

        /// <summary>
        /// Gets the count of messages in the history
        /// </summary>
        /// <returns>Message count</returns>
        public int GetMessageCount()
        {
            ThrowIfDisposed();
            return _messageHistory.Count;
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
                return State != Enums.ChatSessionState.Terminated &&
                       _cryptoSession != null &&
                       DoubleRatchetExchange.ValidateSession(_cryptoSession);
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
        /// Clears the message history
        /// </summary>
        /// <returns>Number of messages cleared</returns>
        public int ClearMessageHistory()
        {
            ThrowIfDisposed();

            int count = 0;
            while (_messageHistory.TryDequeue(out _))
            {
                count++;
            }

            return count;
        }

        /// <summary>
        /// Raises the StateChanged event
        /// </summary>
        /// <param name="previousState">Previous session state</param>
        /// <param name="newState">New session state</param>
        protected virtual void OnStateChanged(Enums.ChatSessionState previousState, Enums.ChatSessionState newState)
        {
            StateChanged?.Invoke(this, new ChatSessionStateChangedEventArgs(previousState, newState));
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

                    // Record termination state
                    var previousState = State;
                    State = Enums.ChatSessionState.Terminated;

                    // Notify of state change if applicable
                    if (previousState != Enums.ChatSessionState.Terminated)
                    {
                        OnStateChanged(previousState, State);
                    }
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
    /// Event arguments for chat session state changes
    /// </summary>
    public class ChatSessionStateChangedEventArgs : EventArgs
    {
        /// <summary>
        /// The previous state of the session
        /// </summary>
        public Enums.ChatSessionState PreviousState { get; }

        /// <summary>
        /// The new state of the session
        /// </summary>
        public Enums.ChatSessionState NewState { get; }

        /// <summary>
        /// When the state change occurred
        /// </summary>
        public DateTime Timestamp { get; }

        /// <summary>
        /// Creates a new instance of ChatSessionStateChangedEventArgs
        /// </summary>
        /// <param name="previousState">The previous state</param>
        /// <param name="newState">The new state</param>
        public ChatSessionStateChangedEventArgs(Enums.ChatSessionState previousState, Enums.ChatSessionState newState)
        {
            PreviousState = previousState;
            NewState = newState;
            Timestamp = DateTime.UtcNow;
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