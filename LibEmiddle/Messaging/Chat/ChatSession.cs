using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Threading.Channels;
using System.Runtime.CompilerServices;
using LibEmiddle.Abstractions;
using LibEmiddle.Core;
using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;
using LibEmiddle.Messaging.Batching;

namespace LibEmiddle.Messaging.Chat
{
    /// <summary>
    /// Represents an end-to-end encrypted chat session with a remote party,
    /// managing Double Ratchet state, message history, and session lifecycle.
    /// </summary>
    public class ChatSession : IChatSession, ISession, IDisposable
    {
        private readonly SemaphoreSlim _sessionLock = new(1, 1);
        private DoubleRatchetSession _cryptoSession;
        private InitialMessageData? _initialMessageData;

        // Disposed flag
        private int _disposedFlag = 0;

        // Required properties from interface
        public string SessionId { get; }
        public SessionType Type => SessionType.Individual;
        public SessionState State { get; private set; }
        public byte[] RemotePublicKey { get; }
        public byte[] LocalPublicKey { get; }

        // Additional properties
        public DateTime CreatedAt { get; }
        public DateTime? LastMessageSentAt { get; private set; }
        public DateTime? LastMessageReceivedAt { get; private set; }
        public DateTime? LastActivatedAt { get; private set; }
        public DateTime? LastSuspendedAt { get; private set; }
        public string? SuspensionReason { get; private set; }
        public KeyRotationStrategy RotationStrategy { get; set; } = KeyRotationStrategy.Standard;

        // Events
        public event EventHandler<SessionStateChangedEventArgs>? StateChanged;
        public event EventHandler<MessageReceivedEventArgs>? MessageReceived;

        // Collections
        private readonly ConcurrentQueue<MessageRecord> _messageHistory = new();
        public ConcurrentDictionary<string, string> Metadata { get; } = new();

        // Services
        private readonly IDoubleRatchetProtocol _doubleRatchetProtocol;

        // v2.5 Async message streaming (opt-in via feature flags)
        private readonly Channel<MessageReceivedEventArgs>? _messageChannel;
        private readonly ChannelWriter<MessageReceivedEventArgs>? _messageWriter;
        private readonly ChannelReader<MessageReceivedEventArgs>? _messageReader;
        private readonly bool _asyncStreamingEnabled;

        // v2.5 Message batching (opt-in via feature flags)
        private readonly IMessageBatcher? _messageBatcher;
        private readonly bool _batchingEnabled;

        /// <summary>
        /// Gets the initial message data for X3DH key exchange (sender-only).
        /// </summary>
        public InitialMessageData? InitialMessageData => _initialMessageData;

        // Constructor with dependency injection (v2.0 compatibility)
        public ChatSession(
            DoubleRatchetSession initialCryptoSession,
            byte[] remotePublicKey,
            byte[] localPublicKey,
            IDoubleRatchetProtocol doubleRatchetProtocol)
        {
            _cryptoSession = initialCryptoSession ?? throw new ArgumentNullException(nameof(initialCryptoSession));
            RemotePublicKey = remotePublicKey ?? throw new ArgumentNullException(nameof(remotePublicKey));
            LocalPublicKey = localPublicKey ?? throw new ArgumentNullException(nameof(localPublicKey));
            _doubleRatchetProtocol = doubleRatchetProtocol ?? throw new ArgumentNullException(nameof(doubleRatchetProtocol));

            SessionId = initialCryptoSession.SessionId;
            CreatedAt = DateTime.UtcNow;
            State = SessionState.Initialized;

            // v2.0 behavior: async streaming and batching disabled
            _asyncStreamingEnabled = false;
            _batchingEnabled = false;
        }

        // Constructor with v2.5 options (async streaming and batching support)
        public ChatSession(
            DoubleRatchetSession initialCryptoSession,
            byte[] remotePublicKey,
            byte[] localPublicKey,
            IDoubleRatchetProtocol doubleRatchetProtocol,
            bool enableAsyncStreaming,
            BatchingOptions? batchingOptions = null)
        {
            _cryptoSession = initialCryptoSession ?? throw new ArgumentNullException(nameof(initialCryptoSession));
            RemotePublicKey = remotePublicKey ?? throw new ArgumentNullException(nameof(remotePublicKey));
            LocalPublicKey = localPublicKey ?? throw new ArgumentNullException(nameof(localPublicKey));
            _doubleRatchetProtocol = doubleRatchetProtocol ?? throw new ArgumentNullException(nameof(doubleRatchetProtocol));

            SessionId = initialCryptoSession.SessionId;
            CreatedAt = DateTime.UtcNow;
            State = SessionState.Initialized;

            // v2.5 behavior: configure async streaming
            _asyncStreamingEnabled = enableAsyncStreaming;
            if (_asyncStreamingEnabled)
            {
                // Create unbounded channel for message streaming
                var channelOptions = new UnboundedChannelOptions()
                {
                    SingleReader = false,
                    SingleWriter = true,
                    AllowSynchronousContinuations = false
                };
                
                _messageChannel = Channel.CreateUnbounded<MessageReceivedEventArgs>(channelOptions);
                _messageWriter = _messageChannel.Writer;
                _messageReader = _messageChannel.Reader;
            }

            // v2.5 behavior: configure message batching
            _batchingEnabled = batchingOptions != null;
            if (_batchingEnabled)
            {
                _messageBatcher = new MessageBatcher(batchingOptions);
            }
        }

        /// <summary>
        /// Sets the initial X3DH message data for this session.
        /// Used when creating a session as the sender.
        /// </summary>
        /// <param name="initialMessageData">The X3DH initial message data.</param>
        public void SetInitialMessageData(InitialMessageData initialMessageData)
        {
            _initialMessageData = initialMessageData ?? throw new ArgumentNullException(nameof(initialMessageData));
        }

        /// <summary>
        /// Gets the current immutable cryptographic session state.
        /// Use for persistence or inspection. Acquire lock if performing operations based on this state.
        /// </summary>
        /// <exception cref="ObjectDisposedException"></exception>
        /// <exception cref="InvalidOperationException">If crypto session is null (e.g., after termination).</exception>
        public DoubleRatchetSession GetCryptoSessionState()
        {
            ThrowIfDisposed();
            // No lock needed just to return the reference, as the object itself is immutable.
            // Lock IS needed if the caller intends to use this state in combination
            // with other actions on this ChatSession instance.
            var currentSession = _cryptoSession; // Read volatile reference
            if (currentSession == null) // Can be null if Terminated/Disposed
                throw new InvalidOperationException("Cryptographic session state is not available (session may be terminated).");
            return currentSession;
        }

        /// <summary>
        /// Activates the session if it's currently Initialized or Suspended.
        /// </summary>
        /// <returns>True if the state was changed to Active, false otherwise.</returns>
        /// <exception cref="InvalidOperationException">If session is Terminated.</exception>
        /// <exception cref="ObjectDisposedException"></exception>
        public async Task<bool> ActivateAsync()
        {
            ThrowIfDisposed();
            await _sessionLock.WaitAsync();
            try
            {
                if (State == SessionState.Terminated)
                    throw new InvalidOperationException("Cannot activate a terminated session.");
                if (State == SessionState.Active)
                    return false;

                var previousState = State;
                State = SessionState.Active;
                LastActivatedAt = DateTime.UtcNow;
                SuspensionReason = null;
                OnStateChanged(previousState, State);
                return true;
            }
            finally
            {
                _sessionLock.Release();
            }
        }

        /// <summary>
        /// Suspends the session if it's currently Active.
        /// </summary>
        /// <param name="reason">Optional reason for suspension.</param>
        /// <returns>True if the state was changed to Suspended, false otherwise.</returns>
        /// <exception cref="InvalidOperationException">If session is Terminated.</exception>
        /// <exception cref="ObjectDisposedException"></exception>
        public async Task<bool> SuspendAsync(string? reason = null)
        {
            ThrowIfDisposed();
            await _sessionLock.WaitAsync();
            try
            {
                if (State == SessionState.Terminated)
                    throw new InvalidOperationException("Cannot suspend a terminated session.");
                if (State == SessionState.Suspended)
                    return false;

                var previousState = State;
                State = SessionState.Suspended;
                LastSuspendedAt = DateTime.UtcNow;
                SuspensionReason = reason;
                OnStateChanged(previousState, State);
                return true;
            }
            finally
            {
                _sessionLock.Release();
            }
        }

        /// <summary>
        /// Terminates the session permanently, clearing cryptographic state.
        /// </summary>
        /// <returns>True if the state was changed to Terminated, false otherwise.</returns>
        /// <exception cref="ObjectDisposedException"></exception>
        public async Task<bool> TerminateAsync()
        {
            ThrowIfDisposed();
            await _sessionLock.WaitAsync();
            try
            {
                if (State == SessionState.Terminated)
                    return false;

                var previousState = State;
                State = SessionState.Terminated;
                _cryptoSession = null!;
                OnStateChanged(previousState, State);
                return true;
            }
            finally
            {
                _sessionLock.Release();
            }
        }

        /// <summary>
        /// Encrypts and sends a message using the current Double Ratchet state.
        /// Handles state updates and emits events.
        /// </summary>
        /// <param name="message">Plaintext message to send.</param>
        /// <returns>True if the message was sent successfully, false otherwise.</returns>
        /// <exception cref="ArgumentException">If message is null or empty.</exception>
        /// <exception cref="InvalidOperationException">If session is Terminated or Suspended.</exception>
        /// <exception cref="ObjectDisposedException"></exception>
        public async Task<bool> SendMessageAsync(string message)
        {
            ThrowIfDisposed();
            ArgumentException.ThrowIfNullOrEmpty(message, nameof(message));

            EncryptedMessage? encryptedMessage = await EncryptAsync(message);
            if (encryptedMessage == null)
            {
                return false;
            }

            // In a real implementation, this would send the message via transport
            // For now, we'll just return success
            return true;
        }

        /// <summary>
        /// Processes an incoming encrypted message.
        /// </summary>
        /// <param name="encryptedMessage">The encrypted message to process.</param>
        /// <returns>The decrypted message, or null if decryption failed.</returns>
        public async Task<string?> ProcessIncomingMessageAsync(EncryptedMessage encryptedMessage)
        {
            var decryptedMessage = await DecryptAsync(encryptedMessage);
            
            if (decryptedMessage != null)
            {
                // Notify listeners about the new message
                OnMessageReceived(new MessageReceivedEventArgs(
                    RemotePublicKey,
                    decryptedMessage,
                    encryptedMessage.Timestamp));
            }
            
            return decryptedMessage;
        }

        /// <summary>
        /// Encrypts a message using the current Double Ratchet state. Handles state updates.
        /// Automatically activates the session if it's Initialized.
        /// </summary>
        /// <param name="message">Plaintext message to encrypt.</param>
        /// <returns>The EncryptedMessage object, or null if encryption failed.</returns>
        /// <exception cref="ArgumentException">If message is null or empty.</exception>
        /// <exception cref="InvalidOperationException">If session is Terminated or Suspended.</exception>
        /// <exception cref="CryptographicException">If underlying encryption fails.</exception>
        /// <exception cref="ObjectDisposedException"></exception>
        public async Task<EncryptedMessage?> EncryptAsync(string message)
        {
            ThrowIfDisposed();
            ArgumentException.ThrowIfNullOrEmpty(message, nameof(message));

            await _sessionLock.WaitAsync();
            try
            {
                // State validation
                if (State == SessionState.Terminated)
                    throw new InvalidOperationException("Cannot encrypt: Session is terminated.");
                if (State == SessionState.Suspended)
                    throw new InvalidOperationException($"Cannot encrypt: Session is suspended. Reason: {SuspensionReason ?? "Unknown"}");

                // Auto-activate if needed
                if (State == SessionState.Initialized)
                {
                    State = SessionState.Active;
                    LastActivatedAt = DateTime.UtcNow;
                    OnStateChanged(SessionState.Initialized, State);
                    LoggingManager.LogDebug(nameof(ChatSession), $"Session {SessionId} auto-activated by sending.");
                }

                // Perform encryption
                var (updatedSession, encryptedMessage) = _doubleRatchetProtocol.EncryptAsync(
                    _cryptoSession, message, RotationStrategy);

                if (updatedSession == null || encryptedMessage == null)
                {
                    LoggingManager.LogError(nameof(ChatSession), $"Encryption failed for session {SessionId}.");
                    return null;
                }

                // Update state
                _cryptoSession = updatedSession;
                LastMessageSentAt = DateTime.UtcNow;

                // Track in history
                if (_messageHistory.Count < Constants.MAX_TRACKED_MESSAGE_IDS)
                {
                    _messageHistory.Enqueue(new MessageRecord
                    {
                        IsOutgoing = true,
                        Timestamp = DateTime.UtcNow,
                        Content = message,
                        EncryptedMessage = encryptedMessage
                    });
                }

                return encryptedMessage;
            }
            finally
            {
                _sessionLock.Release();
            }
        }

        /// <summary>
        /// Decrypts an incoming message using the current Double Ratchet state. Handles state updates.
        /// Automatically activates the session if it's Initialized.
        /// </summary>
        /// <param name="encryptedMessage">The incoming encrypted message.</param>
        /// <returns>The decrypted plaintext message, or null if decryption fails (e.g., authentication error, replay).</returns>
        /// <exception cref="ArgumentNullException">If encryptedMessage is null.</exception>
        /// <exception cref="InvalidOperationException">If session is Terminated.</exception>
        /// <exception cref="CryptographicException">If underlying decryption causes critical error.</exception>
        /// <exception cref="ObjectDisposedException"></exception>
        public async Task<string?> DecryptAsync(EncryptedMessage encryptedMessage)
        {
            ThrowIfDisposed();
            ArgumentNullException.ThrowIfNull(encryptedMessage, nameof(encryptedMessage));

            if (encryptedMessage.Ciphertext == null || encryptedMessage.Nonce == null || encryptedMessage.SenderDHKey == null)
                throw new ArgumentException("Encrypted message is missing required fields.", nameof(encryptedMessage));

            if (encryptedMessage.SessionId != SessionId)
            {
                LoggingManager.LogWarning(nameof(ChatSession), $"Message Session ID '{encryptedMessage.SessionId}' does not match current session '{SessionId}'");
                return null;
            }

            await _sessionLock.WaitAsync();
            try
            {
                // State validation
                if (State == SessionState.Terminated)
                    throw new InvalidOperationException("Cannot decrypt: Session is terminated.");

                // Auto-activate if needed
                if (State == SessionState.Initialized)
                {
                    State = SessionState.Active;
                    LastActivatedAt = DateTime.UtcNow;
                    OnStateChanged(SessionState.Initialized, State);
                    LoggingManager.LogDebug(nameof(ChatSession), $"Session {SessionId} auto-activated by receiving.");
                }

                // Perform decryption
                var (updatedSession, decryptedMessage) = _doubleRatchetProtocol.DecryptAsync(_cryptoSession, encryptedMessage);

                if (updatedSession == null)
                {
                    LoggingManager.LogWarning(nameof(ChatSession), $"Decryption failed for message {encryptedMessage.MessageId}");
                    return null;
                }

                // Update state
                _cryptoSession = updatedSession;
                LastMessageReceivedAt = DateTime.UtcNow;

                // Track in history
                if (_messageHistory.Count < Constants.MAX_TRACKED_MESSAGE_IDS && decryptedMessage != null)
                {
                    _messageHistory.Enqueue(new MessageRecord
                    {
                        IsOutgoing = false,
                        Timestamp = DateTime.UtcNow,
                        Content = decryptedMessage,
                        EncryptedMessage = encryptedMessage
                    });
                }

                return decryptedMessage;
            }
            finally
            {
                _sessionLock.Release();
            }
        }

        /// <summary>
        /// Checks if the session is valid and not terminated or disposed.
        /// Performs basic checks on the crypto session state.
        /// </summary>
        public bool IsValid()
        {
            if (_disposedFlag == 1) return false;

            // No lock needed for reading volatile references and immutable state parts
            var currentCryptoSession = _cryptoSession; // Read reference

            return State != SessionState.Terminated &&
                   currentCryptoSession != null &&
                   // Basic checks on the immutable session state
                   currentCryptoSession.RootKey?.Length == Constants.AES_KEY_SIZE &&
                   currentCryptoSession.SenderRatchetKeyPair.PublicKey?.Length == Constants.X25519_KEY_SIZE &&
                   currentCryptoSession.SenderRatchetKeyPair.PrivateKey?.Length == Constants.X25519_KEY_SIZE &&
                   // Chain keys can be null initially
                   (currentCryptoSession.SenderChainKey == null || currentCryptoSession.SenderChainKey.Length == Constants.AES_KEY_SIZE) &&
                   (currentCryptoSession.ReceiverChainKey == null || currentCryptoSession.ReceiverChainKey.Length == Constants.AES_KEY_SIZE);
        }

        /// <summary>
        /// Retrieves message history (thread-safe read from ConcurrentQueue).
        /// </summary>
        public IReadOnlyCollection<MessageRecord> GetMessageHistory(int limit = 100, int startIndex = 0)
        {
            ThrowIfDisposed();
            // ConcurrentQueue ToArray is snapshot, Skip/Take is LINQ
            return _messageHistory.Skip(Math.Max(0, startIndex)).Take(Math.Max(0, limit)).ToList().AsReadOnly();
        }

        /// <summary> Gets the count of messages in the history. </summary>
        public int GetMessageCount()
        {
            ThrowIfDisposed();
            return _messageHistory.Count;
        }

        /// <summary> Clears the message history. </summary>
        public int ClearMessageHistory()
        {
            ThrowIfDisposed();
            return ClearMessageHistoryInternal();
        }

        private int ClearMessageHistoryInternal()
        {
            int count = 0;
            while (_messageHistory.TryDequeue(out _)) { count++; }
            return count;
        }

        /// <summary> Sets custom metadata. </summary>
        public void SetMetadata(string key, string value)
        {
            ThrowIfDisposed();
            if (string.IsNullOrEmpty(key)) throw new ArgumentException("Metadata key cannot be null or empty.", nameof(key));
            // Dictionary is not thread-safe by default, lock if concurrent access is possible
            lock (_sessionLock) // Or use ConcurrentDictionary for Metadata
            {
                Metadata[key] = value;
            }
        }

        /// <summary> Raises the StateChanged event. </summary>
        protected virtual void OnStateChanged(SessionState previousState, SessionState newState)
        {
            // Ensure event handlers don't block lock if called from within lock
            Task.Run(() => StateChanged?.Invoke(this, new SessionStateChangedEventArgs(previousState, newState)));
            // Or just invoke directly if handlers are known to be fast:
            // StateChanged?.Invoke(this, new SessionStateChangedEventArgs(previousState, newState));
        }

        /// <summary> Raises the MessageReceived event and writes to stream if enabled. </summary>
        protected virtual void OnMessageReceived(MessageReceivedEventArgs e)
        {
            // Traditional event-based notification (always available)
            Task.Run(() => MessageReceived?.Invoke(this, e));

            // v2.5 stream-based notification (optional)
            if (_asyncStreamingEnabled && _messageWriter != null)
            {
                // Non-blocking write to channel
                if (!_messageWriter.TryWrite(e))
                {
                    // Channel might be closed or full, log but don't fail
                    LoggingManager.LogWarning(nameof(ChatSession), 
                        $"Failed to write message to stream for session {SessionId}");
                }
            }
        }

        // --- v2.5 Message Batching Methods ---

        /// <summary>
        /// Sends a message with optional batching (v2.5).
        /// If batching is enabled, the message may be queued for later transmission.
        /// Requires V25Features.EnableMessageBatching = true.
        /// </summary>
        /// <param name="message">The plaintext message to send.</param>
        /// <param name="priority">Priority level for batching.</param>
        /// <param name="forceSend">If true, bypasses batching and sends immediately.</param>
        /// <returns>True if the message was sent or queued successfully.</returns>
        public async Task<bool> SendMessageAsync(string message, MessagePriority priority, bool forceSend = false)
        {
            ThrowIfDisposed();
            ArgumentException.ThrowIfNullOrEmpty(message, nameof(message));

            // Encrypt the message first
            var encryptedMessage = await EncryptAsync(message);
            if (encryptedMessage == null)
            {
                return false;
            }

            // If batching is enabled and not forcing immediate send
            if (_batchingEnabled && _messageBatcher != null && !forceSend)
            {
                // Try to add to batch
                var added = await _messageBatcher.AddMessageAsync(encryptedMessage, priority);
                
                if (!added)
                {
                    // Batch is full, flush it and try again
                    var readyBatch = await _messageBatcher.GetReadyBatchAsync();
                    if (readyBatch != null)
                    {
                        // In a real implementation, this would send the batch via transport
                        LoggingManager.LogDebug(nameof(ChatSession), 
                            $"Batch {readyBatch.BatchId} ready for transmission with {readyBatch.Messages.Count} messages");
                    }

                    // Try adding to new batch
                    added = await _messageBatcher.AddMessageAsync(encryptedMessage, priority);
                }

                if (added)
                {
                    LoggingManager.LogDebug(nameof(ChatSession), 
                        $"Message queued for batching with priority {priority}");
                    return true;
                }
                else
                {
                    // Fall back to immediate send
                    LoggingManager.LogWarning(nameof(ChatSession), 
                        "Failed to queue message for batching, sending immediately");
                }
            }

            // Send immediately (either forced or batching failed/disabled)
            // In a real implementation, this would send via transport
            LoggingManager.LogDebug(nameof(ChatSession), 
                forceSend ? "Message sent immediately (forced)" : "Message sent immediately");
            
            return true;
        }

        /// <summary>
        /// Gets the current message batcher if batching is enabled (v2.5).
        /// Requires V25Features.EnableMessageBatching = true.
        /// </summary>
        /// <returns>The message batcher, or null if batching is not enabled.</returns>
        public IMessageBatcher? GetMessageBatcher()
        {
            ThrowIfDisposed();
            return _messageBatcher;
        }

        /// <summary>
        /// Forces any pending batched messages to be sent immediately (v2.5).
        /// Requires V25Features.EnableMessageBatching = true.
        /// </summary>
        /// <returns>The number of messages flushed.</returns>
        public async Task<int> FlushPendingMessagesAsync()
        {
            ThrowIfDisposed();
            
            if (!_batchingEnabled || _messageBatcher == null)
            {
                return 0;
            }

            var batch = await _messageBatcher.FlushBatchAsync();
            if (batch != null)
            {
                LoggingManager.LogDebug(nameof(ChatSession), 
                    $"Flushed batch {batch.BatchId} with {batch.Messages.Count} messages");
                
                // In a real implementation, this would send the batch via transport
                return batch.Messages.Count;
            }

            return 0;
        }

        // --- v2.5 Async Stream Methods ---

        /// <summary>
        /// Gets an async stream of incoming messages (v2.5).
        /// This runs in parallel with the MessageReceived event.
        /// Requires V25Features.EnableAsyncMessageStreams = true.
        /// </summary>
        /// <param name="cancellationToken">Token to cancel the stream.</param>
        /// <returns>Async enumerable of message received events.</returns>
        /// <exception cref="InvalidOperationException">If async streaming is not enabled.</exception>
        /// <exception cref="ObjectDisposedException">If the session is disposed.</exception>
        public async IAsyncEnumerable<MessageReceivedEventArgs> GetMessageStreamAsync(
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            
            if (!_asyncStreamingEnabled || _messageReader == null)
            {
                throw new InvalidOperationException(
                    "Async message streaming is not enabled. Enable V25Features.EnableAsyncMessageStreams.");
            }

            await foreach (var message in _messageReader.ReadAllAsync(cancellationToken))
            {
                yield return message;
            }
        }

        /// <summary>
        /// Gets an async stream of incoming messages with optional filtering (v2.5).
        /// This runs in parallel with the MessageReceived event.
        /// Requires V25Features.EnableAsyncMessageStreams = true.
        /// </summary>
        /// <param name="messageFilter">Optional filter predicate for messages.</param>
        /// <param name="cancellationToken">Token to cancel the stream.</param>
        /// <returns>Async enumerable of filtered message received events.</returns>
        /// <exception cref="InvalidOperationException">If async streaming is not enabled.</exception>
        /// <exception cref="ObjectDisposedException">If the session is disposed.</exception>
        public async IAsyncEnumerable<MessageReceivedEventArgs> GetFilteredMessageStreamAsync(
            Func<MessageReceivedEventArgs, bool>? messageFilter = null,
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            
            if (!_asyncStreamingEnabled || _messageReader == null)
            {
                throw new InvalidOperationException(
                    "Async message streaming is not enabled. Enable V25Features.EnableAsyncMessageStreams.");
            }

            await foreach (var message in _messageReader.ReadAllAsync(cancellationToken))
            {
                if (messageFilter == null || messageFilter(message))
                {
                    yield return message;
                }
            }
        }

        /// <summary> Checks if disposed and throws. </summary>
        private void ThrowIfDisposed()
        {
            if (_disposedFlag == 1)
                throw new ObjectDisposedException(nameof(ChatSession));
        }

        /// <summary> Cleans up resources. </summary>
        protected virtual void Dispose(bool disposing)
        {
            // Use Interlocked to ensure thread-safe disposal check
            if (Interlocked.Exchange(ref _disposedFlag, 1) == 1)
                return; // Already disposed

            if (disposing)
            {
                SemaphoreSlim? lockToDispose = null;

                try
                {
                    // Try to acquire the lock with a timeout
                    bool lockAcquired = false;
                    try
                    {
                        lockAcquired = _sessionLock.Wait(TimeSpan.FromSeconds(2));
                    }
                    catch (ObjectDisposedException)
                    {
                        // Lock is already disposed, skip cleanup that requires the lock
                        return;
                    }

                    try
                    {
                        if (lockAcquired)
                        {
                            // Clear the crypto session
                            _cryptoSession = null!;

                            // Clear message history
                            ClearMessageHistoryInternal();

                            // Close message stream channel (v2.5)
                            if (_asyncStreamingEnabled && _messageWriter != null)
                            {
                                try
                                {
                                    _messageWriter.Complete();
                                }
                                catch (Exception)
                                {
                                    // Ignore channel completion errors
                                }
                            }

                            // Dispose message batcher (v2.5)
                            if (_batchingEnabled && _messageBatcher != null)
                            {
                                try
                                {
                                    _messageBatcher.Dispose();
                                }
                                catch (Exception)
                                {
                                    // Ignore batcher disposal errors
                                }
                            }

                            // Update state
                            State = SessionState.Terminated;

                            // Store reference to dispose later (outside the lock)
                            lockToDispose = _sessionLock;
                        }
                    }
                    finally
                    {
                        if (lockAcquired)
                        {
                            try
                            {
                                _sessionLock.Release();
                            }
                            catch (ObjectDisposedException)
                            {
                                // Already disposed by another thread
                            }
                        }
                    }
                }
                finally
                {
                    // Dispose the semaphore outside of any lock usage
                    try
                    {
                        lockToDispose?.Dispose();
                    }
                    catch (ObjectDisposedException)
                    {
                        // Already disposed
                    }
                }
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}