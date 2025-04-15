using System.Collections.Concurrent;
using System.Security.Cryptography;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;

namespace LibEmiddle.Messaging.Chat
{
    /// <summary>
    /// Represents an end-to-end encrypted chat session with a remote party,
    /// managing Double Ratchet state, message history, and session lifecycle.
    /// </summary>
    public class ChatSession : IDisposable
    {
        // Underlying cryptographic session state (immutable)
        private DoubleRatchetSession _cryptoSession; // Holds the CURRENT immutable state

        // Lock for thread-safe access and updates to mutable fields (_cryptoSession reference, State, Timestamps, History)
        private readonly SemaphoreSlim _sessionLock = new SemaphoreSlim(1, 1);
        private bool _disposed;

        // --- Session Metadata (Mostly Immutable) ---
        public string SessionId { get; }
        public byte[] RemotePublicKey { get; } // Remote party's Identity Key (Ed25519)
        public byte[] LocalPublicKey { get; } // Our Identity Key (Ed25519)
        public DateTime CreatedAt { get; }

        // --- Mutable State (Managed under _sessionLock) ---
        public Enums.ChatSessionState State { get; private set; }
        public DateTime? LastMessageSentAt { get; private set; }
        public DateTime? LastMessageReceivedAt { get; private set; }
        public DateTime? LastActivatedAt { get; private set; }
        public DateTime? LastSuspendedAt { get; private set; }
        public string? SuspensionReason { get; private set; }
        public Enums.KeyRotationStrategy RotationStrategy { get; set; } = Enums.KeyRotationStrategy.Standard;
        public Dictionary<string, string> Metadata { get; } = new Dictionary<string, string>();

        // --- Message History ---
        // ConcurrentQueue is generally thread-safe for Enqueue/Dequeue, but access for Get might need care if combined with state changes.
        private readonly ConcurrentQueue<MessageRecord> _messageHistory = new();

        /// <summary>
        /// Event raised when the session state changes (e.g., Active, Suspended).
        /// </summary>
        public event EventHandler<ChatSessionStateChangedEventArgs>? StateChanged;


        /// <summary>
        /// Creates a new chat session. Called by ChatSessionManager after X3DH/DR initialization.
        /// </summary>
        /// <param name="initialCryptoSession">The initial Double Ratchet session state.</param>
        /// <param name="remotePublicKey">Remote party's public identity key (Ed25519).</param>
        /// <param name="localPublicKey">Local user's public identity key (Ed25519).</param>
        /// <exception cref="ArgumentNullException">Thrown if required parameters are null.</exception>
        public ChatSession(
            DoubleRatchetSession initialCryptoSession,
            byte[] remotePublicKey,
            byte[] localPublicKey)
        {
            _cryptoSession = initialCryptoSession ?? throw new ArgumentNullException(nameof(initialCryptoSession));
            RemotePublicKey = remotePublicKey ?? throw new ArgumentNullException(nameof(remotePublicKey));
            LocalPublicKey = localPublicKey ?? throw new ArgumentNullException(nameof(localPublicKey));

            // Use SessionId from the crypto session
            SessionId = _cryptoSession.SessionId;
            CreatedAt = DateTime.UtcNow;
            State = Enums.ChatSessionState.Initialized; // Start as initialized, activate on first use
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

        // --- State Management ---

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
                if (State == Enums.ChatSessionState.Terminated)
                    throw new InvalidOperationException("Cannot activate a terminated session.");
                if (State == Enums.ChatSessionState.Active)
                    return false; // Already active

                var previousState = State;
                State = Enums.ChatSessionState.Active;
                LastActivatedAt = DateTime.UtcNow;
                SuspensionReason = null; // Clear suspension reason on activation
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
                if (State == Enums.ChatSessionState.Terminated)
                    throw new InvalidOperationException("Cannot suspend a terminated session.");
                if (State == Enums.ChatSessionState.Suspended)
                    return false; // Already suspended

                var previousState = State;
                State = Enums.ChatSessionState.Suspended;
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
                if (State == Enums.ChatSessionState.Terminated)
                    return false; // Already terminated

                var previousState = State;
                State = Enums.ChatSessionState.Terminated;

                // Clear sensitive crypto state reference
                // The actual DoubleRatchetSession object might have its own Dispose/Clear method
                // but we remove our reference to it.
                _cryptoSession = null!; // Set to null, suppress nullable warning as state is Terminated

                // Optionally clear message history on termination
                // ClearMessageHistoryInternal(); // Call helper if needed

                OnStateChanged(previousState, State);
                return true;
            }
            finally
            {
                _sessionLock.Release();
            }
        }

        // --- Encrypt / Decrypt ---

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
            if (string.IsNullOrEmpty(message))
                throw new ArgumentException("Message cannot be null or empty.", nameof(message));

            await _sessionLock.WaitAsync();
            try
            {
                // --- State Checks ---
                if (State == Enums.ChatSessionState.Terminated)
                    throw new InvalidOperationException("Cannot encrypt: Session is terminated.");
                if (State == Enums.ChatSessionState.Suspended)
                    throw new InvalidOperationException($"Cannot encrypt: Session is suspended. Reason: {SuspensionReason ?? "Unknown"}");

                // Auto-activate if needed
                if (State == Enums.ChatSessionState.Initialized)
                {
                    var previousState = State;
                    State = Enums.ChatSessionState.Active;
                    LastActivatedAt = DateTime.UtcNow;
                    SuspensionReason = null;
                    OnStateChanged(previousState, State);
                    LoggingManager.LogDebug(nameof(ChatSession), $"Session {SessionId} auto-activated by sending.");
                }

                var currentCryptoSession = _cryptoSession; // Read current state reference
                if (currentCryptoSession == null) // Should not happen if not terminated, but check
                    throw new InvalidOperationException("Cannot encrypt: Cryptographic session state is missing.");


                // --- Perform Double Ratchet Encryption ---
                var (updatedSession, encryptedMessage) = await DoubleRatchet.DoubleRatchetEncryptAsync(
                    currentCryptoSession, message, RotationStrategy);

                // --- Update State ---
                if (updatedSession == null || encryptedMessage == null)
                {
                    // Encryption failed in DoubleRatchet layer (error should have been logged there)
                    // Optionally transition session to an error state here? Or just return null.
                    LoggingManager.LogError(nameof(ChatSession), $"Encryption failed for session {SessionId}. DoubleRatchet returned null.");
                    return null; // Indicate failure
                }

                // IMPORTANT: Update the internal state reference to the new immutable object
                _cryptoSession = updatedSession;

                // Track message send time
                LastMessageSentAt = DateTime.UtcNow;

                // Add to message history (optional)
                _messageHistory.Enqueue(new MessageRecord
                {
                    IsOutgoing = true,
                    Timestamp = DateTime.UtcNow, // Consider using timestamp from encryptedMessage if needed
                    Content = message, // Store plaintext for local history
                    EncryptedMessage = encryptedMessage // Store ciphertext details
                });

                return encryptedMessage;
            }
            // Catch specific expected exceptions if necessary
            // catch (CryptographicException cex) { ... }
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
            // Validate incoming message structure minimally
            if (encryptedMessage.Ciphertext == null || encryptedMessage.Nonce == null || encryptedMessage.SenderDHKey == null)
                throw new ArgumentException("Encrypted message is missing required fields for decryption.", nameof(encryptedMessage));
            if (encryptedMessage.SessionId != this.SessionId)
            {
                LoggingManager.LogWarning(nameof(ChatSession), $"Message Session ID '{encryptedMessage.SessionId}' does not match current session '{this.SessionId}'. Discarding.");
                return null; // Message not for this session
            }

            await _sessionLock.WaitAsync();
            try
            {
                // --- State Checks ---
                if (State == Enums.ChatSessionState.Terminated)
                    throw new InvalidOperationException("Cannot decrypt: Session is terminated.");

                // Allow decryption even if Suspended, but don't auto-activate
                // Auto-activate if needed and NOT suspended
                if (State == Enums.ChatSessionState.Initialized)
                {
                    var previousState = State;
                    State = Enums.ChatSessionState.Active;
                    LastActivatedAt = DateTime.UtcNow;
                    SuspensionReason = null;
                    OnStateChanged(previousState, State);
                    LoggingManager.LogDebug(nameof(ChatSession), $"Session {SessionId} auto-activated by receiving.");
                }

                var currentCryptoSession = _cryptoSession; // Read current state reference
                if (currentCryptoSession == null)
                    throw new InvalidOperationException("Cannot decrypt: Cryptographic session state is missing.");

                // --- Perform Double Ratchet Decryption ---
                var (updatedSession, decryptedMessage) = await DoubleRatchet.DoubleRatchetDecryptAsync(
                    currentCryptoSession, encryptedMessage);


                // --- Update State ---
                if (updatedSession == null)
                {
                    // Decryption failed (e.g., bad MAC, replay, out-of-order beyond handling)
                    // DoubleRatchet layer should have logged the reason.
                    // Do NOT update the crypto session state on failure.
                    LoggingManager.LogWarning(nameof(ChatSession), $"Decryption failed for message {encryptedMessage.MessageId} in session {SessionId}.");
                    return null;
                }

                // Decryption SUCCESSFUL
                // IMPORTANT: Update the internal state reference
                _cryptoSession = updatedSession;

                // Track message receive time
                LastMessageReceivedAt = DateTime.UtcNow;

                // Add to message history (optional)
                _messageHistory.Enqueue(new MessageRecord
                {
                    IsOutgoing = false,
                    Timestamp = DateTime.UtcNow, // Or use timestamp from message?
                    Content = decryptedMessage, // Store plaintext
                    EncryptedMessage = encryptedMessage // Store original encrypted form
                });

                return decryptedMessage; // Return plaintext
            }
            // Catch specific expected exceptions if necessary
            // catch (CryptographicException cex) { ... }
            finally
            {
                _sessionLock.Release();
            }
        }

        // --- Other Methods ---

        /// <summary>
        /// Checks if the session is valid and not terminated or disposed.
        /// Performs basic checks on the crypto session state.
        /// </summary>
        public bool IsValid()
        {
            if (_disposed) return false;

            // No lock needed for reading volatile references and immutable state parts
            var currentCryptoSession = _cryptoSession; // Read reference
            var currentState = State; // Read current state

            return currentState != Enums.ChatSessionState.Terminated &&
                   currentCryptoSession != null &&
                   // Basic checks on the immutable session state
                   currentCryptoSession.RootKey?.Length == Constants.AES_KEY_SIZE &&
                   currentCryptoSession.RemoteDHRatchetKey?.Length == Constants.X25519_KEY_SIZE &&
                   currentCryptoSession.DHRatchetKeyPair.PublicKey?.Length == Constants.X25519_KEY_SIZE &&
                   currentCryptoSession.DHRatchetKeyPair.PrivateKey?.Length == Constants.X25519_KEY_SIZE &&
                   // Chain keys can be null initially
                   (currentCryptoSession.SendingChainKey == null || currentCryptoSession.SendingChainKey.Length == Constants.AES_KEY_SIZE) &&
                   (currentCryptoSession.ReceivingChainKey == null || currentCryptoSession.ReceivingChainKey.Length == Constants.AES_KEY_SIZE);
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
        protected virtual void OnStateChanged(Enums.ChatSessionState previousState, Enums.ChatSessionState newState)
        {
            // Ensure event handlers don't block lock if called from within lock
            Task.Run(() => StateChanged?.Invoke(this, new ChatSessionStateChangedEventArgs(previousState, newState)));
            // Or just invoke directly if handlers are known to be fast:
            // StateChanged?.Invoke(this, new ChatSessionStateChangedEventArgs(previousState, newState));
        }

        /// <summary> Checks if disposed and throws. </summary>
        private void ThrowIfDisposed()
        {
            if (_disposed) throw new ObjectDisposedException(nameof(ChatSession));
        }

        /// <summary> Cleans up resources. </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary> Cleans up resources. </summary>
        protected virtual void Dispose(bool disposing)
        {
            if (_disposed) return;

            if (disposing)
            {
                // Acquire lock one last time to safely clear state
                _sessionLock.Wait(); // Synchronous wait in Dispose
                try
                {
                    if (_disposed) return; // Check again after acquiring lock

                    // Clear sensitive data
                    // Consider calling a Clear method on DoubleRatchetSession if it exists
                    // to securely wipe internal keys before setting reference to null
                    _cryptoSession = null!; // Set reference to null

                    // Clear message history
                    ClearMessageHistoryInternal();

                    // Set state
                    var previousState = State;
                    State = Enums.ChatSessionState.Terminated;
                    if (previousState != Enums.ChatSessionState.Terminated)
                    {
                        // Don't raise event from Dispose if possible, or do it carefully
                        // OnStateChanged(previousState, State);
                    }

                    // Dispose disposable fields
                    _sessionLock.Dispose();

                    _disposed = true; // Set disposed flag inside lock
                }
                finally
                {
                    // Ensure lock is released even if errors occur during disposal
                    // _sessionLock.Release(); // Don't release if Wait() was used synchronously? Check SemaphoreSlim docs. Dispose handles it.
                }
            }
            // No finalizer needed if only managed resources
            _disposed = true; // Ensure flag is set even if not disposing managed state (e.g. called from finalizer if added)
        }

        // Remove finalizer if no unmanaged resources are directly owned
        // ~ChatSession() { Dispose(false); }
    }

    // --- Supporting Types (Ensure these exist) ---
    public class ChatSessionStateChangedEventArgs : EventArgs
    {
        public Enums.ChatSessionState PreviousState { get; }
        public Enums.ChatSessionState NewState { get; }
        public DateTime Timestamp { get; }
        public ChatSessionStateChangedEventArgs(Enums.ChatSessionState previous, Enums.ChatSessionState @new)
        { PreviousState = previous; NewState = @new; Timestamp = DateTime.UtcNow; }
    }
} // End namespace