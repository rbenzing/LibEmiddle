using LibEmiddle.Abstractions;
using LibEmiddle.Core;
using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;
using LibEmiddle.Messaging.Chat;

namespace LibEmiddle.Protocol
{
    /// <summary>
    /// A protocol adapter that bridges X3DH and Double Ratchet protocols for seamless
    /// encrypted chat session management following Signal Protocol v3 specification.
    /// </summary>
    /// <remarks>
    /// This class simplifies the integration between X3DH (for initial key exchange) and
    /// Double Ratchet (for ongoing message encryption), ensuring proper Signal Protocol
    /// compliance with single root seed derivation.
    /// </remarks>
    public class ProtocolAdapter
    {
        private readonly IX3DHProtocol _x3dhProtocol;
        private readonly IDoubleRatchetProtocol _doubleRatchetProtocol;
        private readonly ICryptoProvider _cryptoProvider;

        /// <summary>
        /// Initializes a new instance of the ProtocolAdapter class.
        /// </summary>
        /// <param name="x3dhProtocol">The X3DH protocol implementation.</param>
        /// <param name="doubleRatchetProtocol">The Double Ratchet protocol implementation.</param>
        /// <param name="cryptoProvider">The cryptographic provider.</param>
        public ProtocolAdapter(
            IX3DHProtocol x3dhProtocol,
            IDoubleRatchetProtocol doubleRatchetProtocol,
            ICryptoProvider cryptoProvider)
        {
            _x3dhProtocol = x3dhProtocol ?? throw new ArgumentNullException(nameof(x3dhProtocol));
            _doubleRatchetProtocol = doubleRatchetProtocol ?? throw new ArgumentNullException(nameof(doubleRatchetProtocol));
            _cryptoProvider = cryptoProvider ?? throw new ArgumentNullException(nameof(cryptoProvider));
        }

        /// <summary>
        /// Prepares a session as the sender (Alice) using X3DH and DoubleRatchet protocols.
        /// Now uses Signal-compliant single root seed derivation.
        /// </summary>
        /// <param name="recipientBundle">The recipient's X3DH key bundle.</param>
        /// <param name="senderIdentityKeyPair">The sender's identity key pair.</param>
        /// <param name="sessionId">Unique identifier for this session.</param>
        /// <returns>A tuple containing the DoubleRatchet session and the X3DH message data to send.</returns>
        public async Task<(DoubleRatchetSession Session, InitialMessageData MessageData)> PrepareSenderSessionAsync(
            X3DHPublicBundle recipientBundle,
            KeyPair senderIdentityKeyPair,
            string sessionId)
        {
            try
            {
                LoggingManager.LogDebug(nameof(ProtocolAdapter), "Preparing sender session with Signal-compliant X3DH and Double Ratchet");

                // Validate inputs
                ArgumentNullException.ThrowIfNull(recipientBundle, nameof(recipientBundle));
                ArgumentNullException.ThrowIfNull(senderIdentityKeyPair, nameof(senderIdentityKeyPair));
                ArgumentException.ThrowIfNullOrEmpty(sessionId, nameof(sessionId));

                // Validate the bundle
                if (!await _x3dhProtocol.ValidateKeyBundleAsync(recipientBundle))
                {
                    throw new ArgumentException("Invalid recipient key bundle", nameof(recipientBundle));
                }

                // Ensure required keys are present
                if (recipientBundle.SignedPreKey == null)
                {
                    throw new ArgumentException("Recipient bundle missing signed prekey", nameof(recipientBundle));
                }

                // Step 1: Perform X3DH key agreement as the sender
                var x3dhResult = await _x3dhProtocol.InitiateSessionAsSenderAsync(
                    recipientBundle,
                    senderIdentityKeyPair);

                if (x3dhResult?.SharedKey == null || x3dhResult.SharedKey.Length != 32)
                {
                    throw new InvalidOperationException("X3DH key agreement failed or produced invalid shared key");
                }

                // Step 2: Initialize Double Ratchet with the shared key from X3DH
                // UPDATED: This now uses our Signal-compliant initialization that calls DeriveInitialSessionKeys()
                var session = _doubleRatchetProtocol.InitializeSessionAsSenderAsync(
                    x3dhResult.SharedKey,
                    recipientBundle.SignedPreKey, // Use recipient's signed prekey as their initial ratchet key
                    sessionId);

                LoggingManager.LogInformation(nameof(ProtocolAdapter),
                    $"Successfully prepared Signal-compliant sender session {sessionId}");

                return (session, x3dhResult.MessageDataToSend);
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(ProtocolAdapter),
                    $"Failed to prepare sender session {sessionId}: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Prepares a session as the receiver (Bob) using X3DH and DoubleRatchet protocols.
        /// Now uses Signal-compliant single root seed derivation.
        /// </summary>
        /// <param name="initialMessage">The initial message from the sender containing X3DH data.</param>
        /// <param name="receiverKeyBundle">The receiver's complete X3DH key bundle.</param>
        /// <param name="sessionId">Unique identifier for this session.</param>
        /// <returns>The initialized DoubleRatchet session.</returns>
        public async Task<DoubleRatchetSession> PrepareReceiverSessionAsync(
            InitialMessageData initialMessage,
            X3DHKeyBundle receiverKeyBundle,
            string sessionId)
        {
            try
            {
                LoggingManager.LogDebug(nameof(ProtocolAdapter), "Preparing receiver session with Signal-compliant X3DH and Double Ratchet");

                // Validate inputs
                ArgumentNullException.ThrowIfNull(initialMessage, nameof(initialMessage));
                ArgumentNullException.ThrowIfNull(receiverKeyBundle, nameof(receiverKeyBundle));
                ArgumentException.ThrowIfNullOrEmpty(sessionId, nameof(sessionId));

                if (!initialMessage.IsValid())
                {
                    throw new ArgumentException("Invalid initial message data", nameof(initialMessage));
                }

                // Step 1: Process X3DH initial message to derive shared key
                byte[] sharedKey = await _x3dhProtocol.EstablishSessionAsReceiverAsync(
                    initialMessage,
                    receiverKeyBundle);

                if (sharedKey?.Length != 32) // 32 bytes = 256 bits
                {
                    throw new InvalidOperationException("X3DH key agreement produced invalid shared key");
                }

                // Step 2: Get the signed prekey private key for Double Ratchet initialization
                byte[]? signedPreKeyPrivate = receiverKeyBundle.GetSignedPreKeyPrivate();
                if (signedPreKeyPrivate == null)
                {
                    throw new InvalidOperationException("Missing signed prekey private key in receiver bundle");
                }

                // Create KeyPair for the signed prekey
                var signedPreKeyPair = new KeyPair
                {
                    PublicKey = receiverKeyBundle.SignedPreKey,
                    PrivateKey = signedPreKeyPrivate
                };

                // Step 3: Initialize Double Ratchet with the shared key from X3DH
                // UPDATED: This now uses our Signal-compliant initialization that calls DeriveInitialSessionKeys()
                var session = _doubleRatchetProtocol.InitializeSessionAsReceiverAsync(
                    sharedKey,
                    signedPreKeyPair,
                    initialMessage.SenderEphemeralKeyPublic, // Sender's ephemeral key from X3DH
                    sessionId);

                LoggingManager.LogInformation(nameof(ProtocolAdapter),
                    $"Successfully prepared Signal-compliant receiver session {sessionId}");

                return session;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(ProtocolAdapter),
                    $"Failed to prepare receiver session {sessionId}: {ex.Message}");
                throw;
            }
            finally
            {
                // Note: sharedKey ownership is transferred to DoubleRatchet, it will handle clearing
            }
        }

        /// <summary>
        /// Creates a complete ChatSession as the sender with properly integrated protocols.
        /// This is the recommended way to create sessions for end-users.
        /// </summary>
        /// <param name="recipientBundle">The recipient's X3DH key bundle.</param>
        /// <param name="senderIdentityKeyPair">The sender's identity key pair.</param>
        /// <param name="options">Optional chat session configuration.</param>
        /// <returns>A fully initialized ChatSession ready for messaging.</returns>
        public async Task<ChatSession> CreateSenderChatSessionAsync(
            X3DHPublicBundle recipientBundle,
            KeyPair senderIdentityKeyPair,
            ChatSessionOptions? options = null)
        {
            string sessionId = Guid.NewGuid().ToString();

            // Prepare the session using our Signal-compliant protocols
            var (doubleRatchetSession, initialMessageData) = await PrepareSenderSessionAsync(
                recipientBundle, senderIdentityKeyPair, sessionId);

            // Create ChatSession with the initialized Double Ratchet session
            var chatSession = new ChatSession(
                doubleRatchetSession,
                recipientBundle.IdentityKey, // Remote public key
                senderIdentityKeyPair.PublicKey, // Local public key
                _doubleRatchetProtocol);

            // Set the initial message data for X3DH handshake
            chatSession.SetInitialMessageData(initialMessageData);

            LoggingManager.LogInformation(nameof(ProtocolAdapter),
                $"Created sender chat session {sessionId}");

            return chatSession;
        }

        /// <summary>
        /// Creates a complete ChatSession as the receiver with properly integrated protocols.
        /// This is the recommended way to create sessions for end-users.
        /// </summary>
        /// <param name="initialMessage">The initial message from the sender containing X3DH data.</param>
        /// <param name="receiverKeyBundle">The receiver's complete X3DH key bundle.</param>
        /// <param name="options">Optional chat session configuration.</param>
        /// <returns>A fully initialized ChatSession ready for messaging.</returns>
        public async Task<ChatSession> CreateReceiverChatSessionAsync(
            InitialMessageData initialMessage,
            X3DHKeyBundle receiverKeyBundle,
            ChatSessionOptions? options = null)
        {
            string sessionId = Guid.NewGuid().ToString();

            // Prepare the session using our Signal-compliant protocols
            var doubleRatchetSession = await PrepareReceiverSessionAsync(
                initialMessage, receiverKeyBundle, sessionId);

            // Create ChatSession with the initialized Double Ratchet session
            var chatSession = new ChatSession(
                doubleRatchetSession,
                initialMessage.SenderIdentityKeyPublic, // Remote public key
                receiverKeyBundle.IdentityKey, // Local public key
                _doubleRatchetProtocol);

            LoggingManager.LogInformation(nameof(ProtocolAdapter),
                $"Created receiver chat session {sessionId}");

            return chatSession;
        }

        /// <summary>
        /// Extracts the initial message data from a mailbox message used for X3DH key exchange.
        /// Enhanced with better validation and error handling.
        /// </summary>
        /// <param name="mailboxMessage">The mailbox message containing the X3DH initial message.</param>
        /// <returns>The extracted InitialMessageData or null if invalid.</returns>
        public InitialMessageData? ExtractInitialMessageData(MailboxMessage mailboxMessage)
        {
            try
            {
                if (mailboxMessage?.Type != MessageType.KeyExchange || mailboxMessage.Metadata == null)
                {
                    LoggingManager.LogDebug(nameof(ProtocolAdapter), "Message is not a key exchange message");
                    return null;
                }

                // Extract required fields
                if (!mailboxMessage.Metadata.TryGetValue("SenderIdentityKey", out var senderIdKeyBase64) ||
                    !mailboxMessage.Metadata.TryGetValue("SenderEphemeralKey", out var senderEphKeyBase64) ||
                    !mailboxMessage.Metadata.TryGetValue("SignedPreKeyId", out var signedPreKeyIdStr))
                {
                    LoggingManager.LogWarning(nameof(ProtocolAdapter),
                        "Missing required X3DH data in key exchange message");
                    return null;
                }

                // Validate and parse the values
                if (string.IsNullOrEmpty(senderIdKeyBase64) ||
                    string.IsNullOrEmpty(senderEphKeyBase64) ||
                    string.IsNullOrEmpty(signedPreKeyIdStr))
                {
                    LoggingManager.LogWarning(nameof(ProtocolAdapter),
                        "Empty X3DH data fields in key exchange message");
                    return null;
                }

                byte[] senderIdentityKey = Convert.FromBase64String(senderIdKeyBase64);
                byte[] senderEphemeralKey = Convert.FromBase64String(senderEphKeyBase64);

                if (!uint.TryParse(signedPreKeyIdStr, out uint signedPreKeyId) || signedPreKeyId == 0)
                {
                    LoggingManager.LogWarning(nameof(ProtocolAdapter),
                        "Invalid signed prekey ID in key exchange message");
                    return null;
                }

                // Validate key sizes
                if (senderIdentityKey.Length != Constants.ED25519_PUBLIC_KEY_SIZE ||
                    senderEphemeralKey.Length != Constants.X25519_KEY_SIZE)
                {
                    LoggingManager.LogWarning(nameof(ProtocolAdapter),
                        "Invalid key sizes in key exchange message");
                    return null;
                }

                // Optional one-time prekey ID
                uint? oneTimePreKeyId = null;
                if (mailboxMessage.Metadata.TryGetValue("OneTimePreKeyId", out var oneTimePreKeyIdStr) &&
                    !string.IsNullOrEmpty(oneTimePreKeyIdStr))
                {
                    if (uint.TryParse(oneTimePreKeyIdStr, out uint opkId) && opkId != 0)
                    {
                        oneTimePreKeyId = opkId;
                    }
                }

                var initialMessage = new InitialMessageData(
                    senderIdentityKey,
                    senderEphemeralKey,
                    signedPreKeyId,
                    oneTimePreKeyId);

                // Final validation
                if (!initialMessage.IsValid())
                {
                    LoggingManager.LogWarning(nameof(ProtocolAdapter),
                        "Extracted initial message data failed validation");
                    return null;
                }

                return initialMessage;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(ProtocolAdapter),
                    $"Failed to extract X3DH initial message data: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Creates a mailbox message containing X3DH initial message data for key exchange.
        /// Enhanced with better validation.
        /// </summary>
        /// <param name="initialMessageData">The X3DH initial message data.</param>
        /// <param name="recipientKey">The recipient's identity key.</param>
        /// <param name="senderKey">The sender's identity key.</param>
        /// <returns>A mailbox message ready to be sent.</returns>
        public MailboxMessage CreateKeyExchangeMessage(
            InitialMessageData initialMessageData,
            byte[] recipientKey,
            byte[] senderKey)
        {
            try
            {
                ArgumentNullException.ThrowIfNull(initialMessageData, nameof(initialMessageData));
                ArgumentNullException.ThrowIfNull(recipientKey, nameof(recipientKey));
                ArgumentNullException.ThrowIfNull(senderKey, nameof(senderKey));

                if (!initialMessageData.IsValid())
                {
                    throw new ArgumentException("Invalid initial message data", nameof(initialMessageData));
                }

                var message = new MailboxMessage(
                    recipientKey,
                    senderKey,
                    new EncryptedMessage()) // Empty encrypted message for key exchange
                {
                    Type = MessageType.KeyExchange,
                    Metadata = new Dictionary<string, string>
                    {
                        ["SenderIdentityKey"] = Convert.ToBase64String(initialMessageData.SenderIdentityKeyPublic),
                        ["SenderEphemeralKey"] = Convert.ToBase64String(initialMessageData.SenderEphemeralKeyPublic),
                        ["SignedPreKeyId"] = initialMessageData.RecipientSignedPreKeyId.ToString(),
                        ["ProtocolVersion"] = ProtocolVersion.FULL_VERSION // Add version for compatibility
                    }
                };

                // Add one-time prekey ID if present
                if (initialMessageData.RecipientOneTimePreKeyId.HasValue)
                {
                    message.Metadata["OneTimePreKeyId"] = initialMessageData.RecipientOneTimePreKeyId.Value.ToString();
                }

                return message;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(ProtocolAdapter),
                    $"Failed to create key exchange message: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Validates that the adapter is properly configured with Signal-compliant protocols.
        /// </summary>
        /// <returns>True if the adapter is ready for use.</returns>
        public bool IsConfiguredProperly()
        {
            try
            {
                // Basic null checks
                if (_x3dhProtocol == null || _doubleRatchetProtocol == null || _cryptoProvider == null)
                {
                    return false;
                }

                // Could add more sophisticated validation here if needed
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}

// =======================================================================================
// EXAMPLE USAGE: How to use the updated ProtocolAdapter
// =======================================================================================

/*
public class ExampleUsage
{
    private readonly ProtocolAdapter _protocolAdapter;

    public ExampleUsage(ProtocolAdapter protocolAdapter)
    {
        _protocolAdapter = protocolAdapter;
    }

    // Alice wants to start a conversation with Bob
    public async Task<ChatSession> StartConversationAsync(X3DHPublicBundle bobBundle, KeyPair aliceIdentity)
    {
        // This creates a complete ChatSession ready for messaging
        // All the X3DH + Double Ratchet integration is handled internally
        var aliceChatSession = await _protocolAdapter.CreateSenderChatSessionAsync(
            bobBundle, 
            aliceIdentity);

        // Alice can now send messages
        var encryptedMessage = await aliceChatSession.EncryptAsync("Hello Bob!");
        
        return aliceChatSession;
    }

    // Bob receives Alice's key exchange and creates his session
    public async Task<ChatSession> ReceiveConversationAsync(
        InitialMessageData aliceInitialMessage, 
        X3DHKeyBundle bobBundle)
    {
        // This creates a complete ChatSession ready for messaging
        // All the X3DH + Double Ratchet integration is handled internally
        var bobChatSession = await _protocolAdapter.CreateReceiverChatSessionAsync(
            aliceInitialMessage, 
            bobBundle);

        // Bob can now receive and send messages
        return bobChatSession;
    }

    // Lower-level usage if you need more control
    public async Task<DoubleRatchetSession> LowerLevelUsageAsync(
        X3DHPublicBundle recipientBundle,
        KeyPair senderIdentity)
    {
        // Get just the Double Ratchet session without ChatSession wrapper
        var (session, initialMessageData) = await _protocolAdapter.PrepareSenderSessionAsync(
            recipientBundle, 
            senderIdentity, 
            Guid.NewGuid().ToString());

        // Handle initialMessageData separately (e.g., send via mailbox)
        return session;
    }
}
*/