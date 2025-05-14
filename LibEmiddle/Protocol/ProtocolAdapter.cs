using LibEmiddle.Abstractions;
using LibEmiddle.Core;
using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;
using LibEmiddle.Messaging.Chat;
using Microsoft.Extensions.Logging;

namespace LibEmiddle.Protocol
{
    /// <summary>
    /// A protocol adapter that bridges X3DH and Double Ratchet protocols for seamless
    /// encrypted chat session management.
    /// </summary>
    /// <remarks>
    /// This class simplifies the integration between X3DH (for initial key exchange) and
    /// Double Ratchet (for ongoing message encryption), making it easier to create
    /// secure sessions with proper protocol flows.
    /// </remarks>
    /// <remarks>
    /// Initializes a new instance of the ProtocolAdapter class.
    /// </remarks>
    /// <param name="x3dhProtocol">The X3DH protocol implementation.</param>
    /// <param name="doubleRatchetProtocol">The Double Ratchet protocol implementation.</param>
    /// <param name="cryptoProvider">The cryptographic provider.</param>
    public class ProtocolAdapter(
        IX3DHProtocol x3dhProtocol,
        IDoubleRatchetProtocol doubleRatchetProtocol,
        ICryptoProvider cryptoProvider)
    {
        private readonly IX3DHProtocol _x3dhProtocol = x3dhProtocol ?? throw new ArgumentNullException(nameof(x3dhProtocol));
        private readonly IDoubleRatchetProtocol _doubleRatchetProtocol = doubleRatchetProtocol ?? throw new ArgumentNullException(nameof(doubleRatchetProtocol));
        private readonly ICryptoProvider _cryptoProvider = cryptoProvider ?? throw new ArgumentNullException(nameof(cryptoProvider));

        /// <summary>
        /// Prepares a session as the sender (Alice) using X3DH and DoubleRatchet protocols.
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
                LoggingManager.LogDebug("ProtocolAdapter", "Preparing sender session with X3DH and Double Ratchet");

                // Validate the bundle
                if (!await _x3dhProtocol.ValidateKeyBundleAsync(recipientBundle))
                {
                    throw new ArgumentException("Invalid recipient key bundle", nameof(recipientBundle));
                }

                // Step 1: Perform X3DH key agreement as the sender
                var x3dhResult = await _x3dhProtocol.InitiateSessionAsSenderAsync(
                    recipientBundle,
                    senderIdentityKeyPair);

                if (x3dhResult == null || x3dhResult.SharedKey == null)
                {
                    throw new InvalidOperationException("X3DH key agreement failed");
                }

                // Step 2: Initialize Double Ratchet with the shared key from X3DH
                var session = await _doubleRatchetProtocol.InitializeSessionAsSenderAsync(
                    x3dhResult.SharedKey,
                    recipientBundle.SignedPreKey!, // Use recipient's signed prekey as their initial ratchet key
                    sessionId);

                LoggingManager.LogInformation("ProtocolAdapter", $"Successfully prepared sender session {sessionId}");

                return (session, x3dhResult.MessageDataToSend);
            }
            catch (Exception ex)
            {
                LoggingManager.LogError("ProtocolAdapter", $"Failed to prepare sender session {sessionId}", ex);
                throw;
            }
        }

        /// <summary>
        /// Prepares a session as the receiver (Bob) using X3DH and DoubleRatchet protocols.
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
                LoggingManager.LogDebug("ProtocolAdapter", "Preparing receiver session with X3DH and Double Ratchet");

                // Step 1: Process X3DH initial message to derive shared key
                byte[] sharedKey = await _x3dhProtocol.EstablishSessionAsReceiverAsync(
                    initialMessage,
                    receiverKeyBundle);

                if (sharedKey.Length != 32) // 32 bytes = 256 bits
                {
                    throw new InvalidOperationException("X3DH key agreement produced invalid shared key");
                }

                // Step 2: Create a KeyPair for the signed prekey
                KeyPair signedPreKeyPair = new KeyPair
                {
                    PublicKey = receiverKeyBundle.SignedPreKey,
                    PrivateKey = receiverKeyBundle.GetSignedPreKeyPrivate() ??
                        throw new InvalidOperationException("Missing signed prekey private key")
                };

                // Step 3: Initialize Double Ratchet with the shared key from X3DH
                var session = await _doubleRatchetProtocol.InitializeSessionAsReceiverAsync(
                    sharedKey,
                    signedPreKeyPair,
                    initialMessage.SenderEphemeralKeyPublic!, // Sender's ephemeral key from X3DH
                    sessionId);

                LoggingManager.LogInformation("ProtocolAdapter", $"Successfully prepared receiver session {sessionId}");

                return session;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError("ProtocolAdapter", $"Failed to prepare receiver session {sessionId}", ex);
                throw;
            }
        }

        /// <summary>
        /// Extracts the initial message data from a mailbox message used for X3DH key exchange.
        /// </summary>
        /// <param name="mailboxMessage">The mailbox message containing the X3DH initial message.</param>
        /// <returns>The extracted InitialMessageData or null if invalid.</returns>
        public InitialMessageData? ExtractInitialMessageData(MailboxMessage mailboxMessage)
        {
            try
            {
                if (mailboxMessage.Type != MessageType.KeyExchange || mailboxMessage.Metadata == null)
                {
                    return null;
                }

                if (!mailboxMessage.Metadata.TryGetValue("SenderIdentityKey", out var senderIdKeyBase64) ||
                    !mailboxMessage.Metadata.TryGetValue("SenderEphemeralKey", out var senderEphKeyBase64) ||
                    !mailboxMessage.Metadata.TryGetValue("SignedPreKeyId", out var signedPreKeyIdStr))
                {
                    LoggingManager.LogWarning("ProtocolAdapter", "Missing required X3DH data in key exchange message");
                    return null;
                }

                // Parse the values
                byte[] senderIdentityKey = Convert.FromBase64String(senderIdKeyBase64);
                byte[] senderEphemeralKey = Convert.FromBase64String(senderEphKeyBase64);
                uint signedPreKeyId = uint.Parse(signedPreKeyIdStr);

                // Optional one-time prekey ID
                uint? oneTimePreKeyId = null;
                if (mailboxMessage.Metadata.TryGetValue("OneTimePreKeyId", out var oneTimePreKeyIdStr))
                {
                    oneTimePreKeyId = uint.Parse(oneTimePreKeyIdStr);
                }

                return new InitialMessageData(
                    senderIdentityKey,
                    senderEphemeralKey,
                    signedPreKeyId,
                    oneTimePreKeyId);
            }
            catch (Exception ex)
            {
                LoggingManager.LogError("ProtocolAdapter", "Failed to extract X3DH initial message data", ex);
                return null;
            }
        }

        /// <summary>
        /// Creates a mailbox message containing X3DH initial message data for key exchange.
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
                        ["SignedPreKeyId"] = initialMessageData.RecipientSignedPreKeyId.ToString()
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
                LoggingManager.LogError("ProtocolAdapter", "Failed to create key exchange message", ex);
                throw;
            }
        }
    }
}