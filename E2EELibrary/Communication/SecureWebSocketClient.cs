using System.Net.WebSockets;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using E2EELibrary.Models;
using E2EELibrary.Encryption;
using System.Text.Json;

namespace E2EELibrary.Communication
{
    /// <summary>
    /// Secure WebSocket client for encrypted communications
    /// </summary>
    public class SecureWebSocketClient
    {
        private readonly IWebSocketClient _webSocket;
        private readonly Uri _serverUri;
        private DoubleRatchetSession? _session = null;

        /// <summary>
        /// Creates a new secure WebSocket client
        /// </summary>
        /// <param name="serverUrl">Server URL</param>
        public SecureWebSocketClient(string serverUrl)
            : this(serverUrl, new StandardWebSocketClient())
        {
        }

        /// <summary>
        /// Creates a new secure WebSocket client with a provided WebSocket instance
        /// </summary>
        /// <param name="serverUrl">Server URL</param>
        /// <param name="webSocket">WebSocket client to use</param>
        public SecureWebSocketClient(string serverUrl, IWebSocketClient webSocket)
        {
            _serverUri = new Uri(serverUrl);
            _webSocket = webSocket ?? throw new ArgumentNullException(nameof(webSocket));
        }

        /// <summary>
        /// Connects to the server and establishes encrypted session
        /// </summary>
        public async Task ConnectAsync()
        {
            await _webSocket.ConnectAsync(_serverUri, CancellationToken.None);
        }

        /// <summary>
        /// Sets the Double Ratchet session for encrypted communication
        /// </summary>
        /// <param name="session">Double Ratchet session</param>
        public void SetSession(DoubleRatchetSession session)
        {
            _session = session;
        }

        /// <summary>
        /// Sends an encrypted message to the server
        /// </summary>
        /// <param name="message">Plain text message</param>
        public async Task SendEncryptedMessageAsync(string message, CancellationToken cancellationToken = default)
        {
            // Validate input parameters
            ArgumentNullException.ThrowIfNull(message, nameof(message));

            // Validate session state
            if (_session is null)
            {
                throw new InvalidOperationException("Session not established. Call SetSession first.");
            }

            // Validate WebSocket connection
            if (_webSocket is null || _webSocket.State != WebSocketState.Open)
            {
                throw new InvalidOperationException("WebSocket connection is not open.");
            }

            try
            {
                // Encrypt the message
                var (updatedSession, encryptedMessage) = DoubleRatchet.DoubleRatchetEncrypt(_session, message);

                // Validate the encryption result
                if (updatedSession is null)
                {
                    throw new CryptographicException("Encryption failed: null session returned.");
                }

                if (encryptedMessage is null ||
                    encryptedMessage.Ciphertext is null ||
                    encryptedMessage.Nonce is null ||
                    encryptedMessage.SenderDHKey is null)
                {
                    throw new CryptographicException("Encryption failed: incomplete encrypted message returned.");
                }

                // Update session only after successful encryption
                _session = updatedSession;

                // Set timestamp in the EncryptedMessage object for replay protection
                encryptedMessage.Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

                // Convert encrypted message to transportable format
                var messageData = new
                {
                    ciphertext = Convert.ToBase64String(encryptedMessage.Ciphertext),
                    nonce = Convert.ToBase64String(encryptedMessage.Nonce),
                    messageNumber = encryptedMessage.MessageNumber,
                    senderDHKey = Convert.ToBase64String(encryptedMessage.SenderDHKey),
                    timestamp = encryptedMessage.Timestamp,
                    messageId = encryptedMessage.MessageId.ToString(),
                    sessionId = encryptedMessage.SessionId
                };

                // Serialize with options for better formatting and security
                var options = new JsonSerializerOptions
                {
                    WriteIndented = false, // More compact for network transmission
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                    DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
                };

                string jsonMessage = JsonSerializer.Serialize(messageData, options);
                byte[] messageBytes = Encoding.UTF8.GetBytes(jsonMessage);

                // Send the message with cancellation support
                await _webSocket.SendAsync(
                    new ArraySegment<byte>(messageBytes),
                    WebSocketMessageType.Text,
                    true, // endOfMessage
                    cancellationToken);
            }
            catch (WebSocketException wsEx)
            {
                // Specific handling for WebSocket errors
                throw new WebSocketException($"WebSocket error while sending message: {wsEx.Message}", wsEx);
            }
            catch (OperationCanceledException)
            {
                // Pass through cancellation
                throw;
            }
            catch (Exception ex) when (
                ex is not InvalidOperationException &&
                ex is not ArgumentException &&
                ex is not WebSocketException &&
                ex is not CryptographicException)
            {
                // Wrap unexpected errors
                throw new Exception($"Error sending encrypted message: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Receives and decrypts a message from the server
        /// </summary>
        /// <returns>Decrypted message</returns>
        public async Task<string?> ReceiveEncryptedMessageAsync(CancellationToken cancellationToken = default)
        {
            if (_session is null)
            {
                throw new InvalidOperationException("Session not established. Call SetSession first.");
            }

            if (_webSocket is null || _webSocket.State != WebSocketState.Open)
            {
                throw new InvalidOperationException("WebSocket connection is not open.");
            }

            // Use a reasonably sized buffer
            byte[] buffer = new byte[8192];

            try
            {
                // Receive message with cancellation support
                WebSocketReceiveResult result = await _webSocket.ReceiveAsync(
                    new ArraySegment<byte>(buffer), cancellationToken);

                // Check if the socket was closed
                if (result.MessageType == WebSocketMessageType.Close)
                {
                    throw new WebSocketException("WebSocket connection was closed by the server.");
                }

                // Parse message - only use the bytes we actually received
                string json = Encoding.UTF8.GetString(buffer, 0, result.Count);

                // Add explicit type and options for better deserialization safety
                var options = new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                };

                Dictionary<string, object> messageData;

                try
                {
                    messageData = JsonSerializer.Deserialize<Dictionary<string, object>>(json, options);
                    if (messageData is null)
                    {
                        throw new FormatException("Failed to deserialize message data.");
                    }
                }
                catch (JsonException jsonEx)
                {
                    throw new FormatException(jsonEx.Message, jsonEx);
                }

                // Validate required fields exist
                if (!messageData.ContainsKey("ciphertext") ||
                    !messageData.ContainsKey("nonce") ||
                    !messageData.ContainsKey("messageNumber") ||
                    !messageData.ContainsKey("senderDHKey"))
                {
                    throw new FormatException("Message is missing required fields.");
                }

                // Safely extract values with null checking
                string? ciphertextBase64 = messageData["ciphertext"]?.ToString();
                string? nonceBase64 = messageData["nonce"]?.ToString();
                string? senderDHKeyBase64 = messageData["senderDHKey"]?.ToString();

                if (string.IsNullOrEmpty(ciphertextBase64) ||
                    string.IsNullOrEmpty(nonceBase64) ||
                    string.IsNullOrEmpty(senderDHKeyBase64))
                {
                    throw new FormatException("Message contains null or empty required fields.");
                }

                // Try-catch each conversion separately for better error messages
                byte[] ciphertext;
                byte[] nonce;
                byte[] senderDHKey;
                int messageNumber;
                long timestamp = 0;

                try
                {
                    ciphertext = Convert.FromBase64String(ciphertextBase64);
                }
                catch (FormatException)
                {
                    throw new FormatException("Invalid Base64 encoding for ciphertext.");
                }

                try
                {
                    nonce = Convert.FromBase64String(nonceBase64);
                }
                catch (FormatException)
                {
                    throw new FormatException("Invalid Base64 encoding for nonce.");
                }

                try
                {
                    senderDHKey = Convert.FromBase64String(senderDHKeyBase64);
                }
                catch (FormatException)
                {
                    throw new FormatException("Invalid Base64 encoding for senderDHKey.");
                }

                try
                {
                    // Use TryParse for safer conversion
                    if (!int.TryParse(messageData["messageNumber"]?.ToString(), out messageNumber))
                    {
                        throw new FormatException("Invalid message number format.");
                    }
                }
                catch (Exception ex)
                {
                    throw new FormatException($"Error parsing message number: {ex.Message}");
                }

                // Try to get timestamp if available
                if (messageData.TryGetValue("timestamp", out object? timestampPre) && timestampPre != null)
                {
                    if (!long.TryParse(messageData["timestamp"].ToString(), out timestamp))
                    {
                        // Log warning but don't throw - timestamp is useful but not critical
                        // In production, consider logging this: "Warning: Invalid timestamp format in message"
                    }
                    else
                    {
                        // Check if message is too old (5 minutes threshold for replay protection)
                        long currentTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                        if (timestamp > 0 && currentTime - timestamp > 5 * 60 * 1000)
                        {
                            throw new SecurityException("Message is too old (possible replay attack).");
                        }
                    }
                }

                // Try to get session ID if available
                if (messageData.TryGetValue("sessionId", out object? sessionId) && sessionId != null)
                {
                    sessionId = messageData["sessionId"];
                }

                ArgumentNullException.ThrowIfNull(sessionId);

                var encryptedMessage = new EncryptedMessage
                {
                    Ciphertext = ciphertext,
                    Nonce = nonce,
                    MessageNumber = messageNumber,
                    SenderDHKey = senderDHKey,
                    Timestamp = timestamp,
                    SessionId = sessionId.ToString(),
                };

                // Try to get message ID if available
                if (messageData.ContainsKey("messageId") && messageData["messageId"] != null)
                {
                    string? messageIdStr = messageData["messageId"].ToString();
                    if (!string.IsNullOrEmpty(messageIdStr) && Guid.TryParse(messageIdStr, out Guid messageId))
                    {
                        encryptedMessage.MessageId = messageId;
                    }
                }

                // Validate the message before attempting decryption
                if (!encryptedMessage.Validate())
                {
                    throw new SecurityException("Message validation failed.");
                }

                var (updatedSession, decryptedMessage) = DoubleRatchet.DoubleRatchetDecrypt(_session, encryptedMessage);

                // Only update the session if decryption was successful
                _session = updatedSession ?? throw new CryptographicException("Decryption produced a null session.");

                return decryptedMessage;
            }
            catch (WebSocketException wsEx)
            {
                // Specific handling for WebSocket errors
                throw new WebSocketException($"WebSocket error while receiving message: {wsEx.Message}", wsEx);
            }
            catch (OperationCanceledException)
            {
                // Pass through cancellation
                throw;
            }
            catch (Exception ex) when (
                ex is not InvalidOperationException &&
                ex is not WebSocketException &&
                ex is not FormatException &&
                ex is not SecurityException &&
                ex is not CryptographicException)
            {
                // Wrap unexpected errors
                throw new Exception($"Error receiving encrypted message: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Closes the connection
        /// </summary>
        public async Task CloseAsync()
        {
            await _webSocket.CloseAsync(WebSocketCloseStatus.NormalClosure,
                "Connection closed by client", CancellationToken.None);
        }
    }
}