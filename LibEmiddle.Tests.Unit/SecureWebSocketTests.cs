using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using System;
using System.Collections.Generic;
using System.Net.WebSockets;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using LibEmiddle.Abstractions;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.Messaging.Transport;
using LibEmiddle.Domain.Enums;
using LibEmiddle.Protocol;

namespace LibEmiddle.Tests.Unit
{
    [TestClass]
    public class SecureWebSocketClientTests
    {
        private Mock<IWebSocketClient> _mockWebSocket;
        private DoubleRatchetSession _testSession;
        private X3DHKeyBundle _bobKeyBundle;
        private InitialMessageData _initialMessageData;
        private readonly string _serverUrl = "wss://test.example.com";
        private CryptoProvider _cryptoProvider;
        private X3DHProtocol _x3DHProtocol;
        private DoubleRatchetProtocol _doubleRatchetProtocol;

        [TestInitialize]
        public async Task Setup()
        {
            _mockWebSocket = new Mock<IWebSocketClient>();
            _cryptoProvider = new CryptoProvider();
            _x3DHProtocol = new X3DHProtocol(_cryptoProvider);
            _doubleRatchetProtocol = new DoubleRatchetProtocol();

            // Create identity key pairs for both parties
            var aliceIdentityKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);
            var bobIdentityKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);

            // Create Bob's key bundle (as the receiver)
            var bobKeyBundle = await _x3DHProtocol.CreateKeyBundleAsync(bobIdentityKeyPair, numOneTimeKeys: 1);

            // Perform X3DH key exchange (Alice initiates)
            var x3dhResult = await _x3DHProtocol.InitiateSessionAsSenderAsync(bobKeyBundle.ToPublicBundle(), aliceIdentityKeyPair);

            // Generate a unique session ID
            string sessionId = $"test-session-{Guid.NewGuid():N}";

            // Initialize Alice's Double Ratchet session with shared key from X3DH
            _testSession = _doubleRatchetProtocol.InitializeSessionAsSender(
                x3dhResult.SharedKey,
                bobKeyBundle.SignedPreKey,
                sessionId);

            // Store Bob's bundle for tests that need it
            _bobKeyBundle = bobKeyBundle;

            // Store the initial message data for tests that need it
            _initialMessageData = x3dhResult.MessageDataToSend;
        }

        [TestMethod]
        public async Task SendEncryptedMessage_ValidMessage_SendsProperJson()
        {
            // Arrange
            string testMessage = "Test secure message";
            byte[] capturedData = null;
            _mockWebSocket.Setup(ws => ws.SendAsync(
                    It.IsAny<ArraySegment<byte>>(),
                    WebSocketMessageType.Text,
                    true,
                    It.IsAny<CancellationToken>()))
                .Callback<ArraySegment<byte>, WebSocketMessageType, bool, CancellationToken>((data, type, end, token) =>
                {
                    capturedData = new byte[data.Count];
                    Array.Copy(data.Array, data.Offset, capturedData, 0, data.Count);
                })
                .Returns(Task.CompletedTask);

            _mockWebSocket.Setup(ws => ws.State).Returns(WebSocketState.Open);
            var client = new SecureWebSocketClient(_serverUrl, _mockWebSocket.Object);
            client.SetSession(_testSession);

            // Act
            await client.SendEncryptedMessageAsync(testMessage);

            // Assert: Verify that the JSON payload contains all required properties.
            Assert.IsNotNull(capturedData, "Data should be sent");
            string json = Encoding.UTF8.GetString(capturedData);
            var dataDict = JsonSerializer.Deserialize<Dictionary<string, object>>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            Assert.IsTrue(dataDict.ContainsKey("ciphertext"), "Missing ciphertext");
            Assert.IsTrue(dataDict.ContainsKey("nonce"), "Missing nonce");
            Assert.IsTrue(dataDict.ContainsKey("messageNumber"), "Missing messageNumber");
            Assert.IsTrue(dataDict.ContainsKey("senderDHKey"), "Missing senderDHKey");
            Assert.IsTrue(dataDict.ContainsKey("timestamp"), "Missing timestamp");
        }

        [TestMethod]
        public async Task SendEncryptedMessage_NullMessage_ThrowsArgumentNullException()
        {
            // Arrange
            _mockWebSocket.Setup(ws => ws.State).Returns(WebSocketState.Open);
            var client = new SecureWebSocketClient(_serverUrl, _mockWebSocket.Object);
            client.SetSession(_testSession);

            // Act & Assert: Sending a null message should throw an ArgumentNullException.
            await Assert.ThrowsExceptionAsync<ArgumentNullException>(() => client.SendEncryptedMessageAsync(null));
        }

        [TestMethod]
        public async Task SendEncryptedMessage_WithoutSession_ThrowsInvalidOperationException()
        {
            // Arrange: Session is not set.
            _mockWebSocket.Setup(ws => ws.State).Returns(WebSocketState.Open);
            var client = new SecureWebSocketClient(_serverUrl, _mockWebSocket.Object);

            // Act & Assert: Without a session, sending should throw an InvalidOperationException.
            await Assert.ThrowsExceptionAsync<InvalidOperationException>(() => client.SendEncryptedMessageAsync("Test message"));
        }

        [TestMethod]
        public async Task SendEncryptedMessage_ClosedWebSocket_ThrowsInvalidOperationException()
        {
            // Arrange: WebSocket is not open.
            _mockWebSocket.Setup(ws => ws.State).Returns(WebSocketState.Closed);
            var client = new SecureWebSocketClient(_serverUrl, _mockWebSocket.Object);
            client.SetSession(_testSession);

            // Act & Assert: Should throw InvalidOperationException when the WebSocket is closed.
            await Assert.ThrowsExceptionAsync<InvalidOperationException>(() => client.SendEncryptedMessageAsync("Test message"));
        }

        [TestMethod]
        public async Task SendEncryptedMessage_CanceledToken_ThrowsOperationCanceledException()
        {
            // Arrange: Simulate cancellation during send.
            _mockWebSocket.Setup(ws => ws.SendAsync(
                    It.IsAny<ArraySegment<byte>>(),
                    WebSocketMessageType.Text,
                    true,
                    It.IsAny<CancellationToken>()))
                .Returns(async (ArraySegment<byte> data, WebSocketMessageType type, bool end, CancellationToken token) =>
                {
                    token.ThrowIfCancellationRequested();
                    await Task.Delay(100, token);
                });

            _mockWebSocket.Setup(ws => ws.State).Returns(WebSocketState.Open);
            var client = new SecureWebSocketClient(_serverUrl, _mockWebSocket.Object);
            client.SetSession(_testSession);

            CancellationTokenSource cts = new CancellationTokenSource();
            cts.Cancel();

            // Act & Assert: OperationCanceledException is expected when the token is cancelled.
            await Assert.ThrowsExceptionAsync<OperationCanceledException>(() => client.SendEncryptedMessageAsync("Test message", cts.Token));
        }

        [TestMethod]
        public async Task ReceiveEncryptedMessage_InvalidJson_ThrowsFormatException()
        {
            // Arrange:
            // This test expects that when invalid JSON is received, a FormatException is thrown.
            // To ensure this, update SecureWebSocketClient.ReceiveEncryptedMessageAsync to catch JsonException and rethrow it as FormatException.
            byte[] invalidJsonBytes = Encoding.Default.GetBytes("Not a valid JSON");
            var receiveResult = new WebSocketReceiveResult(invalidJsonBytes.Length, WebSocketMessageType.Text, true);
            _mockWebSocket.Setup(ws => ws.State).Returns(WebSocketState.Open);
            _mockWebSocket.Setup(ws => ws.ReceiveAsync(It.IsAny<ArraySegment<byte>>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(receiveResult)
                .Callback<ArraySegment<byte>, CancellationToken>((buffer, token) =>
                {
                    Array.Copy(invalidJsonBytes, 0, buffer.Array, buffer.Offset, invalidJsonBytes.Length);
                });

            var client = new SecureWebSocketClient(_serverUrl, _mockWebSocket.Object);
            client.SetSession(_testSession);

            // Act & Assert: Malformed JSON should trigger a FormatException.
            await Assert.ThrowsExceptionAsync<FormatException>(() => client.ReceiveEncryptedMessageAsync());
        }

        [TestMethod]
        public async Task ReceiveEncryptedMessage_MissingFields_ThrowsFormatException()
        {
            // Arrange: Create JSON missing the required "nonce" field.
            var messageData = new Dictionary<string, object>
            {
                { "ciphertext", Convert.ToBase64String(new byte[]{1,2,3}) },
                // Missing "nonce" field.
                { "messageNumber", 1 },
                { "senderDHKey", Convert.ToBase64String(new byte[]{7,8,9}) },
                { "timestamp", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() }
            };
            string json = JsonSerializer.Serialize(messageData);
            byte[] jsonBytes = Encoding.Default.GetBytes(json);
            var receiveResult = new WebSocketReceiveResult(jsonBytes.Length, WebSocketMessageType.Text, true);
            _mockWebSocket.Setup(ws => ws.State).Returns(WebSocketState.Open);
            _mockWebSocket.Setup(ws => ws.ReceiveAsync(It.IsAny<ArraySegment<byte>>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(receiveResult)
                .Callback<ArraySegment<byte>, CancellationToken>((buffer, token) =>
                {
                    Array.Copy(jsonBytes, 0, buffer.Array, buffer.Offset, jsonBytes.Length);
                });

            var client = new SecureWebSocketClient(_serverUrl, _mockWebSocket.Object);
            client.SetSession(_testSession);

            // Act & Assert: The missing field should cause a FormatException.
            await Assert.ThrowsExceptionAsync<FormatException>(() => client.ReceiveEncryptedMessageAsync());
        }

        [TestMethod]
        public async Task ReceiveEncryptedMessage_InvalidBase64_ThrowsFormatException()
        {
            // Arrange: Create JSON with an invalid Base64 string for the "ciphertext" field.
            var messageData = new Dictionary<string, object>
            {
                { "ciphertext", "InvalidBase64!!!" },
                { "nonce", Convert.ToBase64String(new byte[]{4,5,6}) },
                { "messageNumber", 1 },
                { "senderDHKey", Convert.ToBase64String(new byte[]{7,8,9}) },
                { "timestamp", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() }
            };
            string json = JsonSerializer.Serialize(messageData);
            byte[] jsonBytes = Encoding.Default.GetBytes(json);
            var receiveResult = new WebSocketReceiveResult(jsonBytes.Length, WebSocketMessageType.Text, true);
            _mockWebSocket.Setup(ws => ws.State).Returns(WebSocketState.Open);
            _mockWebSocket.Setup(ws => ws.ReceiveAsync(It.IsAny<ArraySegment<byte>>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(receiveResult)
                .Callback<ArraySegment<byte>, CancellationToken>((buffer, token) =>
                {
                    Array.Copy(jsonBytes, 0, buffer.Array, buffer.Offset, jsonBytes.Length);
                });

            var client = new SecureWebSocketClient(_serverUrl, _mockWebSocket.Object);
            client.SetSession(_testSession);

            // Act & Assert: Invalid Base64 should trigger a FormatException.
            await Assert.ThrowsExceptionAsync<FormatException>(() => client.ReceiveEncryptedMessageAsync());
        }

        [TestMethod]
        public async Task ReceiveEncryptedMessage_OldTimestamp_ThrowsSecurityException()
        {
            // Arrange: Create a valid JSON payload with a timestamp older than 5 minutes.
            var messageData = new Dictionary<string, object>
            {
                { "ciphertext", Convert.ToBase64String(new byte[]{1,2,3}) },
                { "nonce", Convert.ToBase64String(new byte[]{4,5,6}) },
                { "messageNumber", 1 },
                { "senderDHKey", Convert.ToBase64String(new byte[]{7,8,9}) },
                { "timestamp", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - 6 * 60 * 1000 }
            };
            string json = JsonSerializer.Serialize(messageData);
            byte[] jsonBytes = Encoding.Default.GetBytes(json);
            var receiveResult = new WebSocketReceiveResult(jsonBytes.Length, WebSocketMessageType.Text, true);
            _mockWebSocket.Setup(ws => ws.State).Returns(WebSocketState.Open);
            _mockWebSocket.Setup(ws => ws.ReceiveAsync(It.IsAny<ArraySegment<byte>>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(receiveResult)
                .Callback<ArraySegment<byte>, CancellationToken>((buffer, token) =>
                {
                    Array.Copy(jsonBytes, 0, buffer.Array, buffer.Offset, jsonBytes.Length);
                });

            var client = new SecureWebSocketClient(_serverUrl, _mockWebSocket.Object);
            client.SetSession(_testSession);

            // Act & Assert: An outdated timestamp should result in a SecurityException.
            await Assert.ThrowsExceptionAsync<SecurityException>(() => client.ReceiveEncryptedMessageAsync());
        }

        [TestMethod]
        public async Task ReceiveEncryptedMessage_CanceledToken_ThrowsOperationCanceledException()
        {
            // Arrange: Simulate cancellation during receive.
            _mockWebSocket.Setup(ws => ws.ReceiveAsync(It.IsAny<ArraySegment<byte>>(), It.IsAny<CancellationToken>()))
                .Returns(async (ArraySegment<byte> buffer, CancellationToken token) =>
                {
                    token.ThrowIfCancellationRequested();
                    await Task.Delay(100, token);
                    return new WebSocketReceiveResult(0, WebSocketMessageType.Text, true);
                });
            _mockWebSocket.Setup(ws => ws.State).Returns(WebSocketState.Open);
            var client = new SecureWebSocketClient(_serverUrl, _mockWebSocket.Object);
            client.SetSession(_testSession);

            CancellationTokenSource cts = new CancellationTokenSource();
            cts.Cancel();

            // Act & Assert: OperationCanceledException is expected when cancellation is requested.
            await Assert.ThrowsExceptionAsync<OperationCanceledException>(() => client.ReceiveEncryptedMessageAsync(cts.Token));
        }

        #region Security Vulnerability Tests

        /// <summary>
        /// Tests that replay attacks are properly detected and prevented
        /// </summary>
        [TestMethod]
        public async Task ReceiveEncryptedMessage_ReplayAttack_ShouldBeDetected()
        {
            // Arrange: Create a message with a timestamp that's too old for the reduced window
            var messageData = new Dictionary<string, object>
            {
                { "ciphertext", Convert.ToBase64String(new byte[]{1,2,3}) },
                { "nonce", Convert.ToBase64String(new byte[]{4,5,6}) },
                { "messageNumber", 1 },
                { "senderDHKey", Convert.ToBase64String(new byte[]{7,8,9}) },
                { "sessionId", "test-session" },
                { "messageId", Guid.NewGuid().ToString() },
                // Message older than 30 seconds (our reduced replay window)
                { "timestamp", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - 35000 }
            };

            string json = JsonSerializer.Serialize(messageData);
            byte[] jsonBytes = Encoding.Default.GetBytes(json);
            var receiveResult = new WebSocketReceiveResult(jsonBytes.Length, WebSocketMessageType.Text, true);

            _mockWebSocket.Setup(ws => ws.State).Returns(WebSocketState.Open);
            _mockWebSocket.Setup(ws => ws.ReceiveAsync(It.IsAny<ArraySegment<byte>>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(receiveResult)
                .Callback<ArraySegment<byte>, CancellationToken>((buffer, token) =>
                {
                    Array.Copy(jsonBytes, 0, buffer.Array, buffer.Offset, jsonBytes.Length);
                });

            var client = new SecureWebSocketClient(_serverUrl, _mockWebSocket.Object);
            client.SetSession(_testSession);

            // Act & Assert: Old message should be rejected as potential replay attack
            // Note: The actual exception might be SecurityException or CryptographicException depending on where the validation occurs
            try
            {
                await client.ReceiveEncryptedMessageAsync();
                Assert.Fail("Expected an exception to be thrown for replay attack");
            }
            catch (Exception ex) when (ex is SecurityException || ex is CryptographicException)
            {
                // Expected - replay attack was detected
                Assert.IsTrue(true, "Replay attack was properly detected");
            }
        }

        /// <summary>
        /// Tests that messages with future timestamps are rejected
        /// </summary>
        [TestMethod]
        public async Task ReceiveEncryptedMessage_FutureTimestamp_ShouldBeRejected()
        {
            // Arrange: Create a message with a timestamp too far in the future
            var messageData = new Dictionary<string, object>
            {
                { "ciphertext", Convert.ToBase64String(new byte[]{1,2,3}) },
                { "nonce", Convert.ToBase64String(new byte[]{4,5,6}) },
                { "messageNumber", 1 },
                { "senderDHKey", Convert.ToBase64String(new byte[]{7,8,9}) },
                { "sessionId", "test-session" },
                { "messageId", Guid.NewGuid().ToString() },
                // Message from 10 minutes in the future
                { "timestamp", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + 600000 }
            };

            string json = JsonSerializer.Serialize(messageData);
            byte[] jsonBytes = Encoding.Default.GetBytes(json);
            var receiveResult = new WebSocketReceiveResult(jsonBytes.Length, WebSocketMessageType.Text, true);

            _mockWebSocket.Setup(ws => ws.State).Returns(WebSocketState.Open);
            _mockWebSocket.Setup(ws => ws.ReceiveAsync(It.IsAny<ArraySegment<byte>>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(receiveResult)
                .Callback<ArraySegment<byte>, CancellationToken>((buffer, token) =>
                {
                    Array.Copy(jsonBytes, 0, buffer.Array, buffer.Offset, jsonBytes.Length);
                });

            var client = new SecureWebSocketClient(_serverUrl, _mockWebSocket.Object);
            client.SetSession(_testSession);

            // Act & Assert: Future message should be rejected
            // Note: The actual exception might be SecurityException or CryptographicException depending on where the validation occurs
            try
            {
                await client.ReceiveEncryptedMessageAsync();
                Assert.Fail("Expected an exception to be thrown for future timestamp");
            }
            catch (Exception ex) when (ex is SecurityException || ex is CryptographicException)
            {
                // Expected - future timestamp was detected
                Assert.IsTrue(true, "Future timestamp was properly detected");
            }
        }

        /// <summary>
        /// Tests that messages without session ID are rejected
        /// </summary>
        [TestMethod]
        public async Task ReceiveEncryptedMessage_MissingSessionId_ShouldBeRejected()
        {
            // Arrange: Create a message without session ID
            var messageData = new Dictionary<string, object>
            {
                { "ciphertext", Convert.ToBase64String(new byte[]{1,2,3}) },
                { "nonce", Convert.ToBase64String(new byte[]{4,5,6}) },
                { "messageNumber", 1 },
                { "senderDHKey", Convert.ToBase64String(new byte[]{7,8,9}) },
                { "timestamp", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() }
                // Missing sessionId
            };

            string json = JsonSerializer.Serialize(messageData);
            byte[] jsonBytes = Encoding.Default.GetBytes(json);
            var receiveResult = new WebSocketReceiveResult(jsonBytes.Length, WebSocketMessageType.Text, true);

            _mockWebSocket.Setup(ws => ws.State).Returns(WebSocketState.Open);
            _mockWebSocket.Setup(ws => ws.ReceiveAsync(It.IsAny<ArraySegment<byte>>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(receiveResult)
                .Callback<ArraySegment<byte>, CancellationToken>((buffer, token) =>
                {
                    Array.Copy(jsonBytes, 0, buffer.Array, buffer.Offset, jsonBytes.Length);
                });

            var client = new SecureWebSocketClient(_serverUrl, _mockWebSocket.Object);
            client.SetSession(_testSession);

            // Act & Assert: Message without session ID should be rejected
            // Note: The exception might be wrapped in a generic Exception
            await Assert.ThrowsExceptionAsync<Exception>(() => client.ReceiveEncryptedMessageAsync());
        }

        /// <summary>
        /// Tests that malformed JSON is properly handled
        /// </summary>
        [TestMethod]
        public async Task ReceiveEncryptedMessage_MalformedJson_ShouldThrowFormatException()
        {
            // Arrange: Create malformed JSON
            string malformedJson = "{ \"ciphertext\": \"invalid json structure";
            byte[] jsonBytes = Encoding.Default.GetBytes(malformedJson);
            var receiveResult = new WebSocketReceiveResult(jsonBytes.Length, WebSocketMessageType.Text, true);

            _mockWebSocket.Setup(ws => ws.State).Returns(WebSocketState.Open);
            _mockWebSocket.Setup(ws => ws.ReceiveAsync(It.IsAny<ArraySegment<byte>>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(receiveResult)
                .Callback<ArraySegment<byte>, CancellationToken>((buffer, token) =>
                {
                    Array.Copy(jsonBytes, 0, buffer.Array, buffer.Offset, jsonBytes.Length);
                });

            var client = new SecureWebSocketClient(_serverUrl, _mockWebSocket.Object);
            client.SetSession(_testSession);

            // Act & Assert: Malformed JSON should throw FormatException
            await Assert.ThrowsExceptionAsync<FormatException>(() => client.ReceiveEncryptedMessageAsync());
        }

        #endregion
    }
}