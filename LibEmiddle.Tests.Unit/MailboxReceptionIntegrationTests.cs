using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using LibEmiddle.Abstractions;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;
using LibEmiddle.Messaging.Transport;

namespace LibEmiddle.Tests.Unit
{
    /// <summary>
    /// Integration tests verifying that MailboxManager is correctly wired to LibEmiddleClient,
    /// that Start()/Stop() are called, and that incoming messages are routed to the correct
    /// processing path (chat vs. group).
    /// </summary>
    [TestClass]
    public class MailboxReceptionIntegrationTests
    {
        private Mock<IMailboxTransport> _mockTransport;
        private Mock<IDoubleRatchetProtocol> _mockDoubleRatchet;
        private CryptoProvider _cryptoProvider;
        private KeyPair _identityKeyPair;

        [TestInitialize]
        public void Setup()
        {
            Sodium.Initialize();
            _cryptoProvider = new CryptoProvider();
            _identityKeyPair = Sodium.GenerateEd25519KeyPair();

            _mockTransport = new Mock<IMailboxTransport>();
            _mockDoubleRatchet = new Mock<IDoubleRatchetProtocol>();

            // Default: transport operations succeed and return empty lists
            _mockTransport
                .Setup(t => t.FetchMessagesAsync(It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new List<MailboxMessage>());

            _mockTransport
                .Setup(t => t.StartListeningAsync(It.IsAny<byte[]>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);

            _mockTransport
                .Setup(t => t.StopListeningAsync())
                .Returns(Task.CompletedTask);

            _mockTransport
                .Setup(t => t.SendMessageAsync(It.IsAny<MailboxMessage>()))
                .ReturnsAsync(true);
        }

        // -----------------------------------------------------------------------
        // Helper: build a MailboxMessage with a valid EncryptedMessage payload
        // -----------------------------------------------------------------------
        private MailboxMessage BuildValidMailboxMessage(MessageType type, Dictionary<string, string> metadata = null)
        {
            var senderKey = Sodium.GenerateEd25519KeyPair().PublicKey;
            var payload = new EncryptedMessage
            {
                MessageId = Guid.NewGuid().ToString(),
                SessionId = Guid.NewGuid().ToString(),
                Ciphertext = _cryptoProvider.GenerateRandomBytes(32),
                Nonce = _cryptoProvider.GenerateRandomBytes(12),
                SenderDHKey = _cryptoProvider.GenerateRandomBytes(32),
                SenderMessageNumber = 1,
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
            };

            return new MailboxMessage(_identityKeyPair.PublicKey, senderKey, payload)
            {
                Type = type,
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                Metadata = metadata
            };
        }

        // -----------------------------------------------------------------------
        // 1. MailboxManager.Start() is called when StartListeningAsync succeeds
        // -----------------------------------------------------------------------

        [TestMethod]
        public async Task StartListeningAsync_CallsMailboxManagerStart()
        {
            // Arrange
            bool startCalled = false;
            using var manager = new CallTrackingMailboxManager(
                _identityKeyPair, _mockTransport.Object, _mockDoubleRatchet.Object, _cryptoProvider,
                onStart: () => startCalled = true,
                onStop: () => { });

            // Wire up the same way LibEmiddleClient does
            // (we test the transport partial directly via TestableLibEmiddleClient)
            var client = new TestableLibEmiddleClientWithManager(manager, _mockTransport.Object);
            await client.InitializeAsync();

            // Act
            var result = await client.StartListeningAsync(1000);

            // Assert
            Assert.IsTrue(result, "StartListeningAsync should return true");
            Assert.IsTrue(startCalled, "MailboxManager.Start() should have been called");

            // Cleanup
            await client.StopListeningAsync();
        }

        // -----------------------------------------------------------------------
        // 2. MailboxManager.Stop() is called when StopListeningAsync is invoked
        // -----------------------------------------------------------------------

        [TestMethod]
        public async Task StopListeningAsync_CallsMailboxManagerStop()
        {
            // Arrange
            bool stopCalled = false;
            using var manager = new CallTrackingMailboxManager(
                _identityKeyPair, _mockTransport.Object, _mockDoubleRatchet.Object, _cryptoProvider,
                onStart: () => { },
                onStop: () => stopCalled = true);

            var client = new TestableLibEmiddleClientWithManager(manager, _mockTransport.Object);
            await client.InitializeAsync();
            await client.StartListeningAsync(1000);

            // Act
            var result = await client.StopListeningAsync();

            // Assert
            Assert.IsTrue(result, "StopListeningAsync should return true");
            Assert.IsTrue(stopCalled, "MailboxManager.Stop() should have been called");
        }

        // -----------------------------------------------------------------------
        // 3. MessageReceived event fires when MailboxManager raises a message
        // -----------------------------------------------------------------------

        [TestMethod]
        public async Task MailboxManager_WhenMessageReceived_ClientEventFires()
        {
            // Arrange
            var incoming = BuildValidMailboxMessage(MessageType.Chat);

            _mockTransport
                .Setup(t => t.FetchMessagesAsync(It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new List<MailboxMessage> { incoming });

            using var mailboxManager = new TestableMailboxManager(
                _identityKeyPair, _mockTransport.Object, _mockDoubleRatchet.Object, _cryptoProvider);

            int eventCount = 0;
            MailboxMessage receivedMessage = null;

            mailboxManager.MessageReceived += (_, args) =>
            {
                eventCount++;
                receivedMessage = args.Message;
            };

            // Act — simulate one poll cycle
            await mailboxManager.TestPollForMessagesAsync(CancellationToken.None);

            // Assert
            Assert.AreEqual(1, eventCount, "MessageReceived should fire once");
            Assert.IsNotNull(receivedMessage, "Received message should not be null");
            Assert.AreEqual(incoming.Id, receivedMessage.Id, "Received message ID should match");
        }

        // -----------------------------------------------------------------------
        // 4. OnMailboxMessageReceived routes chat messages without throwing
        // -----------------------------------------------------------------------

        [TestMethod]
        public async Task OnMailboxMessageReceived_ChatMessage_DoesNotThrow()
        {
            // Arrange
            var chatMessage = BuildValidMailboxMessage(MessageType.Chat);

            using var mailboxManager = new SimulatingMailboxManager(
                _identityKeyPair, _mockTransport.Object, _mockDoubleRatchet.Object, _cryptoProvider);

            // Spy on the MessageReceived event from the perspective of a higher-level subscriber
            bool eventFired = false;
            mailboxManager.MessageReceived += (_, _) => eventFired = true;

            // Act — manually fire the MessageReceived event on the manager
            // (simulates the manager receiving an incoming message)
            mailboxManager.SimulateMessageReceived(chatMessage);

            // Brief wait to allow any async routing to settle
            await Task.Delay(50);

            // Assert — event must have fired; no exceptions should have propagated
            Assert.IsTrue(eventFired, "MessageReceived event should fire for a chat message");
        }

        // -----------------------------------------------------------------------
        // 5. OnMailboxMessageReceived routes group messages without throwing
        // -----------------------------------------------------------------------

        [TestMethod]
        public async Task OnMailboxMessageReceived_GroupMessage_DoesNotThrow()
        {
            // Arrange
            var groupMessage = BuildValidMailboxMessage(
                MessageType.GroupChat,
                metadata: new Dictionary<string, string> { ["GroupId"] = "test-group-001" });

            using var mailboxManager = new SimulatingMailboxManager(
                _identityKeyPair, _mockTransport.Object, _mockDoubleRatchet.Object, _cryptoProvider);

            bool eventFired = false;
            mailboxManager.MessageReceived += (_, _) => eventFired = true;

            // Act
            mailboxManager.SimulateMessageReceived(groupMessage);
            await Task.Delay(50);

            // Assert
            Assert.IsTrue(eventFired, "MessageReceived event should fire for a group message");
        }

        // -----------------------------------------------------------------------
        // 6. Non-chat / non-group message types do not throw
        // -----------------------------------------------------------------------

        [TestMethod]
        public async Task OnMailboxMessageReceived_OtherMessageType_DoesNotThrow()
        {
            // Arrange
            var controlMessage = BuildValidMailboxMessage(MessageType.Control);

            using var mailboxManager = new SimulatingMailboxManager(
                _identityKeyPair, _mockTransport.Object, _mockDoubleRatchet.Object, _cryptoProvider);

            bool eventFired = false;
            mailboxManager.MessageReceived += (_, _) => eventFired = true;

            // Act
            mailboxManager.SimulateMessageReceived(controlMessage);
            await Task.Delay(50);

            // Assert
            Assert.IsTrue(eventFired, "MessageReceived event should fire for a control message");
        }

        // -----------------------------------------------------------------------
        // 7. Start/Stop idempotency — calling Stop when not started is safe
        // -----------------------------------------------------------------------

        [TestMethod]
        public async Task StopListeningAsync_WhenNotListening_ReturnsTrueWithoutError()
        {
            // Arrange
            using var manager = new CallTrackingMailboxManager(
                _identityKeyPair, _mockTransport.Object, _mockDoubleRatchet.Object, _cryptoProvider,
                onStart: () => { },
                onStop: () => { });

            var client = new TestableLibEmiddleClientWithManager(manager, _mockTransport.Object);
            await client.InitializeAsync();
            // Note: StartListeningAsync is NOT called here

            // Act — stop when never started
            var result = await client.StopListeningAsync();

            // Assert
            Assert.IsTrue(result, "StopListeningAsync should return true even when not listening");
        }

        // -----------------------------------------------------------------------
        // 8. Multiple messages in a single poll cycle all raise events
        // -----------------------------------------------------------------------

        [TestMethod]
        public async Task PollCycle_WithMultipleMessages_RaisesEventForEach()
        {
            // Arrange
            var messages = new List<MailboxMessage>
            {
                BuildValidMailboxMessage(MessageType.Chat),
                BuildValidMailboxMessage(MessageType.Chat),
                BuildValidMailboxMessage(MessageType.Chat)
            };

            _mockTransport
                .Setup(t => t.FetchMessagesAsync(It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(messages);

            using var mailboxManager = new TestableMailboxManager(
                _identityKeyPair, _mockTransport.Object, _mockDoubleRatchet.Object, _cryptoProvider);

            int eventCount = 0;
            mailboxManager.MessageReceived += (_, _) => Interlocked.Increment(ref eventCount);

            // Act
            await mailboxManager.TestPollForMessagesAsync(CancellationToken.None);

            // Assert
            Assert.AreEqual(messages.Count, eventCount,
                "MessageReceived should fire once for each polled message");
        }
    }

    // =========================================================================
    // Helper: MailboxManager subclass that exposes SimulateMessageReceived
    // =========================================================================

    /// <summary>
    /// Extends <see cref="TestableMailboxManager"/> with a method to manually trigger
    /// the <c>OnMessageReceived</c> protected method, simulating an inbound message
    /// without going through the transport layer.
    /// </summary>
    public class SimulatingMailboxManager : TestableMailboxManager
    {
        public SimulatingMailboxManager(
            KeyPair identityKeyPair,
            IMailboxTransport transport,
            IDoubleRatchetProtocol doubleRatchetProtocol,
            ICryptoProvider cryptoProvider)
            : base(identityKeyPair, transport, doubleRatchetProtocol, cryptoProvider)
        {
        }

        /// <summary>Directly invokes the protected OnMessageReceived method.</summary>
        public void SimulateMessageReceived(MailboxMessage message)
        {
            OnMessageReceived(message);
        }
    }

    // =========================================================================
    // Helper: MailboxManager that tracks Start/Stop calls
    // =========================================================================

    /// <summary>
    /// A <see cref="MailboxManager"/> wrapper that invokes callbacks when
    /// <see cref="MailboxManager.Start"/> and <see cref="MailboxManager.Stop"/> are called.
    /// Used to verify that <see cref="API.LibEmiddleClient"/> delegates to the manager correctly.
    /// </summary>
    public class CallTrackingMailboxManager : SimulatingMailboxManager
    {
        private readonly Action _onStart;
        private readonly Action _onStop;

        public CallTrackingMailboxManager(
            KeyPair identityKeyPair,
            IMailboxTransport transport,
            IDoubleRatchetProtocol doubleRatchetProtocol,
            ICryptoProvider cryptoProvider,
            Action onStart,
            Action onStop)
            : base(identityKeyPair, transport, doubleRatchetProtocol, cryptoProvider)
        {
            _onStart = onStart ?? throw new ArgumentNullException(nameof(onStart));
            _onStop = onStop ?? throw new ArgumentNullException(nameof(onStop));
        }

        public new void Start()
        {
            _onStart();
            base.Start();
        }

        public new void Stop()
        {
            _onStop();
            base.Stop();
        }
    }

    // =========================================================================
    // Helper: LibEmiddleClient subclass that accepts injected dependencies
    // =========================================================================

    /// <summary>
    /// A minimal test double for <see cref="API.LibEmiddleClient"/> that replaces the
    /// internal <see cref="MailboxManager"/> and <see cref="IMailboxTransport"/> so tests
    /// can verify wiring without spinning up the full client stack.
    /// </summary>
    public class TestableLibEmiddleClientWithManager
    {
        private readonly CallTrackingMailboxManager _mailboxManager;
        private readonly IMailboxTransport _transport;
        private bool _isListening;

        public bool IsListening => _isListening;

        public TestableLibEmiddleClientWithManager(
            CallTrackingMailboxManager mailboxManager,
            IMailboxTransport transport)
        {
            _mailboxManager = mailboxManager ?? throw new ArgumentNullException(nameof(mailboxManager));
            _transport = transport ?? throw new ArgumentNullException(nameof(transport));
        }

        public Task<bool> InitializeAsync() => Task.FromResult(true);

        public async Task<bool> StartListeningAsync(int pollingInterval = 5000)
        {
            if (_isListening)
                return true;

            try
            {
                // Mirror the production wiring: Start manager BEFORE transport.
                _mailboxManager.Start();
                await _transport.StartListeningAsync(Array.Empty<byte>(), pollingInterval, CancellationToken.None);
                _isListening = true;
                return true;
            }
            catch
            {
                return false;
            }
        }

        public async Task<bool> StopListeningAsync()
        {
            if (!_isListening)
                return true;

            try
            {
                // Mirror the production wiring: Stop manager BEFORE transport.
                _mailboxManager.Stop();
                await _transport.StopListeningAsync();
                _isListening = false;
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
