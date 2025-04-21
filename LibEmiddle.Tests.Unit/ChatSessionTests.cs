using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Linq;
using System.Threading.Tasks;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.KeyExchange;
using LibEmiddle.Messaging.Chat;

namespace LibEmiddle.Tests.Unit
{
    [TestClass]
    public class ChatSessionTests
    {
        private KeyPair _aliceKeyPair;
        private KeyPair _bobKeyPair;
        private DoubleRatchetSession _aliceRatchetSession;
        private DoubleRatchetSession _bobRatchetSession;
        private ChatSession _aliceChatSession;
        private CryptoProvider _cryptoProvider;

        [TestInitialize]
        public void Setup()
        {

            _cryptoProvider = new CryptoProvider();

            // Generate proper key pairs for Alice and Bob
            _aliceKeyPair = Sodium.GenerateEd25519KeyPair();
            _bobKeyPair = Sodium.GenerateEd25519KeyPair();

            byte[] _alicePrivateKey = _cryptoProvider.DeriveX25519PrivateKeyFromEd25519(_aliceKeyPair.PrivateKey);

            // Create a shared secret (simulating X3DH)
            byte[] sharedSecret = X3DHExchange.PerformX25519DH(_alicePrivateKey, _bobKeyPair.PublicKey);

            // Initialize Double Ratchet
            var (rootKey, chainKey) = _cryptoProvider.DeriveDoubleRatchet(sharedSecret);

            string sessionId = Guid.NewGuid().ToString();

            // Create Alice's sending session
            _aliceRatchetSession = new DoubleRatchetSession(
                dhRatchetKeyPair: _aliceKeyPair,
                remoteDHRatchetKey: _bobKeyPair.PublicKey,
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumberSending: 0,
                messageNumberReceiving: 0,
                sessionId: sessionId
            );

            // Create Bob's receiving session
            _bobRatchetSession = new DoubleRatchetSession(
                dhRatchetKeyPair: _bobKeyPair,
                remoteDHRatchetKey: _aliceKeyPair.PublicKey,
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumberSending: 0,
                messageNumberReceiving: 0,
                sessionId: sessionId
            );

            // Create Alice's chat session
            _aliceChatSession = new ChatSession(
                _aliceRatchetSession,
                _bobKeyPair.PublicKey,
                _aliceKeyPair.PublicKey
            );
        }

        [TestMethod]
        public void ChatSession_InitialState_ShouldBeInitialized()
        {
            // Assert
            Assert.AreEqual(Enums.ChatSessionState.Initialized, _aliceChatSession.State);
            Assert.IsNotNull(_aliceChatSession.CreatedAt);
            Assert.IsNull(_aliceChatSession.LastActivatedAt);
            Assert.IsNull(_aliceChatSession.LastSuspendedAt);
        }

        [TestMethod]
        public async Task ChatSession_Activate_ShouldChangeStateToActive()
        {
            // Act
            bool result = await _aliceChatSession.ActivateAsync();

            // Assert
            Assert.IsTrue(result);
            Assert.AreEqual(Enums.ChatSessionState.Active, _aliceChatSession.State);
            Assert.IsNotNull(_aliceChatSession.LastActivatedAt);
        }

        [TestMethod]
        public async Task ChatSession_ActivateAlreadyActiveSession_ShouldReturnFalse()
        {
            // Arrange
            await _aliceChatSession.ActivateAsync();

            // Act
            bool result = await _aliceChatSession.ActivateAsync();

            // Assert
            Assert.IsFalse(result);
            Assert.AreEqual(Enums.ChatSessionState.Active, _aliceChatSession.State);
        }

        [TestMethod]
        public async Task ChatSession_Suspend_ShouldChangeStateToSuspended()
        {
            // Arrange
            await _aliceChatSession.ActivateAsync();
            string suspensionReason = "Testing suspension";

            // Act
            bool result = await _aliceChatSession.SuspendAsync(suspensionReason);

            // Assert
            Assert.IsTrue(result);
            Assert.AreEqual(Enums.ChatSessionState.Suspended, _aliceChatSession.State);
            Assert.IsNotNull(_aliceChatSession.LastSuspendedAt);
            Assert.AreEqual(suspensionReason, _aliceChatSession.SuspensionReason);
        }

        [TestMethod]
        public async Task ChatSession_SuspendFromInitialized_ShouldChangeStateToSuspended()
        {
            // Act
            bool result = await _aliceChatSession.SuspendAsync("Direct suspension"); ;

            // Assert
            Assert.IsTrue(result);
            Assert.AreEqual(Enums.ChatSessionState.Suspended, _aliceChatSession.State);
        }

        [TestMethod]
        public async Task ChatSession_Terminate_ShouldChangeStateToTerminated()
        {
            // Act
            bool result = await _aliceChatSession.TerminateAsync();

            // Assert
            Assert.IsTrue(result);
            Assert.AreEqual(Enums.ChatSessionState.Terminated, _aliceChatSession.State);
        }

        [TestMethod]
        public async Task ChatSession_ActivateTerminatedSession_ShouldThrowException()
        {
            // Arrange
            await _aliceChatSession.TerminateAsync();

            // Act & Assert
            await Assert.ThrowsExceptionAsync<InvalidOperationException>(() => _aliceChatSession.ActivateAsync());
        }

        [TestMethod]
        public async Task ChatSession_SuspendTerminatedSession_ShouldThrowException()
        {
            // Arrange
            await _aliceChatSession.TerminateAsync();

            // Act & Assert
            await Assert.ThrowsExceptionAsync<InvalidOperationException>(() => _aliceChatSession.SuspendAsync());
        }

        [TestMethod]
        public async Task ChatSession_StateChangeEvents_ShouldBeRaised()
        {
            // Arrange: Create a TaskCompletionSource to await the event.
            var tcs = new TaskCompletionSource<(Enums.ChatSessionState previous, Enums.ChatSessionState current, DateTime timestamp)>();

            _aliceChatSession.StateChanged += (sender, e) =>
            {
                tcs.TrySetResult((e.PreviousState, e.NewState, e.Timestamp));
            };

            // Act: Activate the session.
            await _aliceChatSession.ActivateAsync();

            // Wait for the event to be raised, or time out after 1 second.
            var completedTask = await Task.WhenAny(tcs.Task, Task.Delay(1000));
            if (completedTask != tcs.Task)
            {
                Assert.Fail("StateChanged event was not raised within the expected time.");
            }

            // Retrieve the event results.
            var (previousState, currentState, eventTimestamp) = await tcs.Task;

            // Assert: Verify that the event reflects the expected state change.
            Assert.AreEqual(Enums.ChatSessionState.Initialized, previousState, "Expected previous state to be Initialized.");
            Assert.AreEqual(Enums.ChatSessionState.Active, currentState, "Expected new state to be Active.");
            Assert.IsTrue(eventTimestamp > DateTime.MinValue, "Expected a valid timestamp to be set.");
        }


        [TestMethod]
        public async Task ChatSession_EncryptMessage_ShouldAutoActivateSession()
        {
            // Arrange
            string message = "Auto-activation test";

            // Act
            EncryptedMessage encryptedMessage = await _aliceChatSession.EncryptAsync(message);

            // Assert
            Assert.AreEqual(Enums.ChatSessionState.Active, _aliceChatSession.State);
            Assert.IsNotNull(_aliceChatSession.LastActivatedAt);
            Assert.IsNotNull(encryptedMessage);
        }

        [TestMethod]
        public async Task ChatSession_EncryptMessageWithoutPriorActivation_ShouldAutoActivateSession()
        {
            // Arrange
            // Make sure the session is in the default Initialized state.
            // (No activation call is made beforehand.)
            string message = "Test auto-activation message";

            // Act
            EncryptedMessage encryptedMessage = await _aliceChatSession.EncryptAsync(message);

            // Assert
            // Instead of expecting an exception, we expect the session to auto-activate.
            Assert.IsNotNull(encryptedMessage, "Encryption should succeed and return an encrypted message.");
            Assert.AreEqual(Enums.ChatSessionState.Active, _aliceChatSession.State, "Session should be auto-activated on encryption.");
            Assert.IsNotNull(_aliceChatSession.LastActivatedAt, "LastActivatedAt should be set upon activation.");
        }

        [TestMethod]
        public async Task ChatSession_EncryptMessageInSuspendedState_ShouldThrowException()
        {
            // Arrange
            await _aliceChatSession.SuspendAsync("Testing encryption rejection");
            string message = "Should fail in suspended state";

            // Act
            await Assert.ThrowsExceptionAsync<InvalidOperationException>(() => _aliceChatSession.EncryptAsync(message));
        }

        [TestMethod]
        public async Task ChatSession_DecryptMessage_ShouldWorkInSuspendedState()
        {
            // Arrange
            await _aliceChatSession.ActivateAsync();
            string originalMessage = "Test message";
            EncryptedMessage encryptedMessage = await _aliceChatSession.EncryptAsync(originalMessage);

            // Create Bob's chat session
            var bobChatSession = new ChatSession(
                _bobRatchetSession,
                _aliceKeyPair.PublicKey,
                _bobKeyPair.PublicKey
            );

            // Suspend Bob's session
            await bobChatSession.SuspendAsync("Testing decryption in suspended state");

            // Act
            string decryptedMessage = await bobChatSession.DecryptAsync(encryptedMessage);

            // Assert
            Assert.IsNotNull(decryptedMessage);
            Assert.AreEqual(originalMessage, decryptedMessage);
            Assert.AreEqual(Enums.ChatSessionState.Suspended, bobChatSession.State, "State should remain suspended");
        }

        [TestMethod]
        public async Task ChatSession_DecryptMessageInTerminatedState_ShouldThrowException()
        {
            // Arrange
            await _aliceChatSession.ActivateAsync();
            string originalMessage = "Test message";
            EncryptedMessage encryptedMessage = await _aliceChatSession.EncryptAsync(originalMessage);

            // Create Bob's chat session
            var bobChatSession = new ChatSession(
                _bobRatchetSession,
                _aliceKeyPair.PublicKey,
                _bobKeyPair.PublicKey
            );

            // Terminate Bob's session
            await bobChatSession.TerminateAsync();

            // Act & Assert
            await Assert.ThrowsExceptionAsync<InvalidOperationException>(() => bobChatSession.DecryptAsync(encryptedMessage));
        }

        [TestMethod]
        public async Task ChatSession_MessageHistory_ShouldTrackSentAndReceivedMessages()
        {
            // Arrange
            await _aliceChatSession.ActivateAsync();
            string message1 = "First message";
            string message2 = "Second message";

            // Create Bob's chat session
            var bobChatSession = new ChatSession(
                _bobRatchetSession,
                _aliceKeyPair.PublicKey,
                _bobKeyPair.PublicKey
            );
            await bobChatSession.ActivateAsync();

            // Act - Send messages both ways
            EncryptedMessage encryptedMessage1 = await _aliceChatSession.EncryptAsync(message1);
            string decryptedMessage1 = await bobChatSession.DecryptAsync(encryptedMessage1);

            EncryptedMessage encryptedMessage2 = await bobChatSession.EncryptAsync(message2);
            string decryptedMessage2 = await _aliceChatSession.DecryptAsync(encryptedMessage2);

            // Assert
            var aliceHistory = _aliceChatSession.GetMessageHistory();
            var bobHistory = bobChatSession.GetMessageHistory();

            Assert.AreEqual(2, aliceHistory.Count);
            Assert.AreEqual(2, bobHistory.Count);

            Assert.IsTrue(aliceHistory.First().IsOutgoing);
            Assert.IsFalse(aliceHistory.Last().IsOutgoing);

            Assert.IsFalse(bobHistory.First().IsOutgoing);
            Assert.IsTrue(bobHistory.Last().IsOutgoing);
        }

        [TestMethod]
        public async Task ChatSession_ClearMessageHistory_ShouldRemoveAllMessages()
        {
            // Arrange
            await _aliceChatSession.ActivateAsync();
            await _aliceChatSession.EncryptAsync("Message 1");
            await _aliceChatSession.EncryptAsync("Message 2");
            await _aliceChatSession.EncryptAsync("Message 3");

            Assert.AreEqual(3, _aliceChatSession.GetMessageCount());

            // Act
            int clearedCount = _aliceChatSession.ClearMessageHistory();

            // Assert
            Assert.AreEqual(3, clearedCount);
            Assert.AreEqual(0, _aliceChatSession.GetMessageCount());
            Assert.AreEqual(0, _aliceChatSession.GetMessageHistory().Count);
        }

        [TestMethod]
        public async Task ChatSession_IsValid_ShouldReturnFalseWhenTerminated()
        {
            // Act - first activate the session
            Assert.IsTrue(await _aliceChatSession.ActivateAsync());

            // Terminate the session - should return true (successful termination)
            Assert.IsTrue(await _aliceChatSession.TerminateAsync());

            // Assert - IsValid should return false for a terminated session
            Assert.IsFalse(_aliceChatSession.IsValid());
        }

        [TestMethod]
        public async Task ChatSession_Dispose_ShouldTerminateSession()
        {
            // Arrange
            await _aliceChatSession.ActivateAsync();

            // Act
            _aliceChatSession.Dispose();

            // Assert - try to use the session, should throw ObjectDisposedException
            bool exceptionThrown = false;
            try
            {
                await _aliceChatSession.ActivateAsync();
            }
            catch (ObjectDisposedException)
            {
                exceptionThrown = true;
            }

            Assert.IsTrue(exceptionThrown);
        }

        [TestMethod]
        public async Task ChatSession_MessagePagination_ShouldReturnCorrectSubset()
        {
            // Arrange
            await _aliceChatSession.ActivateAsync();
            for (int i = 0; i < 10; i++)
            {
                await _aliceChatSession.EncryptAsync($"Message {i + 1}");
            }

            // Act - Get second page of messages (3 per page)
            var firstPage = _aliceChatSession.GetMessageHistory(limit: 3, startIndex: 0);
            var secondPage = _aliceChatSession.GetMessageHistory(limit: 3, startIndex: 3);
            var thirdPage = _aliceChatSession.GetMessageHistory(limit: 3, startIndex: 6);
            var fourthPage = _aliceChatSession.GetMessageHistory(limit: 3, startIndex: 9);

            // Assert
            Assert.AreEqual(3, firstPage.Count);
            Assert.AreEqual(3, secondPage.Count);
            Assert.AreEqual(3, thirdPage.Count);
            Assert.AreEqual(1, fourthPage.Count);

            Assert.AreEqual("Message 1", firstPage.First().Content);
            Assert.AreEqual("Message 4", secondPage.First().Content);
            Assert.AreEqual("Message 7", thirdPage.First().Content);
            Assert.AreEqual("Message 10", fourthPage.First().Content);
        }
    }
}