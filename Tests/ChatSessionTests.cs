using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Linq;
using E2EELibrary.Models;
using E2EELibrary.Core;
using E2EELibrary.KeyExchange;
using E2EELibrary.KeyManagement;

namespace E2EELibraryTests
{
    [TestClass]
    public class ChatSessionTests
    {
        private (byte[] publicKey, byte[] privateKey) _aliceKeyPair;
        private (byte[] publicKey, byte[] privateKey) _bobKeyPair;
        private DoubleRatchetSession _aliceRatchetSession;
        private DoubleRatchetSession _bobRatchetSession;
        private ChatSession _aliceChatSession;

        [TestInitialize]
        public void TestInitialize()
        {
            // Generate proper key pairs for Alice and Bob
            _aliceKeyPair = KeyGenerator.GenerateX25519KeyPair();
            _bobKeyPair = KeyGenerator.GenerateX25519KeyPair();

            // Create a shared secret (simulating X3DH)
            byte[] sharedSecret = X3DHExchange.X3DHKeyExchange(_bobKeyPair.publicKey, _aliceKeyPair.privateKey);

            // Initialize Double Ratchet
            var (rootKey, chainKey) = DoubleRatchetExchange.InitializeDoubleRatchet(sharedSecret);

            string sessionId = Guid.NewGuid().ToString();

            // Create Alice's sending session
            _aliceRatchetSession = new DoubleRatchetSession(
                dhRatchetKeyPair: _aliceKeyPair,
                remoteDHRatchetKey: _bobKeyPair.publicKey,
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumber: 0,
                sessionId: sessionId
            );

            // Create Bob's receiving session
            _bobRatchetSession = new DoubleRatchetSession(
                dhRatchetKeyPair: _bobKeyPair,
                remoteDHRatchetKey: _aliceKeyPair.publicKey,
                rootKey: rootKey,
                sendingChainKey: chainKey,
                receivingChainKey: chainKey,
                messageNumber: 0,
                sessionId: sessionId
            );

            // Create Alice's chat session
            _aliceChatSession = new ChatSession(
                _aliceRatchetSession,
                _bobKeyPair.publicKey,
                _aliceKeyPair.publicKey
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
        public void ChatSession_Activate_ShouldChangeStateToActive()
        {
            // Act
            bool result = _aliceChatSession.Activate();

            // Assert
            Assert.IsTrue(result);
            Assert.AreEqual(Enums.ChatSessionState.Active, _aliceChatSession.State);
            Assert.IsNotNull(_aliceChatSession.LastActivatedAt);
        }

        [TestMethod]
        public void ChatSession_ActivateAlreadyActiveSession_ShouldReturnFalse()
        {
            // Arrange
            _aliceChatSession.Activate();

            // Act
            bool result = _aliceChatSession.Activate();

            // Assert
            Assert.IsFalse(result);
            Assert.AreEqual(Enums.ChatSessionState.Active, _aliceChatSession.State);
        }

        [TestMethod]
        public void ChatSession_Suspend_ShouldChangeStateToSuspended()
        {
            // Arrange
            _aliceChatSession.Activate();
            string suspensionReason = "Testing suspension";

            // Act
            bool result = _aliceChatSession.Suspend(suspensionReason);

            // Assert
            Assert.IsTrue(result);
            Assert.AreEqual(Enums.ChatSessionState.Suspended, _aliceChatSession.State);
            Assert.IsNotNull(_aliceChatSession.LastSuspendedAt);
            Assert.AreEqual(suspensionReason, _aliceChatSession.SuspensionReason);
        }

        [TestMethod]
        public void ChatSession_SuspendFromInitialized_ShouldChangeStateToSuspended()
        {
            // Act
            bool result = _aliceChatSession.Suspend("Direct suspension");

            // Assert
            Assert.IsTrue(result);
            Assert.AreEqual(Enums.ChatSessionState.Suspended, _aliceChatSession.State);
        }

        [TestMethod]
        public void ChatSession_Terminate_ShouldChangeStateToTerminated()
        {
            // Act
            bool result = _aliceChatSession.Terminate();

            // Assert
            Assert.IsTrue(result);
            Assert.AreEqual(Enums.ChatSessionState.Terminated, _aliceChatSession.State);
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidOperationException))]
        public void ChatSession_ActivateTerminatedSession_ShouldThrowException()
        {
            // Arrange
            _aliceChatSession.Terminate();

            // Act
            _aliceChatSession.Activate();
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidOperationException))]
        public void ChatSession_SuspendTerminatedSession_ShouldThrowException()
        {
            // Arrange
            _aliceChatSession.Terminate();

            // Act
            _aliceChatSession.Suspend();
        }

        [TestMethod]
        public void ChatSession_StateChangeEvents_ShouldBeRaised()
        {
            // Arrange
            Enums.ChatSessionState? previousState = null;
            Enums.ChatSessionState? newState = null;
            DateTime? timestamp = null;

            _aliceChatSession.StateChanged += (sender, e) => {
                previousState = e.PreviousState;
                newState = e.NewState;
                timestamp = e.Timestamp;
            };

            // Act
            _aliceChatSession.Activate();

            // Assert
            Assert.IsNotNull(previousState);
            Assert.IsNotNull(newState);
            Assert.IsNotNull(timestamp);
            Assert.AreEqual(Enums.ChatSessionState.Initialized, previousState);
            Assert.AreEqual(Enums.ChatSessionState.Active, newState);
        }

        [TestMethod]
        public void ChatSession_EncryptMessage_ShouldAutoActivateSession()
        {
            // Arrange
            string message = "Auto-activation test";

            // Act
            EncryptedMessage encryptedMessage = _aliceChatSession.EncryptMessage(message);

            // Assert
            Assert.AreEqual(Enums.ChatSessionState.Active, _aliceChatSession.State);
            Assert.IsNotNull(_aliceChatSession.LastActivatedAt);
            Assert.IsNotNull(encryptedMessage);
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidOperationException))]
        public void ChatSession_EncryptMessageWithoutAutoActivate_ShouldThrowException()
        {
            // Arrange
            string message = "Should fail without auto-activation";

            // Act
            _aliceChatSession.EncryptMessage(message, autoActivate: false);
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidOperationException))]
        public void ChatSession_EncryptMessageInSuspendedState_ShouldThrowException()
        {
            // Arrange
            _aliceChatSession.Suspend("Testing encryption rejection");
            string message = "Should fail in suspended state";

            // Act
            _aliceChatSession.EncryptMessage(message);
        }

        [TestMethod]
        public void ChatSession_DecryptMessage_ShouldWorkInSuspendedState()
        {
            // Arrange
            _aliceChatSession.Activate();
            string originalMessage = "Test message";
            EncryptedMessage encryptedMessage = _aliceChatSession.EncryptMessage(originalMessage);

            // Create Bob's chat session
            var bobChatSession = new ChatSession(
                _bobRatchetSession,
                _aliceKeyPair.publicKey,
                _bobKeyPair.publicKey
            );

            // Suspend Bob's session
            bobChatSession.Suspend("Testing decryption in suspended state");

            // Act
            string? decryptedMessage = bobChatSession.DecryptMessage(encryptedMessage);

            // Assert
            Assert.IsNotNull(decryptedMessage);
            Assert.AreEqual(originalMessage, decryptedMessage);
            Assert.AreEqual(Enums.ChatSessionState.Suspended, bobChatSession.State, "State should remain suspended");
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidOperationException))]
        public void ChatSession_DecryptMessageInTerminatedState_ShouldThrowException()
        {
            // Arrange
            _aliceChatSession.Activate();
            string originalMessage = "Test message";
            EncryptedMessage encryptedMessage = _aliceChatSession.EncryptMessage(originalMessage);

            // Create Bob's chat session
            var bobChatSession = new ChatSession(
                _bobRatchetSession,
                _aliceKeyPair.publicKey,
                _bobKeyPair.publicKey
            );

            // Terminate Bob's session
            bobChatSession.Terminate();

            // Act
            bobChatSession.DecryptMessage(encryptedMessage);
        }

        [TestMethod]
        public void ChatSession_MessageHistory_ShouldTrackSentAndReceivedMessages()
        {
            // Arrange
            _aliceChatSession.Activate();
            string message1 = "First message";
            string message2 = "Second message";

            // Create Bob's chat session
            var bobChatSession = new ChatSession(
                _bobRatchetSession,
                _aliceKeyPair.publicKey,
                _bobKeyPair.publicKey
            );
            bobChatSession.Activate();

            // Act - Send messages both ways
            EncryptedMessage encryptedMessage1 = _aliceChatSession.EncryptMessage(message1);
            string? decryptedMessage1 = bobChatSession.DecryptMessage(encryptedMessage1);

            EncryptedMessage encryptedMessage2 = bobChatSession.EncryptMessage(message2);
            string? decryptedMessage2 = _aliceChatSession.DecryptMessage(encryptedMessage2);

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
        public void ChatSession_ClearMessageHistory_ShouldRemoveAllMessages()
        {
            // Arrange
            _aliceChatSession.Activate();
            _aliceChatSession.EncryptMessage("Message 1");
            _aliceChatSession.EncryptMessage("Message 2");
            _aliceChatSession.EncryptMessage("Message 3");

            Assert.AreEqual(3, _aliceChatSession.GetMessageCount());

            // Act
            int clearedCount = _aliceChatSession.ClearMessageHistory();

            // Assert
            Assert.AreEqual(3, clearedCount);
            Assert.AreEqual(0, _aliceChatSession.GetMessageCount());
            Assert.AreEqual(0, _aliceChatSession.GetMessageHistory().Count);
        }

        [TestMethod]
        public void ChatSession_IsValid_ShouldReturnFalseWhenTerminated()
        {
            // Arrange
            _aliceChatSession.Activate();
            Assert.IsTrue(_aliceChatSession.IsValid());

            // Act
            _aliceChatSession.Terminate();

            // Assert
            Assert.IsFalse(_aliceChatSession.IsValid());
        }

        [TestMethod]
        public void ChatSession_Dispose_ShouldTerminateSession()
        {
            // Arrange
            _aliceChatSession.Activate();

            // Act
            _aliceChatSession.Dispose();

            // Assert - try to use the session, should throw ObjectDisposedException
            bool exceptionThrown = false;
            try
            {
                _aliceChatSession.Activate();
            }
            catch (ObjectDisposedException)
            {
                exceptionThrown = true;
            }

            Assert.IsTrue(exceptionThrown);
        }

        [TestMethod]
        public void ChatSession_MessagePagination_ShouldReturnCorrectSubset()
        {
            // Arrange
            _aliceChatSession.Activate();
            for (int i = 0; i < 10; i++)
            {
                _aliceChatSession.EncryptMessage($"Message {i + 1}");
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