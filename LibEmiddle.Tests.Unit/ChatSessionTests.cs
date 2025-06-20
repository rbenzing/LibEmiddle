﻿using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Linq;
using System.Threading.Tasks;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.Messaging.Chat;
using LibEmiddle.Domain.Enums;
using LibEmiddle.Protocol;
using LibEmiddle.Abstractions;
using LibEmiddle.Sessions;

namespace LibEmiddle.Tests.Unit
{
    [TestClass]
    public class ChatSessionTests
    {
        private KeyPair _aliceKeyPair;
        private KeyPair _bobKeyPair;

        private CryptoProvider _cryptoProvider = null!;
        private DoubleRatchetProtocol _doubleRatchetProtocol = null!;
        private X3DHProtocol _x3DHProtocol = null!;
        private ProtocolAdapter _protocolAdapter = null!;

        private ISessionManager _sessionManager = null!;
        private ChatSession _aliceChatSession = null!;
        private ChatSession _bobChatSession = null!;
        private DoubleRatchetSession _aliceDoubleRatchetSession = null!;
        private DoubleRatchetSession _bobDoubleRatchetSession = null!;

        [TestInitialize]
        public async Task Setup()
        {
            // Initialize crypto components
            _cryptoProvider = new CryptoProvider();
            _doubleRatchetProtocol = new DoubleRatchetProtocol();
            _x3DHProtocol = new X3DHProtocol(_cryptoProvider);
            _protocolAdapter = new ProtocolAdapter(_x3DHProtocol, _doubleRatchetProtocol, _cryptoProvider);

            // Generate proper key pairs for Alice and Bob
            _aliceKeyPair = Sodium.GenerateEd25519KeyPair();
            _bobKeyPair = Sodium.GenerateEd25519KeyPair();

            // Generate a consistent session ID
            string sessionId = Guid.NewGuid().ToString();

            // Session manager instance for Alice
            _sessionManager = new SessionManager(_cryptoProvider, _x3DHProtocol, _doubleRatchetProtocol, _aliceKeyPair);

            // Step 1: Create Bob's X3DH key bundle
            X3DHKeyBundle bobX3DHBundle = await _x3DHProtocol.CreateKeyBundleAsync(_bobKeyPair);
            X3DHPublicBundle bobPublicBundle = bobX3DHBundle.ToPublicBundle();

            // Step 2: Alice initiates session (sender side) using ProtocolAdapter
            var (aliceDRSession, initialMessage) = await _protocolAdapter.PrepareSenderSessionAsync(
                bobPublicBundle, _aliceKeyPair, sessionId);

            // Step 3: Bob receives the initial message and establishes session (receiver side) using ProtocolAdapter
            // This ensures proper synchronization between Alice and Bob's sessions
            var bobDRSession = await _protocolAdapter.PrepareReceiverSessionAsync(
                initialMessage, bobX3DHBundle, sessionId);

            // Store the sessions
            _aliceDoubleRatchetSession = aliceDRSession;
            _bobDoubleRatchetSession = bobDRSession;

            // Step 4: Create chat sessions for both Alice and Bob
            _aliceChatSession = new ChatSession(
                _aliceDoubleRatchetSession,
                _bobKeyPair.PublicKey,
                _aliceKeyPair.PublicKey,
                _doubleRatchetProtocol
            );

            _bobChatSession = new ChatSession(
                _bobDoubleRatchetSession,
                _aliceKeyPair.PublicKey,
                _bobKeyPair.PublicKey,
                _doubleRatchetProtocol
            );

            // Set the initial message data for Alice (sender)
            _aliceChatSession.SetInitialMessageData(initialMessage);
        }

        [TestCleanup]
        public void Cleanup()
        {
            try
            {
                _aliceChatSession?.Dispose();
            }
            catch (ObjectDisposedException)
            {
                // Already disposed in test, ignore
            }

            try
            {
                _bobChatSession?.Dispose();
            }
            catch (ObjectDisposedException)
            {
                // Already disposed in test, ignore
            }

            try
            {
                _cryptoProvider?.Dispose();
            }
            catch (ObjectDisposedException)
            {
                // Already disposed, ignore
            }
        }

        [TestMethod]
        public void ChatSession_InitialState_ShouldBeInitialized()
        {
            // Assert
            Assert.AreEqual(SessionState.Initialized, _aliceChatSession.State);
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
            Assert.AreEqual(SessionState.Active, _aliceChatSession.State);
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
            Assert.AreEqual(SessionState.Active, _aliceChatSession.State);
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
            Assert.AreEqual(SessionState.Suspended, _aliceChatSession.State);
            Assert.IsNotNull(_aliceChatSession.LastSuspendedAt);
            Assert.AreEqual(suspensionReason, _aliceChatSession.SuspensionReason);
        }

        [TestMethod]
        public async Task ChatSession_SuspendFromInitialized_ShouldChangeStateToSuspended()
        {
            // Act
            bool result = await _aliceChatSession.SuspendAsync("Direct suspension");

            // Assert
            Assert.IsTrue(result);
            Assert.AreEqual(SessionState.Suspended, _aliceChatSession.State);
        }

        [TestMethod]
        public async Task ChatSession_Terminate_ShouldChangeStateToTerminated()
        {
            // Act
            bool result = await _aliceChatSession.TerminateAsync();

            // Assert
            Assert.IsTrue(result);
            Assert.AreEqual(SessionState.Terminated, _aliceChatSession.State);
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
            var tcs = new TaskCompletionSource<(SessionState previous, SessionState current, DateTime timestamp)>();

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
            Assert.AreEqual(SessionState.Initialized, previousState, "Expected previous state to be Initialized.");
            Assert.AreEqual(SessionState.Active, currentState, "Expected new state to be Active.");
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
            Assert.AreEqual(SessionState.Active, _aliceChatSession.State);
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
            Assert.AreEqual(SessionState.Active, _aliceChatSession.State, "Session should be auto-activated on encryption.");
            Assert.IsNotNull(_aliceChatSession.LastActivatedAt, "LastActivatedAt should be set upon activation.");
        }

        [TestMethod]
        public async Task ChatSession_EncryptMessageInSuspendedState_ShouldThrowException()
        {
            // Arrange
            await _aliceChatSession.SuspendAsync("Testing encryption rejection");
            string message = "Should fail in suspended state";

            // Act & Assert
            await Assert.ThrowsExceptionAsync<InvalidOperationException>(() => _aliceChatSession.EncryptAsync(message));
        }

        [TestMethod]
        public async Task ChatSession_DecryptMessage_ShouldWorkInActiveState()
        {
            // Arrange
            await _aliceChatSession.ActivateAsync();
            await _bobChatSession.ActivateAsync();

            string originalMessage = "Test message";
            EncryptedMessage encryptedMessage = await _aliceChatSession.EncryptAsync(originalMessage);
            Assert.IsNotNull(encryptedMessage);

            // Act
            string decryptedMessage = await _bobChatSession.DecryptAsync(encryptedMessage);

            // Assert
            Assert.IsNotNull(decryptedMessage);
            Assert.AreEqual(originalMessage, decryptedMessage);
        }

        [TestMethod]
        public async Task ChatSession_DecryptMessageInTerminatedState_ShouldThrowException()
        {
            // Arrange
            await _aliceChatSession.ActivateAsync();
            string originalMessage = "Test message";
            EncryptedMessage encryptedMessage = await _aliceChatSession.EncryptAsync(originalMessage);
            Assert.IsNotNull(encryptedMessage);

            // Terminate Bob's session
            await _bobChatSession.TerminateAsync();

            // Act & Assert
            await Assert.ThrowsExceptionAsync<InvalidOperationException>(() => _bobChatSession.DecryptAsync(encryptedMessage));
        }

        [TestMethod]
        public async Task ChatSession_MessageHistory_ShouldTrackSentAndReceivedMessages()
        {
            // Arrange
            await _aliceChatSession.ActivateAsync();
            await _bobChatSession.ActivateAsync();

            string message1 = "First message";
            string message2 = "Second message";

            // Act - Send messages both ways
            EncryptedMessage encryptedMessage1 = await _aliceChatSession.EncryptAsync(message1);
            Assert.IsNotNull(encryptedMessage1);

            string decryptedMessage1 = await _bobChatSession.DecryptAsync(encryptedMessage1);
            Assert.IsNotNull(decryptedMessage1);

            EncryptedMessage encryptedMessage2 = await _bobChatSession.EncryptAsync(message2);
            Assert.IsNotNull(encryptedMessage2);

            string decryptedMessage2 = await _aliceChatSession.DecryptAsync(encryptedMessage2);
            Assert.IsNotNull(decryptedMessage2);

            // Assert
            var aliceHistory = _aliceChatSession.GetMessageHistory();
            var bobHistory = _bobChatSession.GetMessageHistory();

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
            await Assert.ThrowsExceptionAsync<ObjectDisposedException>(() => _aliceChatSession.ActivateAsync());
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

            // Act - Get pages of messages (3 per page)
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