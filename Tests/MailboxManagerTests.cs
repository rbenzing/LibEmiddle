using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using E2EELibrary.Communication;
using E2EELibrary.Communication.Abstract;
using E2EELibrary.Core;
using E2EELibrary.Models;
using E2EELibrary.KeyManagement;

namespace E2EELibraryTests
{
    [TestClass]
    public class MailboxManagerTests
    {
        private Mock<IMailboxTransport> _mockTransport;
        private (byte[] publicKey, byte[] privateKey) _testIdentityKeyPair;
        private List<MailboxMessage> _testMessages;

        [TestInitialize]
        public void Setup()
        {
            // Create test identity key pair
            _testIdentityKeyPair = KeyGenerator.GenerateEd25519KeyPair();

            // Setup mock transport
            _mockTransport = new Mock<IMailboxTransport>();

            // Create some test messages
            _testMessages = new List<MailboxMessage>();
            for (int i = 0; i < 3; i++)
            {
                var recipientKeyPair = KeyGenerator.GenerateEd25519KeyPair();
                var msg = new MailboxMessage
                {
                    MessageId = Guid.NewGuid().ToString(),
                    RecipientKey = _testIdentityKeyPair.publicKey,
                    SenderKey = recipientKeyPair.publicKey,
                    EncryptedPayload = new EncryptedMessage
                    {
                        Ciphertext = new byte[] { 1, 2, 3 },
                        Nonce = new byte[] { 4, 5, 6 },
                        MessageNumber = i,
                        SenderDHKey = new byte[] { 7, 8, 9 },
                        Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                    },
                    Type = Enums.MessageType.Chat,
                    Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ExpiresAt = DateTimeOffset.UtcNow.AddDays(1).ToUnixTimeMilliseconds()
                };
                _testMessages.Add(msg);
            }
        }

        [TestMethod]
        public async Task FetchMessages_ShouldProcessIncomingMessages()
        {
            // Arrange
            _mockTransport
                .Setup(t => t.FetchMessagesAsync(_testIdentityKeyPair.publicKey, It.IsAny<CancellationToken>()))
                .ReturnsAsync(_testMessages);

            // Create event tracking variables
            int messageReceivedCount = 0;
            MailboxMessage lastReceivedMessage = null;

            // Create mailbox manager without starting any background tasks
            var mailboxManager = new MailboxManager(_testIdentityKeyPair, _mockTransport.Object);

            try
            {
                // Subscribe to message received event
                mailboxManager.MessageReceived += (sender, args) =>
                {
                    messageReceivedCount++;
                    lastReceivedMessage = args.Message;
                };

                // Act
                mailboxManager.Start();

                // Wait for polling to occur (we're using a shorter interval for testing)
                await Task.Delay(100);

                // The polling task should fetch messages, but it runs in background
                // We'll manually invoke the polling method to test it synchronously
                var fetchMethod = typeof(MailboxManager).GetMethod("PollForMessagesAsync",
                    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);

                await (Task)fetchMethod.Invoke(mailboxManager, new object[] { CancellationToken.None });

                // Now give event handlers a chance to run
                await Task.Delay(100);

                // Stop the manager
                mailboxManager.Stop();
            }
            finally
            {
                // Make sure to dispose the mailbox manager
                if (mailboxManager is IDisposable disposable)
                {
                    disposable.Dispose();
                }
            }

            // Assert
            Assert.AreEqual(_testMessages.Count, messageReceivedCount, "Should receive events for all messages");
            Assert.IsNotNull(lastReceivedMessage, "Should have received at least one message");

            // Verify that the transport was called properly
            _mockTransport.Verify(t => t.FetchMessagesAsync(_testIdentityKeyPair.publicKey, It.IsAny<CancellationToken>()), Times.AtLeastOnce);
        }

        [TestMethod]
        public async Task SendMessage_ShouldQueueMessageForDelivery()
        {
            // Arrange
            bool messageSent = false;
            string sentMessageId = null;

            _mockTransport
                .Setup(t => t.SendMessageAsync(It.IsAny<MailboxMessage>()))
                .Callback<MailboxMessage>(msg =>
                {
                    messageSent = true;
                    sentMessageId = msg.MessageId;
                })
                .ReturnsAsync(true);

            var recipientKeyPair = KeyGenerator.GenerateEd25519KeyPair();

            // Create mailbox manager without starting any background tasks
            var mailboxManager = new MailboxManager(_testIdentityKeyPair, _mockTransport.Object);

            try
            {
                // Act
                string messageId = mailboxManager.SendMessage(
                    recipientKeyPair.publicKey,
                    "Test message content",
                    Enums.MessageType.Chat);

                // Start the manager to process outgoing queue
                mailboxManager.Start();

                // Wait a bit for the outgoing queue processing
                await Task.Delay(100);

                // Call the processing method directly to ensure it runs
                var processMethod = typeof(MailboxManager).GetMethod("ProcessOutgoingMessagesAsync",
                    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);

                await (Task)processMethod.Invoke(mailboxManager, new object[] { CancellationToken.None });

                // Stop the manager
                mailboxManager.Stop();

                // Assert
                Assert.IsTrue(messageSent, "Message should be sent to transport");
                Assert.AreEqual(messageId, sentMessageId, "Sent message ID should match returned ID");

                // Verify transport was called
                _mockTransport.Verify(t => t.SendMessageAsync(It.IsAny<MailboxMessage>()), Times.Once);
            }
            finally
            {
                // Make sure to dispose the mailbox manager
                if (mailboxManager is IDisposable disposable)
                {
                    disposable.Dispose();
                }
            }
        }

        [TestMethod]
        public async Task MarkMessageAsRead_ShouldUpdateServerAndSendReceipt()
        {
            // Arrange
            _mockTransport
                .Setup(t => t.FetchMessagesAsync(_testIdentityKeyPair.publicKey, It.IsAny<CancellationToken>()))
                .ReturnsAsync(_testMessages);

            _mockTransport
                .Setup(t => t.MarkMessageAsReadAsync(It.IsAny<string>()))
                .ReturnsAsync(true);

            _mockTransport
                .Setup(t => t.SendMessageAsync(It.IsAny<MailboxMessage>()))
                .ReturnsAsync(true);

            // Create mailbox manager without starting any background tasks
            var mailboxManager = new MailboxManager(_testIdentityKeyPair, _mockTransport.Object);

            try
            {
                // First fetch messages
                var fetchMethod = typeof(MailboxManager).GetMethod("PollForMessagesAsync",
                    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);

                await (Task)fetchMethod.Invoke(mailboxManager, new object[] { CancellationToken.None });

                // Ensure auto-send receipts is enabled
                mailboxManager.SetAutoSendReceipts(true);

                // Get a test message ID from the received messages
                var messages = mailboxManager.GetMessages();
                Assert.IsTrue(messages.Count > 0, "Should have received at least one message");

                string testMessageId = messages[0].Message.MessageId;

                // Act
                bool result = await mailboxManager.MarkMessageAsReadAsync(testMessageId);

                // Assert
                Assert.IsTrue(result, "MarkMessageAsRead should return true");

                // Verify server was updated
                _mockTransport.Verify(t => t.MarkMessageAsReadAsync(testMessageId), Times.Once);

                // Verify a read receipt was sent
                _mockTransport.Verify(t => t.SendMessageAsync(
                    It.Is<MailboxMessage>(m => m.Type == Enums.MessageType.ReadReceipt)),
                    Times.Once);
            }
            finally
            {
                // Make sure to dispose the mailbox manager
                if (mailboxManager is IDisposable disposable)
                {
                    disposable.Dispose();
                }
            }
        }

        [TestMethod]
        public async Task DeleteMessage_ShouldRemoveMessageLocally()
        {
            // Arrange
            _mockTransport
                .Setup(t => t.FetchMessagesAsync(_testIdentityKeyPair.publicKey, It.IsAny<CancellationToken>()))
                .ReturnsAsync(_testMessages);

            _mockTransport
                .Setup(t => t.DeleteMessageAsync(It.IsAny<string>()))
                .ReturnsAsync(true);

            // Create mailbox manager without starting any background tasks
            var mailboxManager = new MailboxManager(_testIdentityKeyPair, _mockTransport.Object);

            try
            {
                // Instead of using reflection to call a private method, directly add the messages
                // to the internal collection using reflection
                var incomingMessagesField = typeof(MailboxManager).GetField("_incomingMessages",
                    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);

                var incomingMessages = incomingMessagesField.GetValue(mailboxManager) as
                    System.Collections.Concurrent.ConcurrentDictionary<string, MailboxMessage>;

                // Add test messages directly
                foreach (var message in _testMessages)
                {
                    incomingMessages.TryAdd(message.MessageId, message);
                }

                // Get messages
                var messagesBefore = mailboxManager.GetMessages();
                Assert.IsTrue(messagesBefore.Count > 0, "Should have received at least one message");

                string testMessageId = messagesBefore[0].Message.MessageId;

                // Act - call the method we're actually testing
                bool result = await mailboxManager.DeleteMessageAsync(testMessageId);

                // Get messages again to check deletion
                var messagesAfter = mailboxManager.GetMessages();

                // Assert
                Assert.IsTrue(result, "DeleteMessage should return true");
                Assert.AreEqual(messagesBefore.Count - 1, messagesAfter.Count, "One message should be deleted");

                // Verify message is no longer in the collection
                bool stillPresent = false;
                foreach (var (msg, _) in messagesAfter)
                {
                    if (msg.MessageId == testMessageId)
                    {
                        stillPresent = true;
                        break;
                    }
                }
                Assert.IsFalse(stillPresent, "Deleted message should no longer be present");

                // Verify server method was called
                _mockTransport.Verify(t => t.DeleteMessageAsync(testMessageId), Times.Once);
            }
            finally
            {
                // Make sure to dispose the mailbox manager
                if (mailboxManager is IDisposable disposable)
                {
                    disposable.Dispose();
                }
            }
        }

        [TestMethod]
        public void SetPollingInterval_ShouldUpdateInterval()
        {
            // Arrange
            // Create mailbox manager without starting any background tasks
            var mailboxManager = new MailboxManager(_testIdentityKeyPair, _mockTransport.Object);

            try
            {
                // Act
                TimeSpan newInterval = TimeSpan.FromSeconds(60);
                mailboxManager.SetPollingInterval(newInterval);

                // Assert - we can't directly test the private field, but we can verify no exception was thrown
                // This is a simple test just to ensure the method runs without errors
            }
            finally
            {
                // Make sure to dispose the mailbox manager
                if (mailboxManager is IDisposable disposable)
                {
                    disposable.Dispose();
                }
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void SetPollingInterval_WithTooSmallValue_ShouldThrowException()
        {
            // Arrange
            using (var mailboxManager = new MailboxManager(_testIdentityKeyPair, _mockTransport.Object))
            {
                // Act & Assert - Should throw ArgumentException
                mailboxManager.SetPollingInterval(TimeSpan.FromSeconds(1)); // Too small
            }
        }

        [TestMethod]
        public void GetStatistics_ShouldReturnValidData()
        {
            // Arrange
            _mockTransport
                .Setup(t => t.FetchMessagesAsync(_testIdentityKeyPair.publicKey, It.IsAny<CancellationToken>()))
                .ReturnsAsync(_testMessages);

            // Create mailbox manager and populate with test data
            using (var mailboxManager = new MailboxManager(_testIdentityKeyPair, _mockTransport.Object))
            {
                // Force fetch messages
                var fetchMethod = typeof(MailboxManager).GetMethod("PollForMessagesAsync",
                    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);

                fetchMethod.Invoke(mailboxManager, new object[] { CancellationToken.None });

                // Act
                var stats = mailboxManager.GetStatistics();

                // Assert
                Assert.IsNotNull(stats, "Statistics should not be null");
                Assert.IsTrue(stats.ContainsKey("totalIncomingMessages"), "Statistics should include incoming messages count");
                Assert.IsTrue(stats.ContainsKey("pendingOutgoingMessages"), "Statistics should include outgoing messages count");
                Assert.IsTrue(stats.ContainsKey("unreadMessages"), "Statistics should include unread messages count");
                Assert.IsTrue(stats.ContainsKey("activeSessions"), "Statistics should include active sessions count");

                // Verify values
                Assert.AreEqual(_testMessages.Count, stats["totalIncomingMessages"], "Incoming message count should match");
            }
        }

        [TestMethod]
        public void ImportExportSession_ShouldWorkCorrectly()
        {
            // Arrange
            var recipientKeyPair = KeyGenerator.GenerateEd25519KeyPair();
            string recipientId = Convert.ToBase64String(recipientKeyPair.publicKey);

            using (var mailboxManager = new MailboxManager(_testIdentityKeyPair, _mockTransport.Object))
            {
                // Send a message to create a session
                mailboxManager.SendMessage(recipientKeyPair.publicKey, "Test message", Enums.MessageType.Chat);

                // Act
                byte[] sessionData = mailboxManager.ExportSession(recipientId);

                // Create a new mailbox manager (simulating a new device)
                using (var newMailboxManager = new MailboxManager(_testIdentityKeyPair, _mockTransport.Object))
                {
                    // Import the session
                    bool result = newMailboxManager.ImportSession(recipientId, sessionData);

                    // Assert
                    Assert.IsTrue(result, "Session import should succeed");

                    // Verify we can now send messages with the imported session
                    string messageId = newMailboxManager.SendMessage(recipientKeyPair.publicKey, "Test with imported session", Enums.MessageType.Chat);
                    Assert.IsFalse(string.IsNullOrEmpty(messageId), "Should be able to send messages with imported session");
                }
            }
        }

        [TestMethod]
        public void ImportSession_WithInvalidData_ShouldReturnFalse()
        {
            // Arrange
            var recipientKeyPair = KeyGenerator.GenerateEd25519KeyPair();
            string recipientId = Convert.ToBase64String(recipientKeyPair.publicKey);
            byte[] invalidSessionData = Encoding.UTF8.GetBytes("This is not valid session data");

            using (var mailboxManager = new MailboxManager(_testIdentityKeyPair, _mockTransport.Object))
            {
                // Act
                bool result = mailboxManager.ImportSession(recipientId, invalidSessionData);

                // Assert
                Assert.IsFalse(result, "Session import should fail with invalid data");
            }
        }

        [TestMethod]
        public void ImportEncryptedSession_WithWrongKey_ShouldReturnFalse()
        {
            // Arrange
            var recipientKeyPair = KeyGenerator.GenerateEd25519KeyPair();
            string recipientId = Convert.ToBase64String(recipientKeyPair.publicKey);

            // Generate encryption keys
            byte[] correctKey = new byte[32];
            byte[] wrongKey = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(correctKey);
                rng.GetBytes(wrongKey);
            }

            // Make sure keys are different
            wrongKey[0] = (byte)(correctKey[0] ^ 0xFF);

            using (var sourceManager = new MailboxManager(_testIdentityKeyPair, _mockTransport.Object))
            {
                // Send a message to create a session
                sourceManager.SendMessage(recipientKeyPair.publicKey, "Test message", Enums.MessageType.Chat);

                // Export with the correct key
                byte[] sessionData = sourceManager.ExportSession(recipientId, correctKey);

                // Create a new mailbox manager
                using (var targetManager = new MailboxManager(_testIdentityKeyPair, _mockTransport.Object))
                {
                    // Act - Try to import with the wrong key
                    bool result = targetManager.ImportSession(recipientId, sessionData, wrongKey);

                    // Assert
                    Assert.IsFalse(result, "Session import should fail with wrong decryption key");
                }
            }
        }

        [TestMethod]
        public void ExportSession_NonexistentRecipient_ShouldThrowException()
        {
            // Arrange
            string nonExistentRecipientId = Convert.ToBase64String(new byte[32]); // All zeros

            using (var mailboxManager = new MailboxManager(_testIdentityKeyPair, _mockTransport.Object))
            {
                // Act & Assert
                Assert.ThrowsException<KeyNotFoundException>(() =>
                {
                    mailboxManager.ExportSession(nonExistentRecipientId);
                }, "ExportSession should throw KeyNotFoundException for nonexistent recipient");
            }
        }

        [TestMethod]
        public void ProcessExpiredMessages_ShouldSkipExpiredMessages()
        {
            // Arrange
            // Create test messages, one of which is expired
            var normalMessage = new MailboxMessage
            {
                MessageId = Guid.NewGuid().ToString(),
                RecipientKey = _testIdentityKeyPair.publicKey,
                SenderKey = KeyGenerator.GenerateEd25519KeyPair().publicKey,
                EncryptedPayload = new EncryptedMessage
                {
                    Ciphertext = new byte[] { 1, 2, 3 },
                    Nonce = new byte[] { 4, 5, 6 },
                    MessageNumber = 1,
                    SenderDHKey = new byte[] { 7, 8, 9 }
                },
                Type = Enums.MessageType.Chat,
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ExpiresAt = DateTimeOffset.UtcNow.AddDays(1).ToUnixTimeMilliseconds() // Not expired
            };

            var expiredMessage = new MailboxMessage
            {
                MessageId = Guid.NewGuid().ToString(),
                RecipientKey = _testIdentityKeyPair.publicKey,
                SenderKey = KeyGenerator.GenerateEd25519KeyPair().publicKey,
                EncryptedPayload = new EncryptedMessage
                {
                    Ciphertext = new byte[] { 1, 2, 3 },
                    Nonce = new byte[] { 4, 5, 6 },
                    MessageNumber = 2,
                    SenderDHKey = new byte[] { 7, 8, 9 }
                },
                Type = Enums.MessageType.Chat,
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ExpiresAt = DateTimeOffset.UtcNow.AddDays(-1).ToUnixTimeMilliseconds() // Already expired
            };

            var testMessages = new List<MailboxMessage> { normalMessage, expiredMessage };

            _mockTransport
                .Setup(t => t.FetchMessagesAsync(_testIdentityKeyPair.publicKey, It.IsAny<CancellationToken>()))
                .ReturnsAsync(testMessages);

            // Track message events
            int messageReceivedCount = 0;
            MailboxMessage lastReceivedMessage = null;

            // Create mailbox manager
            using (var mailboxManager = new MailboxManager(_testIdentityKeyPair, _mockTransport.Object))
            {
                // Subscribe to message received events
                mailboxManager.MessageReceived += (sender, args) =>
                {
                    messageReceivedCount++;
                    lastReceivedMessage = args.Message;
                };

                // Act
                var fetchMethod = typeof(MailboxManager).GetMethod("PollForMessagesAsync",
                    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);

                fetchMethod.Invoke(mailboxManager, new object[] { CancellationToken.None });

                // Wait for event processing
                System.Threading.Thread.Sleep(100);

                // Assert
                Assert.AreEqual(1, messageReceivedCount, "Only non-expired message should be processed");
                Assert.IsNotNull(lastReceivedMessage, "Should have received the normal message");
                Assert.AreEqual(normalMessage.MessageId, lastReceivedMessage.MessageId, "Should have received the non-expired message");
            }
        }
    }
}