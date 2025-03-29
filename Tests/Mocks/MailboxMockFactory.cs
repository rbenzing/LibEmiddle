using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Moq;
using E2EELibrary.Models;
using E2EELibrary.Communication.Abstract;

namespace E2EELibraryTests.Mocks
{
    /// <summary>
    /// Provides factory methods for creating mock mailbox transports.
    /// </summary>
    public static class MailboxMockFactory
    {
        /// <summary>
        /// Creates a mock mailbox transport that returns the specified messages.
        /// </summary>
        /// <param name="messages">Messages to return when fetching</param>
        /// <returns>A mock mailbox transport</returns>
        public static Mock<IMailboxTransport> CreateMockTransport(List<MailboxMessage> messages = null)
        {
            var mockTransport = new Mock<IMailboxTransport>();

            // Setup SendMessageAsync to return true
            mockTransport
                .Setup(t => t.SendMessageAsync(It.IsAny<MailboxMessage>()))
                .ReturnsAsync(true);

            // Setup FetchMessagesAsync to return the specified messages
            mockTransport
                .Setup(t => t.FetchMessagesAsync(It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(messages ?? new List<MailboxMessage>());

            // Setup DeleteMessageAsync to return true
            mockTransport
                .Setup(t => t.DeleteMessageAsync(It.IsAny<string>()))
                .ReturnsAsync(true);

            // Setup MarkMessageAsReadAsync to return true
            mockTransport
                .Setup(t => t.MarkMessageAsReadAsync(It.IsAny<string>()))
                .ReturnsAsync(true);

            return mockTransport;
        }

        /// <summary>
        /// Creates a mock mailbox transport that simulates errors.
        /// </summary>
        /// <returns>A mock mailbox transport that fails operations</returns>
        public static Mock<IMailboxTransport> CreateFailingMockTransport()
        {
            var mockTransport = new Mock<IMailboxTransport>();

            // Setup all methods to throw exceptions
            mockTransport
                .Setup(t => t.SendMessageAsync(It.IsAny<MailboxMessage>()))
                .ThrowsAsync(new System.Net.Http.HttpRequestException("Simulated network error"));

            mockTransport
                .Setup(t => t.FetchMessagesAsync(It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
                .ThrowsAsync(new System.Net.Http.HttpRequestException("Simulated network error"));

            mockTransport
                .Setup(t => t.DeleteMessageAsync(It.IsAny<string>()))
                .ThrowsAsync(new System.Net.Http.HttpRequestException("Simulated network error"));

            mockTransport
                .Setup(t => t.MarkMessageAsReadAsync(It.IsAny<string>()))
                .ThrowsAsync(new System.Net.Http.HttpRequestException("Simulated network error"));

            return mockTransport;
        }

        /// <summary>
        /// Creates a mock mailbox transport that simulates network delays.
        /// </summary>
        /// <param name="delayMs">Delay in milliseconds</param>
        /// <returns>A mock mailbox transport with delays</returns>
        public static Mock<IMailboxTransport> CreateDelayedMockTransport(int delayMs = 500)
        {
            var mockTransport = new Mock<IMailboxTransport>();

            // Setup all methods to delay
            mockTransport
                .Setup(t => t.SendMessageAsync(It.IsAny<MailboxMessage>()))
                .Returns(async (MailboxMessage msg) =>
                {
                    await Task.Delay(delayMs);
                    return true;
                });

            mockTransport
                .Setup(t => t.FetchMessagesAsync(It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
                .Returns(async (byte[] key, CancellationToken token) =>
                {
                    await Task.Delay(delayMs, token);
                    return new List<MailboxMessage>();
                });

            mockTransport
                .Setup(t => t.DeleteMessageAsync(It.IsAny<string>()))
                .Returns(async (string id) =>
                {
                    await Task.Delay(delayMs);
                    return true;
                });

            mockTransport
                .Setup(t => t.MarkMessageAsReadAsync(It.IsAny<string>()))
                .Returns(async (string id) =>
                {
                    await Task.Delay(delayMs);
                    return true;
                });

            return mockTransport;
        }
    }
}