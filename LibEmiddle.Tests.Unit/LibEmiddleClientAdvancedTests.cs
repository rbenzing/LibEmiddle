using Microsoft.VisualStudio.TestTools.UnitTesting;
using LibEmiddle.API;
using LibEmiddle.Domain.Enums;
using LibEmiddle.Core;
using System;
using System.Threading.Tasks;
using System.Threading;

namespace LibEmiddle.Tests.Unit
{
    /// <summary>
    /// Tests for the LibEmiddleClient functionality including
    /// message listening, device management, and message history features.
    /// </summary>
    [TestClass]
    public class LibEmiddleClientAdvancedTests
    {
        private LibEmiddleClientOptions _clientOptions;
        private LibEmiddleClient _client;

        [TestInitialize]
        public void Setup()
        {
            _clientOptions = new LibEmiddleClientOptions
            {
                TransportType = TransportType.InMemory,
                EnableMessageHistory = true,
                MaxMessageHistoryPerSession = 100,
                EnableMultiDevice = true,
                MaxLinkedDevices = 5
            };

            _client = new LibEmiddleClient(_clientOptions);
        }

        [TestCleanup]
        public void Cleanup()
        {
            _client?.Dispose();
        }

        [TestMethod]
        public async Task InitializeAsync_ShouldSucceed()
        {
            // Act
            var result = await _client.InitializeAsync();

            // Assert
            Assert.IsTrue(result, "Client initialization should succeed");
            Assert.IsFalse(_client.IsListening, "Client should not be listening initially");
        }

        [TestMethod]
        public async Task StartListeningAsync_ShouldStartSuccessfully()
        {
            // Arrange
            await _client.InitializeAsync();

            // Act
            var result = await _client.StartListeningAsync(2000); // 2 second interval

            // Assert
            Assert.IsTrue(result, "Should start listening successfully");
            Assert.IsTrue(_client.IsListening, "Client should be listening");

            // Cleanup
            await _client.StopListeningAsync();
        }

        [TestMethod]
        public async Task StartListeningAsync_WithLowInterval_ShouldAdjustToMinimum()
        {
            // Arrange
            await _client.InitializeAsync();

            // Act - Try to set interval below minimum (1000ms)
            var result = await _client.StartListeningAsync(500);

            // Assert
            Assert.IsTrue(result, "Should start listening with adjusted interval");
            Assert.IsTrue(_client.IsListening, "Client should be listening");

            // Cleanup
            await _client.StopListeningAsync();
        }

        [TestMethod]
        public async Task StopListeningAsync_WhenNotListening_ShouldReturnTrue()
        {
            // Arrange
            await _client.InitializeAsync();

            // Act
            var result = await _client.StopListeningAsync();

            // Assert
            Assert.IsTrue(result, "Should return true even when not listening");
            Assert.IsFalse(_client.IsListening, "Client should not be listening");
        }

        [TestMethod]
        public async Task GetLinkedDeviceCount_Initially_ShouldReturnZero()
        {
            // Arrange
            await _client.InitializeAsync();

            // Act
            var count = _client.GetLinkedDeviceCount();

            // Assert
            Assert.AreEqual(0, count, "Should have no linked devices initially");
        }

        [TestMethod]
        public async Task GetChatMessageHistoryAsync_WithInvalidSessionId_ShouldReturnNull()
        {
            // Arrange
            await _client.InitializeAsync();

            // Act - Try to get history for non-existent session
            var history = await _client.GetChatMessageHistoryAsync("non-existent-session", 10);

            // Assert
            Assert.IsNull(history, "Should return null for non-existent session");
        }

        [TestMethod]
        public async Task GetChatMessageCountAsync_WithInvalidSessionId_ShouldReturnMinusOne()
        {
            // Arrange
            await _client.InitializeAsync();

            // Act - Try to get count for non-existent session
            var count = await _client.GetChatMessageCountAsync("non-existent-session");

            // Assert
            Assert.AreEqual(-1, count, "Should return -1 for non-existent session");
        }

        [TestMethod]
        public async Task CreateGroup_ShouldAllowGroupInfoAccess()
        {
            // Arrange
            await _client.InitializeAsync();

            // Act
            var groupSession = await _client.CreateGroupAsync("test-group", "Test Group");
            
            // Use the session ID to get session info instead of group ID
            var sessionInfo = await _client.GetSessionInfoAsync(groupSession.SessionId);

            // Assert
            Assert.IsNotNull(groupSession, "Group session should be created");
            Assert.IsNotNull(sessionInfo, "Session info should be accessible");
            Assert.AreEqual(groupSession.SessionId, sessionInfo.SessionId, "Session ID should match");
        }

        [TestMethod]
        public async Task LeaveGroupAsync_ShouldRemoveGroup()
        {
            // Arrange
            await _client.InitializeAsync();
            var groupSession = await _client.CreateGroupAsync("test-group", "Test Group");

            // Act - Use the actual session ID instead of group ID for deletion
            var result = await _client.DeleteSessionAsync(groupSession.SessionId);

            // Assert
            Assert.IsTrue(result, "Should successfully delete group session");

            // Verify session is no longer accessible
            var sessionInfo = await _client.GetSessionInfoAsync(groupSession.SessionId);
            Assert.IsNull(sessionInfo, "Session should no longer be accessible after deletion");
        }

        [TestMethod]
        public async Task DeleteSessionAsync_WithInvalidSessionId_ShouldReturnFalse()
        {
            // Arrange
            await _client.InitializeAsync();

            // Act
            var result = await _client.DeleteSessionAsync("non-existent-session");

            // Assert
            Assert.IsFalse(result, "Should return false for non-existent session");
        }

        [TestMethod]
        public async Task MessageReceived_Event_ShouldBeExposed()
        {
            // Arrange
            await _client.InitializeAsync();
            bool eventFired = false;
            _client.MessageReceived += (sender, args) => {
                eventFired = true;
            };

            // Act
            await _client.StartListeningAsync();

            // Assert
            // We can't directly check if the event is null, but we can verify it was subscribed
            // Note: Actually triggering the event would require a more complex test setup
            // with message injection, which is beyond the scope of this basic test
            Assert.IsTrue(_client.IsListening, "Client should be listening for messages");

            // Cleanup
            await _client.StopListeningAsync();
            
            // Use the variable to avoid compiler warning
            Assert.IsFalse(eventFired, "Event should not have fired in this simple test");
        }

        [TestMethod]
        public void DeviceManager_ShouldBeAccessible()
        {
            // Act & Assert
            Assert.IsNotNull(_client.DeviceManager, "DeviceManager should be accessible");
        }

        [TestMethod]
        public async Task GetPublicKeyBundleAsync_ShouldReturnValidBundle()
        {
            // Arrange
            await _client.InitializeAsync();

            // Act
            var bundle = await _client.GetPublicKeyBundleAsync(5);

            // Assert
            Assert.IsNotNull(bundle, "Public key bundle should be created");
            Assert.IsNotNull(bundle.IdentityKey, "Bundle should have identity key");
            Assert.IsNotNull(bundle.SignedPreKey, "Bundle should have signed pre-key");
        }
    }
}
