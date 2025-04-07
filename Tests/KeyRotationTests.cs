using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Reflection;
using System.Threading;
using System.Collections.Concurrent;
using E2EELibrary.GroupMessaging;
using E2EELibrary.KeyManagement;
using E2EELibrary.Models;

namespace E2EELibraryTests
{
    [TestClass]
    public class KeyRotationTests
    {
        [TestMethod]
        public void GroupKey_ShouldRotate_AfterConfiguredPeriod()
        {
            // Arrange
            var identityKeyPair = KeyGenerator.GenerateEd25519KeyPair();
            var groupChatManager = new GroupChatManager(identityKeyPair);
            var groupId = "testGroup" + Guid.NewGuid().ToString("N").Substring(0, 8);

            // Use reflection to access private fields
            var lastRotationField = typeof(GroupChatManager).GetField(
                "_lastKeyRotationTimestamps",
                BindingFlags.NonPublic | BindingFlags.Instance);

            // Use reflection to directly set the rotation period field for testing
            var rotationPeriodField = typeof(GroupChatManager).GetField(
                "_keyRotationPeriod",
                BindingFlags.NonPublic | BindingFlags.Instance);
            rotationPeriodField.SetValue(groupChatManager, TimeSpan.FromMilliseconds(100));

            // Act
            byte[] originalKey = groupChatManager.CreateGroup(groupId);

            // Wait for rotation period
            Thread.Sleep(200);

            // Trigger key check by sending a message
            var message = groupChatManager.EncryptGroupMessage(groupId, "test message");

            // Assert
            var timestamps = lastRotationField?.GetValue(groupChatManager) as ConcurrentDictionary<string, long>;
            Assert.IsNotNull(timestamps);
            Assert.IsTrue(timestamps.ContainsKey(groupId));

            // Get current key and verify it's different
            var groupSession = GetGroupSession(groupChatManager, groupId);
            Assert.IsNotNull(groupSession);
            Assert.AreNotEqual(
                Convert.ToBase64String(originalKey),
                Convert.ToBase64String(groupSession.SenderKey));
        }

        [TestMethod]
        public void KeyRotation_ShouldHappen_AfterMemberRemoval()
        {
            // Arrange
            var identityKeyPair = KeyGenerator.GenerateEd25519KeyPair();
            var memberKeyPair = KeyGenerator.GenerateEd25519KeyPair();
            var groupChatManager = new GroupChatManager(identityKeyPair);
            var groupId = "testGroup" + Guid.NewGuid().ToString("N").Substring(0, 8);

            // Act - Create group and add member
            byte[] originalKey = groupChatManager.CreateGroup(groupId);
            groupChatManager.AddGroupMember(groupId, memberKeyPair.publicKey);

            // Get group key before removal
            var sessionBefore = GetGroupSession(groupChatManager, groupId);
            byte[] keyBeforeRemoval = sessionBefore.SenderKey;

            // Remove member
            groupChatManager.RemoveGroupMember(groupId, memberKeyPair.publicKey);

            // Get group key after removal
            var sessionAfter = GetGroupSession(groupChatManager, groupId);
            byte[] keyAfterRemoval = sessionAfter.SenderKey;

            // Assert - Keys should be different
            Assert.AreNotEqual(
                Convert.ToBase64String(keyBeforeRemoval),
                Convert.ToBase64String(keyAfterRemoval),
                "Group key should be rotated after member removal");
        }

        // Helper to get group session using reflection
        private static GroupSession GetGroupSession(GroupChatManager manager, string groupId)
        {
            var sessionPersistenceField = typeof(GroupChatManager).GetField(
                "_sessionPersistence",
                BindingFlags.NonPublic | BindingFlags.Instance);
            var sessionPersistence = sessionPersistenceField?.GetValue(manager) as GroupSessionPersistence;
            return sessionPersistence.GetGroupSession(groupId);
        }
    }
}