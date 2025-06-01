using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;
using LibEmiddle.Abstractions;

namespace LibEmiddle.Messaging.Group
{
    /// <summary>
    /// Interface for managing group chat functionality, including creation, joining, messaging, and persistence.
    /// </summary>
    public interface IGroupChatManager : IDisposable
    {
        /// <summary>
        /// Creates a new group chat.
        /// </summary>
        /// <param name="groupId">The unique identifier for the group.</param>
        /// <param name="groupName">The display name for the group.</param>
        /// <param name="initialMembers">Optional initial member identities.</param>
        /// <param name="options">Optional configuration options.</param>
        /// <returns>The created group session.</returns>
        Task<GroupSessionDto> CreateGroupAsync(
            string groupId,
            string groupName,
            IEnumerable<byte[]>? initialMembers = null,
            GroupSessionOptions? options = null);

        /// <summary>
        /// Gets an existing group session by ID.
        /// </summary>
        /// <param name="groupId">The unique identifier of the group.</param>
        /// <returns>The group session.</returns>
        Task<IGroupSession> GetGroupAsync(string groupId);

        /// <summary>
        /// Lists the IDs of all active groups.
        /// </summary>
        /// <returns>A list of group IDs.</returns>
        Task<List<string>> ListGroupsAsync();

        /// <summary>
        /// Joins an existing group using a sender key distribution message.
        /// </summary>
        /// <param name="distribution">The sender key distribution message.</param>
        /// <param name="rotationStrategy">Optional key rotation strategy.</param>
        /// <returns>The group session.</returns>
        Task<IGroupSession> JoinGroupAsync(
            SenderKeyDistributionMessage distribution,
            KeyRotationStrategy rotationStrategy = KeyRotationStrategy.Standard);

        /// <summary>
        /// Leaves a group.
        /// </summary>
        /// <param name="groupId">The unique identifier of the group.</param>
        /// <returns>True if the group was left successfully.</returns>
        Task<bool> LeaveGroupAsync(string groupId);

        /// <summary>
        /// Sends a message to a group.
        /// </summary>
        /// <param name="groupId">The unique identifier of the group.</param>
        /// <param name="message">The message to send.</param>
        /// <returns>The encrypted message.</returns>
        Task<EncryptedGroupMessage?> SendMessageAsync(string groupId, string message);

        /// <summary>
        /// Processes a received encrypted group message.
        /// </summary>
        /// <param name="encryptedMessage">The encrypted message.</param>
        /// <returns>The decrypted message content.</returns>
        Task<string?> ProcessMessageAsync(EncryptedGroupMessage encryptedMessage);

        /// <summary>
        /// Saves the state of all active groups for persistence.
        /// </summary>
        /// <param name="storageProvider">The storage provider to use.</param>
        /// <returns>True if all states were saved successfully.</returns>
        Task<bool> SaveStateAsync(IStorageProvider storageProvider);

        /// <summary>
        /// Loads saved group states from persistence.
        /// </summary>
        /// <param name="storageProvider">The storage provider to use.</param>
        /// <returns>The number of groups successfully loaded.</returns>
        Task<int> LoadStateAsync(IStorageProvider storageProvider);
    }
}
