using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;

namespace LibEmiddle.Abstractions;

/// <summary>
/// Defines the contract for group session operations in LibEmiddle.
/// Provides end-to-end encrypted group messaging with member management,
/// key rotation, and security validation capabilities.
/// </summary>
public interface IGroupSession : ISession
{
    /// <summary>
    /// Gets the unique identifier for this group.
    /// </summary>
    string GroupId { get; }

    /// <summary>
    /// Gets the current chain key for the group.
    /// This is used for message encryption and evolves with each message.
    /// </summary>
    byte[] ChainKey { get; }

    /// <summary>
    /// Gets the current iteration number of the chain key.
    /// This allows tracking of message order and key evolution.
    /// </summary>
    uint Iteration { get; }

    /// <summary>
    /// Gets or sets the key rotation strategy for this group.
    /// Determines when and how often group keys are rotated for security.
    /// </summary>
    KeyRotationStrategy RotationStrategy { get; set; }

    /// <summary>
    /// Gets the public key of the group creator.
    /// This is used for permission validation and group ownership verification.
    /// </summary>
    byte[] CreatorPublicKey { get; }

    /// <summary>
    /// Gets the creator's identity key (alias for CreatorPublicKey for backward compatibility).
    /// </summary>
    byte[] CreatorIdentityKey { get; }

    /// <summary>
    /// Gets the timestamp when the current key was established.
    /// Used for key rotation scheduling and security validation.
    /// </summary>
    DateTime KeyEstablishmentTimestamp { get; }

    /// <summary>
    /// Gets additional metadata associated with this group session.
    /// Can include custom properties, group settings, or application-specific data.
    /// </summary>
    IReadOnlyDictionary<string, string>? Metadata { get; }

    /// <summary>
    /// Adds a new member to the group.
    /// Requires appropriate permissions (admin or owner privileges).
    /// </summary>
    /// <param name="memberPublicKey">The public key of the member to add</param>
    /// <returns>True if the member was added successfully, false if already a member or permission denied</returns>
    /// <exception cref="ArgumentNullException">Thrown when memberPublicKey is null</exception>
    /// <exception cref="UnauthorizedAccessException">Thrown when the current user lacks permission to add members</exception>
    /// <exception cref="InvalidOperationException">Thrown when the session is terminated</exception>
    Task<bool> AddMemberAsync(byte[] memberPublicKey);

    /// <summary>
    /// Removes a member from the group.
    /// Requires appropriate permissions (admin or owner privileges).
    /// Automatically triggers key rotation for forward secrecy.
    /// </summary>
    /// <param name="memberPublicKey">The public key of the member to remove</param>
    /// <returns>True if the member was removed successfully, false if not a member or permission denied</returns>
    /// <exception cref="ArgumentNullException">Thrown when memberPublicKey is null</exception>
    /// <exception cref="UnauthorizedAccessException">Thrown when the current user lacks permission to remove members</exception>
    /// <exception cref="InvalidOperationException">Thrown when the session is terminated or attempting to remove the owner</exception>
    Task<bool> RemoveMemberAsync(byte[] memberPublicKey);

    /// <summary>
    /// Encrypts a message for all group members.
    /// Uses the current chain key and advances the key state.
    /// </summary>
    /// <param name="message">The plaintext message to encrypt</param>
    /// <returns>The encrypted group message ready for distribution, or null if encryption failed</returns>
    /// <exception cref="ArgumentException">Thrown when message is null or empty</exception>
    /// <exception cref="UnauthorizedAccessException">Thrown when the current user lacks permission to send messages</exception>
    /// <exception cref="InvalidOperationException">Thrown when the session is terminated or suspended</exception>
    Task<EncryptedGroupMessage?> EncryptMessageAsync(string message);

    /// <summary>
    /// Decrypts a received group message.
    /// Validates sender permissions, message authenticity, and replay protection.
    /// </summary>
    /// <param name="encryptedMessage">The encrypted message to decrypt</param>
    /// <returns>The decrypted message content, or null if decryption failed or validation failed</returns>
    /// <exception cref="ArgumentNullException">Thrown when encryptedMessage is null</exception>
    /// <exception cref="ArgumentException">Thrown when the message is for a different group</exception>
    /// <exception cref="InvalidOperationException">Thrown when the session is terminated</exception>
    Task<string?> DecryptMessageAsync(EncryptedGroupMessage encryptedMessage);

    /// <summary>
    /// Rotates the group's cryptographic keys for enhanced security.
    /// Generates new chain keys and invalidates old keys.
    /// Requires appropriate permissions (admin or owner privileges).
    /// </summary>
    /// <returns>True if the key rotation was successful, false if permission denied or operation failed</returns>
    /// <exception cref="UnauthorizedAccessException">Thrown when the current user lacks permission to rotate keys</exception>
    /// <exception cref="InvalidOperationException">Thrown when the session is terminated</exception>
    Task<bool> RotateKeyAsync();

    /// <summary>
    /// Creates a sender key distribution message for sharing group keys with new or existing members.
    /// This message contains the current chain key and is used for key synchronization.
    /// </summary>
    /// <returns>A signed distribution message containing the current group key state</returns>
    /// <exception cref="InvalidOperationException">Thrown when the session is not properly initialized or terminated</exception>
    SenderKeyDistributionMessage CreateDistributionMessage();

    /// <summary>
    /// Processes a received sender key distribution message to update local key state.
    /// Validates the message authenticity and sender permissions before applying changes.
    /// </summary>
    /// <param name="distribution">The distribution message to process</param>
    /// <returns>True if the message was processed successfully and keys were updated, false if validation failed</returns>
    /// <exception cref="ArgumentNullException">Thrown when distribution is null</exception>
    bool ProcessDistributionMessage(SenderKeyDistributionMessage distribution);

    /// <summary>
    /// Gets the serialized state of this group session for persistence.
    /// Includes all necessary data to restore the session later.
    /// </summary>
    /// <returns>A JSON string containing the complete session state</returns>
    /// <exception cref="InvalidOperationException">Thrown when the session is terminated or serialization fails</exception>
    Task<string> GetSerializedStateAsync();

    /// <summary>
    /// Restores the group session state from a serialized representation.
    /// Used for loading sessions from persistent storage.
    /// </summary>
    /// <param name="serializedState">The JSON string containing the session state</param>
    /// <returns>True if the state was restored successfully, false if deserialization or validation failed</returns>
    /// <exception cref="ArgumentException">Thrown when serializedState is null, empty, or invalid</exception>
    Task<bool> RestoreSerializedStateAsync(string serializedState);
}