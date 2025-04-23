using System.Collections.Immutable;
using LibEmiddle.Domain;

namespace LibEmiddle.Messaging.Group
{
    /// <summary>
    /// Represents the persistent cryptographic state for a group,
    /// primarily the Sender Key state (Chain Key and Iteration).
    /// This class is immutable; state updates create new instances.
    /// </summary>
    public sealed class GroupSession
    {
        /// <summary>
        /// Group identifier.
        /// </summary>
        public string GroupId { get; }

        /// <summary>
        /// The current Sender Key Chain Key (32 bytes, symmetric).
        /// Used to derive message keys. MUST be kept secret and cleared securely.
        /// </summary>
        public byte[] ChainKey { get; }

        /// <summary>
        /// The current iteration number for the Chain Key.
        /// Increments each time a message key is derived.
        /// </summary>
        public uint Iteration { get; }

        /// <summary>
        /// Public Identity Key (Ed25519, 32 bytes) of the group creator or original key issuer.
        /// </summary>
        public byte[] CreatorIdentityKey { get; }

        /// <summary>
        /// Timestamp when the group was created (milliseconds since Unix epoch).
        /// </summary>
        public long CreationTimestamp { get; }

        /// <summary>
        /// Timestamp when the current ChainKey was established (e.g., creation or last rotation)
        /// (milliseconds since Unix epoch).
        /// </summary>
        public long KeyEstablishmentTimestamp { get; } // Renamed from LastKeyRotation

        /// <summary>
        /// When the key was last rotated (milliseconds since Unix epoch)
        /// </summary>
        public long LastKeyRotation { get; set; }

        /// <summary>
        /// Optional custom metadata for the group. Made immutable.
        /// </summary>
        public ImmutableDictionary<string, string> Metadata { get; }

        /// <summary>
        /// Initializes a new immutable GroupSession state.
        /// </summary>
        public GroupSession(
            string groupId,
            byte[] chainKey,
            uint iteration,
            byte[] creatorIdentityKey,
            long creationTimestamp,
            long keyEstablishmentTimestamp,
            ImmutableDictionary<string, string>? metadata = null) // Accept nullable for convenience
        {
            // --- Validation ---
            if (string.IsNullOrWhiteSpace(groupId))
                throw new ArgumentException("GroupId cannot be null or whitespace.", nameof(groupId));
            ArgumentNullException.ThrowIfNull(chainKey, nameof(chainKey));
            ArgumentNullException.ThrowIfNull(creatorIdentityKey, nameof(creatorIdentityKey));
            if (chainKey.Length != Constants.AES_KEY_SIZE) // Assuming AES_KEY_SIZE is 32
                throw new ArgumentException($"ChainKey must be {Constants.AES_KEY_SIZE} bytes.", nameof(chainKey));
            if (creatorIdentityKey.Length != Constants.ED25519_PUBLIC_KEY_SIZE) // Assuming ED key size constant
                throw new ArgumentException($"CreatorIdentityKey must be {Constants.ED25519_PUBLIC_KEY_SIZE} bytes.", nameof(creatorIdentityKey));

            // --- Assignment ---
            GroupId = groupId;
            // Store copies of mutable byte arrays to ensure true immutability
            ChainKey = (byte[])chainKey.Clone();
            CreatorIdentityKey = (byte[])creatorIdentityKey.Clone();
            Iteration = iteration;
            CreationTimestamp = creationTimestamp;
            KeyEstablishmentTimestamp = keyEstablishmentTimestamp;
            Metadata = metadata ?? ImmutableDictionary<string, string>.Empty;
        }

        /// <summary>
        /// Creates a new GroupSession with the specified rotation strategy
        /// </summary>
        /// <param name="rotationStrategy">The key rotation strategy to use</param>
        /// <returns>A new GroupSession with updated metadata</returns>
        public GroupSession WithRotationStrategy(Enums.KeyRotationStrategy rotationStrategy)
        {
            // Create a dictionary to merge the existing metadata with the new rotation strategy
            var metadataBuilder = ImmutableDictionary.CreateBuilder<string, string>();

            // Copy existing metadata
            foreach (var pair in this.Metadata)
            {
                metadataBuilder.Add(pair.Key, pair.Value);
            }

            // Add or update the rotation strategy
            metadataBuilder["RotationStrategy"] = rotationStrategy.ToString();

            // Create a new session with the updated metadata
            return new GroupSession(
                groupId: this.GroupId,
                chainKey: this.ChainKey,
                iteration: this.Iteration,
                creatorIdentityKey: this.CreatorIdentityKey,
                creationTimestamp: this.CreationTimestamp,
                keyEstablishmentTimestamp: this.KeyEstablishmentTimestamp,
                metadata: metadataBuilder.ToImmutable()
            );
        }

        /// <summary>
        /// Gets the rotation strategy from the session metadata
        /// </summary>
        /// <returns>The key rotation strategy, or Standard if not specified</returns>
        public Enums.KeyRotationStrategy GetRotationStrategy()
        {
            if (Metadata.TryGetValue("RotationStrategy", out string? strategy) &&
                Enum.TryParse<Enums.KeyRotationStrategy>(strategy, out var result))
            {
                return result;
            }

            return Enums.KeyRotationStrategy.Standard;
        }

        /// <summary>
        /// Creates a new GroupSession instance representing the state after a key rotation.
        /// </summary>
        /// <param name="newChainKey">The new Chain Key.</param>
        /// <param name="keyRotationTimestamp">Optional timestamp for the key rotation. If not provided, current time is used.</param>
        /// <returns>A new GroupSession instance with the updated key and reset iteration.</returns>
        /// <exception cref="ArgumentNullException">If newChainKey is null.</exception>
        /// <exception cref="ArgumentException">If newChainKey has invalid length.</exception>
        public GroupSession WithRotatedKey(byte[] newChainKey, long keyRotationTimestamp = 0)
        {
            // Validation happens in constructor
            var timestamp = keyRotationTimestamp > 0 ? keyRotationTimestamp : DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            var newSession = new GroupSession(
                groupId: this.GroupId,
                chainKey: newChainKey, // Constructor will validate and clone
                iteration: this.Iteration + 1, // Increment the iteration
                creatorIdentityKey: this.CreatorIdentityKey, // Creator doesn't change
                creationTimestamp: this.CreationTimestamp, // Group creation time doesn't change
                keyEstablishmentTimestamp: timestamp, // Update key time
                metadata: this.Metadata // Metadata persists
            );

            // Set the last key rotation timestamp
            newSession.LastKeyRotation = timestamp;

            return newSession;
        }

        /// <summary>
        /// Creates a new GroupSession instance representing the state after advancing the chain.
        /// NOTE: This might be better handled internally by the component using the session,
        /// but provided here as an example of immutable update.
        /// </summary>
        /// <param name="nextChainKey">The next Chain Key derived from the current one.</param>
        /// <param name="nextIteration">The next iteration number (current + 1).</param>
        /// <returns>A new GroupSession instance with the updated chain key and iteration.</returns>
        public GroupSession WithAdvancedChain(byte[] nextChainKey, uint nextIteration)
        {
            // Basic check: iteration should advance
            if (nextIteration <= this.Iteration)
                throw new ArgumentException("Next iteration must be greater than current iteration.", nameof(nextIteration));

            // Validation of nextChainKey happens in constructor
            return new GroupSession(
                groupId: this.GroupId,
                chainKey: nextChainKey,
                iteration: nextIteration,
                creatorIdentityKey: this.CreatorIdentityKey,
                creationTimestamp: this.CreationTimestamp,
                keyEstablishmentTimestamp: this.KeyEstablishmentTimestamp, // This timestamp doesn't change on ratchet step
                metadata: this.Metadata
            );
        }

        /// <summary>
        /// Creates a new GroupSession instance with updated metadata.
        /// </summary>
        /// <param name="newMetadata">The new metadata dictionary.</param>
        /// <returns>A new GroupSession instance with the updated metadata.</returns>
        public GroupSession WithMetadata(ImmutableDictionary<string, string> newMetadata)
        {
            ArgumentNullException.ThrowIfNull(newMetadata, nameof(newMetadata));
            return new GroupSession(
                groupId: this.GroupId,
                chainKey: this.ChainKey,
                iteration: this.Iteration,
                creatorIdentityKey: this.CreatorIdentityKey,
                creationTimestamp: this.CreationTimestamp,
                keyEstablishmentTimestamp: this.KeyEstablishmentTimestamp,
                metadata: newMetadata // Use the new metadata
            );
        }

        // No explicit Dispose needed for this immutable class.
        // The SecureClear should happen when the byte[]s within are no longer referenced.
        // However, if the KeyPair contained within had sensitive data AND was IDisposable,
        // we might need to rethink. But GroupSession no longer holds KeyPair directly.
    }
}