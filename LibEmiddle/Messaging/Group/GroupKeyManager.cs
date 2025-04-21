using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;

namespace LibEmiddle.Messaging.Group
{
    /// <summary>
    /// Manages the Sender Key state (Chain Key and Iteration) for groups
    /// where the local user is the sender. Generates initial keys and performs
    /// the symmetric key ratchet to derive message keys.
    /// </summary>
    public class GroupKeyManager : IDisposable // Implement IDisposable if clearing keys on disposal is desired
    {
        // Internal state record for Sender Keys
        private sealed record SenderKeyState
        {
            public byte[] ChainKey { get; init; } = Array.Empty<byte>();
            public uint Iteration { get; init; }

            // Method to securely dispose of the chain key if needed
            public void Clear() => SecureMemory.SecureClear(ChainKey);
        }

        // Stores the current SenderKeyState for each group this client sends to
        // Key: groupId (string)
        // Value: SenderKeyState (containing ChainKey and Iteration)
        private readonly ConcurrentDictionary<string, SenderKeyState> _senderState = new();

        // Constants from Double Ratchet KDF_CK (ensure these are accessible)
        private const byte MESSAGE_KEY_SEED_BYTE = 0x01;
        private const byte CHAIN_KEY_SEED_BYTE = 0x02;

        /// <summary>
        /// Generates a new cryptographically secure initial Chain Key (32 bytes).
        /// </summary>
        /// <returns>A new 32-byte random key suitable as an initial Chain Key.</returns>
        public byte[] GenerateInitialChainKey()
        {
            // Use preferred method for generating secure random bytes
            return Sodium.GenerateRandomBytes(Constants.AES_KEY_SIZE);
        }

        /// <summary>
        /// Initializes the sender state for a group with the given initial chain key.
        /// Typically called when creating a group or rotating the key.
        /// </summary>
        /// <param name="groupId">Group identifier.</param>
        /// <param name="initialChainKey">The initial chain key.</param>
        public void InitializeSenderState(string groupId, byte[] initialChainKey)
        {
            ArgumentException.ThrowIfNullOrEmpty(groupId, nameof(groupId));
            ArgumentNullException.ThrowIfNull(initialChainKey, nameof(initialChainKey));
            if (initialChainKey.Length != Constants.AES_KEY_SIZE)
                throw new ArgumentException($"Initial Chain Key must be {Constants.AES_KEY_SIZE} bytes.", nameof(initialChainKey));

            // Store a copy
            byte[] chainKeyCopy = (byte[])initialChainKey.Clone();

            var initialState = new SenderKeyState
            {
                ChainKey = chainKeyCopy,
                Iteration = 0 // Start iteration at 0
            };

            // AddOrUpdate ensures thread-safety and handles potential existing state clearing
            _senderState.AddOrUpdate(groupId, initialState, (key, existingState) => {
                existingState.Clear(); // Clear old key if replacing
                return initialState;
            });
        }

        /// <summary>
        /// Performs the symmetric ratchet step for the sender's chain.
        /// Derives the next message key and advances the chain state.
        /// </summary>
        /// <param name="groupId">Group identifier.</param>
        /// <returns>A tuple containing the MessageKey (byte[32]) to use for encryption
        /// and the Iteration (uint) associated with that key.</returns>
        /// <exception cref="InvalidOperationException">If sender state is not initialized for the group.</exception>
        /// <exception cref="CryptographicException">If HMAC operation fails.</exception>
        public (byte[] MessageKey, uint Iteration) GetSenderMessageKey(string groupId)
        {
            ArgumentException.ThrowIfNullOrEmpty(groupId, nameof(groupId));

            SenderKeyState currentState;
            SenderKeyState nextState;
            byte[] messageKey;
            byte[] nextChainKey; // Declare here

            // Atomically get current state and update to next state
            do
            {
                if (!_senderState.TryGetValue(groupId, out currentState!))
                {
                    throw new InvalidOperationException($"Sender state not initialized for group {groupId}. Call InitializeSenderState first.");
                }

                // --- Perform KDF_CK using KeyGenerator.GenerateHmacSha256 ---
                byte[] currentChainKey = currentState.ChainKey;
                uint currentIteration = currentState.Iteration;

                // Derive keys using the existing HMAC function
                messageKey = Sodium.GenerateHmacSha256([MESSAGE_KEY_SEED_BYTE], currentChainKey);
                nextChainKey = Sodium.GenerateHmacSha256([CHAIN_KEY_SEED_BYTE], currentChainKey);

                // Validation of output length happens inside GenerateHmacSha256 now (or should)
                // If not, add checks here:
                if (messageKey == null || messageKey.Length != Constants.AES_KEY_SIZE || nextChainKey == null || nextChainKey.Length != Constants.AES_KEY_SIZE)
                    throw new CryptographicException("KDF_CK (HMAC) failed or produced incorrect output length.");

                // Prepare the next state object (with incremented iteration)
                nextState = new SenderKeyState
                {
                    ChainKey = nextChainKey, // Store the newly derived chain key
                    Iteration = currentIteration + 1
                };

                // Attempt to update the state in the dictionary using optimistic concurrency
            } while (!_senderState.TryUpdate(groupId, nextState, currentState)); // Compare-and-swap

            // IMPORTANT: Return the message key derived from the *current* state,
            // along with the *current* iteration number (before it was incremented).
            return (messageKey, currentState.Iteration);
        }

        /// <summary>
        /// Checks if a key should be rotated based on the rotation strategy and establishment time
        /// </summary>
        /// <param name="keyEstablishmentTimeMs">Time when key was established (milliseconds since epoch).</param>
        /// <param name="rotationStrategy">Rotation strategy to apply.</param>
        /// <returns>True if key rotation is recommended.</returns>
        public bool ShouldRotateKey(long keyEstablishmentTimeMs, Enums.KeyRotationStrategy rotationStrategy)
        {
            if (keyEstablishmentTimeMs <= 0) return true; // Rotate if timestamp invalid or unset

            // For Standard strategy, always rotate
            if (rotationStrategy == Enums.KeyRotationStrategy.Standard)
            {
                return true;
            }

            long currentTimeMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            TimeSpan elapsed = TimeSpan.FromMilliseconds(currentTimeMs - keyEstablishmentTimeMs);

            // Check based on strategy
            return rotationStrategy switch
            {
                Enums.KeyRotationStrategy.Hourly => elapsed >= TimeSpan.FromHours(1),
                Enums.KeyRotationStrategy.Daily => elapsed >= TimeSpan.FromDays(1),
                _ => false // Unknown strategy, don't rotate automatically
            };
        }

        /// <summary>
        /// Derives a subkey for a specific purpose from a base key using HKDF.
        /// </summary>
        /// <param name="baseKey">Base key (e.g., Chain Key).</param>
        /// <param name="purpose">Purpose string for the 'info' parameter of HKDF.</param>
        /// <returns>Derived key (32 bytes).</returns>
        public byte[] DeriveSubkey(byte[] baseKey, string purpose)
        {
            ArgumentNullException.ThrowIfNull(baseKey, nameof(baseKey));
            ArgumentException.ThrowIfNullOrEmpty(purpose, nameof(purpose));

            // Assuming KeyConversion.HkdfDerive uses a zero salt by default if not provided
            return KeyConversion.HkdfDerive(
                inputKeyMaterial: baseKey,
                salt: null, // Or provide explicit zero salt if required by implementation
                info: Encoding.UTF8.GetBytes($"SubkeyDerivation-{purpose}"), // Use purpose in info
                outputLength: Constants.AES_KEY_SIZE // Typically 32 bytes
            );
        }

        /// <summary>
        /// Securely clears the stored Chain Key and Iteration state for a specific group.
        /// </summary>
        /// <param name="groupId">Group identifier.</param>
        /// <returns>True if state for the group was found and cleared.</returns>
        public bool ClearSenderState(string groupId)
        {
            ArgumentException.ThrowIfNullOrEmpty(groupId, nameof(groupId));
            if (_senderState.TryRemove(groupId, out SenderKeyState? removedState))
            {
                removedState?.Clear(); // Securely clear the chain key within the state object
                return true;
            }
            return false;
        }

        /// <summary>
        /// Securely clears all stored Sender Key states.
        /// </summary>
        public void ClearAllSenderStates()
        {
            // Get all keys first to avoid issues with modifying dict while iterating
            var allKeys = _senderState.Keys.ToList();
            foreach (var groupId in allKeys)
            {
                if (_senderState.TryRemove(groupId, out SenderKeyState? removedState))
                {
                    removedState?.Clear();
                }
            }
            // Double check if clear is needed - TryRemove might have race conditions if key re-added
            _senderState.Clear(); // Final clear just in case
        }

        /// <summary>
        /// Implements IDisposable to ensure all stored keys are cleared.
        /// </summary>
        public void Dispose()
        {
            ClearAllSenderStates();
            GC.SuppressFinalize(this);
        }

        // Optional Finalizer as safety net
        ~GroupKeyManager() => ClearAllSenderStates();

    } // End Class
} // End Namespace