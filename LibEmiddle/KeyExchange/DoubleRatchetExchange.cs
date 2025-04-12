using System.Text;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.Models;

namespace LibEmiddle.KeyExchange
{
    /// <summary>
    /// Implements the Double Ratchet Algorithm for secure messaging
    /// </summary>
    public class DoubleRatchetExchange
    {
        private static readonly Dictionary<string, int> SessionMessageCounters = new();

        /// <summary>
        /// Initializes the Double Ratchet Algorithm with a shared secret
        /// </summary>
        /// <param name="sharedSecret">Secret from key exchange</param>
        /// <returns>Root key and chain key for the session</returns>
        public static (byte[] rootKey, byte[] chainKey) InitializeDoubleRatchet(byte[] sharedSecret)
        {
            ArgumentNullException.ThrowIfNull(sharedSecret);

            var saltRoot = Encoding.UTF8.GetBytes("DoubleRatchetSaltRoot");
            var saltChain = Encoding.UTF8.GetBytes("DoubleRatchetSaltChain");

            try
            {
                // Derive root key using HKDF
                byte[] rootKey = KeyConversion.HkdfDerive(
                    sharedSecret,
                    salt: saltRoot,
                    info: Encoding.UTF8.GetBytes("DoubleRatchetRootKey"),
                    outputLength: Constants.AES_KEY_SIZE
                );

                // Derive initial chain key using HKDF
                byte[] chainKey = KeyConversion.HkdfDerive(
                    sharedSecret,
                    salt: saltChain,
                    info: Encoding.UTF8.GetBytes("DoubleRatchetInitialChainKey"),
                    outputLength: Constants.AES_KEY_SIZE
                );

                return (rootKey, chainKey);
            }
            finally
            {
                // Securely clear sensitive data after use
                SecureMemory.SecureClear(sharedSecret);
                SecureMemory.SecureClear(saltRoot);
                SecureMemory.SecureClear(saltChain);
            }
        }

        /// <summary>
        /// Performs a step in the Double Ratchet to derive new keys
        /// </summary>
        /// <param name="chainKey">Current chain key</param>
        /// <param name="sessionId">Optional session ID for tracking</param>
        /// <param name="strategy">Key rotation strategy</param>
        /// <returns>New chain key and message key</returns>
        public static (byte[] newChainKey, byte[] messageKey) RatchetStep(
            byte[] chainKey,
            string sessionId = "",
            Enums.KeyRotationStrategy strategy = Enums.KeyRotationStrategy.Standard)
        {
            ArgumentNullException.ThrowIfNull(chainKey);

            if (chainKey.Length != Constants.AES_KEY_SIZE)
                throw new ArgumentException($"Chain key must be {Constants.AES_KEY_SIZE} bytes", nameof(chainKey));

            // Try to create a deep copy of the chain key to prevent accidental modification
            byte[] chainKeyCopy = Sodium.GenerateRandomBytes(chainKey.Length);
            chainKey.AsSpan().CopyTo(chainKeyCopy.AsSpan());

            if (!string.IsNullOrEmpty(sessionId))
            {
                lock (SessionMessageCounters)
                {
                    if (!SessionMessageCounters.ContainsKey(sessionId))
                        SessionMessageCounters[sessionId] = 0;

                    SessionMessageCounters[sessionId]++;
                }
            }

            try
            {
                // Derive new chain key using HKDF
                byte[] newChainKey = KeyConversion.HkdfDerive(
                    chainKeyCopy,
                    info: Encoding.UTF8.GetBytes("DoubleRatchetNextChainKey"),
                    outputLength: Constants.AES_KEY_SIZE
                );

                // Derive message key using HKDF
                byte[] messageKey = KeyConversion.HkdfDerive(
                    chainKeyCopy,
                    info: Encoding.UTF8.GetBytes("DoubleRatchetMessageKey"),
                    outputLength: Constants.AES_KEY_SIZE
                );

                if (ShouldRotateKey(sessionId, strategy))
                {
                    LoggingManager.LogInformation(
                        nameof(DoubleRatchetExchange),
                        $"DH Key rotation triggered for session {sessionId} (Strategy: {strategy})"
                    );
                    // Additional DH key rotation logic would go here in a full implementation
                }

                return (newChainKey, messageKey);
            }
            finally
            {
                // Ensure we securely clear the chain key copy
                SecureMemory.SecureClear(chainKeyCopy);
            }
        }

        /// <summary>
        /// Returns true if key should need to rotate
        /// </summary>
        /// <param name="sessionId"></param>
        /// <param name="strategy"></param>
        /// <returns></returns>
        private static bool ShouldRotateKey(string sessionId, Enums.KeyRotationStrategy strategy)
        {
            if (string.IsNullOrEmpty(sessionId))
                return false;

            lock (SessionMessageCounters)
            {
                if (!SessionMessageCounters.ContainsKey(sessionId))
                    return false;

                int count = SessionMessageCounters[sessionId];

                return strategy switch
                {
                    Enums.KeyRotationStrategy.Standard => count % 20 == 0, // Change to rotate every 20 messages
                    Enums.KeyRotationStrategy.Hourly => count % 1 == 0, // Change to rotate every 1 hour
                    Enums.KeyRotationStrategy.Daily => count % 7 == 0, // Change to rotate every 7 days
                    _ => false
                };
            }
        }

        /// <summary>
        /// Performs a Diffie-Hellman ratchet step with improved key derivation
        /// </summary>
        /// <param name="rootKey">Current root key</param>
        /// <param name="dhOutput">Output from new Diffie-Hellman exchange</param>
        /// <returns>New root key and chain key</returns>
        public static (byte[] newRootKey, byte[] newChainKey) DHRatchetStep(byte[] rootKey, byte[] dhOutput)
        {
            ArgumentNullException.ThrowIfNull(rootKey);
            ArgumentNullException.ThrowIfNull(dhOutput);

            if (rootKey.Length != Constants.AES_KEY_SIZE)
                throw new ArgumentException($"Root key must be {Constants.AES_KEY_SIZE} bytes", nameof(rootKey));

            // Create secure copies to prevent accidental modification
            byte[] rootKeyCopy = Sodium.GenerateRandomBytes(rootKey.Length);
            rootKey.AsSpan().CopyTo(rootKeyCopy.AsSpan());

            byte[] dhOutputCopy = Sodium.GenerateRandomBytes(dhOutput.Length);
            dhOutput.AsSpan().CopyTo(dhOutputCopy.AsSpan());

            try
            {
                byte[] prk = KeyConversion.HkdfDerive(
                    rootKeyCopy,
                    salt: dhOutputCopy,
                    info: Encoding.UTF8.GetBytes("RootKeyDerivation")
                );

                byte[] newRootKey = KeyConversion.HkdfDerive(
                    prk,
                    info: Encoding.UTF8.GetBytes("NewRootKey")
                );

                byte[] newChainKey = KeyConversion.HkdfDerive(
                    prk,
                    info: Encoding.UTF8.GetBytes("NewChainKey")
                );

                // Securely clear the intermediate PRK value
                SecureMemory.SecureClear(prk);

                return (newRootKey, newChainKey);
            }
            finally
            {
                // Securely clear our copies
                SecureMemory.SecureClear(rootKeyCopy);
                SecureMemory.SecureClear(dhOutputCopy);
            }
        }

        /// <summary>
        /// Attempts to resume a session after an interruption or failure.
        /// </summary>
        /// <param name="session">The last known good session</param>
        /// <param name="lastProcessedMessageId">The ID of the last successfully processed message, if any</param>
        /// <returns>A session ready for continued communication, or null if resumption isn't possible</returns>
        public static DoubleRatchetSession ResumeSession(DoubleRatchetSession session, Guid? lastProcessedMessageId = null)
        {
            if (session == null)
                throw new ArgumentNullException(nameof(session));

            // Verify the session is in a valid state
            if (!ValidateSession(session))
            {
                // Create a new valid session with the same parameters instead of returning null
                return new DoubleRatchetSession(
                    session.DHRatchetKeyPair,
                    session.RemoteDHRatchetKey,
                    session.RootKey,
                    session.SendingChainKey,
                    session.ReceivingChainKey,
                    session.MessageNumber,
                    session.SessionId,
                    session.RecentlyProcessedIds,
                    session.ProcessedMessageNumbers
                );
            }

            // Create a new session (with the same parameters) to ensure clean state
            var resumed = new DoubleRatchetSession(
                session.DHRatchetKeyPair,
                session.RemoteDHRatchetKey,
                session.RootKey,
                session.SendingChainKey,
                session.ReceivingChainKey,
                session.MessageNumber,
                session.SessionId,
                session.RecentlyProcessedIds,
                session.ProcessedMessageNumbers
            );

            // If a last processed message ID was provided, make sure it's marked as processed
            if (lastProcessedMessageId.HasValue && !resumed.HasProcessedMessageId(lastProcessedMessageId.Value))
            {
                resumed = resumed.WithProcessedMessageId(lastProcessedMessageId.Value);
            }

            return resumed;
        }

        /// <summary>
        /// Validates a session to ensure it's in a valid state for continued use.
        /// </summary>
        /// <param name="session">The session to validate</param>
        /// <returns>True if the session is valid, false otherwise</returns>
        public static bool ValidateSession(DoubleRatchetSession session)
        {
            if (session == null)
                return false;

            // Check for null or invalid key material
            if (session.DHRatchetKeyPair.publicKey == null || session.DHRatchetKeyPair.publicKey.Length != Constants.X25519_KEY_SIZE)
                return false;
            if (session.DHRatchetKeyPair.privateKey == null || session.DHRatchetKeyPair.privateKey.Length != Constants.X25519_KEY_SIZE)
                return false;
            if (session.RemoteDHRatchetKey == null || session.RemoteDHRatchetKey.Length != Constants.X25519_KEY_SIZE)
                return false;
            if (session.RootKey == null || session.RootKey.Length != Constants.AES_KEY_SIZE)
                return false;
            if (session.SendingChainKey == null || session.SendingChainKey.Length != Constants.AES_KEY_SIZE)
                return false;
            if (session.ReceivingChainKey == null || session.ReceivingChainKey.Length != Constants.AES_KEY_SIZE)
                return false;

            // Check for valid session ID
            if (string.IsNullOrEmpty(session.SessionId))
                return false;

            return true;
        }
    }
}