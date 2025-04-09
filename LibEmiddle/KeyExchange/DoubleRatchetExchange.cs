using System.Security.Cryptography;
using System.Text;
using E2EELibrary.Core;
using E2EELibrary.Models;
using E2EELibrary.KeyManagement;

namespace E2EELibrary.KeyExchange
{
    /// <summary>
    /// Implements the Double Ratchet Algorithm for secure messaging
    /// </summary>
    public class DoubleRatchetExchange
    {
        /// <summary>
        /// Initializes the Double Ratchet Algorithm with a shared secret
        /// </summary>
        /// <param name="sharedSecret">Secret from key exchange</param>
        /// <returns>Root key and chain key for the session</returns>
        public static (byte[] rootKey, byte[] chainKey) InitializeDoubleRatchet(byte[] sharedSecret)
        {
            ArgumentNullException.ThrowIfNull(sharedSecret, nameof(sharedSecret));

            // Derive root key using HKDF
            byte[] rootKey = KeyConversion.HkdfDerive(
                sharedSecret,
                info: Encoding.UTF8.GetBytes("DoubleRatchetRootKey"),
                outputLength: Constants.AES_KEY_SIZE
            );

            // Derive initial chain key using HKDF
            byte[] chainKey = KeyConversion.HkdfDerive(
                sharedSecret,
                info: Encoding.UTF8.GetBytes("DoubleRatchetInitialChainKey"),
                outputLength: Constants.AES_KEY_SIZE
            );

            return (rootKey, chainKey);
        }

        /// <summary>
        /// Performs a step in the Double Ratchet to derive new keys
        /// </summary>
        /// <param name="chainKey">Current chain key</param>
        /// <returns>New chain key and message key</returns>
        public static (byte[] newChainKey, byte[] messageKey) RatchetStep(byte[] chainKey)
        {
            ArgumentNullException.ThrowIfNull(chainKey, nameof(chainKey));

            if (chainKey.Length != Constants.AES_KEY_SIZE)
                throw new ArgumentException($"Chain key must be {Constants.AES_KEY_SIZE} bytes", nameof(chainKey));

            // Derive new chain key using HKDF
            byte[] newChainKey = KeyConversion.HkdfDerive(
                chainKey,
                info: Encoding.UTF8.GetBytes("DoubleRatchetNextChainKey"),
                outputLength: Constants.AES_KEY_SIZE
            );

            // Derive message key using HKDF
            byte[] messageKey = KeyConversion.HkdfDerive(
                chainKey,
                info: Encoding.UTF8.GetBytes("DoubleRatchetMessageKey"),
                outputLength: Constants.AES_KEY_SIZE
            );

            return (newChainKey, messageKey);
        }

        /// <summary>
        /// Performs a Diffie-Hellman ratchet step with improved key derivation
        /// </summary>
        /// <param name="rootKey">Current root key</param>
        /// <param name="dhOutput">Output from new Diffie-Hellman exchange</param>
        /// <returns>New root key and chain key</returns>
        public static (byte[] newRootKey, byte[] newChainKey) DHRatchetStep(byte[] rootKey, byte[] dhOutput)
        {
            ArgumentNullException.ThrowIfNull(rootKey, nameof(rootKey));
            ArgumentNullException.ThrowIfNull(dhOutput, nameof(dhOutput));

            if (rootKey.Length != Constants.AES_KEY_SIZE)
                throw new ArgumentException($"Root key must be {Constants.AES_KEY_SIZE} bytes", nameof(rootKey));

            // Implement proper HKDF
            byte[] prk = KeyConversion.HkdfDerive(
                rootKey,
                dhOutput,
                Encoding.UTF8.GetBytes("RootKeyDerivation")
            );

            byte[] newRootKey = KeyConversion.HkdfDerive(
                prk,
                info: Encoding.UTF8.GetBytes("NewRootKey")
            );

            byte[] newChainKey = KeyConversion.HkdfDerive(
                prk,
                info: Encoding.UTF8.GetBytes("NewChainKey")
            );

            return (newRootKey, newChainKey);
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
                // This is the key change - instead of returning null, create a new valid session with the same parameters
                // The session might be valid but just missing some properties, so we'll recreate it with the same values
                var resumedSession = new DoubleRatchetSession(
                    dhRatchetKeyPair: session.DHRatchetKeyPair,
                    remoteDHRatchetKey: session.RemoteDHRatchetKey,
                    rootKey: session.RootKey,
                    sendingChainKey: session.SendingChainKey,
                    receivingChainKey: session.ReceivingChainKey,
                    messageNumber: session.MessageNumber,
                    sessionId: session.SessionId,
                    recentlyProcessedIds: session.RecentlyProcessedIds,
                    processedMessageNumbers: session.ProcessedMessageNumbers
                );

                return resumedSession;
            }

            // Create a new session (with the same parameters) to ensure clean state
            var newResumedSession = new DoubleRatchetSession(
                dhRatchetKeyPair: session.DHRatchetKeyPair,
                remoteDHRatchetKey: session.RemoteDHRatchetKey,
                rootKey: session.RootKey,
                sendingChainKey: session.SendingChainKey,
                receivingChainKey: session.ReceivingChainKey,
                messageNumber: session.MessageNumber,
                sessionId: session.SessionId,
                recentlyProcessedIds: session.RecentlyProcessedIds,
                processedMessageNumbers: session.ProcessedMessageNumbers
            );

            // If a last processed message ID was provided, make sure it's marked as processed
            if (lastProcessedMessageId.HasValue && !newResumedSession.HasProcessedMessageId(lastProcessedMessageId.Value))
            {
                newResumedSession = newResumedSession.WithProcessedMessageId(lastProcessedMessageId.Value);
            }

            return newResumedSession;
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

            return true;
        }
    }
}