using System.Security.Cryptography;
using System.Text;
using E2EELibrary.Core;

namespace E2EELibrary.KeyExchange
{
    /// <summary>
    /// Implements the Double Ratchet Algorithm for secure messaging
    /// </summary>
    public class DoubleRatchetExchange
    {

        /// <summary>
        /// HMAC-based Key Derivation Function (HKDF) Extract step
        /// </summary>
        /// <param name="key">Input key material</param>
        /// <param name="salt">Salt value</param>
        /// <returns>Pseudorandom key</returns>
        public static byte[] HKDF_Extract(byte[] key, byte[] salt)
        {
            using var hmac = new HMACSHA256(key);

            ArgumentNullException.ThrowIfNull(hmac, nameof(hmac));

            return hmac.ComputeHash(salt);
        }

        /// <summary>
        /// HMAC-based Key Derivation Function (HKDF) Expand step
        /// </summary>
        /// <param name="prk">Pseudorandom key</param>
        /// <param name="info">Context and application specific information</param>
        /// <param name="outputLength">Length of output keying material in bytes</param>
        /// <returns>Output keying material</returns>
        public static byte[] HKDF_Expand(byte[] prk, byte[] info, int outputLength)
        {
            using var hmac = new HMACSHA256(prk);

            ArgumentNullException.ThrowIfNull(hmac, nameof(hmac));

            byte[]? t = [];
            byte[] okm = new byte[outputLength];
            byte[] counter = new byte[1];
            int offset = 0;

            for (counter[0] = 1; offset < outputLength; counter[0]++)
            {
                hmac.Initialize();
                hmac.TransformBlock(t, 0, t.Length, null, 0);
                hmac.TransformBlock(info, 0, info.Length, null, 0);
                hmac.TransformFinalBlock(counter, 0, counter.Length);
                t = hmac.Hash;

                ArgumentNullException.ThrowIfNull(t, nameof(t));

                int remaining = Math.Min(outputLength - offset, t.Length);
                t.AsSpan(0, remaining).CopyTo(okm.AsSpan(offset, remaining));
                offset += t.Length;
            }

            return okm;
        }

        /// <summary>
        /// Initializes the Double Ratchet Algorithm with a shared secret
        /// </summary>
        /// <param name="sharedSecret">Secret from key exchange</param>
        /// <returns>Root key and chain key for the session</returns>
        public static (byte[] rootKey, byte[] chainKey) InitializeDoubleRatchet(byte[] sharedSecret)
        {
            using var hmac = new HMACSHA256(sharedSecret);

            ArgumentNullException.ThrowIfNull(hmac, nameof(hmac));

            byte[] rootKey = hmac.ComputeHash(Encoding.UTF8.GetBytes("RootKeyInit"));

            // Re-initialize HMAC for the second operation
            hmac.Initialize();
            byte[] chainKey = hmac.ComputeHash(Encoding.UTF8.GetBytes("ChainKeyInit"));

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

            // Use HMAC with different info strings to derive separate keys
            using var hmac = new HMACSHA256(chainKey);

            ArgumentNullException.ThrowIfNull(hmac, nameof(hmac));

            // CK_next = HMAC-SHA256(CK, 0x01)
            byte[] newChainKey = hmac.ComputeHash(new byte[] { 0x01 });

            // Reset HMAC with the same key but new message
            hmac.Initialize();

            // MK = HMAC-SHA256(CK, 0x02)
            byte[] messageKey = hmac.ComputeHash(new byte[] { 0x02 });

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
            byte[] prk = HKDF_Extract(rootKey, dhOutput);
            byte[] newRootKey = HKDF_Expand(prk, Encoding.UTF8.GetBytes("RootKeyDerivation"), Constants.AES_KEY_SIZE);
            byte[] newChainKey = HKDF_Expand(prk, Encoding.UTF8.GetBytes("ChainKeyDerivation"), Constants.AES_KEY_SIZE);

            return (newRootKey, newChainKey);
        }
    }
}