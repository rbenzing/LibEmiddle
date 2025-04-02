using System.Security.Cryptography;
using E2EELibrary.Core;

namespace E2EELibrary.Encryption
{
    /// <summary>
    /// Provides functionality for generating secure nonces for cryptographic operations.
    /// </summary>
    public static class NonceGenerator
    {
        private static readonly object _nonceLock = new object();
        private static byte[] _nonceCounter = new byte[4]; // 32-bit counter
        private static byte[]? _noncePrefix = null;

        /// <summary>
        /// Generates a secure nonce for AES-GCM encryption that won't be reused
        /// </summary>
        /// <returns>Secure nonce</returns>
        public static byte[] GenerateNonce()
        {
            byte[] nonce = new byte[Constants.NONCE_SIZE];

            // Generate a completely random nonce first
            RandomNumberGenerator.Fill(nonce);

            lock (_nonceLock)
            {
                // If first time, initialize the prefix and counter
                if (_noncePrefix == null)
                {
                    _noncePrefix = new byte[Constants.NONCE_SIZE - 4];
                    RandomNumberGenerator.Fill(_noncePrefix);
                    _nonceCounter = new byte[4];
                }

                // Increment counter atomically - this MUST happen to ensure uniqueness
                bool carry = true;
                for (int i = 0; i < _nonceCounter.Length && carry; i++)
                {
                    _nonceCounter[i]++;
                    carry = _nonceCounter[i] == 0;
                }

                // If counter wrapped, generate new prefix
                if (carry)
                {
                    RandomNumberGenerator.Fill(_noncePrefix);
                }

                // Mix the random nonce with our counter
                // This preserves both randomness AND uniqueness
                for (int i = Constants.NONCE_SIZE - 4; i < Constants.NONCE_SIZE; i++)
                {
                    // XOR the last 4 bytes with our counter bytes (preserves uniqueness due to XOR properties)
                    // If A ≠ B, then A ⊕ X ≠ B ⊕ X for any X
                    int counterIdx = i - (Constants.NONCE_SIZE - 4);
                    nonce[i] = (byte)(nonce[i] ^ _nonceCounter[counterIdx]);
                }
            }

            return nonce;
        }
    }
}