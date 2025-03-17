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

            lock (_nonceLock)
            {
                // If first time, initialize the prefix
                if (_noncePrefix == null)
                {
                    _noncePrefix = new byte[Constants.NONCE_SIZE - 4];
                    RandomNumberGenerator.Fill(_noncePrefix);
                    _nonceCounter = new byte[4];
                }

                // Copy prefix
                _noncePrefix.AsSpan(0, Constants.NONCE_SIZE - 4).CopyTo(nonce.AsSpan(0, Constants.NONCE_SIZE - 4));

                // Increment counter atomically
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

                // Copy counter
                _nonceCounter.AsSpan(0, 4).CopyTo(nonce.AsSpan(Constants.NONCE_SIZE - 4, 4));
            }

            // Add randomness
            byte[] randomPart = new byte[Constants.NONCE_SIZE];
            RandomNumberGenerator.Fill(randomPart);

            // XOR the counter-based nonce with random data for extra security
            for (int i = 0; i < Constants.NONCE_SIZE; i++)
            {
                nonce[i] ^= randomPart[i];
            }

            return nonce;
        }
    }
}