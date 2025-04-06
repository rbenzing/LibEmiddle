using E2EELibrary.Core;

namespace E2EELibrary.KeyManagement
{
    /// <summary>
    /// Provides validation methods for cryptographic keys.
    /// </summary>
    public static class KeyValidation
    {
        /// <summary>
        /// Validates an X25519 public key to ensure it's not an invalid or dangerous value
        /// </summary>
        /// <param name="publicKey">X25519 public key to validate</param>
        /// <returns>True if the key is valid, false otherwise</returns>
        // In KeyValidation.cs
        public static bool ValidateX25519PublicKey(byte[] publicKey)
        {
            if (publicKey == null)
            {
                Console.WriteLine("Validation failed: Public key is null");
                return false;
            }

            if (publicKey.Length != Constants.X25519_KEY_SIZE)
            {
                Console.WriteLine($"Validation failed: Incorrect key length. Expected {Constants.X25519_KEY_SIZE}, got {publicKey.Length}");
                return false;
            }

            // Check for all-zero key, which is invalid for X25519
            bool allZeros = true;
            for (int i = 0; i < publicKey.Length; i++)
            {
                if (publicKey[i] != 0)
                {
                    allZeros = false;
                    break;
                }
            }

            if (allZeros)
            {
                Console.WriteLine("Validation failed: Public key is all zeros");
                return false;
            }

            // For X25519, we don't need to do extensive validation as the algorithm 
            // itself handles many edge cases. The key check above is sufficient
            // for basic validation purposes.

            return true;
        }
    }
}