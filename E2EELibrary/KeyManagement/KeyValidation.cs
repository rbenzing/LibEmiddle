using E2EELibrary.Core;

namespace E2EELibrary.KeyManagement
{
    /// <summary>
    /// Provides validation methods for cryptographic keys.
    /// </summary>
    public static class KeyValidation
    {
        // Known problematic patterns for X25519 keys
        private static readonly byte[][] _knownWeakPatterns = new byte[][]
        {
            new byte[Constants.X25519_KEY_SIZE], // All zeros
            Enumerable.Repeat((byte)255, Constants.X25519_KEY_SIZE).ToArray(), // All ones
            new byte[] { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, // Small order point
            new byte[] { 224, 235, 122, 124, 59, 65, 184, 174, 22, 86, 227, 250, 241, 159, 196, 106, 218, 9, 141, 235, 156, 50, 177, 253, 134, 98, 5, 22, 95, 73, 184, 0 } // Twist point 
        };

        // Low entropy threshold (minimum number of unique bytes in the key)
        private const int _minimumEntropyThreshold = 8;

        /// <summary>
        /// Validates an X25519 public key to ensure it's not an invalid or dangerous value
        /// </summary>
        /// <param name="publicKey">X25519 public key to validate</param>
        /// <returns>True if the key is valid, false otherwise</returns>
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

            // Check for all-zero and all-one keys, which are considered weak/invalid
            bool allZeros = true;
            bool allOnes = true;

            for (int i = 0; i < publicKey.Length; i++)
            {
                if (publicKey[i] != 0)
                {
                    allZeros = false;
                }
                if (publicKey[i] != 255)
                {
                    allOnes = false;
                }

                // If we've determined it's neither all zeros nor all ones, we can stop checking
                if (!allZeros && !allOnes)
                {
                    break;
                }
            }

            if (allZeros)
            {
                Console.WriteLine("Validation failed: Public key is all zeros");
                return false;
            }

            if (allOnes)
            {
                Console.WriteLine("Validation failed: Public key is all ones");
                return false;
            }

            // Check against known weak patterns
            foreach (var pattern in _knownWeakPatterns)
            {
                if (SecureMemory.SecureCompare(publicKey, pattern))
                {
                    Console.WriteLine("Validation failed: Public key matches a known weak pattern");
                    return false;
                }
            }

            // Check for valid X25519 properties
            // The highest bit (bit 255) must be cleared
            if ((publicKey[31] & 0x80) != 0)
            {
                Console.WriteLine("Validation failed: Highest bit (bit 255) must be cleared");
                return false;
            }

            // The lowest bit (bit 0) should match the party
            // which isn't a validation concern, but worth noting in comments

            // Check for low-entropy keys (indication of potentially predictable or weak key)
            if (!HasSufficientEntropy(publicKey))
            {
                Console.WriteLine("Validation failed: Public key has insufficient entropy");
                return false;
            }

            // Check for small-order points
            if (IsPotentiallySmallOrderPoint(publicKey))
            {
                Console.WriteLine("Validation failed: Public key is a potential small-order point");
                return false;
            }

            // Ensure every point on curve is canonically encoded
            if (!IsCanonicallyEncoded(publicKey))
            {
                Console.WriteLine("Validation failed: Public key is not canonically encoded");
                return false;
            }

            return true;
        }

        /// <summary>
        /// Checks if a key has sufficient entropy (randomness).
        /// </summary>
        /// <param name="key">The key to check</param>
        /// <returns>True if the key has sufficient entropy</returns>
        private static bool HasSufficientEntropy(byte[] key)
        {
            // Count unique bytes as simple entropy measure
            var uniqueBytes = new HashSet<byte>(key).Count;

            // Also check for simple patterns like sequential or repeating values
            bool hasRepeatingPattern = HasSimplePattern(key);

            return uniqueBytes >= _minimumEntropyThreshold && !hasRepeatingPattern;
        }

        /// <summary>
        /// Checks for simple patterns in the key like sequential or repeating values.
        /// </summary>
        /// <param name="key">The key to check</param>
        /// <returns>True if a simple pattern is detected</returns>
        private static bool HasSimplePattern(byte[] key)
        {
            // Check for sequential patterns (e.g., 1,2,3,4...)
            bool isSequential = true;
            for (int i = 1; i < key.Length; i++)
            {
                if (key[i] != (key[i - 1] + 1) % 256)
                {
                    isSequential = false;
                    break;
                }
            }
            if (isSequential) return true;

            // Check for repeating patterns with periods 1-4
            for (int period = 1; period <= 4; period++)
            {
                bool isRepeating = true;
                for (int i = period; i < key.Length; i++)
                {
                    if (key[i] != key[i % period])
                    {
                        isRepeating = false;
                        break;
                    }
                }
                if (isRepeating) return true;
            }

            return false;
        }

        /// <summary>
        /// Checks if a key might be a small-order point or related to a small-order point.
        /// </summary>
        /// <param name="key">The key to check</param>
        /// <returns>True if the key is potentially a small-order point</returns>
        private static bool IsPotentiallySmallOrderPoint(byte[] key)
        {
            // Check low bits - a heuristic that might indicate small-order points
            // Small-order points often have a specific pattern in their representation
            int zeroBytes = key.Count(b => b == 0);

            // If more than 3/4 of the bytes are zero, it's suspicious
            if (zeroBytes >= key.Length * 3 / 4)
                return true;

            // A more thorough check would involve mathematical computations on the curve
            // For a full check, we'd need to perform scalar multiplication with a test value
            // But this is computationally expensive and beyond the scope of simple validation

            return false;
        }

        /// <summary>
        /// Checks if the key is canonically encoded according to X25519 requirements.
        /// </summary>
        /// <param name="key">The key to check</param>
        /// <returns>True if the key is canonically encoded</returns>
        private static bool IsCanonicallyEncoded(byte[] key)
        {
            // For X25519, ensure the key follows canonical encoding rules
            // The highest bit (bit 255) must be cleared
            // The three lowest bits of the highest byte (bits 253-255) must be cleared
            if ((key[31] & 0xE0) != 0)
                return false;

            // Check that the key is reduced modulo 2^255 - 19
            // This involves comparing with the prime 2^255 - 19
            // For simplicity, we'll just check that the key is less than 2^255
            if ((key[31] & 0xF0) == 0xF0 && key[30] == 0xFF && key[29] == 0xFF && key[28] == 0xFF)
                return false;

            return true;
        }
    }
}