using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using E2EELibrary.Core;

namespace E2EELibrary.KeyManagement
{
    public static class KeyValidation
    {
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

            // More sophisticated validation
            // Check for all-zero and all-one keys, which are considered weak/invalid
            bool allZeros = true;
            bool allOnes = true;
            bool hasNonZeroBytes = false;
            bool hasNonOneByte = false;

            for (int i = 0; i < publicKey.Length; i++)
            {
                if (publicKey[i] != 0)
                {
                    allZeros = false;
                    hasNonZeroBytes = true;
                }
                if (publicKey[i] != 255)
                {
                    allOnes = false;
                    hasNonOneByte = true;
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

            // TODO: Add more sophisticated validation
            // For example, checking against known problematic key patterns

            return true;
        }
    }
}
