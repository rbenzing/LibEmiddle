using LibEmiddle.Core;
using LibEmiddle.Domain;

namespace LibEmiddle.Crypto
{
    public class KeyValidation
    {
        /// <summary>
        /// Validates an X25519 public key to ensure it's not an invalid or dangerous value
        /// </summary>
        /// <param name="publicKey">X25519 public key to validate</param>
        /// <returns>True if the key is valid.</returns>
        // In KeyValidation.cs
        public static bool ValidateX25519PublicKey(byte[] publicKey)
        {
            if (publicKey == null)
            {
                return false;
            }

            if (publicKey.Length != Constants.X25519_KEY_SIZE)
            {
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
                return false;
            }

            // For X25519, we don't need to do extensive validation as the algorithm 
            // itself handles many edge cases. The key check above is sufficient
            // for basic validation purposes.

            return true;
        }

        /// <summary>
        /// Performs basic validation checks on an Ed25519 public key.
        ///
        /// Checks for correct length (32 bytes) and ensures the key is not the 'all-zero' key.
        ///
        /// Note: Full cryptographic validation according to RFC 8032 (checking if the
        /// bytes correctly decode to a point on the main subgroup of the Edwards curve)
        /// is complex. This function relies on the signature verification process
        /// (e.g., using Libsodium's crypto_sign_verify_detached) to perform those
        /// deeper checks implicitly when the key is actually used.
        /// </summary>
        /// <param name="publicKey">The public key bytes to validate.</param>
        /// <returns>True if the key passes basic checks (length, not all-zero), false otherwise.</returns>
        public static bool ValidateEd25519PublicKey(ReadOnlySpan<byte> publicKey)
        {
            // 1. Check for empty span and correct length
            if (publicKey.IsEmpty || publicKey.Length != Constants.ED25519_PUBLIC_KEY_SIZE)
            {
                // Optional: Log the failure reason
                // LoggingManager.LogWarning("ValidateEd25519PublicKey", $"Key validation failed: Empty or incorrect length ({publicKey.Length} bytes, expected {ED25519_PUBLIC_KEY_SIZE}).");
                return false;
            }

            // 2. Check if the key consists entirely of zero bytes.
            // This represents the identity element and is often disallowed.
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
                // Optional: Log the failure reason
                // LoggingManager.LogWarning("ValidateEd25519PublicKey", "Key validation failed: Key is all zeros.");
                return false;
            }

            // 3. Use libsodium to check if the point is on the curve
            try
            {
                // Ensure libsodium is initialized
                Sodium.Initialize();

                // Create a temporary array to pass to Sodium's API
                // since it doesn't accept span parameters
                byte[] tempKey = publicKey.ToArray();

                // Call libsodium's function to check if the point is valid
                int result = Sodium.crypto_core_ed25519_is_valid_point(tempKey);

                if (result != 1)
                {
                    // Optional: Log the failure reason
                    // LoggingManager.LogWarning("ValidateEd25519PublicKey", "Key validation failed: Sodium reported point is not on curve.");
                    return false;
                }
            }
            catch (Exception ex)
            {
                // Log the error and return false
                LoggingManager.LogError(nameof(KeyValidation), $"Error during Ed25519 key validation: {ex.Message}");
                return false;
            }

            // If all checks pass, return true.
            return true;
        }
    }
}