#pragma warning disable IDE0130 // Namespace does not match folder structure
namespace LibEmiddle.Domain
#pragma warning restore IDE0130 // Namespace does not match folder structure
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
        public static bool ValidateEd25519PublicKey(byte[]? publicKey)
        {
            // 1. Check for null and correct length
            if (publicKey == null || publicKey.Length != Constants.ED25519_PUBLIC_KEY_SIZE)
            {
                // Optional: Log the failure reason
                // LoggingManager.LogWarning("ValidateEd25519PublicKey", $"Key validation failed: Null or incorrect length ({(publicKey == null ? "null" : publicKey.Length)} bytes, expected {ED25519_PUBLIC_KEY_SIZE}).");
                return false;
            }

            // 2. Check if the key consists entirely of zero bytes.
            // This represents the identity element and is often disallowed.
            if (publicKey.All(b => b == 0))
            {
                // Optional: Log the failure reason
                // LoggingManager.LogWarning("ValidateEd25519PublicKey", "Key validation failed: Key is all zeros.");
                return false;
            }

            // 3. Placeholder for Library-Specific Point Validation (if available)
            // If your cryptographic library (e.g., NSec, BouncyCastle wrapper)
            // provides an explicit function to check if the bytes represent a
            // valid point on the curve, call it here.
            // Example (conceptual):
            // try
            // {
            //     if (!YourCryptoLib.Ed25519.IsPointOnCurve(publicKey))
            //     {
            //         LoggingManager.LogWarning("ValidateEd25519PublicKey", "Key validation failed: Library reported point is not on curve.");
            //         return false;
            //     }
            // }
            // catch (Exception ex) // Catch potential decoding errors
            // {
            //     LoggingManager.LogError("ValidateEd25519PublicKey", $"Error during library key validation: {ex.Message}");
            //     return false;
            // }


            // If basic checks pass, return true.
            // Deeper cryptographic validity will be checked during signature verification.
            return true;
        }
    }
}