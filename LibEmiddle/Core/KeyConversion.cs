using LibEmiddle.Domain;

namespace LibEmiddle.Core
{
    /// <summary>
    /// Provides shared utilities for converting between Ed25519 and X25519 key formats.
    /// </summary>
    public static class KeyConversion
    {
        /// <summary>
        /// Converts an Ed25519 or X25519 public key to X25519 format.
        /// If the key is already in X25519 format it is returned as a copy.
        /// If the key is in Ed25519 format it is converted to X25519.
        /// </summary>
        /// <param name="ed25519PublicKey">
        /// A 32-byte public key in either Ed25519 or X25519 format.
        /// </param>
        /// <returns>The key in X25519 format.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="ed25519PublicKey"/> is null.</exception>
        /// <exception cref="ArgumentException">
        /// Thrown when the key length is incorrect, or the key fails both Ed25519 and X25519 validation.
        /// </exception>
        public static byte[] ConvertEd25519PublicKeyToX25519(byte[] ed25519PublicKey)
        {
            ArgumentNullException.ThrowIfNull(ed25519PublicKey);

            // Both Ed25519 and X25519 public keys are 32 bytes, so we need validation
            // to determine which type it is. Try Ed25519 first since that is more common.
            if (ed25519PublicKey.Length != Constants.ED25519_PUBLIC_KEY_SIZE)
            {
                throw new ArgumentException(
                    $"Invalid public key length: {ed25519PublicKey.Length}. " +
                    $"Expected {Constants.ED25519_PUBLIC_KEY_SIZE} bytes (32 bytes).",
                    nameof(ed25519PublicKey));
            }

            if (Sodium.ValidateEd25519PublicKey(ed25519PublicKey))
            {
                // It is an Ed25519 key — convert to X25519
                return Sodium.ConvertEd25519PublicKeyToX25519(ed25519PublicKey);
            }

            if (Sodium.ValidateX25519PublicKey(ed25519PublicKey))
            {
                // It is already an X25519 key — return a copy
                return (byte[])ed25519PublicKey.Clone();
            }

            throw new ArgumentException(
                "Invalid public key — neither Ed25519 nor X25519 validation passed.",
                nameof(ed25519PublicKey));
        }
    }
}
