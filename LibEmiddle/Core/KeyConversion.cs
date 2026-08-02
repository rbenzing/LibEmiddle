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

        /// <summary>
        /// Converts a public key to X25519 format using an explicitly declared input format.
        /// </summary>
        /// <remarks>
        /// Prefer this over <see cref="ConvertEd25519PublicKeyToX25519(byte[])"/> whenever the
        /// caller knows the key's format. Ed25519 and X25519 public keys are both 32 opaque bytes
        /// and cannot be reliably told apart by inspection: roughly one in eight X25519 public keys
        /// also decodes as a valid Ed25519 point, so format sniffing silently converts those keys
        /// into a different (wrong) key.
        /// </remarks>
        /// <param name="publicKey">A 32-byte public key.</param>
        /// <param name="inputIsEd25519">
        /// True when <paramref name="publicKey"/> is an Ed25519 key that must be converted;
        /// false when it is already an X25519 key and should only be validated and copied.
        /// </param>
        /// <returns>The key in X25519 format.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="publicKey"/> is null.</exception>
        /// <exception cref="ArgumentException">Thrown when the key length is wrong or validation fails.</exception>
        public static byte[] ConvertPublicKeyToX25519(byte[] publicKey, bool inputIsEd25519)
        {
            ArgumentNullException.ThrowIfNull(publicKey);

            if (publicKey.Length != Constants.ED25519_PUBLIC_KEY_SIZE)
            {
                throw new ArgumentException(
                    $"Invalid public key length: {publicKey.Length}. Expected 32 bytes.",
                    nameof(publicKey));
            }

            if (inputIsEd25519)
            {
                if (!Sodium.ValidateEd25519PublicKey(publicKey))
                    throw new ArgumentException("Key failed Ed25519 validation.", nameof(publicKey));

                return Sodium.ConvertEd25519PublicKeyToX25519(publicKey);
            }

            if (!Sodium.ValidateX25519PublicKey(publicKey))
                throw new ArgumentException("Key failed X25519 validation.", nameof(publicKey));

            return (byte[])publicKey.Clone();
        }
    }
}
