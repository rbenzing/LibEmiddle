#pragma warning disable IDE0130 // Namespace does not match folder structure
namespace LibEmiddle.Domain
#pragma warning restore IDE0130 // Namespace does not match folder structure
{
    /// <summary>
    /// Constants used across the library for cryptographic operations.
    /// Centralizing these values ensures consistency and makes it easier to update security parameters.
    /// </summary>
    public static class Constants
    {
        /// <summary>
        /// Size of nonce used in AES-GCM encryption (12 bytes)
        /// </summary>
        public const int NONCE_SIZE = 12;

        /// <summary>
        /// Size of AES key in bytes (32 bytes for AES-256)
        /// </summary>
        public const int AES_KEY_SIZE = 32;

        /// <summary>
        /// Size of the DoubleRatchet chain key (32 bytes)
        /// </summary>
        public const int CHAIN_KEY_SIZE = 32;

        /// <summary>
        /// Size of the DoubleRatchet root key (32 bytes)
        /// </summary>
        public const int ROOT_KEY_SIZE = 32;

        /// <summary>
        /// Size of the DoubleRatchet message key (32 bytes)
        /// </summary>
        public const int MESSAGE_KEY_SIZE = 32;

        /// <summary>
        /// Size of authentication tag in AES-GCM (16 bytes)
        /// </summary>
        public const int AUTH_TAG_SIZE = 16;

        /// <summary>
        /// Size of X25519 public and private keys (32 bytes)
        /// </summary>
        public const int X25519_KEY_SIZE = 32;

        /// <summary>
        /// Size of Ed25519 public key (32 bytes)
        /// </summary>
        public const int ED25519_PUBLIC_KEY_SIZE = 32;

        /// <summary>
        /// Size of Ed25519 private key (64 bytes)
        /// </summary>
        public const int ED25519_PRIVATE_KEY_SIZE = 64;

        /// <summary>
        /// Default number of iterations for PBKDF2 key derivation
        /// </summary>
        public const int PBKDF2_ITERATIONS = 600000;

        /// <summary>
        /// Maximum age for messages in milliseconds (5 minutes) for replay protection
        /// </summary>
        public const long MAX_MESSAGE_AGE_MS = 5 * 60 * 1000;

        /// <summary>
        /// Maximum clock skew tolerance in milliseconds (5 minutes) for timestamp validation
        /// </summary>
        public const long MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;

        /// <summary>
        /// Maximum number of message IDs to track for replay protection
        /// </summary>
        public const int MAX_TRACKED_MESSAGE_IDS = 2000;

        /// <summary>
        /// Maximum number of messages to track when skipping
        /// </summary>
        public const int MAX_SKIPPED_MESSAGES = 2000;

        /// <summary>
        /// Default number of one-time prekeys to generate for key bundles
        /// </summary>
        public const int DEFAULT_ONE_TIME_PREKEY_COUNT = 5;

        /// <summary>
        /// Default salt size in bytes for key derivation
        /// </summary>
        public const int DEFAULT_SALT_SIZE = 32;

        /// <summary>
        /// Default number of days before salt rotation
        /// </summary>
        public const int DEFAULT_SALT_ROTATION_DAYS = 30;

        /// <summary>
        /// Default number of days before key rotation
        /// </summary>
        public const int DEFAULT_KEY_ROTATION_DAILY = 7;

        /// <summary>
        /// Default number of hours before key rotation
        /// </summary>
        public const int DEFAULT_KEY_ROTATION_HOURLY = 1;

        /// <summary>
        /// Default number of messages before key rotation
        /// </summary>
        public const int DEFAULT_KEY_ROTATION = 20;

        /// <summary>
        /// Default number of days in miliseconds to rotate keys (7 days)
        /// </summary>
        public const long SIGNED_PREKEY_MAX_AGE_MS = 7L * 24 * 60 * 60 * 1000;

        /// <summary>
        /// Default number of days until key rotation (6 days)
        /// </summary>
        public const long SIGNED_PREKEY_ROTATION_MS = 6L * 24 * 60 * 60 * 1000;
    }
}