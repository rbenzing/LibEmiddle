namespace LibEmiddle.Domain
{
    /// <summary>
    /// Constants used across the library for cryptographic operations.
    /// Centralizing these values ensures consistency and makes it easier to update security parameters.
    /// </summary>
    public static class Constants
    {
        /// <summary>
        /// The eMiddle protocol version
        /// </summary>
        public const string PROTOCOL_VERSION = "1.0";

        /// <summary>
        /// Size of nonce used in AES-GCM encryption (12 bytes)
        /// </summary>
        public const int NONCE_SIZE = 12;

        /// <summary>
        /// Size of AES key in bytes (32 bytes for AES-256)
        /// </summary>
        public const int AES_KEY_SIZE = 32;

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
        public const int MAX_TRACKED_MESSAGE_IDS = 100;

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
        /// Default number of days before group key rotation
        /// </summary>
        public const int DEFAULT_KEY_ROTATION_DAILY = 7;

        /// <summary>
        /// Default number of hours before group key rotation
        /// </summary>
        public const int DEFAULT_KEY_ROTATION_HOURLY = 1;
    }
}