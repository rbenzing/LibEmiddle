﻿using LibEmiddle.Core;
using LibEmiddle.Domain;
using static LibEmiddle.Core.SecureMemory;

namespace LibEmiddle.Crypto
{
    /// <summary>
    /// Provides functionality for generating secure nonces for cryptographic operations
    /// using libsodium's high-quality random number generation.
    /// </summary>
    internal static class Nonce
    {
        private static readonly object _nonceLock = new();
        private static nuint _nonceCounter = 0;
        private static byte[]? _noncePrefix = null;

        /// <summary>
        /// Generates a secure nonce for AES-GCM encryption that won't be reused.
        /// Combines high-quality randomness from libsodium with a counter to ensure uniqueness.
        /// </summary>
        /// <param name="size">Size of the nonce in bytes (defaults to the standard AES-GCM nonce size)</param>
        /// <returns>Secure nonce</returns>
        public static byte[] GenerateNonce(uint size = Constants.NONCE_SIZE)
        {
            if (size <= 0)
                throw new ArgumentException("Nonce size must be positive", nameof(size));

            // Generate a completely random nonce using libsodium's secure CSPRNG
            byte[] nonce = SecureMemory.CreateSecureBuffer(size);

            lock (_nonceLock)
            {
                // Initialize nonce prefix if it hasn't been done yet
                if (_noncePrefix == null)
                {
                    _noncePrefix = SecureMemory.CreateSecureBuffer(4);
                }

                // Increment counter to ensure uniqueness even if random generation produces duplicates
                _nonceCounter++;

                // Rotate prefix if counter wraps around to maintain uniqueness across restarts
                if (_nonceCounter == 0)
                {
                    _noncePrefix = SecureMemory.CreateSecureBuffer(4);
                }

                // If we have room, mix in counter and prefix to ensure uniqueness
                // This maintains our defense-in-depth approach by combining:
                // 1. High quality randomness from libsodium
                // 2. Counter-based uniqueness
                // 3. Runtime-specific prefix
                if (size >= 8)
                {
                    // Add counter to the last 8 bytes
                    byte[] counterBytes = BitConverter.GetBytes(_nonceCounter);
                    for (int i = 0; i < 8 && i < size; i++)
                    {
                        // XOR the last bytes with counter bytes
                        nonce[size - i - 1] ^= counterBytes[i % counterBytes.Length];
                    }

                    // Add prefix to the beginning of the nonce
                    for (int i = 0; i < _noncePrefix.Length && i < 4 && i < size; i++)
                    {
                        // XOR with prefix
                        nonce[i] ^= _noncePrefix[i];
                    }
                }
            }

            return nonce;
        }

        public static byte[] GenerateNonce(ReadOnlySpan<byte> sessionContext, uint sequenceNumber)
        {
            using var buffer = new SecureBuffer(Constants.NONCE_SIZE);
            var span = buffer.AsSpan();

            // Pure random for base
            Sodium.RandomFill(span);

            // Session-specific derivation
            var derived = Sodium.HkdfDerive(
                sessionContext,
                span[..16], // Use part of random as salt
                "LibEmiddle-Nonce"u8,
                Constants.NONCE_SIZE);

            // Mix in sequence number for uniqueness
            var seqBytes = BitConverter.GetBytes(sequenceNumber);
            for (int i = 0; i < seqBytes.Length; i++)
                derived[i] ^= seqBytes[i];

            return derived;
        }

        /// <summary>
        /// Generates a nonce specifically for XChaCha20-Poly1305 (24 bytes)
        /// </summary>
        /// <returns>A 24-byte nonce suitable for XChaCha20-Poly1305</returns>
        public static byte[] GenerateXChaCha20Nonce()
        {
            // XChaCha20-Poly1305 uses 24-byte nonces
            return GenerateNonce(24);
        }
    }
}