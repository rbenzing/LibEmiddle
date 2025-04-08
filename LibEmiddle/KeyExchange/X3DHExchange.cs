using System.Text;
using System.Security.Cryptography;
using E2EELibrary.Core;
using E2EELibrary.Models;
using E2EELibrary.KeyManagement;
using E2EELibrary.Communication;

namespace E2EELibrary.KeyExchange
{
    /// <summary>
    /// Implements the Extended Triple Diffie-Hellman (X3DH) key agreement protocol.
    /// X3DH establishes a shared secret key between two parties who mutually authenticate
    /// each other based on public keys.
    /// </summary>
    public static class X3DHExchange
    {
        /// <summary>
        /// Performs X3DH (Extended Triple Diffie-Hellman) key exchange
        /// </summary>
        /// <param name="recipientPublicKey">Recipient's public key (32 bytes)</param>
        /// <param name="senderPrivateKey">Sender's private key (32 or 64 bytes)</param>
        /// <returns>Shared secret key</returns>
        public static byte[] X3DHKeyExchange(byte[] recipientPublicKey, byte[] senderPrivateKey)
        {
            ArgumentNullException.ThrowIfNull(recipientPublicKey, nameof(recipientPublicKey));
            ArgumentNullException.ThrowIfNull(senderPrivateKey, nameof(senderPrivateKey));

            // Ensure the recipient's public key is valid before proceeding
            if (!KeyValidation.ValidateX25519PublicKey(recipientPublicKey))
                throw new ArgumentException("Invalid recipient public key", nameof(recipientPublicKey));

            // Convert to 32-byte X25519 private key if needed
            byte[] senderX25519PrivateKey;
            if (senderPrivateKey.Length != Constants.X25519_KEY_SIZE)
            {
                senderX25519PrivateKey = KeyConversion.DeriveX25519PrivateKeyFromEd25519(senderPrivateKey);
            }
            else
            {
                // Create a copy to avoid modifying the original
                senderX25519PrivateKey = Sodium.GenerateRandomBytes(Constants.X25519_KEY_SIZE);
                senderPrivateKey.AsSpan(0, Constants.X25519_KEY_SIZE).CopyTo(senderX25519PrivateKey.AsSpan(0, Constants.X25519_KEY_SIZE));
            }

            try
            {
                // Both keys must be 32 bytes for X25519 operation
                if (recipientPublicKey.Length != Constants.X25519_KEY_SIZE || senderX25519PrivateKey.Length != Constants.X25519_KEY_SIZE)
                {
                    throw new ArgumentException($"Both keys must be {Constants.X25519_KEY_SIZE} bytes long for X25519 key exchange");
                }

                // Perform the actual key exchange
                return Sodium.ScalarMult(senderX25519PrivateKey, recipientPublicKey);
            }
            finally
            {
                // Securely clear our copy of the private key
                SecureMemory.SecureClear(senderX25519PrivateKey);
            }
        }

        /// <summary>
        /// Creates a complete X3DH key bundle with identity, signed prekey, and one-time prekeys
        /// </summary>
        /// <returns>X3DH key bundle for publishing to a server</returns>
        public static X3DHKeyBundle CreateX3DHKeyBundle()
        {
            // Generate the identity key pair using full Ed25519 keys.
            var (publicKey, privateKey) = KeyGenerator.GenerateEd25519KeyPair();

            // Store both the Ed25519 identity key (for verification) and X25519 key (for key exchange)
            byte[] identityX25519Private = KeyConversion.DeriveX25519PrivateKeyFromEd25519(privateKey);
            byte[] identityX25519Public = Sodium.ScalarMultBase(identityX25519Private);

            // Generate the signed prekey pair
            var signedPreKeyPair = KeyGenerator.GenerateX25519KeyPair();
            byte[] signedPreX25519Public = signedPreKeyPair.publicKey;
            byte[] signedPreX25519Private = signedPreKeyPair.privateKey;

            // Create one-time prekeys
            var oneTimePreKeys = new List<byte[]>();
            for (int i = 0; i < 5; i++)
            {
                var oneTimeKeyPair = KeyGenerator.GenerateX25519KeyPair();
                oneTimePreKeys.Add(oneTimeKeyPair.publicKey);
            }

            // Sign the prekey with Ed25519 identity key
            byte[] signature = MessageSigning.SignMessage(signedPreX25519Public, privateKey);

            var bundle = new X3DHKeyBundle
            {
                IdentityKey = publicKey,
                SignedPreKey = signedPreX25519Public,
                SignedPreKeySignature = signature,
                OneTimePreKeys = oneTimePreKeys
            };

            bundle.SetIdentityKeyPrivate(privateKey);
            bundle.SetSignedPreKeyPrivate(signedPreX25519Private);

            return bundle;
        }

        /// <summary>
        /// Add proper key derivation following Signal spec
        /// </summary>
        /// <param name="secrets">Secret key materials to combine</param>
        /// <returns>Derived shared secret</returns>
        private static byte[] DeriveSharedSecret(params byte[][] secrets)
        {
            // Use HKDF for proper key derivation
            byte[] combinedInput = new byte[secrets.Sum(s => s.Length)];
            int offset = 0;

            foreach (var secret in secrets)
            {
                secret.CopyTo(combinedInput, offset);
                offset += secret.Length;
            }

            // Use a proper info string as per spec
            byte[] info = Encoding.UTF8.GetBytes("X3DH_Signal_Protocol_v1");

            // 32 bytes output (AES-256 key)
            return Hkdf(combinedInput, null, info, 32);
        }

        /// <summary>
        /// Implement proper HKDF as per RFC 5869
        /// </summary>
        /// <param name="inputKeyMaterial">Initial key material</param>
        /// <param name="salt">Optional salt (can be null)</param>
        /// <param name="info">Context and application specific information</param>
        /// <param name="outputLength">Length of output in bytes</param>
        /// <returns>Derived key material</returns>
        private static byte[] Hkdf(byte[] inputKeyMaterial, byte[]? salt, byte[] info, int outputLength)
        {
            salt ??= new byte[32]; // Use empty salt if not provided

            // HKDF-Extract
            byte[] prk;
            using (var hmac = new HMACSHA256(salt))
            {
                prk = hmac.ComputeHash(inputKeyMaterial);
            }

            // HKDF-Expand
            byte[] okm = new byte[outputLength];
            byte[] t = Array.Empty<byte>();
            byte[] counter = new byte[1];
            int offset = 0;

            using var hmacExpand = new HMACSHA256(prk);

            for (counter[0] = 1; offset < outputLength; counter[0]++)
            {
                hmacExpand.Initialize();

                using var ms = new MemoryStream();
                ms.Write(t);
                ms.Write(info);
                ms.Write(counter);

                t = hmacExpand.ComputeHash(ms.ToArray());

                int remaining = Math.Min(outputLength - offset, t.Length);
                t.AsSpan(0, remaining).CopyTo(okm.AsSpan(offset, remaining));
                offset += remaining;
            }

            return okm;
        }

        /// <summary>
        /// Initiates a session with a recipient using their X3DH key bundle with enhanced security validation
        /// </summary>
        /// <param name="recipientBundle">Recipient's X3DH key bundle</param>
        /// <param name="senderIdentityKeyPair">Sender's identity key pair</param>
        /// <returns>Initial message keys and session data</returns>
        public static X3DHSession InitiateX3DHSession(X3DHPublicBundle recipientBundle,
            (byte[] publicKey, byte[] privateKey) senderIdentityKeyPair)
        {
            ArgumentNullException.ThrowIfNull(recipientBundle, nameof(recipientBundle));

            if (recipientBundle.IdentityKey == null || recipientBundle.SignedPreKey == null)
                throw new ArgumentException("Missing required keys in recipient bundle", nameof(recipientBundle));
            if (senderIdentityKeyPair.publicKey == null || senderIdentityKeyPair.privateKey == null)
                throw new ArgumentException("Invalid sender identity key pair", nameof(senderIdentityKeyPair));

            try
            {
                // Validate recipient's keys
                if (!KeyValidation.ValidateX25519PublicKey(recipientBundle.IdentityKey))
                    throw new ArgumentException("Invalid recipient identity key", nameof(recipientBundle));
                if (!KeyValidation.ValidateX25519PublicKey(recipientBundle.SignedPreKey))
                    throw new ArgumentException("Invalid recipient signed prekey", nameof(recipientBundle));

                // Verify the signature on the signed prekey
                if (recipientBundle.SignedPreKeySignature != null &&
                    !MessageSigning.VerifySignature(recipientBundle.SignedPreKey, recipientBundle.SignedPreKeySignature, recipientBundle.IdentityKey))
                {
                    throw new CryptographicException("Signature verification failed for recipient's signed prekey");
                }

                // Validate and select a one-time prekey if available
                byte[]? oneTimePreKey = null;
                if (recipientBundle.OneTimePreKeys != null && recipientBundle.OneTimePreKeys.Count > 0)
                {
                    // Create a list of valid one-time prekeys
                    var validOneTimePreKeys = new List<byte[]>();
                    foreach (var preKey in recipientBundle.OneTimePreKeys)
                    {
                        if (preKey != null && KeyValidation.ValidateX25519PublicKey(preKey))
                        {
                            validOneTimePreKeys.Add(preKey);
                        }
                    }

                    // Only select a prekey if we have valid ones
                    if (validOneTimePreKeys.Count > 0)
                    {
                        // Use secure random for selection
                        int index = 0;
                        if (validOneTimePreKeys.Count > 1)
                        {
                            byte[] randomBytes = Sodium.GenerateRandomBytes(4);
                            using (var rng = RandomNumberGenerator.Create())
                            {
                                rng.GetBytes(randomBytes);
                            }
                            // Ensure positive value and proper modulo
                            uint randomValue = BitConverter.ToUInt32(randomBytes, 0);
                            index = (int)(randomValue % (uint)validOneTimePreKeys.Count);
                        }
                        oneTimePreKey = validOneTimePreKeys[index];
                    }
                    else
                    {
                        // Log a warning that no valid prekeys were found, but continue without a one-time prekey
                        // In production, consider adding proper logging here
                        // Logger.LogWarning("No valid one-time prekeys found in recipient bundle");
                    }
                }

                // Generate ephemeral key
                var ephemeralKeyPair = KeyGenerator.GenerateX25519KeyPair();

                // Convert sender's identity key to X25519 format if needed
                byte[] senderX25519Private;
                if (senderIdentityKeyPair.privateKey.Length != Constants.X25519_KEY_SIZE)
                {
                    senderX25519Private = KeyConversion.DeriveX25519PrivateKeyFromEd25519(senderIdentityKeyPair.privateKey);
                }
                else
                {
                    // Create a copy to avoid modifying the original
                    senderX25519Private = Sodium.GenerateRandomBytes(Constants.X25519_KEY_SIZE);
                    senderIdentityKeyPair.privateKey.AsSpan(0, Constants.X25519_KEY_SIZE).CopyTo(senderX25519Private.AsSpan(0, Constants.X25519_KEY_SIZE));
                }

                try
                {
                    // Calculate DH results for each key component
                    // DH1 = DH(IKA, SPKB) - A's identity key with B's signed prekey
                    byte[] dh1 = X3DHKeyExchange(recipientBundle.SignedPreKey, senderX25519Private);

                    // DH2 = DH(EKA, IKB) - A's ephemeral key with B's identity key
                    byte[] dh2 = X3DHKeyExchange(recipientBundle.IdentityKey, ephemeralKeyPair.privateKey);

                    // DH3 = DH(EKA, SPKB) - A's ephemeral key with B's signed prekey
                    byte[] dh3 = X3DHKeyExchange(recipientBundle.SignedPreKey, ephemeralKeyPair.privateKey);

                    // DH4 = DH(EKA, OPKB) - A's ephemeral key with B's one-time prekey (if available)
                    byte[]? dh4 = null;
                    if (oneTimePreKey != null)
                    {
                        dh4 = X3DHKeyExchange(oneTimePreKey, ephemeralKeyPair.privateKey);
                    }

                    // Derive the shared secret using proper HKDF
                    byte[] sharedSecret = dh4 != null
                        ? DeriveSharedSecret(dh1, dh2, dh3, dh4)
                        : DeriveSharedSecret(dh1, dh2, dh3);

                    // Initialize Double Ratchet with this master secret
                    var (rootKey, chainKey) = DoubleRatchetExchange.InitializeDoubleRatchet(sharedSecret);

                    // Create the session object
                    var session = new X3DHSession(
                        recipientIdentityKey: recipientBundle.IdentityKey,
                        senderIdentityKey: senderIdentityKeyPair.publicKey,
                        ephemeralKey: ephemeralKeyPair.publicKey,
                        usedOneTimePreKey: oneTimePreKey != null,
                        rootKey: rootKey,
                        chainKey: chainKey
                    );

                    // Clean up sensitive key material
                    SecureMemory.SecureClear(senderX25519Private);
                    SecureMemory.SecureClear(dh1);
                    SecureMemory.SecureClear(dh2);
                    SecureMemory.SecureClear(dh3);
                    if (dh4 != null) SecureMemory.SecureClear(dh4);
                    SecureMemory.SecureClear(sharedSecret);
                    SecureMemory.SecureClear(ephemeralKeyPair.privateKey);

                    return session;
                }
                finally
                {
                    // Ensure we always clear the private key copy
                    SecureMemory.SecureClear(senderX25519Private);
                }
            }
            catch (Exception ex)
            {
                throw new CryptographicException("Failed to initiate X3DH session", ex);
            }
        }
    }
}