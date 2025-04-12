using System.Text;
using System.Security.Cryptography;
using LibEmiddle.Core;
using LibEmiddle.Messaging.Transport;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.Models;

namespace LibEmiddle.KeyExchange
{
    /// <summary>
    /// Implements the Extended Triple Diffie-Hellman (X3DH) key agreement protocol
    /// as defined in the Signal Protocol specification.
    /// X3DH establishes a shared secret key between two parties who mutually authenticate
    /// each other based on public keys.
    /// </summary>
    public static class X3DHExchange
    {
        // Current protocol version
        private const string PROTOCOL_VERSION = "1.0";

        // Recommended rotation period for signed pre-keys (7 days in milliseconds)
        private const long SIGNED_PREKEY_ROTATION_MS = 7 * 24 * 60 * 60 * 1000L;

        // Maximum age for a signed pre-key before it's considered expired (30 days in milliseconds)
        private const long SIGNED_PREKEY_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000L;

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
        /// Creates a complete X3DH key bundle with identity, signed prekey, and one-time prekeys.
        /// Follows the Signal Protocol specification.
        /// </summary>
        /// <param name="identityKeyPair">Optional existing identity key pair to use. If null, a new one will be generated.</param>
        /// <param name="numOneTimeKeys">Number of one-time pre-keys to generate.</param>
        /// <returns>X3DH key bundle for publishing to a server</returns>
        public static X3DHKeyBundle CreateX3DHKeyBundle(
            (byte[] publicKey, byte[] privateKey)? identityKeyPair = null,
            int numOneTimeKeys = Constants.DEFAULT_ONE_TIME_PREKEY_COUNT)
        {
            // Generate or use the provided identity key pair
            var (publicKey, privateKey) = identityKeyPair ?? KeyGenerator.GenerateEd25519KeyPair();

            // Validate the identity key pair
            if (publicKey.Length != Constants.ED25519_PUBLIC_KEY_SIZE ||
                privateKey.Length != Constants.ED25519_PRIVATE_KEY_SIZE)
            {
                throw new ArgumentException("Invalid identity key pair format");
            }

            // Store both the Ed25519 identity key (for verification) and X25519 key (for key exchange)
            byte[] identityX25519Private = KeyConversion.DeriveX25519PrivateKeyFromEd25519(privateKey);
            byte[] identityX25519Public = Sodium.ScalarMultBase(identityX25519Private);

            try
            {
                // Generate the signed prekey pair with proper error handling
                (byte[] signedPreX25519Public, byte[] signedPreX25519Private) signedPreKeyPair;
                try
                {
                    signedPreKeyPair = KeyGenerator.GenerateX25519KeyPair();
                }
                catch (Exception ex)
                {
                    throw new CryptographicException("Failed to generate signed pre-key pair", ex);
                }

                // Create one-time prekeys with proper validation
                var oneTimePreKeys = new List<byte[]>();
                var oneTimePreKeyIds = new List<uint>();

                for (int i = 0; i < numOneTimeKeys; i++)
                {
                    try
                    {
                        var oneTimeKeyPair = KeyGenerator.GenerateX25519KeyPair();

                        // Validate the generated key
                        if (KeyValidation.ValidateX25519PublicKey(oneTimeKeyPair.publicKey))
                        {
                            oneTimePreKeys.Add(oneTimeKeyPair.publicKey);

                            // Assign a unique ID to this pre-key (used for tracking usage)
                            byte[] idBytes = Sodium.GenerateRandomBytes(4);
                            uint preKeyId = BitConverter.ToUInt32(idBytes, 0);
                            // Ensure the ID is not zero
                            if (preKeyId == 0) preKeyId = 1;
                            oneTimePreKeyIds.Add(preKeyId);
                        }
                        else
                        {
                            // Log and retry if key validation fails
                            LoggingManager.LogWarning(nameof(X3DHExchange), "Generated one-time pre-key failed validation, retrying...");
                            i--; // Retry this iteration
                        }
                    }
                    catch (Exception ex)
                    {
                        // Log error but continue with the keys we have
                        LoggingManager.LogError(nameof(X3DHExchange), $"Error generating one-time pre-key: {ex.Message}");
                        if (oneTimePreKeys.Count == 0)
                        {
                            throw new CryptographicException("Failed to generate any valid one-time pre-keys", ex);
                        }
                        // Break if we've tried enough times and have at least one key
                        break;
                    }
                }

                // Sign the prekey with Ed25519 identity key to ensure authenticity
                byte[] signature = MessageSigning.SignMessage(signedPreKeyPair.signedPreX25519Public, privateKey);

                // Generate a unique ID for the signed pre-key
                uint signedPreKeyId = GenerateSecureRandomId();

                // Current timestamp for key creation
                long timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

                // Create and populate the bundle
                var bundle = new X3DHKeyBundle
                {
                    IdentityKey = publicKey,
                    SignedPreKey = signedPreKeyPair.signedPreX25519Public,
                    SignedPreKeySignature = signature,
                    OneTimePreKeys = oneTimePreKeys,
                    ProtocolVersion = PROTOCOL_VERSION,
                    SignedPreKeyId = signedPreKeyId,
                    OneTimePreKeyIds = oneTimePreKeyIds,
                    CreationTimestamp = timestamp
                };

                // Set private key data with proper memory handling
                bundle.SetIdentityKeyPrivate(privateKey);
                bundle.SetSignedPreKeyPrivate(signedPreKeyPair.signedPreX25519Private);

                // Log successful bundle creation
                LoggingManager.LogInformation(nameof(X3DHExchange),
                    $"Created X3DH key bundle with {oneTimePreKeys.Count} one-time pre-keys");

                return bundle;
            }
            finally
            {
                // Ensure we securely clear the sensitive derived key
                SecureMemory.SecureClear(identityX25519Private);
            }
        }

        /// <summary>
        /// Validates if an X3DH key bundle is valid and secure.
        /// </summary>
        /// <param name="bundle">Bundle to validate</param>
        /// <returns>True if the bundle is valid and secure</returns>
        public static bool ValidateKeyBundle(X3DHPublicBundle bundle)
        {
            if (bundle == null)
                return false;

            try
            {
                // Check required fields
                if (bundle.IdentityKey == null || bundle.SignedPreKey == null ||
                    bundle.SignedPreKeySignature == null)
                {
                    LoggingManager.LogWarning(nameof(X3DHExchange), "Bundle missing required fields");
                    return false;
                }

                // Validate key sizes
                if (bundle.IdentityKey.Length != Constants.ED25519_PUBLIC_KEY_SIZE)
                {
                    LoggingManager.LogWarning(nameof(X3DHExchange),
                        $"Invalid identity key length: {bundle.IdentityKey.Length}, expected {Constants.ED25519_PUBLIC_KEY_SIZE}");
                    return false;
                }

                if (bundle.SignedPreKey.Length != Constants.X25519_KEY_SIZE)
                {
                    LoggingManager.LogWarning(nameof(X3DHExchange),
                        $"Invalid signed pre-key length: {bundle.SignedPreKey.Length}, expected {Constants.X25519_KEY_SIZE}");
                    return false;
                }

                // Check for all zeros (invalid key)
                bool identityAllZeros = true;
                for (int i = 0; i < bundle.IdentityKey.Length; i++)
                {
                    if (bundle.IdentityKey[i] != 0)
                    {
                        identityAllZeros = false;
                        break;
                    }
                }

                bool preKeyAllZeros = true;
                for (int i = 0; i < bundle.SignedPreKey.Length; i++)
                {
                    if (bundle.SignedPreKey[i] != 0)
                    {
                        preKeyAllZeros = false;
                        break;
                    }
                }

                if (identityAllZeros || preKeyAllZeros)
                {
                    LoggingManager.LogWarning(nameof(X3DHExchange), "Bundle contains invalid zero keys");
                    return false;
                }

                // Verify the signature on the signed prekey
                bool validSignature = MessageSigning.VerifySignature(
                    bundle.SignedPreKey,
                    bundle.SignedPreKeySignature,
                    bundle.IdentityKey);

                if (!validSignature)
                {
                    LoggingManager.LogWarning(nameof(X3DHExchange), "Bundle signature verification failed");
                    return false;
                }

                // Check pre-key age if timestamp is available
                if (bundle.CreationTimestamp > 0)
                {
                    long currentTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                    long ageMs = currentTime - bundle.CreationTimestamp;

                    if (ageMs > SIGNED_PREKEY_MAX_AGE_MS)
                    {
                        LoggingManager.LogWarning(nameof(X3DHExchange),
                            $"Bundle signed pre-key is too old: {ageMs / (24 * 60 * 60 * 1000)} days");
                        return false;
                    }

                    // Log warning if pre-key should be rotated soon
                    if (ageMs > SIGNED_PREKEY_ROTATION_MS)
                    {
                        LoggingManager.LogWarning(nameof(X3DHExchange),
                            "Bundle signed pre-key is due for rotation");
                    }
                }

                // Bundle is valid
                return true;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(X3DHExchange), $"Error validating bundle: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Performs proper key derivation following Signal spec.
        /// Combines multiple DH outputs to derive a shared secret.
        /// </summary>
        /// <param name="secrets">Secret key materials to combine</param>
        /// <returns>Derived shared secret</returns>
        private static byte[] DeriveSharedSecret(params byte[][] secrets)
        {
            try
            {
                // Combine input key materials
                byte[] combinedInput = new byte[secrets.Sum(s => s.Length)];
                int offset = 0;
                foreach (var secret in secrets)
                {
                    if (secret == null)
                        throw new ArgumentNullException("A secret key component is null");

                    // Use Span<T> for efficient memory copying
                    secret.AsSpan().CopyTo(combinedInput.AsSpan(offset, secret.Length));
                    offset += secret.Length;
                }

                // Use HKDF for key derivation with protocol-specific info
                return KeyConversion.HkdfDerive(
                    combinedInput,
                    info: Encoding.UTF8.GetBytes($"X3DH-v{PROTOCOL_VERSION}"),
                    outputLength: Constants.AES_KEY_SIZE);
            }
            catch (Exception ex)
            {
                throw new CryptographicException("Failed to derive shared secret", ex);
            }
        }

        /// <summary>
        /// Initiates a session with a recipient using their X3DH key bundle with enhanced security validation.
        /// Follows the Signal Protocol specification for the X3DH key agreement.
        /// </summary>
        /// <param name="recipientBundle">Recipient's X3DH key bundle</param>
        /// <param name="senderIdentityKeyPair">Sender's identity key pair</param>
        /// <param name="usedOneTimePreKeyId">Output parameter containing the ID of the used one-time pre-key, if any</param>
        /// <returns>Initial message keys and session data</returns>
        public static X3DHSession InitiateX3DHSession(
            X3DHPublicBundle recipientBundle,
            (byte[] publicKey, byte[] privateKey) senderIdentityKeyPair,
            out uint? usedOneTimePreKeyId)
        {
            // Initialize output parameter
            usedOneTimePreKeyId = null;

            ArgumentNullException.ThrowIfNull(recipientBundle, nameof(recipientBundle));

            if (!ValidateKeyBundle(recipientBundle))
                throw new ArgumentException("Invalid or incomplete recipient bundle", nameof(recipientBundle));

            if (recipientBundle.IdentityKey == null || recipientBundle.SignedPreKey == null)
                throw new ArgumentException("Missing required keys in recipient bundle", nameof(recipientBundle));

            if (senderIdentityKeyPair.publicKey == null || senderIdentityKeyPair.privateKey == null)
                throw new ArgumentException("Invalid sender identity key pair", nameof(senderIdentityKeyPair));

            try
            {
                // Prepare sender's identity key in X25519 format for key exchange
                byte[]? senderX25519Private = null;
                try
                {
                    // Convert Ed25519 identity key to X25519 format if needed
                    if (senderIdentityKeyPair.privateKey.Length == Constants.ED25519_PRIVATE_KEY_SIZE)
                    {
                        senderX25519Private = KeyConversion.DeriveX25519PrivateKeyFromEd25519(
                            senderIdentityKeyPair.privateKey);
                    }
                    else if (senderIdentityKeyPair.privateKey.Length == Constants.X25519_KEY_SIZE)
                    {
                        // Create a copy to avoid modifying the original
                        senderX25519Private = SecureMemory.SecureCopy(senderIdentityKeyPair.privateKey);
                    }
                    else
                    {
                        throw new ArgumentException(
                            $"Invalid sender private key length: {senderIdentityKeyPair.privateKey.Length}",
                            nameof(senderIdentityKeyPair));
                    }

                    // Convert recipient's Ed25519 identity key to X25519 format
                    byte[] recipientX25519Public;
                    if (recipientBundle.IdentityKey.Length == Constants.ED25519_PUBLIC_KEY_SIZE)
                    {
                        recipientX25519Public = KeyConversion.ConvertEd25519PublicKeyToX25519(
                            recipientBundle.IdentityKey);
                    }
                    else if (recipientBundle.IdentityKey.Length == Constants.X25519_KEY_SIZE)
                    {
                        recipientX25519Public = SecureMemory.SecureCopy(recipientBundle.IdentityKey);
                    }
                    else
                    {
                        throw new ArgumentException(
                            $"Invalid recipient identity key length: {recipientBundle.IdentityKey.Length}",
                            nameof(recipientBundle));
                    }

                    // Validate recipient's signed pre-key
                    if (!KeyValidation.ValidateX25519PublicKey(recipientBundle.SignedPreKey))
                    {
                        throw new ArgumentException("Invalid recipient signed pre-key",
                            nameof(recipientBundle));
                    }

                    // Generate ephemeral key pair for this session
                    var ephemeralKeyPair = KeyGenerator.GenerateX25519KeyPair();

                    // Select a one-time pre-key if available
                    byte[]? oneTimePreKey = null;
                    int oneTimePreKeyIndex = -1;

                    if (recipientBundle.OneTimePreKeys != null && recipientBundle.OneTimePreKeys.Count > 0)
                    {
                        // Select a random pre-key with secure random generation
                        byte[] randomBytes = Sodium.GenerateRandomBytes(4);
                        // Use BitConverter.ToInt32 to convert the random bytes to an int
                        int index = Math.Abs(BitConverter.ToInt32(randomBytes, 0)) %
                            recipientBundle.OneTimePreKeys.Count;

                        oneTimePreKey = recipientBundle.OneTimePreKeys[index];
                        oneTimePreKeyIndex = index;

                        // Set the output parameter if IDs are available
                        if (recipientBundle.OneTimePreKeyIds != null &&
                            recipientBundle.OneTimePreKeyIds.Count > index)
                        {
                            usedOneTimePreKeyId = recipientBundle.OneTimePreKeyIds[index];
                        }

                        // Validate the selected one-time pre-key
                        if (!KeyValidation.ValidateX25519PublicKey(oneTimePreKey))
                        {
                            // Try to find a valid key instead
                            oneTimePreKey = null;
                            usedOneTimePreKeyId = null;

                            for (int i = 0; i < recipientBundle.OneTimePreKeys.Count; i++)
                            {
                                if (KeyValidation.ValidateX25519PublicKey(recipientBundle.OneTimePreKeys[i]))
                                {
                                    oneTimePreKey = recipientBundle.OneTimePreKeys[i];
                                    oneTimePreKeyIndex = i;

                                    if (recipientBundle.OneTimePreKeyIds != null &&
                                        recipientBundle.OneTimePreKeyIds.Count > i)
                                    {
                                        usedOneTimePreKeyId = recipientBundle.OneTimePreKeyIds[i];
                                    }
                                    break;
                                }
                            }

                            if (oneTimePreKey == null)
                            {
                                LoggingManager.LogWarning(nameof(X3DHExchange),
                                    "No valid one-time pre-keys found, proceeding without one");
                            }
                        }
                    }

                    // Log the key exchange process for diagnostic purposes
                    LoggingManager.LogInformation(nameof(X3DHExchange),
                        $"Initiating X3DH session with{(oneTimePreKey != null ? "" : "out")} one-time pre-key");

                    // Calculate DH results for the X3DH key agreement
                    // Following the Signal Protocol specification

                    // DH1 = DH(IKA, SPKB) - Sender's identity key with Recipient's signed prekey
                    byte[] dh1 = X3DHKeyExchange(recipientBundle.SignedPreKey, senderX25519Private);

                    // DH2 = DH(EKA, IKB) - Sender's ephemeral key with Recipient's identity key
                    byte[] dh2 = X3DHKeyExchange(recipientX25519Public, ephemeralKeyPair.privateKey);

                    // DH3 = DH(EKA, SPKB) - Sender's ephemeral key with Recipient's signed prekey
                    byte[] dh3 = X3DHKeyExchange(recipientBundle.SignedPreKey, ephemeralKeyPair.privateKey);

                    // DH4 = DH(EKA, OPKB) - Sender's ephemeral key with Recipient's one-time prekey (if available)
                    byte[]? dh4 = null;
                    if (oneTimePreKey != null)
                    {
                        dh4 = X3DHKeyExchange(oneTimePreKey, ephemeralKeyPair.privateKey);
                    }

                    // Derive the shared secret using HKDF according to Signal spec
                    byte[] sharedSecret = dh4 != null
                        ? DeriveSharedSecret(dh1, dh2, dh3, dh4)
                        : DeriveSharedSecret(dh1, dh2, dh3);

                    // Initialize Double Ratchet with the master secret from X3DH
                    var (rootKey, chainKey) = DoubleRatchetExchange.InitializeDoubleRatchet(sharedSecret);

                    // Create the session object with all necessary information
                    var session = new X3DHSession(
                        recipientIdentityKey: recipientBundle.IdentityKey,
                        senderIdentityKey: senderIdentityKeyPair.publicKey,
                        ephemeralKey: ephemeralKeyPair.publicKey,
                        usedOneTimePreKey: oneTimePreKey != null,
                        usedOneTimePreKeyId: usedOneTimePreKeyId,
                        usedSignedPreKeyId: recipientBundle.SignedPreKeyId,
                        rootKey: rootKey,
                        chainKey: chainKey,
                        creationTimestamp: DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                    );

                    // Clean up sensitive key material
                    SecureMemory.SecureClear(dh1);
                    SecureMemory.SecureClear(dh2);
                    SecureMemory.SecureClear(dh3);
                    if (dh4 != null) SecureMemory.SecureClear(dh4);
                    SecureMemory.SecureClear(sharedSecret);
                    SecureMemory.SecureClear(ephemeralKeyPair.privateKey);
                    SecureMemory.SecureClear(recipientX25519Public);

                    return session;
                }
                finally
                {
                    // Ensure we always clear sensitive key material
                    if (senderX25519Private != null)
                    {
                        SecureMemory.SecureClear(senderX25519Private);
                    }
                }
            }
            catch (Exception ex)
            {
                // Enhanced error reporting for troubleshooting
                LoggingManager.LogError(nameof(X3DHExchange), $"X3DH session initiation failed: {ex.Message}");
                throw new CryptographicException("Failed to initiate X3DH session", ex);
            }
        }

        /// <summary>
        /// Creates a new X3DHKeyBundle with a rotated signed pre-key while keeping the
        /// same identity key and one-time pre-keys.
        /// </summary>
        /// <param name="existingBundle">The existing bundle to rotate</param>
        /// <returns>A new bundle with a fresh signed pre-key</returns>
        public static X3DHKeyBundle RotateSignedPreKey(X3DHKeyBundle existingBundle)
        {
            ArgumentNullException.ThrowIfNull(existingBundle, nameof(existingBundle));

            // Get the identity private key from the existing bundle
            byte[]? identityPrivateKey = existingBundle.GetIdentityKeyPrivate();
            if (identityPrivateKey == null || existingBundle.IdentityKey == null)
            {
                throw new InvalidOperationException("Cannot rotate signed pre-key: missing identity key");
            }

            try
            {
                // Generate a new signed pre-key pair
                var newSignedPreKeyPair = KeyGenerator.GenerateX25519KeyPair();

                // Sign the new pre-key with the identity key
                byte[] signature = MessageSigning.SignMessage(
                    newSignedPreKeyPair.publicKey,
                    identityPrivateKey);

                // Generate a unique ID for the new signed pre-key
                uint signedPreKeyId = GenerateSecureRandomId();

                // Current timestamp for key creation
                long timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

                // Create a new bundle with the rotated signed pre-key
                var newBundle = new X3DHKeyBundle
                {
                    // Keep the same identity key
                    IdentityKey = existingBundle.IdentityKey,

                    // Use the new signed pre-key
                    SignedPreKey = newSignedPreKeyPair.publicKey,
                    SignedPreKeySignature = signature,
                    SignedPreKeyId = signedPreKeyId,

                    // Keep the existing one-time pre-keys
                    OneTimePreKeys = existingBundle.OneTimePreKeys,
                    OneTimePreKeyIds = existingBundle.OneTimePreKeyIds,

                    // Update metadata
                    ProtocolVersion = PROTOCOL_VERSION,
                    CreationTimestamp = timestamp
                };

                // Set the private keys
                newBundle.SetIdentityKeyPrivate(identityPrivateKey);
                newBundle.SetSignedPreKeyPrivate(newSignedPreKeyPair.privateKey);

                // Log the rotation
                LoggingManager.LogInformation(nameof(X3DHExchange),
                    "Rotated signed pre-key in X3DH key bundle");

                return newBundle;
            }
            finally
            {
                // Always securely clear the identity private key
                if (identityPrivateKey != null)
                {
                    SecureMemory.SecureClear(identityPrivateKey);
                }
            }
        }

        /// <summary>
        /// Replenishes one-time pre-keys in an existing bundle.
        /// </summary>
        /// <param name="existingBundle">The existing bundle to update</param>
        /// <param name="targetCount">The desired number of one-time pre-keys</param>
        /// <returns>A new bundle with replenished one-time pre-keys</returns>
        public static X3DHKeyBundle ReplenishOneTimePreKeys(
            X3DHKeyBundle existingBundle,
            int targetCount = Constants.DEFAULT_ONE_TIME_PREKEY_COUNT)
        {
            ArgumentNullException.ThrowIfNull(existingBundle, nameof(existingBundle));

            // Get the identity private key from the existing bundle
            byte[]? identityPrivateKey = existingBundle.GetIdentityKeyPrivate();
            if (identityPrivateKey == null || existingBundle.IdentityKey == null)
            {
                throw new InvalidOperationException("Cannot replenish pre-keys: missing identity key");
            }

            byte[]? signedPreKeyPrivate = existingBundle.GetSignedPreKeyPrivate();
            if (signedPreKeyPrivate == null || existingBundle.SignedPreKey == null)
            {
                throw new InvalidOperationException("Cannot replenish pre-keys: missing signed pre-key");
            }

            try
            {
                // Create lists for the pre-keys
                var oneTimePreKeys = new List<byte[]>();
                var oneTimePreKeyIds = new List<uint>();

                // Keep existing pre-keys if any
                if (existingBundle.OneTimePreKeys != null)
                {
                    oneTimePreKeys.AddRange(existingBundle.OneTimePreKeys);
                }

                if (existingBundle.OneTimePreKeyIds != null)
                {
                    oneTimePreKeyIds.AddRange(existingBundle.OneTimePreKeyIds);
                }

                // Check how many new keys we need to generate
                int keysToGenerate = Math.Max(0, targetCount - oneTimePreKeys.Count);

                if (keysToGenerate > 0)
                {
                    for (int i = 0; i < keysToGenerate; i++)
                    {
                        try
                        {
                            var oneTimeKeyPair = KeyGenerator.GenerateX25519KeyPair();

                            // Validate the generated key
                            if (KeyValidation.ValidateX25519PublicKey(oneTimeKeyPair.publicKey))
                            {
                                oneTimePreKeys.Add(oneTimeKeyPair.publicKey);

                                // Generate a unique ID for this pre-key
                                uint preKeyId;
                                do
                                {
                                    byte[] randomIdBytes = Sodium.GenerateRandomBytes(4);
                                    preKeyId = BitConverter.ToUInt32(randomIdBytes, 0);
                                    // Ensure the ID is not zero
                                    if (preKeyId == 0) preKeyId = 1;
                                } while (oneTimePreKeyIds.Contains(preKeyId));

                                oneTimePreKeyIds.Add(preKeyId);
                            }
                            else
                            {
                                // Log and retry if key validation fails
                                LoggingManager.LogWarning(nameof(X3DHExchange),
                                    "Generated one-time pre-key failed validation, retrying...");
                                i--; // Retry this iteration
                            }
                        }
                        catch (Exception ex)
                        {
                            // Log error but continue with the keys we have
                            LoggingManager.LogError(nameof(X3DHExchange),
                                $"Error generating one-time pre-key: {ex.Message}");
                            break;
                        }
                    }
                }

                // Create a new bundle with the updated one-time pre-keys
                var newBundle = new X3DHKeyBundle
                {
                    // Keep the same identity key and signed pre-key
                    IdentityKey = existingBundle.IdentityKey,
                    SignedPreKey = existingBundle.SignedPreKey,
                    SignedPreKeySignature = existingBundle.SignedPreKeySignature,
                    SignedPreKeyId = existingBundle.SignedPreKeyId,

                    // Set the updated one-time pre-keys
                    OneTimePreKeys = oneTimePreKeys,
                    OneTimePreKeyIds = oneTimePreKeyIds,

                    // Keep other metadata
                    ProtocolVersion = existingBundle.ProtocolVersion ?? PROTOCOL_VERSION,
                    CreationTimestamp = existingBundle.CreationTimestamp
                };

                // Set the private keys
                newBundle.SetIdentityKeyPrivate(identityPrivateKey);
                newBundle.SetSignedPreKeyPrivate(signedPreKeyPrivate);

                // Log the replenishment
                LoggingManager.LogInformation(nameof(X3DHExchange),
                    $"Replenished one-time pre-keys: {oneTimePreKeys.Count} keys available");

                return newBundle;
            }
            finally
            {
                // Always securely clear private keys
                if (identityPrivateKey != null)
                {
                    SecureMemory.SecureClear(identityPrivateKey);
                }

                if (signedPreKeyPrivate != null)
                {
                    SecureMemory.SecureClear(signedPreKeyPrivate);
                }
            }
        }

        /// <summary>
        /// Checks if a bundle's signed pre-key needs rotation based on age.
        /// </summary>
        /// <param name="bundle">The bundle to check</param>
        /// <returns>True if the signed pre-key should be rotated</returns>
        public static bool ShouldRotateSignedPreKey(X3DHKeyBundle bundle)
        {
            ArgumentNullException.ThrowIfNull(bundle, nameof(bundle));

            // If no timestamp, assume rotation is needed
            if (bundle.CreationTimestamp <= 0)
                return true;

            long currentTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            long ageMs = currentTime - bundle.CreationTimestamp;

            // Rotate if older than recommended period
            return ageMs > SIGNED_PREKEY_ROTATION_MS;
        }

        /// <summary>
        /// Checks if a bundle needs one-time pre-key replenishment.
        /// </summary>
        /// <param name="bundle">The bundle to check</param>
        /// <param name="minimumCount">Minimum number of one-time pre-keys desired</param>
        /// <returns>True if one-time pre-keys should be replenished</returns>
        public static bool ShouldReplenishOneTimePreKeys(X3DHKeyBundle bundle, int minimumCount = 5)
        {
            ArgumentNullException.ThrowIfNull(bundle, nameof(bundle));

            // Check if we have enough one-time pre-keys
            return bundle.OneTimePreKeys == null || bundle.OneTimePreKeys.Count < minimumCount;
        }

        // And add this helper method at the bottom of the class:
        /// <summary>
        /// Generates a cryptographically secure random ID using libsodium
        /// </summary>
        /// <returns>A secure random ID</returns>
        private static uint GenerateSecureRandomId()
        {
            byte[] randomBytes = Sodium.GenerateRandomBytes(4);
            uint id = BitConverter.ToUInt32(randomBytes, 0);

            // Ensure the ID is not zero (which could be used as a special value)
            return id == 0 ? 1 : id;
        }
    }
}