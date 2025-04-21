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
    public sealed class X3DHExchange
    {
        // Recommended rotation period for signed pre-keys (7 days in milliseconds)
        private const long SIGNED_PREKEY_ROTATION_MS = 7 * 24 * 60 * 60 * 1000L;

        // Maximum age for a signed pre-key before it's considered expired (30 days in milliseconds)
        private const long SIGNED_PREKEY_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000L;

        private static readonly byte[] KdfInfo = Encoding.UTF8.GetBytes("WhisperText"); // Or "" or other context per spec version
        private static readonly byte[] KdfSalt = new byte[32]; // 32 zero bytes for salt in HKDF
        private static readonly byte[] KdfFValue = Enumerable.Repeat((byte)0xFF, 32).ToArray(); // 32 0xFF bytes prefix for IKM

        /// <summary>
        /// Creates a new X3DH key bundle, generating necessary public and private keys,
        /// signing the Signed PreKey, and populating the bundle object securely.
        /// </summary>
        /// <param name="identityKeyPair">Optional existing Ed25519 identity key pair. If null, a new one is generated.</param>
        /// <param name="numOneTimeKeys">Number of one-time prekeys to generate.</param>
        /// <returns>A complete X3DHKeyBundle containing public and private keys.</returns>
        /// <exception cref="ArgumentException">Thrown if the provided identity key pair is invalid.</exception>
        /// <exception cref="CryptographicException">Thrown if key generation or signing fails.</exception>
        public static X3DHKeyBundle CreateX3DHKeyBundle(
            KeyPair? identityKeyPair = null,
            int numOneTimeKeys = 5)
        {
            // Ensures bundle contains private keys for IK, SPK, and OPKs
            KeyPair localIdentityKeyPair;
            KeyPair signedPreKeyPair;
            var oneTimePreKeysPublic = new List<byte[]>(numOneTimeKeys);
            var oneTimePreKeyIds = new List<uint>(numOneTimeKeys);
            // Temporary storage for private OPKs before adding securely to bundle
            var oneTimePreKeysPrivateTemp = new Dictionary<uint, byte[]>(numOneTimeKeys);

            ReadOnlySpan<byte> signature = default;
            uint signedPreKeyId = 0;

            // --- 1. Identity Key ---
            try
            {
                localIdentityKeyPair = identityKeyPair ?? Sodium.GenerateEd25519KeyPair();

                // Validate the identity key pair format/size
                if (localIdentityKeyPair.PublicKey == null || localIdentityKeyPair.PrivateKey == null ||
                    localIdentityKeyPair.PublicKey.Length != Constants.ED25519_PUBLIC_KEY_SIZE ||
                    localIdentityKeyPair.PrivateKey.Length != Constants.ED25519_PRIVATE_KEY_SIZE) // Adjust size check if needed
                {
                    throw new ArgumentException("Invalid identity key pair format or size.");
                }
                 LoggingManager.LogDebug(nameof(X3DHExchange), "Identity Key generated/validated.");
            }
            catch (Exception ex) when (!(ex is ArgumentException))
            {
                LoggingManager.LogError(nameof(X3DHExchange), $"Failed Identity Key generation/validation: {ex.Message}");
                throw new CryptographicException("Failed identity key pair gen/validation.", ex);
            }

            try // Wrap remaining crypto operations
            {
                // --- 2. Signed PreKey ---
                signedPreKeyPair = Sodium.GenerateX25519KeyPair();
                if (signedPreKeyPair.PublicKey == null || signedPreKeyPair.PrivateKey == null ||
                    signedPreKeyPair.PublicKey.Length != Constants.X25519_KEY_SIZE || signedPreKeyPair.PrivateKey.Length != Constants.X25519_KEY_SIZE)
                { throw new CryptographicException("Generated signed pre-key pair has invalid size."); }
                // Optional: Validate generated X25519 public key
                if (!Sodium.ValidateX25519PublicKey(signedPreKeyPair.PublicKey))
                { throw new CryptographicException("Generated signed pre-key public key failed validation."); }
                 LoggingManager.LogDebug(nameof(X3DHExchange), "Signed PreKey generated/validated.");

                // --- 3. Sign the Signed PreKey ---
                // Use SignObject or SignMessage depending on your signing abstraction
                signature = MessageSigning.SignObject(signedPreKeyPair.PublicKey, localIdentityKeyPair.PrivateKey);
                if (signature == null || signature.Length != 64) // Ed25519 signature size
                { throw new CryptographicException("Failed to sign SPK or invalid signature size."); }
                 LoggingManager.LogDebug(nameof(X3DHExchange), "Signed PreKey signed.");

                // --- 4. Signed PreKey ID ---
                signedPreKeyId = GenerateSecureRandomId(); // Assumes this returns non-zero
                 LoggingManager.LogDebug(nameof(X3DHExchange), $"Generated Signed PreKey ID: {signedPreKeyId}");

                // --- 5. One-Time PreKeys ---
                 LoggingManager.LogDebug(nameof(X3DHExchange), $"Generating {numOneTimeKeys} One-Time PreKeys...");
                int generatedCount = 0;
                for (int i = 0; i < numOneTimeKeys; i++)
                {
                    try
                    {
                        var opkPair = Sodium.GenerateX25519KeyPair();
                        if (opkPair.PublicKey == null || opkPair.PrivateKey == null ||
                            opkPair.PublicKey.Length != Constants.X25519_KEY_SIZE || opkPair.PrivateKey.Length != Constants.X25519_KEY_SIZE)
                        { LoggingManager.LogWarning(nameof(X3DHExchange), "Generated invalid OPK size, retrying..."); i--; continue; }

                        // Validate the generated key (recommended)
                        if (Sodium.ValidateX25519PublicKey(opkPair.PublicKey))
                        {
                            uint opkId = GenerateSecureRandomId();
                            // Store public key and ID
                            oneTimePreKeysPublic.Add(opkPair.PublicKey);
                            oneTimePreKeyIds.Add(opkId);
                            // Store private key temporarily (critical!)
                            oneTimePreKeysPrivateTemp.Add(opkId, opkPair.PrivateKey);
                            generatedCount++;
                        }
                        else
                        {
                            LoggingManager.LogWarning(nameof(X3DHExchange), "Generated invalid OPK, retrying...");
                            i--; // Retry this iteration
                        }
                    }
                    catch (Exception ex)
                    {
                        LoggingManager.LogError(nameof(X3DHExchange), $"Error generating OPK #{i + 1}: {ex.Message}");
                        if (generatedCount == 0 && i == numOneTimeKeys - 1) {
                            throw new CryptographicException($"Failed all OPK generation attempts. Last error: {ex.Message}", ex);
                        }
                        // Optionally break, or continue trying to generate remaining keys
                        // break; // Stop generating more on error
                        LoggingManager.LogWarning(nameof(X3DHExchange), "Continuing OPK generation after error...");
                    }
                }
                if (generatedCount == 0) { throw new CryptographicException("Failed to generate any valid OPKs."); }
                 LoggingManager.LogDebug(nameof(X3DHExchange), $"Successfully generated {generatedCount} OPKs.");

                // --- 6. Create and Populate the Bundle ---
                 LoggingManager.LogDebug(nameof(X3DHExchange), "Populating X3DHKeyBundle object...");
                var bundle = new X3DHKeyBundle
                {
                    // Public parts
                    IdentityKey = localIdentityKeyPair.PublicKey,
                    SignedPreKey = signedPreKeyPair.PublicKey,
                    SignedPreKeySignature = signature.ToArray(),
                    OneTimePreKeys = oneTimePreKeysPublic,
                    SignedPreKeyId = signedPreKeyId,
                    OneTimePreKeyIds = oneTimePreKeyIds,
                    // Meta
                    ProtocolVersion = $"{ProtocolVersion.MAJOR_VERSION}.{ProtocolVersion.MINOR_VERSION}",
                    CreationTimestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() // Or use bundle constructor's time
                };

                // --- 7. Set Private Keys Securely into Bundle ---
                bundle.SetIdentityKeyPrivate(localIdentityKeyPair.PrivateKey);
                bundle.SetSignedPreKeyPrivate(signedPreKeyPair.PrivateKey);
                // Add all collected private OPKs to the bundle
                foreach (var kvp in oneTimePreKeysPrivateTemp)
                {
                    bundle.SetOneTimePreKeyPrivate(kvp.Key, kvp.Value);
                }
                 LoggingManager.LogDebug(nameof(X3DHExchange), "Private keys set in bundle.");

                LoggingManager.LogInformation(nameof(X3DHExchange), $"Created X3DH key bundle: SPK ID {signedPreKeyId}, {generatedCount} OPKs.");
                return bundle;

            }
            catch (Exception ex) when (!(ex is ArgumentException)) // Catch crypto errors during SPK/OPK/Sign phase
            {
                LoggingManager.LogError(nameof(X3DHExchange), $"Failed during bundle creation (SPK/OPK/Sign phase): {ex.Message}");
                throw new CryptographicException($"Failed bundle creation: {ex.Message}", ex);
            }
            finally
            {
                // --- 8. Securely Clear Temporary Private Keys ---
                // Clear temporary private OPKs (copies are now securely in the bundle)
                 LoggingManager.LogDebug(nameof(X3DHExchange), "Clearing temporary private OPKs...");
                foreach (var kvp in oneTimePreKeysPrivateTemp)
                {
                    SecureMemory.SecureClear(kvp.Value); // Clear original references from temp store
                }
                oneTimePreKeysPrivateTemp.Clear();

                // SPK private key was transferred to bundle via SetSignedPreKeyPrivate (which makes a copy).
                // The 'signedPreKeyPair' variable holding the original reference goes out of scope.
                // If KeyPair is IDisposable, it should be in a using block or disposed here.

                // IK private key was transferred to bundle via SetIdentityKeyPrivate.
                // If localIdentityKeyPair was generated HERE, its original reference goes out of scope.
                // If identityKeyPair was PASSED IN, we MUST NOT clear it here.
            }
        }

        /// <summary>
        /// Validates a public X3DH key bundle for correctness and security properties.
        /// </summary>
        /// <param name="bundle">The public bundle to validate.</param>
        /// <returns>True if the bundle is valid, false otherwise.</returns>
        public static bool ValidateKeyBundle(in X3DHPublicBundle bundle)
        {
            if (bundle == null) return false;

            try
            {
                // Check required fields & sizes
                if (bundle.IdentityKey?.Length != Constants.ED25519_PUBLIC_KEY_SIZE ||
                    bundle.SignedPreKey?.Length != Constants.X25519_KEY_SIZE ||
                    bundle.SignedPreKeySignature?.Length != 64 || // Ed25519 sig size
                    bundle.SignedPreKeyId == 0) // ID must be non-zero
                {
                    LoggingManager.LogWarning(nameof(X3DHExchange), "Bundle missing required fields or invalid sizes/ID.");
                    return false;
                }

                // Validate Key formats (replace with actual validation calls)
                if (!Sodium.ValidateEd25519PublicKey(bundle.IdentityKey))
                {
                    LoggingManager.LogWarning(nameof(X3DHExchange), "Invalid Ed25519 Identity Key format/value.");
                    return false;
                }
                if (!Sodium.ValidateX25519PublicKey(bundle.SignedPreKey))
                {
                    LoggingManager.LogWarning(nameof(X3DHExchange), "Invalid X25519 Signed PreKey format/value.");
                    return false;
                }

                // Validate One-Time PreKeys if present
                if (bundle.OneTimePreKeys != null)
                {
                    if (bundle.OneTimePreKeyIds == null || bundle.OneTimePreKeys.Count != bundle.OneTimePreKeyIds.Count)
                    {
                        LoggingManager.LogWarning(nameof(X3DHExchange), "Mismatched OneTimePreKeys and IDs count.");
                        return false;
                    }
                    for (int i = 0; i < bundle.OneTimePreKeys.Count; ++i)
                    {
                        if (bundle.OneTimePreKeys[i]?.Length != Constants.X25519_KEY_SIZE ||
                            !Sodium.ValidateX25519PublicKey(bundle.OneTimePreKeys[i]) ||
                             bundle.OneTimePreKeyIds[i] == 0) // ID must be non-zero
                        {
                            LoggingManager.LogWarning(nameof(X3DHExchange), $"Invalid OneTimePreKey at index {i}.");
                            return false;
                        }
                    }
                }

                // Verify the signature on the signed prekey
                if (!MessageSigning.VerifySignature(bundle.SignedPreKey, bundle.SignedPreKeySignature, bundle.IdentityKey))
                {
                    LoggingManager.LogWarning(nameof(X3DHExchange), "Bundle signature verification failed.");
                    return false;
                }

                // Check pre-key age
                if (bundle.CreationTimestamp > 0)
                {
                    long ageMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - bundle.CreationTimestamp;
                    if (ageMs < 0) // Timestamp from the future?
                    {
                        LoggingManager.LogWarning(nameof(X3DHExchange), "Bundle timestamp appears to be from the future.");
                        return false; // Or handle clock skew differently
                    }
                    if (ageMs > SIGNED_PREKEY_MAX_AGE_MS)
                    {
                        LoggingManager.LogWarning(nameof(X3DHExchange), $"Bundle signed pre-key is too old ({ageMs / (24 * 60 * 60 * 1000)} days).");
                        return false;
                    }
                    if (ageMs > SIGNED_PREKEY_ROTATION_MS)
                    {
                        LoggingManager.LogWarning(nameof(X3DHExchange), "Bundle signed pre-key is due for rotation.");
                        // Note: Still valid, just a warning for the user.
                    }
                }

                return true; // All checks passed
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
                return Sodium.HkdfDerive(
                    combinedInput,
                    info: Encoding.UTF8.GetBytes($"{ProtocolVersion.PROTOCOL_ID}-v{ProtocolVersion.MAJOR_VERSION}.{ProtocolVersion.MINOR_VERSION}"),
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
            in X3DHPublicBundle recipientBundle,
            in KeyPair senderIdentityKeyPair,
            out uint? usedOneTimePreKeyId)
        {
            // Initialize output parameter
            usedOneTimePreKeyId = null;

            ArgumentNullException.ThrowIfNull(recipientBundle, nameof(recipientBundle));

            if (!ValidateKeyBundle(recipientBundle))
                throw new ArgumentException("Invalid or incomplete recipient bundle", nameof(recipientBundle));

            if (recipientBundle.IdentityKey == null || recipientBundle.SignedPreKey == null)
                throw new ArgumentException("Missing required keys in recipient bundle", nameof(recipientBundle));

            if (senderIdentityKeyPair.PublicKey == null || senderIdentityKeyPair.PrivateKey == null)
                throw new ArgumentException("Invalid sender identity key pair", nameof(senderIdentityKeyPair));

            try
            {
                // Prepare sender's identity key in X25519 format for key exchange
                byte[]? senderX25519Private = null;
                try
                {
                    // Convert Ed25519 identity key to X25519 format if needed
                    if (senderIdentityKeyPair.PrivateKey.Length == Constants.ED25519_PRIVATE_KEY_SIZE)
                    {
                        senderX25519Private = Sodium.ConvertEd25519PrivateKeyToX25519(
                            senderIdentityKeyPair.PrivateKey);
                    }
                    else if (senderIdentityKeyPair.PrivateKey.Length == Constants.X25519_KEY_SIZE)
                    {
                        // Create a copy to avoid modifying the original
                        senderX25519Private = SecureMemory.SecureCopy(senderIdentityKeyPair.PrivateKey);
                    }
                    else
                    {
                        throw new ArgumentException(
                            $"Invalid sender private key length: {senderIdentityKeyPair.PrivateKey.Length}",
                            nameof(senderIdentityKeyPair));
                    }

                    // Convert recipient's Ed25519 identity key to X25519 format
                    byte[] recipientX25519Public;
                    if (recipientBundle.IdentityKey.Length == Constants.ED25519_PUBLIC_KEY_SIZE)
                    {
                        recipientX25519Public = Sodium.ConvertEd25519PublicKeyToX25519(
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
                    if (!Sodium.ValidateX25519PublicKey(recipientBundle.SignedPreKey))
                    {
                        throw new ArgumentException("Invalid recipient signed pre-key",
                            nameof(recipientBundle));
                    }

                    // Generate ephemeral key pair for this session
                    var ephemeralKeyPair = Sodium.GenerateX25519KeyPair();

                    // Select a one-time pre-key if available
                    byte[]? oneTimePreKey = null;
                    int oneTimePreKeyIndex = -1;

                    if (recipientBundle.OneTimePreKeys != null && recipientBundle.OneTimePreKeys.Count > 0)
                    {
                        // Select a random pre-key with secure random generation
                        byte[] randomBytes = SecureMemory.CreateSecureBuffer(4);
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
                        if (!Sodium.ValidateX25519PublicKey(oneTimePreKey))
                        {
                            // Try to find a valid key instead
                            oneTimePreKey = null;
                            usedOneTimePreKeyId = null;

                            for (int i = 0; i < recipientBundle.OneTimePreKeys.Count; i++)
                            {
                                if (Sodium.ValidateX25519PublicKey(recipientBundle.OneTimePreKeys[i]))
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
                    byte[] dh1 = PerformX25519DH(recipientBundle.SignedPreKey, senderX25519Private);

                    // DH2 = DH(EKA, IKB) - Sender's ephemeral key with Recipient's identity key
                    byte[] dh2 = PerformX25519DH(recipientX25519Public, ephemeralKeyPair.PrivateKey);

                    // DH3 = DH(EKA, SPKB) - Sender's ephemeral key with Recipient's signed prekey
                    byte[] dh3 = PerformX25519DH(recipientBundle.SignedPreKey, ephemeralKeyPair.PrivateKey);

                    // DH4 = DH(EKA, OPKB) - Sender's ephemeral key with Recipient's one-time prekey (if available)
                    byte[]? dh4 = null;
                    if (oneTimePreKey != null)
                    {
                        dh4 = PerformX25519DH(oneTimePreKey, ephemeralKeyPair.PrivateKey);
                    }

                    // Derive the shared secret using HKDF according to Signal spec
                    byte[] sharedSecret = dh4 != null
                        ? DeriveSharedSecret(dh1, dh2, dh3, dh4)
                        : DeriveSharedSecret(dh1, dh2, dh3);

                    // Initialize Double Ratchet with the master secret from X3DH
                    var (rootKey, chainKey) = DoubleRatchet.DeriveDoubleRatchet(sharedSecret);

                    // Create the session object with all necessary information
                    var session = new X3DHSession(
                        recipientIdentityKey: recipientBundle.IdentityKey,
                        senderIdentityKey: senderIdentityKeyPair.PublicKey,
                        ephemeralKey: ephemeralKeyPair.PublicKey,
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
                    SecureMemory.SecureClear(ephemeralKeyPair.PrivateKey);
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
        /// Initiates an X3DH session AS THE SENDER (Alice).
        /// Calculates the shared secret and prepares the initial message data for the receiver.
        /// </summary>
        /// <param name="recipientBundle">The recipient's public key bundle (fetched from server).</param>
        /// <param name="senderIdentityKeyPair">The sender's long-term identity key pair (Ed25519).</param>
        /// <returns>A SenderSessionResult containing the derived shared key (SK) and the initial message data.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentException">If bundle or keys are invalid.</exception>
        /// <exception cref="CryptographicException">If cryptographic operations fail.</exception>
        public static SenderSessionResult InitiateSessionAsSender(
            X3DHPublicBundle recipientBundle,
            KeyPair senderIdentityKeyPair)
        {
            ArgumentNullException.ThrowIfNull(recipientBundle, nameof(recipientBundle));
            ArgumentNullException.ThrowIfNull(senderIdentityKeyPair, nameof(senderIdentityKeyPair));
            // Assuming KeyPair is a struct or class where properties can be null
            if (senderIdentityKeyPair.PublicKey == null) throw new ArgumentNullException(nameof(senderIdentityKeyPair.PublicKey));
            if (senderIdentityKeyPair.PrivateKey == null) throw new ArgumentNullException(nameof(senderIdentityKeyPair.PrivateKey));

            // Validate recipient bundle thoroughly (ensure your implementation is robust)
            if (!ValidateKeyBundle(recipientBundle))
                throw new ArgumentException("Invalid or incomplete recipient bundle.", nameof(recipientBundle));
            // We know required keys exist from validation, but check again for safety
            if (recipientBundle.IdentityKey == null || recipientBundle.SignedPreKey == null)
                throw new ArgumentException("Validated bundle unexpectedly missing required keys.", nameof(recipientBundle));

            byte[]? senderIK_X25519_Private = null;
            byte[]? ephemeralPrivateKey = null; // Store separately for clarity and clearing
            byte[]? ephemeralPublicKey = null;
            byte[]? recipientIK_X25519_Public = null;
            byte[]? dh1 = null, dh2 = null, dh3 = null, dh4 = null;
            byte[]? sk = null; // The final shared key output of X3DH KDF

            uint? usedOneTimePreKeyId = null;
            byte[]? selectedOneTimePreKey = null; // Public key

            try
            {
                // 1. Convert Keys
                senderIK_X25519_Private = Sodium.ConvertEd25519PrivateKeyToX25519(senderIdentityKeyPair.PrivateKey);
                recipientIK_X25519_Public = Sodium.ConvertEd25519PublicKeyToX25519(recipientBundle.IdentityKey);

                // 2. Generate Ephemeral Key Pair (EK)
                KeyPair ephemeralKeyPairGen = Sodium.GenerateX25519KeyPair(); // Generate into temp var

                // Validate the generated pair immediately and robustly
                if (ephemeralKeyPairGen.PrivateKey == null || ephemeralKeyPairGen.PublicKey == null ||
                    ephemeralKeyPairGen.PrivateKey.Length != Constants.X25519_KEY_SIZE ||
                    ephemeralKeyPairGen.PublicKey.Length != Constants.X25519_KEY_SIZE)
                {
                    // Securely clear potentially partial keys before throwing
                    if (ephemeralKeyPairGen.PrivateKey != null)
                        SecureMemory.SecureClear(ephemeralKeyPairGen.PrivateKey);
                    throw new CryptographicException("Failed to generate a valid ephemeral key pair (null or invalid size).");
                }
                // Assign to local variables AFTER validation
                ephemeralPrivateKey = ephemeralKeyPairGen.PrivateKey;
                ephemeralPublicKey = ephemeralKeyPairGen.PublicKey;
                // ephemeralKeyPairGen struct/object goes out of scope, keys are in local vars


                // 3. Select Recipient's One-Time PreKey (OPK) if available
                if (recipientBundle.OneTimePreKeys != null && recipientBundle.OneTimePreKeys.Count > 0)
                {
                    // Using previously discussed robust random selection + validation logic
                    int count = recipientBundle.OneTimePreKeys.Count;
                    int startIndex = RandomNumberGenerator.GetInt32(0, count); // Use crypto random index
                    for (int i = 0; i < count; ++i)
                    {
                        int currentIndex = (startIndex + i) % count;
                        byte[]? candidateKey = recipientBundle.OneTimePreKeys[currentIndex];
                        // Ensure ID list exists and matches count before accessing
                        if (candidateKey != null &&
                           Sodium.ValidateX25519PublicKey(candidateKey) &&
                           recipientBundle.OneTimePreKeyIds != null &&
                           recipientBundle.OneTimePreKeyIds.Count == count)
                        {
                            selectedOneTimePreKey = candidateKey;
                            usedOneTimePreKeyId = recipientBundle.OneTimePreKeyIds[currentIndex];
                            LoggingManager.LogDebug(nameof(X3DHExchange), $"Selected valid OPK with ID {usedOneTimePreKeyId}.");
                            break; // Found a valid key
                        }
                    }
                    if (selectedOneTimePreKey == null)
                    {
                        LoggingManager.LogWarning(nameof(X3DHExchange), "No valid one-time pre-key found in recipient bundle, proceeding without OPK.");
                    }
                }

                // 4. Perform Diffie-Hellman Calculations
                // Pass non-nullable keys now after checks
                dh1 = PerformX25519DH(senderIK_X25519_Private, recipientBundle.SignedPreKey);
                dh2 = PerformX25519DH(ephemeralPrivateKey, recipientIK_X25519_Public);
                dh3 = PerformX25519DH(ephemeralPrivateKey, recipientBundle.SignedPreKey);
                if (selectedOneTimePreKey != null)
                {
                    dh4 = PerformX25519DH(ephemeralPrivateKey, selectedOneTimePreKey);
                }

                // 5. Derive Shared Key (SK) using X3DH KDF
                sk = DeriveX3DHSharedKey(dh1, dh2, dh3, dh4); // Assumes this helper exists and works

                // 6. Prepare Result
                var messageData = new InitialMessageData(
                    senderIdentityKeyPair.PublicKey, // Alice's public Ed25519 IK
                    ephemeralPublicKey,              // Alice's public X25519 EK
                    recipientBundle.SignedPreKeyId,
                    usedOneTimePreKeyId
                );

                var result = new SenderSessionResult
                {
                    SharedKey = sk, // Transfer ownership of sk to result
                    MessageDataToSend = messageData
                };

                sk = null; // Null out local reference so finally block doesn't clear the returned key

                return result;
            }
            catch (Exception ex) // Catch specific exceptions if needed
            {
                LoggingManager.LogError(nameof(X3DHExchange), $"X3DH Sender initiation failed: {ex.Message} {ex.StackTrace}");
                // Re-throw as specific type if desired
                if (ex is CryptographicException || ex is KeyNotFoundException || ex is ArgumentException || ex is InvalidOperationException) throw;
                throw new CryptographicException("Failed to initiate X3DH session as sender.", ex);
            }
            finally
            {
                // Securely clear all intermediate secrets and private keys
                if (senderIK_X25519_Private != null)
                    SecureMemory.SecureClear(senderIK_X25519_Private);
                if (ephemeralPrivateKey != null)
                    SecureMemory.SecureClear(ephemeralPrivateKey); // Clear the separated private key
                if (dh1 != null)
                    SecureMemory.SecureClear(dh1);
                if (dh2 != null)
                    SecureMemory.SecureClear(dh2);
                if (dh3 != null)
                    SecureMemory.SecureClear(dh3);
                if (dh4 != null)
                    SecureMemory.SecureClear(dh4); // SecureClear handles null check internally
                if (sk != null)
                    SecureMemory.SecureClear(sk); // Clear sk if it wasn't nulled out on success path (defense in depth)
                // Public keys (ephemeralPublicKey, recipientIK_X25519_Public, selectedOneTimePreKey) generally don't need clearing.
            }
        }

        /// <summary>
        /// Establishes an X3DH session AS THE RECEIVER (Bob).
        /// Uses the initial message from the sender and the receiver's own key bundle to derive the shared secret.
        /// </summary>
        /// <param name="initialMessage">The initial message data received from the sender.</param>
        /// <param name="receiverBundle">The receiver's complete key bundle (including private keys).</param>
        /// <returns>The derived 32-byte shared secret (SK).</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentException">If initial message or bundle is invalid/incomplete.</exception>
        /// <exception cref="KeyNotFoundException">If required pre-keys are not found in the bundle.</exception>
        /// <exception cref="CryptographicException">If cryptographic operations fail.</exception>
        public static byte[] EstablishSessionAsReceiver(
            InitialMessageData initialMessage,
            X3DHKeyBundle receiverBundle)
        {
            ArgumentNullException.ThrowIfNull(initialMessage, nameof(initialMessage));
            ArgumentNullException.ThrowIfNull(receiverBundle, nameof(receiverBundle));
            if (!initialMessage.IsValid()) throw new ArgumentException("Invalid initial message data.", nameof(initialMessage));

            // Local variables for keys and DH results
            byte[]? receiverIK_Ed_Private = null;
            byte[]? receiverIK_X25519_Private = null;
            byte[]? receiverSPK_X25519_Private = null;
            byte[]? receiverOPK_X25519_Private = null;
            byte[]? senderIK_X25519_Public = null;
            byte[]? dh1 = null, dh2 = null, dh3 = null, dh4 = null;
            byte[]? sk = null;

            try
            {
                // 1. Load Receiver's Private Keys (get copies where needed) & Verify SPK ID
                receiverIK_Ed_Private = receiverBundle.GetIdentityKeyPrivate();
                if (receiverIK_Ed_Private == null) throw new InvalidOperationException("Receiver bundle missing identity private key.");

                // Check SPK ID match BEFORE getting private key
                if (receiverBundle.SignedPreKeyId != initialMessage.RecipientSignedPreKeyId)
                    throw new KeyNotFoundException($"Received initial message using Signed PreKey ID {initialMessage.RecipientSignedPreKeyId}, but the receiver's current bundle has ID {receiverBundle.SignedPreKeyId}.");

                receiverSPK_X25519_Private = receiverBundle.GetSignedPreKeyPrivate(); // Get copy
                if (receiverSPK_X25519_Private == null) throw new InvalidOperationException($"Receiver's Signed PreKey private part missing for matching ID {initialMessage.RecipientSignedPreKeyId}.");

                // Get OPK private key if needed
                if (initialMessage.RecipientOneTimePreKeyId.HasValue)
                {
                    uint opkId = initialMessage.RecipientOneTimePreKeyId.Value;
                    receiverOPK_X25519_Private = receiverBundle.GetOneTimePreKeyPrivate(opkId); // Get copy
                    if (receiverOPK_X25519_Private == null) throw new KeyNotFoundException($"Receiver's one-time pre-key private part for ID {opkId} not found.");
                    // Optional: Remove OPK from bundle now
                    // receiverBundle.RemoveOneTimePreKey(opkId);
                }

                // 2. Convert Keys
                receiverIK_X25519_Private = Sodium.ConvertEd25519PrivateKeyToX25519(receiverIK_Ed_Private);
                senderIK_X25519_Public = Sodium.ConvertEd25519PublicKeyToX25519(initialMessage.SenderIdentityKeyPublic);

                // Validate sender public keys from message
                if (!Sodium.ValidateX25519PublicKey(senderIK_X25519_Public) || !Sodium.ValidateX25519PublicKey(initialMessage.SenderEphemeralKeyPublic))
                    throw new ArgumentException("Invalid public key format received from sender.", nameof(initialMessage));

                // 3. Perform DH Calculations
                //    DH(Our Private Key, Their Public Key)
                dh1 = PerformX25519DH(receiverSPK_X25519_Private, senderIK_X25519_Public);         // DH(SPKB_priv, IKA_pub)
                dh2 = PerformX25519DH(receiverIK_X25519_Private, initialMessage.SenderEphemeralKeyPublic); // DH(IKB_priv, EKA_pub)
                dh3 = PerformX25519DH(receiverSPK_X25519_Private, initialMessage.SenderEphemeralKeyPublic); // DH(SPKB_priv, EKA_pub)
                if (receiverOPK_X25519_Private != null)
                {
                    dh4 = PerformX25519DH(receiverOPK_X25519_Private, initialMessage.SenderEphemeralKeyPublic); // DH(OPKB_priv, EKA_pub)
                }

                // 4. Derive Shared Key (SK)
                sk = DeriveX3DHSharedKey(dh1, dh2, dh3, dh4);

                return sk; // Return the derived shared secret
            }
            // catch blocks...
            finally
            {
                // Securely clear all intermediate secrets and key copies
                if (receiverIK_Ed_Private != null)
                    SecureMemory.SecureClear(receiverIK_Ed_Private);
                if (receiverIK_X25519_Private != null)
                    SecureMemory.SecureClear(receiverIK_X25519_Private);
                if (receiverSPK_X25519_Private != null)
                    SecureMemory.SecureClear(receiverSPK_X25519_Private); // Clear the copy
                if (receiverOPK_X25519_Private != null)
                    SecureMemory.SecureClear(receiverOPK_X25519_Private); // Clear the copy
                if (dh1 != null)
                    SecureMemory.SecureClear(dh1);
                if (dh2 != null)
                    SecureMemory.SecureClear(dh2);
                if (dh3 != null)
                    SecureMemory.SecureClear(dh3);
                if (dh4 != null)
                    SecureMemory.SecureClear(dh4);
                // Do NOT clear 'sk' if it's the successful return value
            }
        }

        /// <summary>
        /// Updates the Signed PreKey in an existing bundle, keeping the same Identity Key.
        /// The old Signed PreKey (public and private) is securely overwritten/cleared.
        /// </summary>
        /// <param name="existingBundle">The bundle to update.</param>
        /// <returns>The same bundle instance, now modified with a new Signed PreKey.</returns>
        /// <exception cref="ArgumentNullException">If existingBundle is null.</exception>
        /// <exception cref="InvalidOperationException">If the bundle is missing the identity key.</exception>
        /// <exception cref="CryptographicException">If key generation or signing fails.</exception>
        public static X3DHKeyBundle RotateSignedPreKey(X3DHKeyBundle existingBundle)
        {
            ArgumentNullException.ThrowIfNull(existingBundle, nameof(existingBundle));

            ReadOnlySpan<byte> identityPrivateKey = default;
            KeyPair newSignedPreKeyPair;
            ReadOnlySpan<byte> signature;

            try
            {
                identityPrivateKey = existingBundle.GetIdentityKeyPrivate(); // Get a copy
                if (identityPrivateKey == null || existingBundle.IdentityKey == null)
                {
                    throw new InvalidOperationException("Cannot rotate signed pre-key: missing identity key in bundle.");
                }

                // Generate new SPK pair
                newSignedPreKeyPair = Sodium.GenerateX25519KeyPair();
                if (newSignedPreKeyPair.PublicKey == null || newSignedPreKeyPair.PrivateKey == null ||
                    !Sodium.ValidateX25519PublicKey(newSignedPreKeyPair.PublicKey)) // Validate new key
                {
                    throw new CryptographicException("Failed to generate a valid new signed pre-key pair.");
                }

                // Sign the new public SPK
                signature = MessageSigning.SignObject(newSignedPreKeyPair.PublicKey, identityPrivateKey);
                if (signature == null || signature.Length != 64)
                {
                    throw new CryptographicException("Failed to sign the new signed pre-key.");
                }

                // Generate a new ID
                uint newSignedPreKeyId = GenerateSecureRandomId();

                // Update the existing bundle IN PLACE
                existingBundle.SignedPreKey = newSignedPreKeyPair.PublicKey; // Set new public key
                existingBundle.SignedPreKeySignature = signature.ToArray(); // Set new signature
                existingBundle.SignedPreKeyId = newSignedPreKeyId; // Set new ID
                existingBundle.SetSignedPreKeyPrivate(newSignedPreKeyPair.PrivateKey); // Securely set new private key (clears old one)
                existingBundle.CreationTimestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(); // Update timestamp

                LoggingManager.LogInformation(nameof(X3DHExchange), $"Rotated Signed PreKey for bundle. New SPK ID: {newSignedPreKeyId}");

                return existingBundle; // Return the modified bundle
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(X3DHExchange), $"Failed to rotate signed pre-key: {ex.Message}");
                // Re-throw as specific crypto exception if appropriate
                if (ex is CryptographicException || ex is InvalidOperationException || ex is ArgumentNullException) throw;
                throw new CryptographicException($"Failed to rotate signed pre-key: {ex.Message}", ex);
            }
            finally
            {
                // Clear the intermediate new SPK private key *only if* it wasn't successfully stored
                // Note: SetSignedPreKeyPrivate stores a copy, so the original newSignedPreKeyPair.PrivateKey
                // should ideally be cleared *after* the Set call succeeds or if it fails.
                // However, SetSignedPreKeyPrivate internally clears the *old* key.
                // We rely on the bundle's Dispose/ClearPrivateKeys to handle the stored keys.
                // Clearing newSignedPreKeyPair?.PrivateKey here might be redundant if Set worked.
                // If Set failed, the key is lost anyway unless caught and stored elsewhere.
            }
        }

        /// <summary>
        /// Performs a single X25519 Diffie-Hellman calculation.
        /// </summary>
        /// <param name="privateKey">Our 32-byte X25519 private key.</param>
        /// <param name="publicKey">Their 32-byte X25519 public key.</param>
        /// <returns>The 32-byte shared secret result.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentException">If keys are invalid size.</exception>
        /// <exception cref="CryptographicException">If DH calculation fails.</exception>
        public static byte[] PerformX25519DH(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey)
        {
            if (privateKey.IsEmpty)
                throw new ArgumentException("Private key cannot be empty", nameof(privateKey));
            if (publicKey.IsEmpty)
                throw new ArgumentException("Public key cannot be empty", nameof(publicKey));

            if (privateKey.Length != Constants.X25519_KEY_SIZE || publicKey.Length != Constants.X25519_KEY_SIZE)
                throw new ArgumentException($"Both keys must be {Constants.X25519_KEY_SIZE} bytes for X25519 DH.");

            // Validate the public key (optional security check)
            if (!Sodium.ValidateX25519PublicKey(publicKey.ToArray()))
                throw new ArgumentException("Invalid peer public key provided for DH.", nameof(publicKey));

            // Create result array
            byte[] sharedOutput = SecureMemory.CreateSecureBuffer(Constants.X25519_KEY_SIZE);
            // Create a secure copy of the private key to avoid modification
            byte[] privateKeyCopy = SecureMemory.SecureCopy(privateKey.ToArray());

            try
            {
                // Perform the DH calculation
                Sodium.ComputeSharedSecret(sharedOutput, privateKeyCopy, publicKey.ToArray());

                // Ensure we got a valid result
                if (sharedOutput.Length != Constants.X25519_KEY_SIZE)
                    throw new CryptographicException("X25519 scalar multiplication returned invalid result size.");

                return sharedOutput;
            }
            catch (Exception ex)
            {
                // Clean up on failure
                SecureMemory.SecureClear(sharedOutput);
                throw new CryptographicException("X25519 scalar multiplication failed.", ex);
            }
            finally
            {
                // Always clear the private key copy
                SecureMemory.SecureClear(privateKeyCopy);
            }
        }

        /// <summary>
        /// Derives the final X3DH Shared Key (SK) using HKDF according to Signal spec.
        /// </summary>
        /// <param name="dh1">DH result (IKA_priv, SPKB_pub) or (SPKB_priv, IKA_pub)</param>
        /// <param name="dh2">DH result (EKA_priv, IKB_pub) or (IKB_priv, EKA_pub)</param>
        /// <param name="dh3">DH result (EKA_priv, SPKB_pub) or (SPKB_priv, EKA_pub)</param>
        /// <param name="dh4">DH result (EKA_priv, OPKB_pub) or (OPKB_priv, EKA_pub), or null if no OPK used.</param>
        /// <returns>The 32-byte derived shared key (SK).</returns>
        /// <exception cref="CryptographicException"></exception>
        private static byte[] DeriveX3DHSharedKey(byte[] dh1, byte[] dh2, byte[] dh3, byte[]? dh4)
        {
            // Construct IKM = F || DH1 || DH2 || DH3 || DH4 (F=32 0xFF bytes, DH4 optional)
            int ikmLength = KdfFValue.Length + dh1.Length + dh2.Length + dh3.Length + (dh4?.Length ?? 0);
            byte[] ikm = new byte[ikmLength];
            byte[]? derivedKey = null;
            try
            {
                int offset = 0;
                Buffer.BlockCopy(KdfFValue, 0, ikm, offset, KdfFValue.Length); offset += KdfFValue.Length;
                Buffer.BlockCopy(dh1, 0, ikm, offset, dh1.Length); offset += dh1.Length;
                Buffer.BlockCopy(dh2, 0, ikm, offset, dh2.Length); offset += dh2.Length;
                Buffer.BlockCopy(dh3, 0, ikm, offset, dh3.Length); offset += dh3.Length;
                if (dh4 != null)
                {
                    Buffer.BlockCopy(dh4, 0, ikm, offset, dh4.Length); // offset += dh4.Length; // No need to update offset after last copy
                }

                // Perform HKDF-SHA256 (or SHA512 depending on library/spec version)
                // Output length = 32 bytes for SK
                derivedKey = KeyConversion.HkdfDerive(
                    inputKeyMaterial: ikm,
                    salt: KdfSalt, // 32 zero bytes
                    info: KdfInfo, // Typically "WhisperText" or "" for SK
                    outputLength: 32); // 32 bytes for SK

                if (derivedKey == null || derivedKey.Length != 32)
                {
                    throw new CryptographicException("HKDF derivation for SK failed or produced incorrect length.");
                }
                return derivedKey;
            }
            catch (Exception ex)
            {
                if (derivedKey != null) 
                    SecureMemory.SecureClear(derivedKey); // Clear potentially partial output
                throw new CryptographicException("Failed to derive X3DH shared key using HKDF.", ex);
            }
            finally
            {
                SecureMemory.SecureClear(ikm); // Clear the combined Input Keying Material
            }
        }

        /// <summary>
        /// Generates a secure, random, non-zero uint identifier.
        /// </summary>
        /// <returns>A random uint ID (1 to uint.MaxValue).</returns>
        private static uint GenerateSecureRandomId()
        {
            uint id;
            do
            {
                id = BitConverter.ToUInt32(RandomNumberGenerator.GetBytes(4), 0);
            } while (id == 0); // Ensure non-zero
            return id;
        }
    }
}