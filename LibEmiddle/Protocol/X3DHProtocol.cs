using System.Security.Cryptography;
using System.Text;
using LibEmiddle.Abstractions;
using LibEmiddle.Core;
using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;

namespace LibEmiddle.Protocol
{
    /// <summary>
    /// Provides an implementation of the Signal X3DH (Extended Triple Diffie-Hellman) protocol
    /// to establish secure session keys between parties.
    /// </summary>
    public class X3DHProtocol : IX3DHProtocol
    {
        private readonly ICryptoProvider _cryptoProvider;

        public X3DHProtocol(ICryptoProvider cryptoProvider)
        {
            _cryptoProvider = cryptoProvider ?? throw new ArgumentNullException(nameof(cryptoProvider));
        }

        /// <summary>
        /// Creates a new X3DH key bundle, generating necessary public and private keys,
        /// signing the Signed PreKey, and populating the bundle object securely.
        /// </summary>
        /// <param name="identityKeyPair">Optional existing Ed25519 identity key pair. If null, a new one is generated.</param>
        /// <param name="numOneTimeKeys">Number of one-time prekeys to generate.</param>
        /// <returns>A complete X3DHKeyBundle containing public and private keys.</returns>
        public async Task<X3DHKeyBundle> CreateKeyBundleAsync(KeyPair? identityKeyPair = null, int numOneTimeKeys = 5)
        {
            // Ensures bundle contains private keys for IK, SPK, and OPKs
            KeyPair localIdentityKeyPair;
            KeyPair signedPreKeyPair;
            var oneTimePreKeysPublic = new List<byte[]>(numOneTimeKeys);
            var oneTimePreKeyIds = new List<uint>(numOneTimeKeys);
            var oneTimePreKeysPrivateTemp = new Dictionary<uint, byte[]>(numOneTimeKeys);

            byte[]? signature = null;
            uint signedPreKeyId = 0;

            try
            {
                // --- 1. Identity Key ---
                localIdentityKeyPair = identityKeyPair ?? await _cryptoProvider.GenerateKeyPairAsync(KeyType.Ed25519);

                // Validate the identity key pair
                if (localIdentityKeyPair.PublicKey == null || localIdentityKeyPair.PrivateKey == null ||
                    localIdentityKeyPair.PublicKey.Length != Constants.ED25519_PUBLIC_KEY_SIZE ||
                    localIdentityKeyPair.PrivateKey.Length != Constants.ED25519_PRIVATE_KEY_SIZE)
                {
                    throw new ArgumentException("Invalid identity key pair format or size.");
                }

                // --- 2. Signed PreKey ---
                signedPreKeyPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.X25519);
                if (signedPreKeyPair.PublicKey == null || signedPreKeyPair.PrivateKey == null ||
                    signedPreKeyPair.PublicKey.Length != Constants.X25519_KEY_SIZE ||
                    signedPreKeyPair.PrivateKey.Length != Constants.X25519_KEY_SIZE)
                {
                    throw new CryptographicException("Generated signed pre-key pair has invalid size.");
                }

                // --- 3. Sign the Signed PreKey ---
                signature = await _cryptoProvider.SignAsync(signedPreKeyPair.PublicKey, localIdentityKeyPair.PrivateKey);
                if (signature == null || signature.Length != 64) // Ed25519 signature size
                {
                    throw new CryptographicException("Failed to sign SPK or invalid signature size.");
                }

                // --- 4. Signed PreKey ID ---
                signedPreKeyId = GenerateSecureRandomId(); // Generate non-zero ID

                // --- 5. One-Time PreKeys ---
                LoggingManager.LogDebug(nameof(X3DHProtocol), $"Generating {numOneTimeKeys} One-Time PreKeys...");
                int generatedCount = 0;
                for (int i = 0; i < numOneTimeKeys; i++)
                {
                    try
                    {
                        var opkPair = await _cryptoProvider.GenerateKeyPairAsync(KeyType.X25519);
                        if (opkPair.PublicKey == null || opkPair.PrivateKey == null ||
                            opkPair.PublicKey.Length != Constants.X25519_KEY_SIZE ||
                            opkPair.PrivateKey.Length != Constants.X25519_KEY_SIZE)
                        {
                            LoggingManager.LogWarning(nameof(X3DHProtocol), "Generated invalid OPK size, retrying...");
                            i--;
                            continue;
                        }

                        uint opkId = GenerateSecureRandomId();
                        // Store public key and ID
                        oneTimePreKeysPublic.Add(opkPair.PublicKey);
                        oneTimePreKeyIds.Add(opkId);
                        // Store private key temporarily
                        oneTimePreKeysPrivateTemp.Add(opkId, opkPair.PrivateKey);
                        generatedCount++;
                    }
                    catch (Exception ex)
                    {
                        LoggingManager.LogError(nameof(X3DHProtocol), $"Error generating OPK #{i + 1}: {ex.Message}");
                        if (generatedCount == 0 && i == numOneTimeKeys - 1)
                        {
                            throw new CryptographicException($"Failed all OPK generation attempts. Last error: {ex.Message}", ex);
                        }
                    }
                }

                if (generatedCount == 0)
                {
                    throw new CryptographicException("Failed to generate any valid OPKs.");
                }

                // --- 6. Create and Populate the Bundle ---
                var bundle = new X3DHKeyBundle
                {
                    // Public parts
                    IdentityKey = localIdentityKeyPair.PublicKey,
                    SignedPreKey = signedPreKeyPair.PublicKey,
                    SignedPreKeySignature = signature,
                    OneTimePreKeys = oneTimePreKeysPublic,
                    SignedPreKeyId = signedPreKeyId,
                    OneTimePreKeyIds = oneTimePreKeyIds,
                    // Meta
                    ProtocolVersion = $"{ProtocolVersion.MAJOR_VERSION}.{ProtocolVersion.MINOR_VERSION}",
                    CreationTimestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                };

                // --- 7. Set Private Keys Securely into Bundle ---
                bundle.SetIdentityKeyPrivate(localIdentityKeyPair.PrivateKey);
                bundle.SetSignedPreKeyPrivate(signedPreKeyPair.PrivateKey);
                // Add all private OPKs to the bundle
                foreach (var kvp in oneTimePreKeysPrivateTemp)
                {
                    bundle.SetOneTimePreKeyPrivate(kvp.Key, kvp.Value);
                }

                return bundle;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(X3DHProtocol), $"Failed during bundle creation: {ex.Message}");
                throw;
            }
            finally
            {
                // --- 8. Securely Clear Temporary Private Keys ---
                foreach (var kvp in oneTimePreKeysPrivateTemp)
                {
                    SecureMemory.SecureClear(kvp.Value);
                }
                oneTimePreKeysPrivateTemp.Clear();
            }
        }

        /// <summary>
        /// Validates a public X3DH key bundle for correctness and security properties.
        /// </summary>
        /// <param name="bundle">The public bundle to validate.</param>
        /// <returns>True if the bundle is valid, false otherwise.</returns>
        public Task<bool> ValidateKeyBundleAsync(X3DHPublicBundle bundle)
        {
            if (bundle == null) return Task.FromResult(false);

            try
            {
                // Check required fields & sizes
                if (bundle.IdentityKey?.Length != Constants.ED25519_PUBLIC_KEY_SIZE ||
                    bundle.SignedPreKey?.Length != Constants.X25519_KEY_SIZE ||
                    bundle.SignedPreKeySignature?.Length != 64 || // Ed25519 sig size
                    bundle.SignedPreKeyId == 0) // ID must be non-zero
                {
                    LoggingManager.LogWarning(nameof(X3DHProtocol), "Bundle missing required fields or invalid sizes/ID.");
                    return Task.FromResult(false);
                }

                // Validate Key formats
                if (!_cryptoProvider.ValidateEd25519PublicKey(bundle.IdentityKey))
                {
                    LoggingManager.LogWarning(nameof(X3DHProtocol), "Invalid Ed25519 Identity Key format/value.");
                    return Task.FromResult(false);
                }
                if (!_cryptoProvider.ValidateX25519PublicKey(bundle.SignedPreKey))
                {
                    LoggingManager.LogWarning(nameof(X3DHProtocol), "Invalid X25519 Signed PreKey format/value.");
                    return Task.FromResult(false);
                }

                // Validate One-Time PreKeys if present
                if (bundle.OneTimePreKeys != null && bundle.OneTimePreKeys.Count > 0)
                {
                    // Only validate OneTimePreKeyIds if OneTimePreKeys are present
                    if (bundle.OneTimePreKeyIds == null || bundle.OneTimePreKeys.Count != bundle.OneTimePreKeyIds.Count)
                    {
                        LoggingManager.LogWarning(nameof(X3DHProtocol), "Mismatched OneTimePreKeys and IDs count.");
                        return Task.FromResult(false);
                    }

                    for (int i = 0; i < bundle.OneTimePreKeys.Count; ++i)
                    {
                        if (bundle.OneTimePreKeys[i]?.Length != Constants.X25519_KEY_SIZE ||
                            !_cryptoProvider.ValidateX25519PublicKey(bundle.OneTimePreKeys[i]) ||
                             bundle.OneTimePreKeyIds[i] == 0) // ID must be non-zero
                        {
                            LoggingManager.LogWarning(nameof(X3DHProtocol), $"Invalid OneTimePreKey at index {i}.");
                            return Task.FromResult(false);
                        }
                    }
                }

                // Verify the signature on the signed prekey
                if (!_cryptoProvider.VerifySignature(bundle.SignedPreKey, bundle.SignedPreKeySignature, bundle.IdentityKey))
                {
                    LoggingManager.LogWarning(nameof(X3DHProtocol), "Bundle signature verification failed.");
                    return Task.FromResult(false);
                }

                // Check pre-key age
                if (bundle.CreationTimestamp > 0)
                {
                    long ageMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - bundle.CreationTimestamp;
                    if (ageMs < 0) // Timestamp from the future?
                    {
                        LoggingManager.LogWarning(nameof(X3DHProtocol), "Bundle timestamp appears to be from the future.");
                        return Task.FromResult(false);
                    }
                    if (ageMs > Constants.SIGNED_PREKEY_MAX_AGE_MS)
                    {
                        LoggingManager.LogWarning(nameof(X3DHProtocol), $"Bundle signed pre-key is too old ({ageMs / (24 * 60 * 60 * 1000)} days).");
                        return Task.FromResult(false);
                    }
                    if (ageMs > Constants.SIGNED_PREKEY_ROTATION_MS)
                    {
                        LoggingManager.LogWarning(nameof(X3DHProtocol), "Bundle signed pre-key is due for rotation.");
                        // Note: Still valid, just a warning for the user.
                    }
                }

                return Task.FromResult(true); // All checks passed
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(X3DHProtocol), $"Error validating bundle: {ex.Message}");
                return Task.FromResult(false);
            }
        }

        /// <summary>
        /// Initiates an X3DH session AS THE SENDER (Alice).
        /// Calculates the shared secret and prepares the initial message data for the receiver.
        /// </summary>
        /// <param name="recipientBundle">The recipient's public key bundle.</param>
        /// <param name="senderIdentityKeyPair">The sender's long-term identity key pair (Ed25519).</param>
        /// <returns>A SenderSessionResult containing the derived shared key (SK) and the initial message data.</returns>
        public async Task<SenderSessionResult> InitiateSessionAsSenderAsync(
            X3DHPublicBundle recipientBundle,
            KeyPair senderIdentityKeyPair)
        {
            ArgumentNullException.ThrowIfNull(recipientBundle, nameof(recipientBundle));
            ArgumentNullException.ThrowIfNull(senderIdentityKeyPair, nameof(senderIdentityKeyPair));

            if (senderIdentityKeyPair.PublicKey == null) throw new ArgumentNullException(nameof(senderIdentityKeyPair.PublicKey));
            if (senderIdentityKeyPair.PrivateKey == null) throw new ArgumentNullException(nameof(senderIdentityKeyPair.PrivateKey));

            // Validate recipient bundle
            if (!await ValidateKeyBundleAsync(recipientBundle))
                throw new ArgumentException("Invalid or incomplete recipient bundle.", nameof(recipientBundle));

            // We know required keys exist from validation, but check again for safety
            if (recipientBundle.IdentityKey == null || recipientBundle.SignedPreKey == null)
                throw new ArgumentException("Validated bundle unexpectedly missing required keys.", nameof(recipientBundle));

            byte[]? senderIK_X25519_Private = null;
            byte[]? ephemeralPrivateKey = null;
            byte[]? ephemeralPublicKey = null;
            byte[]? recipientIK_X25519_Public = null;
            byte[]? dh1 = null, dh2 = null, dh3 = null, dh4 = null;
            byte[]? sk = null; // The final shared key output of X3DH KDF

            uint? usedOneTimePreKeyId = null;
            byte[]? selectedOneTimePreKey = null;

            try
            {
                // 1. Convert Keys
                senderIK_X25519_Private = _cryptoProvider.ConvertEd25519PrivateKeyToX25519(senderIdentityKeyPair.PrivateKey);
                recipientIK_X25519_Public = _cryptoProvider.ConvertEd25519PublicKeyToX25519(recipientBundle.IdentityKey);

                // 2. Generate Ephemeral Key Pair (EK)
                var ephemeralKeyPairGen = await _cryptoProvider.GenerateKeyPairAsync(KeyType.X25519);

                // Validate the generated pair
                if (ephemeralKeyPairGen.PrivateKey == null || ephemeralKeyPairGen.PublicKey == null ||
                    ephemeralKeyPairGen.PrivateKey.Length != Constants.X25519_KEY_SIZE ||
                    ephemeralKeyPairGen.PublicKey.Length != Constants.X25519_KEY_SIZE)
                {
                    throw new CryptographicException("Failed to generate a valid ephemeral key pair (null or invalid size).");
                }

                ephemeralPrivateKey = ephemeralKeyPairGen.PrivateKey;
                ephemeralPublicKey = ephemeralKeyPairGen.PublicKey;

                // 3. Select Recipient's One-Time PreKey (OPK) if available
                if (recipientBundle.OneTimePreKeys != null && recipientBundle.OneTimePreKeys.Count > 0)
                {
                    int count = recipientBundle.OneTimePreKeys.Count;
                    int startIndex = RandomNumberGenerator.GetInt32(0, count);
                    for (int i = 0; i < count; ++i)
                    {
                        int currentIndex = (startIndex + i) % count;
                        byte[]? candidateKey = recipientBundle.OneTimePreKeys[currentIndex];

                        if (candidateKey != null &&
                           _cryptoProvider.ValidateX25519PublicKey(candidateKey) &&
                           recipientBundle.OneTimePreKeyIds != null &&
                           recipientBundle.OneTimePreKeyIds.Count == count)
                        {
                            selectedOneTimePreKey = candidateKey;
                            usedOneTimePreKeyId = recipientBundle.OneTimePreKeyIds[currentIndex];
                            LoggingManager.LogDebug(nameof(X3DHProtocol), $"Selected valid OPK with ID {usedOneTimePreKeyId}.");
                            break;
                        }
                    }
                    if (selectedOneTimePreKey == null)
                    {
                        LoggingManager.LogWarning(nameof(X3DHProtocol), "No valid one-time pre-key found in recipient bundle, proceeding without OPK.");
                    }
                }

                // 4. Perform Diffie-Hellman Calculations
                dh1 = await PerformDHAsync(senderIK_X25519_Private, recipientBundle.SignedPreKey);
                dh2 = await PerformDHAsync(ephemeralPrivateKey, recipientIK_X25519_Public);
                dh3 = await PerformDHAsync(ephemeralPrivateKey, recipientBundle.SignedPreKey);
                if (selectedOneTimePreKey != null)
                {
                    dh4 = await PerformDHAsync(ephemeralPrivateKey, selectedOneTimePreKey);
                }

                // 5. Derive Shared Key (SK) using X3DH KDF
                sk = await DeriveX3DHSharedKeyAsync(dh1, dh2, dh3, dh4);

                // 6. Prepare Result
                var messageData = new InitialMessageData(
                    senderIdentityKeyPair.PublicKey,  // Alice's public Ed25519 IK
                    ephemeralPublicKey,               // Alice's public X25519 EK
                    recipientBundle.SignedPreKeyId,
                    usedOneTimePreKeyId
                );

                var result = new SenderSessionResult
                {
                    SharedKey = sk,
                    MessageDataToSend = messageData
                };

                sk = null; // Set local reference to null so finally block doesn't clear the returned key

                return result;
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(X3DHProtocol), $"X3DH Sender initiation failed: {ex.Message}");
                throw;
            }
            finally
            {
                // Clear all sensitive materials
                SecureMemory.SecureClear(senderIK_X25519_Private);
                SecureMemory.SecureClear(ephemeralPrivateKey);
                SecureMemory.SecureClear(dh1);
                SecureMemory.SecureClear(dh2);
                SecureMemory.SecureClear(dh3);
                SecureMemory.SecureClear(dh4);
                SecureMemory.SecureClear(sk);
            }
        }

        /// <summary>
        /// Establishes an X3DH session AS THE RECEIVER (Bob).
        /// Uses the initial message from the sender and the receiver's own key bundle to derive the shared secret.
        /// </summary>
        /// <param name="initialMessage">The initial message data received from the sender.</param>
        /// <param name="receiverBundle">The receiver's complete key bundle (including private keys).</param>
        /// <returns>The derived 32-byte shared secret (SK).</returns>
        public async Task<byte[]> EstablishSessionAsReceiverAsync(
            InitialMessageData initialMessage,
            X3DHKeyBundle receiverBundle)
        {
            ArgumentNullException.ThrowIfNull(initialMessage, nameof(initialMessage));
            ArgumentNullException.ThrowIfNull(receiverBundle, nameof(receiverBundle));

            if (!initialMessage.IsValid())
                throw new ArgumentException("Invalid initial message data.", nameof(initialMessage));

            byte[]? receiverIK_Ed_Private = null;
            byte[]? receiverIK_X25519_Private = null;
            byte[]? receiverSPK_X25519_Private = null;
            byte[]? receiverOPK_X25519_Private = null;
            byte[]? senderIK_X25519_Public = null;
            byte[]? dh1 = null, dh2 = null, dh3 = null, dh4 = null;
            byte[]? sk = null;

            try
            {
                // 1. Load Receiver's Private Keys & Verify SPK ID
                receiverIK_Ed_Private = receiverBundle.GetIdentityKeyPrivate();
                if (receiverIK_Ed_Private == null)
                    throw new InvalidOperationException("Receiver bundle missing identity private key.");

                // Check SPK ID match
                if (receiverBundle.SignedPreKeyId != initialMessage.RecipientSignedPreKeyId)
                    throw new KeyNotFoundException($"Received initial message using Signed PreKey ID {initialMessage.RecipientSignedPreKeyId}, but the receiver's bundle has ID {receiverBundle.SignedPreKeyId}.");

                receiverSPK_X25519_Private = receiverBundle.GetSignedPreKeyPrivate();
                if (receiverSPK_X25519_Private == null)
                    throw new InvalidOperationException($"Receiver's Signed PreKey private part missing for ID {initialMessage.RecipientSignedPreKeyId}.");

                // Get OPK private key if needed
                if (initialMessage.RecipientOneTimePreKeyId.HasValue)
                {
                    uint opkId = initialMessage.RecipientOneTimePreKeyId.Value;
                    receiverOPK_X25519_Private = receiverBundle.GetOneTimePreKeyPrivate(opkId);
                    if (receiverOPK_X25519_Private == null)
                        throw new KeyNotFoundException($"Receiver's one-time pre-key private part for ID {opkId} not found.");
                }

                // 2. Convert Keys
                receiverIK_X25519_Private = _cryptoProvider.ConvertEd25519PrivateKeyToX25519(receiverIK_Ed_Private);
                senderIK_X25519_Public = _cryptoProvider.ConvertEd25519PublicKeyToX25519(initialMessage.SenderIdentityKeyPublic);

                // Validate sender public keys
                if (!_cryptoProvider.ValidateX25519PublicKey(senderIK_X25519_Public) ||
                    !_cryptoProvider.ValidateX25519PublicKey(initialMessage.SenderEphemeralKeyPublic))
                    throw new ArgumentException("Invalid public key format received from sender.", nameof(initialMessage));

                // 3. Perform DH Calculations
                dh1 = await PerformDHAsync(receiverSPK_X25519_Private, senderIK_X25519_Public);
                dh2 = await PerformDHAsync(receiverIK_X25519_Private, initialMessage.SenderEphemeralKeyPublic);
                dh3 = await PerformDHAsync(receiverSPK_X25519_Private, initialMessage.SenderEphemeralKeyPublic);
                if (receiverOPK_X25519_Private != null)
                {
                    dh4 = await PerformDHAsync(receiverOPK_X25519_Private, initialMessage.SenderEphemeralKeyPublic);
                }

                // 4. Derive Shared Key (SK)
                sk = await DeriveX3DHSharedKeyAsync(dh1, dh2, dh3, dh4);

                return sk; // Return the derived shared secret
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(X3DHProtocol), $"X3DH Receiver establishment failed: {ex.Message}");
                throw;
            }
            finally
            {
                // Clear all sensitive materials except the returned sk
                SecureMemory.SecureClear(receiverIK_Ed_Private);
                SecureMemory.SecureClear(receiverIK_X25519_Private);
                SecureMemory.SecureClear(receiverSPK_X25519_Private);
                SecureMemory.SecureClear(receiverOPK_X25519_Private);
                SecureMemory.SecureClear(dh1);
                SecureMemory.SecureClear(dh2);
                SecureMemory.SecureClear(dh3);
                SecureMemory.SecureClear(dh4);
                // Note: sk is returned and ownership transferred to caller
            }
        }

        // Helper methods for DH operations and key derivation
        private async Task<byte[]> PerformDHAsync(byte[] privateKey, byte[] publicKey)
        {
            return await Task.Run(() => {
                return _cryptoProvider.ScalarMult(privateKey, publicKey);
            });
        }

        private async Task<byte[]> DeriveX3DHSharedKeyAsync(byte[] dh1, byte[] dh2, byte[] dh3, byte[]? dh4 = null)
        {
            // Construct IKM = F || DH1 || DH2 || DH3 || DH4 (F=32 0xFF bytes, DH4 optional)
            int ikmLength = 32 + dh1.Length + dh2.Length + dh3.Length + (dh4?.Length ?? 0);
            byte[] ikm = new byte[ikmLength];

            // Fill with 0xFF prefix
            for (int i = 0; i < 32; i++)
            {
                ikm[i] = 0xFF;
            }

            int offset = 32;
            Buffer.BlockCopy(dh1, 0, ikm, offset, dh1.Length); offset += dh1.Length;
            Buffer.BlockCopy(dh2, 0, ikm, offset, dh2.Length); offset += dh2.Length;
            Buffer.BlockCopy(dh3, 0, ikm, offset, dh3.Length); offset += dh3.Length;
            if (dh4 != null)
            {
                Buffer.BlockCopy(dh4, 0, ikm, offset, dh4.Length);
            }

            try
            {
                // Use HKDF to derive the final key
                return await Task.Run(() => {
                    return _cryptoProvider.DeriveKey(
                        ikm,
                        salt: new byte[32], // 32 zero bytes for salt
                        info: Encoding.UTF8.GetBytes("WhisperText"),
                        length: 32);
                });
            }
            finally
            {
                // Clear the combined key material
                SecureMemory.SecureClear(ikm);
            }
        }

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
