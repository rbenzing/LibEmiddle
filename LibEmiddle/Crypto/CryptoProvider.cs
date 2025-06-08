using System.Text;
using LibEmiddle.Abstractions;
using LibEmiddle.Core;
using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;
using LibEmiddle.KeyManagement;

namespace LibEmiddle.Crypto
{
    /// <summary>
    /// Implementation of the ICryptoProvider interface that provides cryptographic
    /// operations using modern cryptographic algorithms for secure messaging.
    /// </summary>
    public sealed class CryptoProvider : ICryptoProvider, IDisposable
    {
        private readonly KeyStorage _keyStorage;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the CryptoProvider class.
        /// </summary>
        public CryptoProvider()
        {
            _keyStorage = new KeyStorage();
        }

        /// <summary>
        /// Initializes a new instance of the CryptoProvider class with a custom storage path.
        /// </summary>
        /// <param name="storagePath">Custom path for key storage. If null, the default path is used.</param>
        public CryptoProvider(string? storagePath)
        {
            _keyStorage = new KeyStorage(storagePath);
        }

        /// <inheritdoc/>
        public Task<KeyPair> GenerateKeyPairAsync(KeyType keyType)
        {
            try
            {
                KeyPair keyPair;

                switch (keyType)
                {
                    case KeyType.Ed25519:
                        keyPair = Sodium.GenerateEd25519KeyPair();
                        break;

                    case KeyType.X25519:
                        keyPair = Sodium.GenerateX25519KeyPair();
                        break;

                    default:
                        throw new ArgumentOutOfRangeException(nameof(keyType), "Unsupported key type.");
                }

                return Task.FromResult(keyPair);
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(CryptoProvider), $"Error generating key pair: {ex.Message}");
                throw;
            }
        }

        /// <inheritdoc/>
        public byte[] GenerateRandomBytes(uint count)
        {
            return Sodium.GenerateRandomBytes(count);
        }

        /// <inheritdoc/>
        public byte[] Sign(byte[] data, byte[] privateKey)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            if (privateKey == null)
                throw new ArgumentNullException(nameof(privateKey));

            try
            {
                return Sodium.SignDetached(data, privateKey);
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(CryptoProvider), $"Error signing data: {ex.Message}");
                throw;
            }
            // Note: We should NOT clear the private key here as it's owned by the caller
            // The caller is responsible for managing the lifetime of their private key
        }

        /// <inheritdoc/>
        public Task<byte[]> SignAsync(byte[] data, byte[] privateKey)
        {
            return Task.Run(() => Sign(data, privateKey));
        }

        /// <inheritdoc/>
        public bool VerifySignature(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKey)
        {
            bool validKey = Sodium.ValidateEd25519PublicKey(publicKey);
            bool validSig = false;

            if (validKey) // Only verify if key is valid, but in constant time
            {
                validSig = Sodium.SignVerifyDetached(signature, message, publicKey);
            }

            // Constant-time return
            return validKey & validSig;
        }

        /// <inheritdoc/>
        public byte[] Encrypt(byte[] plaintext, byte[] key, byte[]? nonce, byte[]? associatedData)
        {
            if (plaintext == null)
                throw new ArgumentNullException(nameof(plaintext));

            if (plaintext.Length == 0)
                throw new ArgumentException("Plaintext cannot be empty.", nameof(plaintext));

            if (key == null)
                throw new ArgumentNullException(nameof(key));

            if (nonce == null)
                throw new ArgumentNullException(nameof(nonce));

            try
            {
                // Use AES-GCM for encryption
                return AES.AESEncrypt(plaintext, key, nonce, associatedData);
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(CryptoProvider), $"Error encrypting data: {ex.Message}");
                throw;
            }
        }

        /// <inheritdoc/>
        public byte[] Decrypt(byte[] ciphertext, byte[] key, byte[]? nonce, byte[]? associatedData)
        {
            if (ciphertext == null)
                throw new ArgumentNullException(nameof(ciphertext));

            if (key == null)
                throw new ArgumentNullException(nameof(key));

            if (nonce == null)
                throw new ArgumentNullException(nameof(nonce));

            try
            {
                // Use AES-GCM for decryption
                return AES.AESDecrypt(ciphertext, key, nonce, associatedData);
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(CryptoProvider), $"Error decrypting data: {ex.Message}");
                throw;
            }
        }

        /// <inheritdoc/>
        public byte[] ScalarMult(byte[] privateKey, byte[] publicKey)
        {
            if (privateKey == null)
                throw new ArgumentNullException(nameof(privateKey));

            if (publicKey == null)
                throw new ArgumentNullException(nameof(publicKey));

            try
            {
                return Sodium.ScalarMult(privateKey, publicKey);
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(CryptoProvider), $"Error performing scalar multiplication: {ex.Message}");
                throw;
            }
        }

        /// <inheritdoc/>
        public byte[] AdvanceChainKey(ReadOnlySpan<byte> chainKey)
        {
            if (chainKey.Length != 32)
                throw new ArgumentException("Chain key must be 32 bytes", nameof(chainKey));
 
            try
            {
                return Sodium.AdvanceChainKey(chainKey);
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(CryptoProvider), $"Error performing chain key advancement: {ex.Message}");
                throw;
            }
        }

        /// <inheritdoc/>
        public byte[] DeriveMessageKey(ReadOnlySpan<byte> chainKey)
        {
            if (chainKey.Length != 32)
                throw new ArgumentException("Chain key must be 32 bytes", nameof(chainKey));

            try
            {
                return Sodium.DeriveMessageKey(chainKey);
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(CryptoProvider), $"Error performing message key derivation: {ex.Message}");
                throw;
            }
        }

        /// <inheritdoc/>
        public  (byte[] RootKey, byte[] InitialChainKey) DeriveInitialSessionKeys(ReadOnlySpan<byte> sharedSecret)
        {
            if (sharedSecret.Length != 32)
                throw new ArgumentException("Shared secret must be 32 bytes", nameof(sharedSecret));

            try
            {
                return Sodium.DeriveInitialSessionKeys(sharedSecret);
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(CryptoProvider), $"Error performing initial session key derivation: {ex.Message}");
                throw;
            }
        }

        /// <inheritdoc/>
        public byte[] DeriveKey(byte[] inputKeyMaterial, byte[]? salt, byte[]? info, int length = 32)
        {
            if (inputKeyMaterial == null)
                throw new ArgumentNullException(nameof(inputKeyMaterial));

            if (length <= 0 || length > 64)
                throw new ArgumentOutOfRangeException(nameof(length), "Length must be between 1 and 64 bytes.");

            try
            {
                // Use Signal-compliant HKDF from Sodium (much simpler!)
                return Sodium.HkdfDerive(inputKeyMaterial, salt, info, length);
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(CryptoProvider), $"Error deriving key: {ex.Message}");
                throw;
            }
            finally
            {
                SecureMemory.SecureClear(inputKeyMaterial);
            }
        }

        /// <inheritdoc/>
        public Task<byte[]> DeriveKeyAsync(byte[] inputKeyMaterial, byte[]? salt, byte[]? info, int length = 32)
        {
            return Task.Run(() => DeriveKey(inputKeyMaterial, salt, info, length));
        }

        /// <inheritdoc/>
        public byte[] DeriveKeyFromPassword(string password)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Password cannot be null or empty.", nameof(password));

            try
            {
                // Use a deterministic approach for key derivation
                // Convert password to bytes
                byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

                // Use a fixed salt for deterministic key derivation
                // In production, you might want to use a per-application salt
                byte[] salt = Encoding.UTF8.GetBytes("LibEmiddle-KeyDerivation-Salt-v1");

                // Use HKDF to derive exactly 32 bytes for AES encryption
                return Sodium.HkdfDerive(passwordBytes, salt, Encoding.UTF8.GetBytes("LibEmiddle-Password-Key"), 32);
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(CryptoProvider), $"Error deriving key from password: {ex.Message}");
                throw;
            }
        }

        /// <inheritdoc/>
        public Task<byte[]> DeriveKeyFromPasswordAsync(string password)
        {
            return Task.Run(() => DeriveKeyFromPassword(password));
        }

        /// <inheritdoc/>
        public byte[] ConvertEd25519PublicKeyToX25519(byte[] ed25519PublicKey)
        {
            ArgumentNullException.ThrowIfNull(ed25519PublicKey);

            if (ed25519PublicKey.Length != Constants.ED25519_PUBLIC_KEY_SIZE)
                throw new ArgumentException($"Ed25519 public key must be {Constants.ED25519_PUBLIC_KEY_SIZE} bytes.", nameof(ed25519PublicKey));

            try
            {
                return Sodium.ConvertEd25519PublicKeyToX25519(ed25519PublicKey);
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(CryptoProvider), $"Error converting Ed25519 public key to X25519: {ex.Message}");
                throw;
            }
        }

        /// <inheritdoc/>
        public byte[] ConvertEd25519PrivateKeyToX25519(byte[] ed25519PrivateKey)
        {
            if (ed25519PrivateKey == null)
                throw new ArgumentNullException(nameof(ed25519PrivateKey));

            if (ed25519PrivateKey.Length == Constants.X25519_KEY_SIZE)
                return ed25519PrivateKey; // if the key is 32 and not 64 then send it back

            if (ed25519PrivateKey.Length != Constants.ED25519_PRIVATE_KEY_SIZE)
                throw new ArgumentException($"Ed25519 private key must be {Constants.ED25519_PRIVATE_KEY_SIZE} bytes.", nameof(ed25519PrivateKey));

            try
            {
                return Sodium.ConvertEd25519PrivateKeyToX25519(ed25519PrivateKey);
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(CryptoProvider), $"Error converting Ed25519 private key to X25519: {ex.Message}");
                throw;
            }
        }

        /// <inheritdoc/>
        public bool ValidateEd25519PublicKey(byte[] publicKey)
        {
            if (publicKey == null)
                return false;

            if (publicKey.Length != Constants.ED25519_PUBLIC_KEY_SIZE)
                return false;

            try
            {
                return Sodium.ValidateEd25519PublicKey(publicKey);
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(CryptoProvider), $"Error validating Ed25519 public key: {ex.Message}");
                return false;
            }
        }

        /// <inheritdoc/>
        public bool ValidateX25519PublicKey(byte[] publicKey)
        {
            if (publicKey == null)
                return false;

            if (publicKey.Length != Constants.X25519_KEY_SIZE)
                return false;

            try
            {
                return Sodium.ValidateX25519PublicKey(publicKey);
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(CryptoProvider), $"Error validating X25519 public key: {ex.Message}");
                return false;
            }
        }

        /// <inheritdoc/>
        public Task<bool> StoreKeyAsync(string keyId, byte[] key, string? password = null)
        {
            if (string.IsNullOrEmpty(keyId))
                throw new ArgumentException("Key ID cannot be null or empty.", nameof(keyId));

            if (key == null)
                throw new ArgumentNullException(nameof(key));

            if (key.Length == 0)
                return Task.FromResult(false);

            try
            {
                if (password != null)
                {
                    // Encrypt the key before storage
                    byte[] encryptionKey = DeriveKeyFromPassword(password);
                    try
                    {
                        byte[] nonce = GenerateNonce(Constants.NONCE_SIZE);
                        byte[] encryptedKey = Encrypt(key, encryptionKey, nonce, null);

                        // Store encrypted key with nonce using StoreData (which doesn't double-encrypt)
                        byte[] combinedData = new byte[nonce.Length + encryptedKey.Length];
                        nonce.AsSpan().CopyTo(combinedData.AsSpan(0));
                        encryptedKey.AsSpan().CopyTo(combinedData.AsSpan(nonce.Length));

                        return Task.FromResult(_keyStorage.StoreData($"password-key:{keyId}", combinedData));
                    }
                    finally
                    {
                        SecureMemory.SecureClear(encryptionKey);
                    }
                }
                else
                {
                    // Store the key directly
                    return Task.FromResult(_keyStorage.StoreKey(keyId, key));
                }
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(CryptoProvider), $"Error storing key {keyId}: {ex.Message}");
                return Task.FromResult(false);
            }
        }

        /// <inheritdoc/>
        public byte[] GenerateNonce(uint size = Constants.NONCE_SIZE)
        {
            return Nonce.GenerateNonce(size);
        }

        /// <inheritdoc/>
        public Task<byte[]?> RetrieveKeyAsync(string keyId, string? password = null)
        {
            if (string.IsNullOrEmpty(keyId))
                throw new ArgumentException("Key ID cannot be null or empty.", nameof(keyId));

            try
            {
                if (password != null)
                {
                    // Try to retrieve password-protected key
                    byte[]? storedData = _keyStorage.RetrieveData($"password-key:{keyId}");
                    if (storedData == null)
                        return Task.FromResult<byte[]?>(null);

                    // Key is encrypted, decrypt it
                    byte[] encryptionKey = DeriveKeyFromPassword(password);
                    try
                    {
                        // Extract nonce and encrypted key
                        byte[] nonce = new byte[Constants.NONCE_SIZE];
                        byte[] encryptedKey = new byte[storedData.Length - Constants.NONCE_SIZE];

                        storedData.AsSpan(0, Constants.NONCE_SIZE).CopyTo(nonce);
                        storedData.AsSpan(Constants.NONCE_SIZE).CopyTo(encryptedKey);

                        // Decrypt the key
                        return Task.FromResult<byte[]?>(Decrypt(encryptedKey, encryptionKey, nonce, null));
                    }
                    catch (Exception ex)
                    {
                        LoggingManager.LogError(nameof(CryptoProvider), $"Error decrypting key {keyId}: {ex.Message}");
                        return Task.FromResult<byte[]?>(null);
                    }
                    finally
                    {
                        SecureMemory.SecureClear(encryptionKey);
                    }
                }
                else
                {
                    // Key is not password-protected
                    byte[]? storedData = _keyStorage.RetrieveKey(keyId);
                    return Task.FromResult<byte[]?>(storedData);
                }
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(CryptoProvider), $"Error retrieving key {keyId}: {ex.Message}");
                return Task.FromResult<byte[]?>(null);
            }
        }

        /// <inheritdoc/>
        public Task<bool> DeleteKeyAsync(string keyId, string? password = null)
        {
            if (string.IsNullOrEmpty(keyId))
                throw new ArgumentException("Key ID cannot be null or empty.", nameof(keyId));

            byte[]? keyFound = RetrieveKeyAsync(keyId, password).GetAwaiter().GetResult();
            if (keyFound == null && password == null)
                throw new FileNotFoundException();
            if (keyFound == null && password != null)
                throw new ArgumentException("Invalid request.", nameof(password));

            try
            {
                if (password != null)
                {
                    // Delete password-protected key
                    return Task.FromResult(_keyStorage.DeleteData($"password-key:{keyId}"));
                }
                else
                {
                    // Delete regular key
                    return Task.FromResult(_keyStorage.DeleteKey(keyId));
                }
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(CryptoProvider), $"Error deleting key {keyId}: {ex.Message}");
                return Task.FromResult(false);
            }
        }

        /// <inheritdoc/>
        public Task<bool> StoreJsonAsync(string keyId, string jsonData)
        {
            return StoreAsync(keyId, jsonData);
        }

        /// <inheritdoc/>
        public Task<string?> RetrieveJsonAsync(string keyId)
        {
            return RetrieveAsync(keyId);
        }

        /// <inheritdoc/>
        public Task<bool> StoreAsync(string keyId, string data)
        {
            if (string.IsNullOrEmpty(keyId))
                throw new ArgumentException("Key ID cannot be null or empty.", nameof(keyId));

            if (data == null)
                throw new ArgumentNullException(nameof(data));

            try
            {
                byte[] bytes = Encoding.Default.GetBytes(data);
                return Task.FromResult(_keyStorage.StoreData(keyId, bytes));
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(CryptoProvider), $"Error storing data for key {keyId}: {ex.Message}");
                return Task.FromResult(false);
            }
        }

        /// <inheritdoc/>
        public Task<string?> RetrieveAsync(string keyId)
        {
            if (string.IsNullOrEmpty(keyId))
                throw new ArgumentException("Key ID cannot be null or empty.", nameof(keyId));

            try
            {
                byte[]? bytes = _keyStorage.RetrieveData(keyId);
                if (bytes == null)
                    return Task.FromResult<string?>(null);

                return Task.FromResult<string?>(Encoding.UTF8.GetString(bytes));
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(CryptoProvider), $"Error retrieving data for key {keyId}: {ex.Message}");
                return Task.FromResult<string?>(null);
            }
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Disposes of resources used by the CryptoProvider.
        /// </summary>
        /// <param name="disposing">True if disposing, false if finalizing.</param>
        private void Dispose(bool disposing)
        { 
            if (!_disposed)
            {
                if (disposing)
                {
                    _keyStorage.Dispose();
                    // Clear any other sensitive state
                }
                _disposed = true;
            }
        }
    }
}