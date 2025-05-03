using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;

namespace LibEmiddle.Abstractions
{
    /// <summary>
    /// Defines the contract for cryptographic operations used by the library.
    /// Implementing this interface allows swapping the underlying cryptographic engine.
    /// </summary>
    public interface ICryptoProvider
    {
        public Task<KeyPair> GenerateKeyPairAsync(KeyType keyType);
        public Span<byte> DerivePublicKey(Span<byte> privateKey, KeyType keyType);
        public byte[] GenerateRandomBytes(int count);
        public byte[] Sign(byte[] data, byte[] privateKey);
        public bool VerifySignature(byte[] data, byte[] signature, byte[] publicKey);
        public byte[] Encrypt(byte[] plaintext, byte[] key, byte[] nonce, byte[]? associatedData);
        public byte[] Decrypt(byte[] ciphertext, byte[] key, byte[] nonce, byte[]? associatedData);
        public byte[] ScalarMult(byte[] privateKey, byte[] publicKey);
        public byte[] DeriveKey(byte[] inputKeyMaterial, byte[]? salt, byte[]? info, int length);
        public byte[] DeriveKeyFromPassword(string password);
        public byte[] ConvertEd25519PublicKeyToX25519(byte[] ed25519PublicKey);
        public byte[] ConvertEd25519PrivateKeyToX25519(byte[] ed25519PrivateKey);
        public bool ValidateEd25519PublicKey(byte[] publicKey);
        public bool ValidateX25519PublicKey(byte[] publicKey);
        public bool ConstantTimeEquals(byte[] a, byte[] b);


        // ASYNC
        public Task<byte[]> DeriveKeyAsync(byte[] inputKeyMaterial, byte[]? salt, byte[]? info, int length);
        public Task<byte[]> DeriveKeyFromPasswordAsync(string password);
        public Task<bool> StoreKeyAsync(string keyId, byte[] key, string? password = null);
        public Task<byte[]?> RetrieveKeyAsync(string keyId, string? password = null);
        public Task<bool> DeleteKeyAsync(string keyId);
        public Task<bool> StoreJsonAsync(string keyId, string jsonData);
        public Task<string?> RetrieveJsonAsync(string keyId);
        public Task<bool> StoreAsync(string keyId, string data);
        public Task<string?> RetrieveAsync(string keyId);
        public Task<byte[]> SignAsync(byte[] data, byte[] privateKey);

    }
}