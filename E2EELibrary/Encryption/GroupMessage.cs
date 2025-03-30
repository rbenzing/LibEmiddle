using System.Text;
using E2EELibrary.Models;

namespace E2EELibrary.Encryption
{
    /// <summary>
    /// Provides functionality for encrypting and decrypting messages in group conversations.
    /// Uses a shared sender key for secure group communications while maintaining efficiency.
    /// </summary>
    public static class GroupMessage
    {
        /// <summary>
        /// Encrypts a group message using a sender key
        /// </summary>
        /// <param name="message">Message to encrypt</param>
        /// <param name="senderKey">Sender key</param>
        /// <returns>Encrypted message</returns>
        public static EncryptedMessage EncryptGroupMessage(string message, byte[] senderKey)
        {
            byte[] plaintext = Encoding.UTF8.GetBytes(message);
            byte[] nonce = NonceGenerator.GenerateNonce();
            byte[] ciphertext = AES.AESEncrypt(plaintext, senderKey, nonce);

            return new EncryptedMessage
            {
                Ciphertext = ciphertext,
                Nonce = nonce
            };
        }

        /// <summary>
        /// Decrypts a group message using a sender key
        /// </summary>
        /// <param name="encryptedMessage">Encrypted message</param>
        /// <param name="senderKey">Sender key</param>
        /// <returns>Decrypted message</returns>
        public static string DecryptGroupMessage(EncryptedMessage encryptedMessage, byte[] senderKey)
        {
            ArgumentNullException.ThrowIfNull(encryptedMessage.Ciphertext);
            ArgumentNullException.ThrowIfNull(encryptedMessage.Nonce);

            byte[] plaintext = AES.AESDecrypt(encryptedMessage.Ciphertext, senderKey, encryptedMessage.Nonce);
            return Encoding.UTF8.GetString(plaintext);
        }
    }
}
