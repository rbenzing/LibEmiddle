using LibEmiddle.Domain;

namespace LibEmiddle.Abstractions
{
    /// <summary>
    /// Interface for group message cryptographic operations including encryption,
    /// decryption, and authentication.
    /// </summary>
    public interface IGroupMessageCrypto
    {
        /// <summary>
        /// Encrypts a message for a group using a message key.
        /// </summary>
        EncryptedGroupMessage EncryptMessage(
            string groupId,
            string message,
            byte[] messageKey,
            KeyPair senderKeyPair,
            long rotationTimestamp);

        /// <summary>
        /// Decrypts a group message using a sender key.
        /// </summary>
        string? DecryptMessage(EncryptedGroupMessage encryptedMessage, byte[] senderKey);

        /// <summary>
        /// Records the timestamp when a user joined a group.
        /// </summary>
        long RecordGroupJoin(string groupId, KeyPair identityKeyPair);
    }
}
