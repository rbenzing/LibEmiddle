using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;
using LibEmiddle.Models;

namespace LibEmiddle.Abstractions
{
    public interface IDoubleRatchetProtocol
    {
        Task<DoubleRatchetSession> InitializeSessionAsSenderAsync(byte[] sharedKeyFromX3DH, byte[] recipientInitialPublicKey, string sessionId);
        Task<DoubleRatchetSession> InitializeSessionAsReceiverAsync(byte[] sharedKeyFromX3DH, KeyPair receiverInitialKeyPair, byte[] senderEphemeralKeyPublic, string sessionId);
        Task<(DoubleRatchetSession?, EncryptedMessage?)> EncryptAsync(DoubleRatchetSession session, string message, KeyRotationStrategy rotationStrategy = KeyRotationStrategy.Standard);
        Task<(DoubleRatchetSession?, string?)> DecryptAsync(DoubleRatchetSession session, EncryptedMessage encryptedMessage);
    }
}
