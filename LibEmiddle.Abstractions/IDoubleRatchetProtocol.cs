using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;

namespace LibEmiddle.Abstractions
{
    public interface IDoubleRatchetProtocol
    {
        DoubleRatchetSession InitializeSessionAsSender(byte[] sharedKeyFromX3DH, byte[] recipientInitialPublicKey, string sessionId);
        DoubleRatchetSession InitializeSessionAsReceiver(byte[] sharedKeyFromX3DH, KeyPair receiverInitialKeyPair, byte[] senderEphemeralKeyPublic, string sessionId);
        (DoubleRatchetSession?, EncryptedMessage?) EncryptAsync(DoubleRatchetSession session, string message, KeyRotationStrategy rotationStrategy = KeyRotationStrategy.Standard);
        (DoubleRatchetSession?, string?) DecryptAsync(DoubleRatchetSession session, EncryptedMessage encryptedMessage);
    }
}
