using LibEmiddle.Domain;

namespace LibEmiddle.Abstractions
{
    public interface IX3DHProtocol
    {
        Task<X3DHKeyBundle> CreateKeyBundleAsync(KeyPair? identityKeyPair = null, int numOneTimeKeys = 5);
        Task<SenderSessionResult> InitiateSessionAsSenderAsync(X3DHPublicBundle recipientBundle, KeyPair senderIdentityKeyPair);
        Task<byte[]> EstablishSessionAsReceiverAsync(InitialMessageData initialMessage, X3DHKeyBundle localKeyBundle);
        Task<bool> ValidateKeyBundleAsync(X3DHPublicBundle bundle);
    }
}
