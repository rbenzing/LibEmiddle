using LibEmiddle.Domain;

namespace LibEmiddle.Abstractions
{
    public interface IChatSession : ISession
    {
        byte[] RemotePublicKey { get; }
        byte[] LocalPublicKey { get; }
        Task<EncryptedMessage?> EncryptAsync(string message);
        Task<string?> DecryptAsync(EncryptedMessage message);
    }
}
