using LibEmiddle.Domain;

namespace LibEmiddle.Abstractions
{
    public interface IGroupSession : ISession
    {
        string GroupId { get; }
        Task<bool> AddMemberAsync(byte[] memberPublicKey);
        Task<bool> RemoveMemberAsync(byte[] memberPublicKey);
        Task<EncryptedGroupMessage?> EncryptMessageAsync(string message);
        Task<string?> DecryptMessageAsync(EncryptedGroupMessage message);
        Task<bool> RotateKeyAsync();
    }
}
