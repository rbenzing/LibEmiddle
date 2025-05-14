using LibEmiddle.Domain;

namespace LibEmiddle.Abstractions
{
    public interface ISessionManager
    {
        // Generic session management for both individual and group chats
        Task<ISession> CreateSessionAsync(byte[] recipientKey, object? options = null);
        Task<ISession> GetSessionAsync(string sessionId);
        Task<bool> SaveSessionAsync(ISession session);
        Task<bool> DeleteSessionAsync(string sessionId);
    }
}
