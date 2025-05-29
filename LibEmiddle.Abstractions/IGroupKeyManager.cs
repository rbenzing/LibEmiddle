using LibEmiddle.Domain;

namespace LibEmiddle.Abstractions
{
    /// <summary>
    /// Defines the interface for managing cryptographic keys and ratchet chains
    /// for group messaging sessions.
    /// </summary>
    public interface IGroupKeyManager
    {
        byte[] GenerateInitialChainKey();
        bool InitializeSenderState(string groupId, byte[] initialChainKey);
        GroupSenderState? GetSenderState(string groupId);
        bool ClearSenderState(string groupId);
        (byte[] MessageKey, uint Iteration) GetSenderMessageKey(string groupId);
        bool StoreSenderKey(string groupId, byte[] senderIdentityKey, byte[] senderKey);
        byte[]? GetSenderKey(string groupId, byte[] senderIdentityKey);
        bool ValidateEncryptedMessage(EncryptedGroupMessage message);
        bool ValidateDistributionMessage(SenderKeyDistributionMessage distribution);
        long GetLastRotationTimestamp(string groupId);
        void UpdateLastRotationTimestamp(string groupId, long timestamp);
        Task<GroupKeyState> ExportKeyStateAsync(string groupId);
        Task<bool> ImportKeyStateAsync(GroupKeyState keyState);
    }
}
