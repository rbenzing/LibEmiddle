using LibEmiddle.Domain;

namespace LibEmiddle.Abstractions
{
    /// <summary>
    /// Interface for managing the distribution of sender keys for secure group messaging.
    /// </summary>
    public interface ISenderKeyDistribution
    {
        SenderKeyDistributionMessage CreateDistributionMessage(
            string groupId,
            byte[] chainKey,
            uint iteration,
            KeyPair senderKeyPair);

        bool ProcessDistributionMessage(SenderKeyDistributionMessage distribution);

        byte[]? GetSenderKeyForMessage(EncryptedGroupMessage message);

        SenderKeyDistributionMessage? GetDistributionMessage(string groupId, byte[] senderIdentityKey);

        bool DeleteGroupDistributions(string groupId);

        string ExportState();

        bool ImportState(string serializedState);
    }
}
