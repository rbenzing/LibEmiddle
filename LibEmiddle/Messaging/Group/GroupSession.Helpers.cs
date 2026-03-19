using System.Collections.Concurrent;
using System.Text;
using LibEmiddle.Abstractions;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;

namespace LibEmiddle.Messaging.Group;

public sealed partial class GroupSession
{
    #region Helper Methods

    private async Task CheckAndRotateKeyIfNeededAsync()
    {
        // Prevent infinite recursion by checking if we're already in a rotation
        if (_isRotating)
            return;

        long currentTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        TimeSpan elapsed = TimeSpan.FromMilliseconds(currentTime - _lastRotationTimestamp);

        bool shouldRotate = RotationStrategy switch
        {
            KeyRotationStrategy.Hourly => elapsed >= TimeSpan.FromHours(1),
            KeyRotationStrategy.Daily => elapsed >= TimeSpan.FromDays(1),
            KeyRotationStrategy.Weekly => elapsed >= TimeSpan.FromDays(7),
            KeyRotationStrategy.Standard => elapsed >= TimeSpan.FromDays(7),
            KeyRotationStrategy.AfterEveryMessage => true,
            _ => false
        };

        if (shouldRotate && HasPermission(GroupOperation.RotateKey))
        {
            try
            {
                // Use internal rotation to avoid double-locking
                await RotateKeyInternalAsync();
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(GroupSession), $"Failed to rotate group key: {ex.Message}");
            }
        }
    }

    private void RecordJoinTime(byte[] publicKey)
    {
        string userId = GetMemberId(publicKey);
        _joinTimestamps[userId] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
    }

    private bool IsMember(byte[] publicKey)
    {
        string userId = GetMemberId(publicKey);
        return _members.ContainsKey(userId);
    }

    private bool WasRemovedBeforeTimestamp(byte[] publicKey, long timestamp)
    {
        string userId = GetMemberId(publicKey);
        return _removedMembers.TryGetValue(userId, out long removalTime) && removalTime < timestamp;
    }

    private static string GetMemberId(byte[] publicKey) => Convert.ToBase64String(publicKey);

    private static long? ExtractSequenceFromMessageId(string? messageId)
    {
        if (string.IsNullOrEmpty(messageId) || !messageId.StartsWith("iter:"))
            return null;

        var parts = messageId.Split(':');
        if (parts.Length >= 2 && uint.TryParse(parts[1], out uint iteration))
        {
            return iteration;
        }

        return null;
    }

    private static byte[] GetMessageDataToSign(EncryptedGroupMessage message)
    {
        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);

        writer.Write(Encoding.UTF8.GetBytes(message.GroupId));
        writer.Write(message.SenderIdentityKey);
        writer.Write(message.Ciphertext);
        writer.Write(message.Nonce);
        writer.Write(message.Timestamp);
        writer.Write(message.RotationEpoch);
        writer.Write(Encoding.UTF8.GetBytes(message.MessageId ?? string.Empty));

        return ms.ToArray();
    }

    private static byte[] GetDistributionDataToSign(SenderKeyDistributionMessage distribution)
    {
        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);

        writer.Write(Encoding.UTF8.GetBytes(distribution.GroupId!));
        writer.Write(distribution.ChainKey!);
        writer.Write(distribution.Iteration);
        writer.Write(distribution.Timestamp);
        if (distribution.SenderIdentityKey != null)
        {
            writer.Write(distribution.SenderIdentityKey);
        }

        return ms.ToArray();
    }

    private void OnStateChanged(SessionState previousState, SessionState newState)
    {
        Task.Run(() => StateChanged?.Invoke(this, new SessionStateChangedEventArgs(previousState, newState)));
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(GroupSession));
    }

    #endregion

    #region Advanced Group Management Helper Methods

    private bool HasAdvancedPermission(GroupPermission permission)
    {
        string currentUserId = GetMemberId(_identityKeyPair.PublicKey);
        if (!_members.TryGetValue(currentUserId, out var currentMember))
            return false;

        return currentMember.HasPermission(permission);
    }

    private int CalculateGroupHealthScore(GroupStatistics stats)
    {
        int score = 100;

        // Deduct points for low activity
        if (stats.MemberActivityRate < 0.3) score -= 20;
        else if (stats.MemberActivityRate < 0.5) score -= 10;

        // Deduct points for no recent messages
        if (stats.LastMessageAt.HasValue)
        {
            var daysSinceLastMessage = (DateTime.UtcNow - stats.LastMessageAt.Value).TotalDays;
            if (daysSinceLastMessage > 30) score -= 30;
            else if (daysSinceLastMessage > 7) score -= 15;
        }
        else
        {
            score -= 40; // No messages ever
        }

        // Deduct points for high mute ratio
        if (stats.TotalMembers > 0)
        {
            var muteRatio = (double)stats.MutedMembers / stats.TotalMembers;
            if (muteRatio > 0.3) score -= 20;
            else if (muteRatio > 0.1) score -= 10;
        }

        // Deduct points for missing admins in large groups
        if (stats.TotalMembers > 10 && !stats.MembersByRole.ContainsKey(MemberRole.Admin))
            score -= 15;

        return Math.Max(0, Math.Min(100, score));
    }

    #endregion
}
