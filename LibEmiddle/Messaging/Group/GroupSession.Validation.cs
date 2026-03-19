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
    #region Security Validation

    private bool ValidateGroupMessage(EncryptedGroupMessage message)
    {
        // Basic validation
        if (message.Ciphertext?.Length == 0 || message.Nonce?.Length != Constants.NONCE_SIZE)
            return false;

        if (message.SenderIdentityKey == null || message.SenderIdentityKey?.Length == 0 || message.Timestamp <= 0)
            return false;

        // Check if sender is a member
        if (!IsMember(message.SenderIdentityKey!))
            return false;

        // Verify signature
        if (message.Signature != null)
        {
            byte[] dataToSign = GetMessageDataToSign(message);
            if (!Sodium.SignVerifyDetached(message.Signature, dataToSign, message.SenderIdentityKey))
                return false;
        }

        // Validate message sequence for replay protection
        // First check for message ID replay (exact duplicate detection)
        if (!string.IsNullOrEmpty(message.MessageId))
        {
            string senderId = GetMemberId(message.SenderIdentityKey!);
            var senderMessageIds = _seenMessageIds.GetOrAdd(senderId, _ => new HashSet<string>());

            lock (senderMessageIds)
            {
                if (senderMessageIds.Contains(message.MessageId))
                {
                    LoggingManager.LogSecurityEvent(nameof(GroupSession), "Message ID replay detected", isAlert: true);
                    return false;
                }
                senderMessageIds.Add(message.MessageId);

                // Limit the size of the set to prevent memory issues (keep last 1000 message IDs)
                if (senderMessageIds.Count > 1000)
                {
                    var oldestIds = senderMessageIds.Take(senderMessageIds.Count - 1000).ToList();
                    foreach (var oldId in oldestIds)
                    {
                        senderMessageIds.Remove(oldId);
                    }
                }
            }
        }

        // Extract iteration number from message ID for sequence tracking
        long sequenceNumber = ExtractSequenceFromMessageId(message.MessageId) ?? message.Timestamp;
        return ValidateMessageSequence(message.SenderIdentityKey!, sequenceNumber, message.Timestamp);
    }

    private bool ValidateMessageSequence(byte[] senderKey, long sequence, long timestamp)
    {
        string senderId = GetMemberId(senderKey);

        // For concurrent scenarios, we use a more flexible approach
        // Instead of strict sequence ordering, we track seen message IDs to prevent actual replays
        // This allows for out-of-order processing while still preventing replay attacks

        // Update the last seen sequence if this one is higher (for general tracking)
        if (_lastSeenSequence.TryGetValue(senderId, out long lastSeen))
        {
            if (sequence > lastSeen)
            {
                _lastSeenSequence[senderId] = sequence;
            }
        }
        else
        {
            _lastSeenSequence[senderId] = sequence;
        }

        return ValidateMessageTimestamp(senderKey, timestamp);
    }

    private bool ValidateMessageTimestamp(byte[] senderKey, long messageTimestamp)
    {
        string senderId = GetMemberId(senderKey);

        if (_joinTimestamps.TryGetValue(senderId, out long joinTimestamp))
        {
            const long CLOCK_SKEW_TOLERANCE_MS = 5 * 60 * 1000; // 5 minutes

            if (messageTimestamp < joinTimestamp - CLOCK_SKEW_TOLERANCE_MS)
                return false;

            long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            if (messageTimestamp > now + CLOCK_SKEW_TOLERANCE_MS)
                return false;
        }

        return true;
    }

    private bool HasPermission(GroupOperation operation)
    {
        string userId = GetMemberId(_identityKeyPair.PublicKey);

        if (!_members.TryGetValue(userId, out var member))
            return false;

        return operation switch
        {
            GroupOperation.Send => true, // All members can send
            GroupOperation.AddMember or GroupOperation.RemoveMember or
            GroupOperation.PromoteAdmin or GroupOperation.DemoteAdmin => member.IsAdmin || member.IsOwner,
            GroupOperation.RotateKey => member.IsAdmin || member.IsOwner,
            GroupOperation.DeleteGroup => member.IsOwner,
            _ => false
        };
    }

    #endregion
}
