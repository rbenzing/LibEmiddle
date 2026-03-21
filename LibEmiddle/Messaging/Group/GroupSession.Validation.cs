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
        // Check message ID for exact duplicate detection (read-only — registration happens after successful decryption)
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
                // NOTE: Do NOT add to senderMessageIds here — that happens after successful decryption
            }
        }

        // When the message carries a MessageId the _seenMessageIds check above provides complete replay
        // protection, so no additional sequence-order check is needed (and strict ordering would break
        // legitimate out-of-order delivery in concurrent scenarios).
        // Only apply sequence-order validation for legacy messages without a MessageId, where we fall
        // back to using the timestamp as a proxy sequence number.
        bool hasMessageId = !string.IsNullOrEmpty(message.MessageId);
        long sequenceNumber = hasMessageId
            ? (ExtractSequenceFromMessageId(message.MessageId) ?? message.Timestamp)
            : message.Timestamp;
        return ValidateMessageSequence(message.SenderIdentityKey!, sequenceNumber, message.Timestamp, enforceOrdering: !hasMessageId);
    }

    private bool ValidateMessageSequence(byte[] senderKey, long sequence, long timestamp, bool enforceOrdering = false)
    {
        string senderId = GetMemberId(senderKey);

        // Only enforce strict sequence ordering for the timestamp-based fallback path
        // (messages without a MessageId).  When a MessageId is present, the _seenMessageIds
        // set provides complete replay protection without requiring in-order delivery, allowing
        // concurrent and out-of-order message delivery to work correctly.
        if (enforceOrdering && _lastSeenSequence.TryGetValue(senderId, out long lastSeen))
        {
            if (sequence <= lastSeen)
            {
                LoggingManager.LogSecurityEvent(nameof(GroupSession), "Sequence-number replay detected", isAlert: true);
                return false;
            }
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

    /// <summary>
    /// Records a successfully decrypted message as seen, updating both the message-ID set and
    /// the last-seen sequence number for the sender.  Must only be called after the plaintext
    /// has been obtained, so that a decryption failure does not permanently block a legitimate
    /// future retry of the same message.
    /// </summary>
    private void RecordMessageSeen(EncryptedGroupMessage message)
    {
        if (message.SenderIdentityKey == null || message.SenderIdentityKey.Length == 0)
            return;

        string senderId = GetMemberId(message.SenderIdentityKey);

        // Register the message ID so subsequent presentations of the same message are rejected
        if (!string.IsNullOrEmpty(message.MessageId))
        {
            var senderMessageIds = _seenMessageIds.GetOrAdd(senderId, _ => new HashSet<string>());
            lock (senderMessageIds)
            {
                senderMessageIds.Add(message.MessageId);

                // Cap the set at 1000 entries per sender to prevent unbounded memory growth
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

        // Advance the last-seen sequence so that any equal-or-lower sequence is rejected in future
        long sequenceNumber = ExtractSequenceFromMessageId(message.MessageId) ?? message.Timestamp;
        _lastSeenSequence.AddOrUpdate(
            senderId,
            sequenceNumber,
            (_, existing) => sequenceNumber > existing ? sequenceNumber : existing);
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
