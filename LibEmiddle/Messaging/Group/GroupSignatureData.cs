using System;
using System.Buffers.Binary;
using System.IO;
using System.Text;
using LibEmiddle.Domain;

namespace LibEmiddle.Messaging.Group;

/// <summary>
/// Builds the canonical byte string that group signatures are computed over.
///
/// The format is: a single leading domain-separation tag byte, followed by a fixed
/// schedule of fields, all encoded big-endian. Variable-length fields (strings and byte
/// arrays) are each preceded by their length as a 4-byte big-endian unsigned integer;
/// fixed-width fields (timestamps, epoch, iteration counters) are written bare at their
/// natural width. Every value is present in every schedule position — none are omitted
/// based on nullability — so a given byte string corresponds to exactly one decomposition
/// into fields:
///
///   - The domain tag exists because, without it, a byte string produced by one schedule
///     (e.g. <see cref="ForMessage"/>) could also be a valid parse of a different schedule
///     (e.g. <see cref="ForDistribution"/>) that happens to have a compatible field-width
///     sequence. Both schedules are signed with the same Ed25519 identity key, so without
///     a tag a signature over one payload type could be reinterpreted as covering the
///     other.
///   - Length prefixes on variable-length fields exist because, without them, adjacent
///     variable-length fields could be re-split to produce identical signing input for
///     different content, so a signature would not uniquely commit to the message it was
///     computed over.
///
/// Big-endian is explicit because BinaryWriter is little-endian. Endianness here is a
/// format decision, not an implementation detail: it must be identical on every platform.
/// This format — including the domain tag values — is frozen by golden vectors in W3;
/// changing any part of it invalidates every signature produced by an earlier version.
/// </summary>
internal static class GroupSignatureData
{
    /// <summary>
    /// Domain-separation tag for <see cref="ForMessage"/>. Frozen by W3's golden vectors —
    /// must never be reused for another payload type or renumbered.
    /// </summary>
    private const byte MessageDomainTag = 0x01;

    /// <summary>
    /// Domain-separation tag for <see cref="ForDistribution"/>. Frozen by W3's golden
    /// vectors — must never be reused for another payload type or renumbered.
    /// </summary>
    private const byte DistributionDomainTag = 0x02;

    internal static byte[] ForMessage(EncryptedGroupMessage message)
    {
        using var ms = new MemoryStream();

        ms.WriteByte(MessageDomainTag);
        WriteField(ms, Encoding.UTF8.GetBytes(message.GroupId ?? string.Empty));
        WriteField(ms, message.SenderIdentityKey ?? Array.Empty<byte>());
        WriteField(ms, message.Ciphertext ?? Array.Empty<byte>());
        WriteField(ms, message.Nonce ?? Array.Empty<byte>());
        WriteInt64(ms, message.Timestamp);
        WriteInt64(ms, message.RotationEpoch);
        WriteField(ms, Encoding.UTF8.GetBytes(message.MessageId ?? string.Empty));

        return ms.ToArray();
    }

    internal static byte[] ForDistribution(SenderKeyDistributionMessage distribution)
    {
        using var ms = new MemoryStream();

        ms.WriteByte(DistributionDomainTag);
        WriteField(ms, Encoding.UTF8.GetBytes(distribution.GroupId ?? string.Empty));
        WriteField(ms, distribution.ChainKey ?? Array.Empty<byte>());
        WriteUInt32(ms, distribution.Iteration);
        WriteInt64(ms, distribution.Timestamp);
        WriteField(ms, distribution.SenderIdentityKey ?? Array.Empty<byte>());

        return ms.ToArray();
    }

    private static void WriteField(Stream stream, byte[] value)
    {
        WriteUInt32(stream, (uint)value.Length);
        stream.Write(value, 0, value.Length);
    }

    private static void WriteUInt32(Stream stream, uint value)
    {
        Span<byte> buffer = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(buffer, value);
        stream.Write(buffer);
    }

    private static void WriteInt64(Stream stream, long value)
    {
        Span<byte> buffer = stackalloc byte[sizeof(long)];
        BinaryPrimitives.WriteInt64BigEndian(buffer, value);
        stream.Write(buffer);
    }
}
