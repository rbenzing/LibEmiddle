using System;
using System.Buffers.Binary;
using System.IO;
using System.Text;
using LibEmiddle.Domain;

namespace LibEmiddle.Messaging.Group;

/// <summary>
/// Builds the canonical byte string that group signatures are computed over.
///
/// Every field is preceded by its length as a 4-byte big-endian unsigned integer, so
/// that a given byte string corresponds to exactly one decomposition into fields.
/// Without those prefixes, adjacent fields could be re-split to produce identical
/// signing input for different content, meaning a signature would not uniquely commit
/// to the message it was computed over.
///
/// Big-endian is explicit because BinaryWriter is little-endian. Endianness here is a
/// format decision, not an implementation detail: it must be identical on every
/// platform. This format is frozen by golden vectors — changing it invalidates every
/// signature produced by an earlier version.
/// </summary>
internal static class GroupSignatureData
{
    internal static byte[] ForMessage(EncryptedGroupMessage message)
    {
        using var ms = new MemoryStream();

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
