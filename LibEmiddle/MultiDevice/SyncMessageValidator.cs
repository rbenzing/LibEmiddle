using LibEmiddle.Abstractions;
using LibEmiddle.Core;
using LibEmiddle.Domain;

public class SyncMessageValidator : ISyncMessageValidator
{
    private readonly ICryptoProvider _cryptoProvider;

    // Maximum message age for replay protection
    private const long MAX_MESSAGE_AGE_MS = 5 * 60 * 1000; // 5 minutes

    public SyncMessageValidator(ICryptoProvider cryptoProvider)
    {
        _cryptoProvider = cryptoProvider ?? throw new ArgumentNullException(nameof(cryptoProvider));
    }

    public bool ValidateSyncMessage(DeviceSyncMessage message, byte[] trustedPublicKey)
    {
        // Basic validations
        if (message.SenderPublicKey == null || message.SenderPublicKey.Length == 0)
            return false;

        if (message.Data == null || message.Data.Length == 0)
            return false;

        if (message.Signature == null || message.Signature.Length == 0)
            return false;

        if (message.Timestamp <= 0)
            return false;

        // Check message age (prevent replay)
        long currentTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        // Reject messages older than 5 minutes
        if (currentTime - message.Timestamp > MAX_MESSAGE_AGE_MS)
            return false;

        // Reject future messages with more than 1 minute time skew
        if (message.Timestamp > currentTime + 60 * 1000)
            return false;

        // Check protocol version compatibility if set
        if (!string.IsNullOrEmpty(message.Version))
        {
            if (!IsValidProtocolVersion(message.Version))
                return false;
        }

        // Use SequenceEqual to validate the expected sender matches the trusted key
        if (!SecureMemory.SecureCompare(message.SenderPublicKey, trustedPublicKey))
            return false;

        // Verify the signature
        return _cryptoProvider.VerifySignature(message.Data, message.Signature, message.SenderPublicKey);
    }

    private bool IsValidProtocolVersion(string version)
    {
        // Check format (e.g., "LibEmiddle/v1.0")
        string[] parts = version.Split('/');
        if (parts.Length != 2 || !parts[1].StartsWith("v"))
            return false;

        // Parse version number
        string versionNumber = parts[1].Substring(1);
        string[] versionParts = versionNumber.Split('.');
        if (versionParts.Length != 2)
            return false;

        if (!int.TryParse(versionParts[0], out int majorVersion) ||
            !int.TryParse(versionParts[1], out int minorVersion))
            return false;

        // Check compatibility
        return ProtocolVersion.IsCompatible(majorVersion, minorVersion);
    }
}