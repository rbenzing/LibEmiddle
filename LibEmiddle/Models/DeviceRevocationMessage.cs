using System;
using System.Text;
using E2EELibrary.Communication;
using E2EELibrary.Core;

namespace E2EELibrary.Models
{
    /// <summary>
    /// Message indicating a device has been revoked.
    /// </summary>
    public class DeviceRevocationMessage
    {
        /// <summary>
        /// Public key of the revoked device
        /// </summary>
        public byte[] RevokedDeviceKey { get; set; }

        /// <summary>
        /// Timestamp when the device was revoked (milliseconds since Unix epoch)
        /// </summary>
        public long RevocationTimestamp { get; set; }

        /// <summary>
        /// Signature of the revoked device key and timestamp, signed by the authorizing device
        /// </summary>
        public byte[] Signature { get; set; }

        /// <summary>
        /// Protocol version information for compatibility checking
        /// </summary>
        public string Version { get; set; } = ProtocolVersion.FULL_VERSION;

        /// <summary>
        /// Creates a new device revocation message with empty non-null properties.
        /// </summary>
        public DeviceRevocationMessage()
        {
            RevokedDeviceKey = Array.Empty<byte>();
            Signature = Array.Empty<byte>();
            RevocationTimestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        }

        /// <summary>
        /// Creates a new device revocation message with the specified parameters.
        /// </summary>
        /// <param name="revokedDeviceKey">The public key of the device being revoked</param>
        /// <param name="signature">The signature of the combined device key and timestamp</param>
        /// <param name="revocationTimestamp">The revocation timestamp (defaults to current time if not specified)</param>
        /// <exception cref="ArgumentNullException">Thrown when required parameters are null</exception>
        public DeviceRevocationMessage(byte[] revokedDeviceKey, byte[] signature, long revocationTimestamp = 0)
        {
            RevokedDeviceKey = revokedDeviceKey ?? throw new ArgumentNullException(nameof(revokedDeviceKey));
            Signature = signature ?? throw new ArgumentNullException(nameof(signature));
            RevocationTimestamp = revocationTimestamp > 0 ? revocationTimestamp : DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        }

        /// <summary>
        /// Validates this revocation message against a trusted public key.
        /// </summary>
        /// <param name="trustedPublicKey">The trusted public key for verification</param>
        /// <returns>True if the message is valid and properly signed</returns>
        public bool Validate(byte[] trustedPublicKey)
        {
            if (RevokedDeviceKey == null || RevokedDeviceKey.Length == 0)
                return false;

            if (Signature == null || Signature.Length == 0)
                return false;

            if (RevocationTimestamp <= 0)
                return false;

            // Check for expired revocation (> 30 days old)
            long currentTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            if (currentTime - RevocationTimestamp > 30 * 24 * 60 * 60 * 1000L) // 30 days in milliseconds
                return false;

            // Check protocol version compatibility if set
            if (!string.IsNullOrEmpty(Version))
            {
                if (!IsValidProtocolVersion(Version))
                    return false;
            }

            // Combine device key and timestamp for verification
            byte[] timestampBytes = BitConverter.GetBytes(RevocationTimestamp);
            byte[] dataToVerify = Sodium.GenerateRandomBytes(RevokedDeviceKey.Length + timestampBytes.Length);

            RevokedDeviceKey.AsSpan().CopyTo(dataToVerify.AsSpan(0, RevokedDeviceKey.Length));
            timestampBytes.AsSpan().CopyTo(dataToVerify.AsSpan(RevokedDeviceKey.Length, timestampBytes.Length));

            // Verify the signature
            return MessageSigning.VerifySignature(dataToVerify, Signature, trustedPublicKey);
        }

        /// <summary>
        /// Validates the protocol version format and compatibility
        /// </summary>
        /// <param name="version">Protocol version string to check</param>
        /// <returns>True if the version is compatible</returns>
        private bool IsValidProtocolVersion(string version)
        {
            // Check format (e.g., "E2EELibrary/v1.0")
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

        /// <summary>
        /// Combines device key, timestamp, and optional version for signature verification.
        /// </summary>
        private byte[] CombineForVerification()
        {
            using var ms = new MemoryStream();

            // Add the revoked device key
            ms.Write(RevokedDeviceKey, 0, RevokedDeviceKey.Length);

            // Add the timestamp
            byte[] timestampBytes = BitConverter.GetBytes(RevocationTimestamp);
            ms.Write(timestampBytes, 0, timestampBytes.Length);

            // If using protocol v1.1+, also include the protocol version in the data to sign
            if (!string.Equals(Version, ProtocolVersion.LEGACY_VERSION, StringComparison.Ordinal))
            {
                byte[] versionBytes = Encoding.UTF8.GetBytes(Version);
                ms.Write(versionBytes, 0, versionBytes.Length);
            }

            return ms.ToArray();
        }

        /// <summary>
        /// Serializes this message to a dictionary for transport
        /// </summary>
        public Dictionary<string, string> ToDictionary()
        {
            var dict = new Dictionary<string, string>
            {
                ["revokedDeviceKey"] = Convert.ToBase64String(RevokedDeviceKey),
                ["revocationTimestamp"] = RevocationTimestamp.ToString(),
                ["signature"] = Convert.ToBase64String(Signature),
                ["protocolVersion"] = Version
            };

            return dict;
        }

        /// <summary>
        /// Creates a DeviceRevocationMessage from a dictionary
        /// </summary>
        public static DeviceRevocationMessage FromDictionary(Dictionary<string, string> dict)
        {
            if (!dict.TryGetValue("revokedDeviceKey", out string? keyBase64) ||
                !dict.TryGetValue("signature", out string? sigBase64) ||
                !dict.TryGetValue("revocationTimestamp", out string? timestampStr))
            {
                throw new ArgumentException("Missing required fields in dictionary", nameof(dict));
            }

            byte[] deviceKey = Convert.FromBase64String(keyBase64);
            byte[] signature = Convert.FromBase64String(sigBase64);
            long timestamp = long.Parse(timestampStr);

            var message = new DeviceRevocationMessage(deviceKey, signature, timestamp);

            // Set protocol version if present
            if (dict.TryGetValue("protocolVersion", out string? version))
            {
                message.Version = version;
            }

            return message;
        }

        /// <summary>
        /// Serializes this message to JSON
        /// </summary>
        public string ToJson()
        {
            return JsonSerialization.Serialize(ToDictionary());
        }

        /// <summary>
        /// Creates a DeviceRevocationMessage from JSON
        /// </summary>
        public static DeviceRevocationMessage FromJson(string json)
        {
            var dict = JsonSerialization.Deserialize<Dictionary<string, string>>(json)
                ?? throw new ArgumentException("Failed to deserialize JSON", nameof(json));

            return FromDictionary(dict);
        }
    }
}