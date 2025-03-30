using System;
using E2EELibrary.Communication;

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

            // Verify the signature
            byte[] signedData = CombineForVerification();
            return MessageSigning.VerifySignature(signedData, Signature, trustedPublicKey);
        }

        /// <summary>
        /// Combines device key and timestamp for signature verification.
        /// </summary>
        private byte[] CombineForVerification()
        {
            byte[] timestampBytes = BitConverter.GetBytes(RevocationTimestamp);
            byte[] combined = new byte[RevokedDeviceKey.Length + timestampBytes.Length];

            RevokedDeviceKey.AsSpan().CopyTo(combined.AsSpan(0, RevokedDeviceKey.Length));
            timestampBytes.AsSpan().CopyTo(combined.AsSpan(RevokedDeviceKey.Length));

            return combined;
        }
    }
}