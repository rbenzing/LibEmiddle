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