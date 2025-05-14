namespace LibEmiddle.Domain
{
    /// <summary>
    /// Interface for validating sync messages between devices.
    /// </summary>
    public interface ISyncMessageValidator
    {
        /// <summary>
        /// Validates a sync message using the provided public key.
        /// </summary>
        /// <param name="message">The sync message to validate</param>
        /// <param name="trustedPublicKey">The trusted public key for verification</param>
        /// <returns>True if the message is valid</returns>
        bool ValidateSyncMessage(DeviceSyncMessage message, byte[] trustedPublicKey);
    }
}