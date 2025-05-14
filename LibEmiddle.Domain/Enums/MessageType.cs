namespace LibEmiddle.Domain.Enums
{
    /// <summary>
    /// Type of mailbox message
    /// </summary>
    public enum MessageType
    {
        /// <summary>
        /// A regular chat message
        /// </summary>
        Chat = 0,

        /// <summary>
        /// A device sync message
        /// </summary>
        DeviceSync = 1,

        /// <summary>
        /// A key exchange or key update message
        /// </summary>
        KeyExchange = 2,

        /// <summary>
        /// A group chat message
        /// </summary>
        GroupChat = 3,

        /// <summary>
        /// A device revocation message
        /// </summary>
        DeviceRevocation = 4,

        /// <summary>
        /// A file transfer message
        /// </summary>
        FileTransfer = 5,

        /// <summary>
        /// A delivery receipt
        /// </summary>
        DeliveryReceipt = 7,

        /// <summary>
        /// A read receipt
        /// </summary>
        ReadReceipt = 8,

        /// <summary>
        /// Control message for session management.
        /// </summary>
        Control = 9,

        /// <summary>
        /// Sender key distribution for group messaging.
        /// </summary>
        SenderKeyDistribution = 10,

        /// <summary>
        /// Message for requesting sender key distribution.
        /// </summary>
        SenderKeyRequest = 11,

        /// <summary>
        /// Message containing pre-key bundles.
        /// </summary>
        PreKeyBundle = 12,
    }
}