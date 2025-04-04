﻿namespace E2EELibrary.Core
{
    /// <summary>
    /// Enumerations
    /// </summary>
    public static class Enums
    {
        /// <summary>
        /// Represents a member's role in a group
        /// </summary>
        public enum MemberRole
        {
            /// <summary>
            /// Group member
            /// </summary>
            Member = 0,

            /// <summary>
            /// Group admin
            /// </summary>
            Admin = 1,

            /// <summary>
            /// Group owner
            /// </summary>
            Owner = 2
        }

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
            ReadReceipt = 8
        }
    }
}
