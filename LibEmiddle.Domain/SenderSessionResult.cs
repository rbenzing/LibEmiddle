using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LibEmiddle.Domain
{
    /// <summary>
    /// Result of the sender initiating an X3DH session.
    /// Contains the derived shared secret and the data needed for the initial message to the receiver.
    /// </summary>
    public class SenderSessionResult
    {
        /// <summary>
        /// The derived 32-byte shared secret (SK) from X3DH.
        /// Used to initialize the Double Ratchet. MUST be cleared after use.
        /// </summary>
        public byte[] SharedKey { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// The data containing sender public keys and recipient pre-key IDs
        /// that must be sent to the receiver in the initial message.
        /// </summary>
        public InitialMessageData MessageDataToSend { get; set; } = new InitialMessageData();
    }
}
