using System.Buffers;
using System.Security.Cryptography;
using System.Runtime.CompilerServices;
using System.Text;

namespace E2EELibrary.Core
{
    /// <summary>
    /// Utility methods for cryptographic operations used across the library.
    /// </summary>
    public static class Utils
    {
        /// <summary>
        /// Validates UTF-8 encoding of a byte array
        /// </summary>
        /// <param name="data">Byte array to validate</param>
        /// <returns>True if the data is valid UTF-8</returns>
        public static bool IsValidUtf8(byte[] data)
        {
            try
            {
                // Attempt to decode
                string decoded = Encoding.UTF8.GetString(data);
                // Re-encode and check if the bytes match
                byte[] reEncoded = Encoding.UTF8.GetBytes(decoded);

                if (data.Length != reEncoded.Length)
                    return false;

                for (int i = 0; i < data.Length; i++)
                {
                    if (data[i] != reEncoded[i])
                        return false;
                }

                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Validates a message ID against recently processed IDs to prevent replay attacks
        /// </summary>
        /// <param name="messageId">Message ID to validate</param>
        /// <param name="recentlyProcessedIds">Queue of recently processed message IDs</param>
        /// <returns>True if the message ID is new and valid</returns>
        public static bool ValidateMessageId(Guid messageId, Queue<Guid> recentlyProcessedIds)
        {
            lock (recentlyProcessedIds)
            {
                // Check if we've seen this message ID before
                if (recentlyProcessedIds.Contains(messageId))
                {
                    return false;
                }

                // Add the new message ID to the queue
                recentlyProcessedIds.Enqueue(messageId);

                // If queue exceeds capacity, remove oldest ID
                if (recentlyProcessedIds.Count > Constants.MAX_TRACKED_MESSAGE_IDS)
                {
                    recentlyProcessedIds.Dequeue();
                }

                return true;
            }
        }
    }
}