using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;

namespace LibEmiddle.Abstractions
{
    /// <summary>
    /// Interface for batching messages for efficient transport (v2.5).
    /// Supports compression and configurable batching strategies.
    /// </summary>
    public interface IMessageBatcher : IDisposable
    {
        /// <summary>
        /// Adds a message to the current batch.
        /// </summary>
        /// <param name="message">The encrypted message to add.</param>
        /// <param name="priority">Optional priority for message ordering.</param>
        /// <returns>True if the message was added successfully.</returns>
        Task<bool> AddMessageAsync(EncryptedMessage message, MessagePriority priority = MessagePriority.Normal);

        /// <summary>
        /// Gets the current batch if it's ready for transmission.
        /// A batch is ready based on configured criteria (size, count, time).
        /// </summary>
        /// <returns>The batch if ready, null otherwise.</returns>
        Task<MessageBatch?> GetReadyBatchAsync();

        /// <summary>
        /// Forces the current batch to be ready for transmission.
        /// </summary>
        /// <returns>The current batch, even if it doesn't meet normal criteria.</returns>
        Task<MessageBatch?> FlushBatchAsync();

        /// <summary>
        /// Gets statistics about the current batching state.
        /// </summary>
        /// <returns>Batching statistics.</returns>
        BatchingStatistics GetStatistics();

        /// <summary>
        /// Gets the current batching configuration.
        /// </summary>
        BatchingOptions Options { get; }
    }

    /// <summary>
    /// A batch of messages ready for transmission (v2.5).
    /// </summary>
    public class MessageBatch
    {
        /// <summary>
        /// Unique identifier for this batch.
        /// </summary>
        public string BatchId { get; set; } = Guid.NewGuid().ToString();

        /// <summary>
        /// Messages in this batch, ordered by priority and timestamp.
        /// </summary>
        public List<BatchedMessage> Messages { get; set; } = new();

        /// <summary>
        /// When this batch was created.
        /// </summary>
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// When this batch was finalized.
        /// </summary>
        public DateTime FinalizedAt { get; set; }

        /// <summary>
        /// Compression used for this batch.
        /// </summary>
        public CompressionLevel Compression { get; set; } = CompressionLevel.None;

        /// <summary>
        /// Compressed payload if compression is enabled.
        /// </summary>
        public byte[]? CompressedPayload { get; set; }

        /// <summary>
        /// Original size before compression.
        /// </summary>
        public long OriginalSizeBytes { get; set; }

        /// <summary>
        /// Compressed size (same as original if no compression).
        /// </summary>
        public long CompressedSizeBytes { get; set; }

        /// <summary>
        /// Metadata about the batch.
        /// </summary>
        public Dictionary<string, object> Metadata { get; set; } = new();

        /// <summary>
        /// Gets the compression ratio (compressed/original).
        /// </summary>
        public double CompressionRatio => OriginalSizeBytes > 0 ? (double)CompressedSizeBytes / OriginalSizeBytes : 1.0;
    }

    /// <summary>
    /// A message within a batch with its metadata (v2.5).
    /// </summary>
    public class BatchedMessage
    {
        /// <summary>
        /// The encrypted message.
        /// </summary>
        public EncryptedMessage Message { get; set; } = new();

        /// <summary>
        /// Priority of this message.
        /// </summary>
        public MessagePriority Priority { get; set; } = MessagePriority.Normal;

        /// <summary>
        /// When this message was added to the batch.
        /// </summary>
        public DateTime AddedAt { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Sequence number within the batch.
        /// </summary>
        public int SequenceNumber { get; set; }

        /// <summary>
        /// Additional metadata for this message.
        /// </summary>
        public Dictionary<string, object> Metadata { get; set; } = new();
    }

    /// <summary>
    /// Statistics about message batching (v2.5).
    /// </summary>
    public class BatchingStatistics
    {
        /// <summary>
        /// Number of messages currently in the batch.
        /// </summary>
        public int CurrentBatchSize { get; set; }

        /// <summary>
        /// Total size of messages in the current batch.
        /// </summary>
        public long CurrentBatchSizeBytes { get; set; }

        /// <summary>
        /// When the current batch was started.
        /// </summary>
        public DateTime? CurrentBatchStartedAt { get; set; }

        /// <summary>
        /// Total number of batches sent.
        /// </summary>
        public long TotalBatchesSent { get; set; }

        /// <summary>
        /// Total number of messages sent.
        /// </summary>
        public long TotalMessagesSent { get; set; }

        /// <summary>
        /// Average batch size (messages per batch).
        /// </summary>
        public double AverageBatchSize { get; set; }

        /// <summary>
        /// Average compression ratio achieved.
        /// </summary>
        public double AverageCompressionRatio { get; set; }

        /// <summary>
        /// Total bytes saved through compression.
        /// </summary>
        public long TotalBytesSaved { get; set; }

        /// <summary>
        /// Last time statistics were updated.
        /// </summary>
        public DateTime LastUpdated { get; set; } = DateTime.UtcNow;
    }
}