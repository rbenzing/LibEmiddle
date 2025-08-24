using System.Text.Json;
using LibEmiddle.Abstractions;
using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;
using LibEmiddle.Core;
using SystemCompression = System.IO.Compression;

namespace LibEmiddle.Messaging.Batching
{
    /// <summary>
    /// Implementation of message batching with compression support (v2.5).
    /// Provides efficient batching strategies and optional compression for message transport.
    /// </summary>
    public class MessageBatcher : IMessageBatcher, IDisposable
    {
        private readonly BatchingOptions _options;
        private readonly Timer _flushTimer;
        private readonly SemaphoreSlim _batchLock = new(1, 1);
        
        private readonly List<BatchedMessage> _currentBatch = new();
        private DateTime? _currentBatchStartedAt;
        private long _currentBatchSizeBytes = 0;
        private int _sequenceCounter = 0;
        
        private readonly BatchingStatistics _statistics = new();
        private bool _disposed = false;

        public BatchingOptions Options => _options;

        public MessageBatcher(BatchingOptions? options = null)
        {
            _options = options ?? BatchingOptions.Default;
            
            // Validate options
            if (_options.MaxBatchSize <= 0)
                throw new ArgumentException("MaxBatchSize must be positive", nameof(options));
            if (_options.MaxBatchSizeBytes <= 0)
                throw new ArgumentException("MaxBatchSizeBytes must be positive", nameof(options));
            if (_options.MaxBatchAge <= TimeSpan.Zero)
                throw new ArgumentException("MaxBatchAge must be positive", nameof(options));

            // Start flush timer if auto-flush is enabled
            if (_options.EnableAutoFlush)
            {
                var flushInterval = TimeSpan.FromMilliseconds(_options.MaxBatchAge.TotalMilliseconds / 2);
                _flushTimer = new Timer(AutoFlushCallback, null, flushInterval, flushInterval);
            }
            else
            {
                _flushTimer = new Timer(_ => { }, null, Timeout.Infinite, Timeout.Infinite);
            }
        }

        public async Task<bool> AddMessageAsync(EncryptedMessage message, MessagePriority priority = MessagePriority.Normal)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(MessageBatcher));

            ArgumentNullException.ThrowIfNull(message);

            await _batchLock.WaitAsync();
            try
            {
                // Initialize batch if this is the first message
                if (_currentBatch.Count == 0)
                {
                    _currentBatchStartedAt = DateTime.UtcNow;
                    _sequenceCounter = 0;
                }

                // Estimate message size
                var messageSize = EstimateMessageSize(message);

                // Check if adding this message would exceed limits
                if (_currentBatch.Count > 0)
                {
                    if (_currentBatch.Count >= _options.MaxBatchSize ||
                        _currentBatchSizeBytes + messageSize > _options.MaxBatchSizeBytes)
                    {
                        // Current batch is full, return false to indicate caller should get the batch
                        return false;
                    }
                }

                // Add message to batch
                var batchedMessage = new BatchedMessage
                {
                    Message = message,
                    Priority = priority,
                    AddedAt = DateTime.UtcNow,
                    SequenceNumber = ++_sequenceCounter
                };

                _currentBatch.Add(batchedMessage);
                _currentBatchSizeBytes += messageSize;

                LoggingManager.LogDebug(nameof(MessageBatcher), 
                    $"Added message to batch. Batch size: {_currentBatch.Count}, Bytes: {_currentBatchSizeBytes}");

                return true;
            }
            finally
            {
                _batchLock.Release();
            }
        }

        public async Task<MessageBatch?> GetReadyBatchAsync()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(MessageBatcher));

            await _batchLock.WaitAsync();
            try
            {
                if (_currentBatch.Count == 0)
                    return null;

                // Check if batch is ready based on criteria
                var batchAge = _currentBatchStartedAt.HasValue ? 
                    DateTime.UtcNow - _currentBatchStartedAt.Value : TimeSpan.Zero;

                bool isReady = 
                    _currentBatch.Count >= _options.MaxBatchSize ||
                    _currentBatchSizeBytes >= _options.MaxBatchSizeBytes ||
                    batchAge >= _options.MaxBatchAge ||
                    _currentBatch.Any(m => m.Priority == MessagePriority.Critical);

                if (!isReady)
                    return null;

                return await CreateBatchFromCurrentMessages();
            }
            finally
            {
                _batchLock.Release();
            }
        }

        public async Task<MessageBatch?> FlushBatchAsync()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(MessageBatcher));

            await _batchLock.WaitAsync();
            try
            {
                if (_currentBatch.Count == 0)
                    return null;

                return await CreateBatchFromCurrentMessages();
            }
            finally
            {
                _batchLock.Release();
            }
        }

        public BatchingStatistics GetStatistics()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(MessageBatcher));

            lock (_statistics)
            {
                // Update current batch info
                _statistics.CurrentBatchSize = _currentBatch.Count;
                _statistics.CurrentBatchSizeBytes = _currentBatchSizeBytes;
                _statistics.CurrentBatchStartedAt = _currentBatchStartedAt;
                _statistics.LastUpdated = DateTime.UtcNow;

                // Calculate averages
                if (_statistics.TotalBatchesSent > 0)
                {
                    _statistics.AverageBatchSize = (double)_statistics.TotalMessagesSent / _statistics.TotalBatchesSent;
                }

                return new BatchingStatistics
                {
                    CurrentBatchSize = _statistics.CurrentBatchSize,
                    CurrentBatchSizeBytes = _statistics.CurrentBatchSizeBytes,
                    CurrentBatchStartedAt = _statistics.CurrentBatchStartedAt,
                    TotalBatchesSent = _statistics.TotalBatchesSent,
                    TotalMessagesSent = _statistics.TotalMessagesSent,
                    AverageBatchSize = _statistics.AverageBatchSize,
                    AverageCompressionRatio = _statistics.AverageCompressionRatio,
                    TotalBytesSaved = _statistics.TotalBytesSaved,
                    LastUpdated = _statistics.LastUpdated
                };
            }
        }

        private async Task<MessageBatch> CreateBatchFromCurrentMessages()
        {
            // Sort messages by priority (highest first) then by sequence
            var sortedMessages = _currentBatch
                .OrderByDescending(m => (int)m.Priority)
                .ThenBy(m => m.SequenceNumber)
                .ToList();

            var batch = new MessageBatch
            {
                Messages = sortedMessages,
                CreatedAt = _currentBatchStartedAt ?? DateTime.UtcNow,
                FinalizedAt = DateTime.UtcNow,
                OriginalSizeBytes = _currentBatchSizeBytes,
                Compression = _options.CompressionLevel
            };

            // Apply compression if enabled
            if (_options.CompressionLevel != CompressionLevel.None)
            {
                batch.CompressedPayload = await CompressBatch(batch);
                batch.CompressedSizeBytes = batch.CompressedPayload?.Length ?? _currentBatchSizeBytes;
            }
            else
            {
                batch.CompressedSizeBytes = _currentBatchSizeBytes;
            }

            // Update statistics
            lock (_statistics)
            {
                _statistics.TotalBatchesSent++;
                _statistics.TotalMessagesSent += _currentBatch.Count;
                
                if (_options.CompressionLevel != CompressionLevel.None)
                {
                    var compressionRatio = batch.CompressionRatio;
                    _statistics.AverageCompressionRatio = 
                        (_statistics.AverageCompressionRatio * (_statistics.TotalBatchesSent - 1) + compressionRatio) / 
                        _statistics.TotalBatchesSent;
                    _statistics.TotalBytesSaved += batch.OriginalSizeBytes - batch.CompressedSizeBytes;
                }
            }

            // Clear current batch
            _currentBatch.Clear();
            _currentBatchSizeBytes = 0;
            _currentBatchStartedAt = null;
            _sequenceCounter = 0;

            LoggingManager.LogDebug(nameof(MessageBatcher), 
                $"Created batch {batch.BatchId} with {batch.Messages.Count} messages. " +
                $"Original: {batch.OriginalSizeBytes} bytes, Compressed: {batch.CompressedSizeBytes} bytes");

            return batch;
        }

        private async Task<byte[]> CompressBatch(MessageBatch batch)
        {
            try
            {
                var json = JsonSerializer.Serialize(batch.Messages, new JsonSerializerOptions
                {
                    WriteIndented = false
                });

                var originalBytes = System.Text.Encoding.UTF8.GetBytes(json);

                using var outputStream = new MemoryStream();
                
                // Choose compression algorithm based on level
                var systemCompressionLevel = MapToSystemCompressionLevel(_options.CompressionLevel);
                using (var gzipStream = new SystemCompression.GZipStream(outputStream, systemCompressionLevel))
                {
                    await gzipStream.WriteAsync(originalBytes);
                }

                return outputStream.ToArray();
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(MessageBatcher), 
                    $"Compression failed: {ex.Message}");
                
                // Fall back to uncompressed
                var json = JsonSerializer.Serialize(batch.Messages);
                return System.Text.Encoding.UTF8.GetBytes(json);
            }
        }

        private static long EstimateMessageSize(EncryptedMessage message)
        {
            // Rough estimation of serialized message size
            long size = 0;
            
            size += message.Ciphertext?.Length ?? 0;
            size += message.Nonce?.Length ?? 0;
            size += message.SenderDHKey?.Length ?? 0;
            size += message.MessageId?.Length ?? 0;
            size += message.SessionId?.Length ?? 0;
            size += 100; // Overhead for JSON structure and metadata
            
            return size;
        }

        private static SystemCompression.CompressionLevel MapToSystemCompressionLevel(CompressionLevel level)
        {
            return level switch
            {
                CompressionLevel.Fastest => SystemCompression.CompressionLevel.Fastest,
                CompressionLevel.Optimal => SystemCompression.CompressionLevel.Optimal,
                CompressionLevel.SmallestSize => SystemCompression.CompressionLevel.SmallestSize,
                CompressionLevel.None => SystemCompression.CompressionLevel.NoCompression,
                _ => SystemCompression.CompressionLevel.Optimal
            };
        }

        private async void AutoFlushCallback(object? state)
        {
            if (_disposed)
                return;

            try
            {
                var batch = await GetReadyBatchAsync();
                if (batch != null)
                {
                    LoggingManager.LogDebug(nameof(MessageBatcher), 
                        $"Auto-flushed batch {batch.BatchId} with {batch.Messages.Count} messages");
                }
            }
            catch (Exception ex)
            {
                LoggingManager.LogError(nameof(MessageBatcher), 
                    $"Auto-flush failed: {ex.Message}");
            }
        }

        public void Dispose()
        {
            if (_disposed)
                return;

            _disposed = true;
            
            _flushTimer?.Dispose();
            _batchLock?.Dispose();
            
            GC.SuppressFinalize(this);
        }
    }
}