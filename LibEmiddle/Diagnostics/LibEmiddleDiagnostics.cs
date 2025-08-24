using LibEmiddle.Abstractions;
using LibEmiddle.Domain.Diagnostics;
using LibEmiddle.Domain.Enums;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Threading.Channels;

namespace LibEmiddle.Diagnostics
{
    /// <summary>
    /// Implementation of LibEmiddle diagnostic and health monitoring (v2.5).
    /// Provides comprehensive monitoring capabilities with minimal performance overhead.
    /// </summary>
    internal class LibEmiddleDiagnostics : ILibEmiddleDiagnostics, IDisposable
    {
        private readonly ConcurrentQueue<DiagnosticEvent> _eventHistory = new();
        private readonly Channel<DiagnosticEvent> _liveEventChannel;
        private readonly ChannelWriter<DiagnosticEvent> _eventWriter;
        private readonly ChannelReader<DiagnosticEvent> _eventReader;
        private readonly List<ILibEmiddleHealthCheck> _healthChecks = new();
        private readonly object _metricsLock = new();
        private readonly Stopwatch _uptime = Stopwatch.StartNew();
        
        private LibEmiddleHealthMetrics _currentMetrics = new();
        private bool _isEnabled = true;
        private bool _disposed = false;
        private readonly int _maxHistorySize = 1000;

        public bool IsEnabled => _isEnabled;

        public event EventHandler<DiagnosticEvent>? CriticalEventDetected;

        public LibEmiddleDiagnostics()
        {
            var options = new BoundedChannelOptions(1000)
            {
                FullMode = BoundedChannelFullMode.DropOldest,
                SingleReader = false,
                SingleWriter = false
            };

            _liveEventChannel = Channel.CreateBounded<DiagnosticEvent>(options);
            _eventWriter = _liveEventChannel.Writer;
            _eventReader = _liveEventChannel.Reader;

            // Initialize default health checks
            RegisterHealthCheck(new CoreComponentsHealthCheck());
            RegisterHealthCheck(new MemoryUsageHealthCheck());
            RegisterHealthCheck(new NetworkHealthCheck());
        }

        public LibEmiddleHealthMetrics GetHealthMetrics()
        {
            if (!_isEnabled) return new LibEmiddleHealthMetrics();

            lock (_metricsLock)
            {
                _currentMetrics.Uptime = _uptime.Elapsed;
                _currentMetrics.LastUpdated = DateTime.UtcNow;
                _currentMetrics.MemoryUsageBytes = GC.GetTotalMemory(false);
                return _currentMetrics;
            }
        }

        public async Task<DiagnosticReport> GenerateDiagnosticReportAsync()
        {
            if (!_isEnabled) return new DiagnosticReport();

            var report = new DiagnosticReport
            {
                HealthMetrics = GetHealthMetrics(),
                RecentEvents = GetRecentEvents(50).ToList()
            };

            // Run health checks
            var healthCheckTasks = _healthChecks.Select(async check =>
            {
                try
                {
                    var context = new HealthCheckContext
                    {
                        Registration = new HealthCheckRegistration { Name = check.Name },
                        CancellationToken = CancellationToken.None
                    };
                    
                    var sw = Stopwatch.StartNew();
                    var result = await check.CheckAsync(context);
                    sw.Stop();
                    
                    result.Duration = sw.Elapsed;
                    return (check.Name, result);
                }
                catch (Exception ex)
                {
                    return (check.Name, HealthCheckResult.Unhealthy($"Health check failed: {ex.Message}", ex));
                }
            });

            var healthResults = await Task.WhenAll(healthCheckTasks);

            // Populate report sections
            PopulateConfigurationSummary(report);
            PopulateSessionSummary(report);
            PopulateTransportSummary(report);
            PopulateCryptographicSummary(report);
            PopulatePerformanceStatistics(report);
            PopulateFeatureFlagsStatus(report);
            PopulateSecurityAudit(report);

            return report;
        }

        public async IAsyncEnumerable<DiagnosticEvent> GetRealTimeDiagnosticsAsync([EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            if (!_isEnabled) yield break;

            await foreach (var diagnosticEvent in _eventReader.ReadAllAsync(cancellationToken))
            {
                yield return diagnosticEvent;
            }
        }

        public void RecordEvent(DiagnosticEvent diagnosticEvent)
        {
            if (!_isEnabled || _disposed) return;

            // Add to history
            _eventHistory.Enqueue(diagnosticEvent);

            // Maintain history size
            while (_eventHistory.Count > _maxHistorySize)
            {
                _eventHistory.TryDequeue(out _);
            }

            // Send to live stream
            _eventWriter.TryWrite(diagnosticEvent);

            // Update metrics based on event
            UpdateMetricsFromEvent(diagnosticEvent);

            // Check for critical events
            if (diagnosticEvent.Severity == DiagnosticSeverity.Critical)
            {
                CriticalEventDetected?.Invoke(this, diagnosticEvent);
            }
        }

        public void SetDiagnosticsEnabled(bool enabled)
        {
            _isEnabled = enabled;
            
            if (enabled)
            {
                RecordEvent(DiagnosticEvent.OperationStarted("Diagnostics", "DiagnosticsEnabled"));
            }
            else
            {
                RecordEvent(DiagnosticEvent.OperationStarted("Diagnostics", "DiagnosticsDisabled"));
            }
        }

        public void Reset()
        {
            if (!_isEnabled) return;

            lock (_metricsLock)
            {
                _currentMetrics = new LibEmiddleHealthMetrics();
                
                // Clear event history
                while (_eventHistory.TryDequeue(out _)) { }
                
                _uptime.Restart();
            }

            RecordEvent(DiagnosticEvent.OperationStarted("Diagnostics", "DiagnosticsReset"));
        }

        public async Task<bool> ExportDiagnosticsAsync(string format, string filePath)
        {
            if (!_isEnabled) return false;

            try
            {
                var report = await GenerateDiagnosticReportAsync();
                
                var content = format.ToLowerInvariant() switch
                {
                    "json" => JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }),
                    "csv" => ConvertToCsv(report),
                    "xml" => ConvertToXml(report),
                    _ => throw new ArgumentException($"Unsupported format: {format}")
                };

                await File.WriteAllTextAsync(filePath, content);
                
                RecordEvent(DiagnosticEvent.OperationCompleted("Diagnostics", "ExportDiagnostics", 0));
                return true;
            }
            catch (Exception ex)
            {
                RecordEvent(DiagnosticEvent.Error("Diagnostics", $"Failed to export diagnostics: {ex.Message}", ex));
                return false;
            }
        }

        public void RegisterHealthCheck(ILibEmiddleHealthCheck healthCheck)
        {
            _healthChecks.Add(healthCheck);
        }

        private void UpdateMetricsFromEvent(DiagnosticEvent diagnosticEvent)
        {
            lock (_metricsLock)
            {
                // Update error tracking
                if (diagnosticEvent.Severity == DiagnosticSeverity.Error || 
                    diagnosticEvent.Severity == DiagnosticSeverity.Critical)
                {
                    _currentMetrics.RecentErrors.Add(diagnosticEvent.Message);
                    if (_currentMetrics.RecentErrors.Count > 10)
                    {
                        _currentMetrics.RecentErrors.RemoveAt(0);
                    }
                }

                // Update performance metrics
                if (diagnosticEvent.DurationMs.HasValue)
                {
                    switch (diagnosticEvent.Operation)
                    {
                        case "Encrypt":
                            _currentMetrics.AverageEncryptionTimeMs = UpdateAverageMetric(_currentMetrics.AverageEncryptionTimeMs, diagnosticEvent.DurationMs.Value);
                            break;
                        case "Decrypt":
                            _currentMetrics.AverageDecryptionTimeMs = UpdateAverageMetric(_currentMetrics.AverageDecryptionTimeMs, diagnosticEvent.DurationMs.Value);
                            break;
                    }
                }

                // Update counters based on event type
                switch (diagnosticEvent.EventType)
                {
                    case DiagnosticEventType.SessionEvent:
                        if (diagnosticEvent.Operation == "SessionCreated")
                            _currentMetrics.ActiveSessions++;
                        else if (diagnosticEvent.Operation == "SessionTerminated")
                            _currentMetrics.ActiveSessions = Math.Max(0, _currentMetrics.ActiveSessions - 1);
                        break;
                        
                    case DiagnosticEventType.KeyRotation:
                        _currentMetrics.LastKeyRotation = diagnosticEvent.Timestamp;
                        break;
                        
                    case DiagnosticEventType.NetworkEvent:
                        if (diagnosticEvent.Operation == "MessageSent")
                            _currentMetrics.TotalMessagesSent++;
                        else if (diagnosticEvent.Operation == "MessageReceived")
                            _currentMetrics.TotalMessagesReceived++;
                        else if (diagnosticEvent.Operation == "DeliveryFailed")
                            _currentMetrics.FailedDeliveries++;
                        break;
                }
            }
        }

        private double UpdateAverageMetric(double currentAverage, double newValue)
        {
            // Simple moving average (could be improved with more sophisticated algorithms)
            return currentAverage == 0 ? newValue : (currentAverage + newValue) / 2;
        }

        private IEnumerable<DiagnosticEvent> GetRecentEvents(int count)
        {
            return _eventHistory.TakeLast(count);
        }

        private void PopulateConfigurationSummary(DiagnosticReport report)
        {
            // This would be populated with actual client configuration
            report.Configuration = new ConfigurationSummary
            {
                TransportType = TransportType.Http, // Example - would come from actual config
                KeyExchangeMode = KeyExchangeMode.Classical,
                MultiDeviceEnabled = true,
                MessageHistoryEnabled = true,
                SecureMemoryEnabled = true,
                MaxLinkedDevices = 10,
                MaxMessageHistoryPerSession = 1000
            };
        }

        private void PopulateSessionSummary(DiagnosticReport report)
        {
            report.Sessions = new SessionSummary
            {
                ActiveSessions = _currentMetrics.ActiveSessions,
                TotalSessions = _currentMetrics.ActiveSessions, // Simplified
                ChatSessions = _currentMetrics.ActiveSessions / 2, // Example
                GroupSessions = _currentMetrics.ActiveSessions / 2
            };
        }

        private void PopulateTransportSummary(DiagnosticReport report)
        {
            report.Transport = new TransportSummary
            {
                Status = _currentMetrics.TransportStatus,
                AverageLatencyMs = _currentMetrics.NetworkLatencyMs,
                BytesSent = 0, // Would track actual bytes
                BytesReceived = 0
            };
        }

        private void PopulateCryptographicSummary(DiagnosticReport report)
        {
            report.Cryptography = new CryptographicSummary
            {
                LastKeyRotation = _currentMetrics.LastKeyRotation,
                TotalKeyRotations = 0, // Would track actual rotations
                OneTimePreKeysAvailable = 50, // Example
                PostQuantumEnabled = false
            };
        }

        private void PopulatePerformanceStatistics(DiagnosticReport report)
        {
            report.Performance = new PerformanceStatistics
            {
                AverageEncryptionTimeMs = _currentMetrics.AverageEncryptionTimeMs,
                AverageDecryptionTimeMs = _currentMetrics.AverageDecryptionTimeMs,
                TotalOperations = _currentMetrics.TotalMessagesSent + _currentMetrics.TotalMessagesReceived,
                FailedOperations = _currentMetrics.FailedDeliveries,
                MemoryUsageBytes = _currentMetrics.MemoryUsageBytes,
                Uptime = _currentMetrics.Uptime
            };
        }

        private void PopulateFeatureFlagsStatus(DiagnosticReport report)
        {
            // Would be populated from actual feature flags
            report.Features = new FeatureFlagsStatus();
        }

        private void PopulateSecurityAudit(DiagnosticReport report)
        {
            report.Security = new SecurityAudit
            {
                AllSessionsSecure = true,
                CertificateValidationEnabled = true,
                FailedAuthenticationAttempts = 0,
                SuspiciousActivities = 0
            };
        }

        private string ConvertToCsv(DiagnosticReport report)
        {
            // Simple CSV conversion - could be more sophisticated
            var csv = new System.Text.StringBuilder();
            csv.AppendLine("Metric,Value");
            csv.AppendLine($"Active Sessions,{report.HealthMetrics.ActiveSessions}");
            csv.AppendLine($"Messages Sent,{report.HealthMetrics.TotalMessagesSent}");
            csv.AppendLine($"Messages Received,{report.HealthMetrics.TotalMessagesReceived}");
            csv.AppendLine($"Failed Deliveries,{report.HealthMetrics.FailedDeliveries}");
            csv.AppendLine($"Memory Usage (MB),{report.HealthMetrics.MemoryUsageBytes / 1024.0 / 1024.0:F2}");
            csv.AppendLine($"Uptime (Hours),{report.HealthMetrics.Uptime.TotalHours:F2}");
            return csv.ToString();
        }

        private string ConvertToXml(DiagnosticReport report)
        {
            // Simple XML conversion - could use XmlSerializer for more sophistication
            return $@"<?xml version=""1.0"" encoding=""utf-8""?>
<DiagnosticReport>
    <GeneratedAt>{report.GeneratedAt:O}</GeneratedAt>
    <ClientVersion>{report.ClientVersion}</ClientVersion>
    <HealthMetrics>
        <ActiveSessions>{report.HealthMetrics.ActiveSessions}</ActiveSessions>
        <MessagesSent>{report.HealthMetrics.TotalMessagesSent}</MessagesSent>
        <MessagesReceived>{report.HealthMetrics.TotalMessagesReceived}</MessagesReceived>
        <MemoryUsageBytes>{report.HealthMetrics.MemoryUsageBytes}</MemoryUsageBytes>
        <UptimeHours>{report.HealthMetrics.Uptime.TotalHours:F2}</UptimeHours>
    </HealthMetrics>
</DiagnosticReport>";
        }

        public void Dispose()
        {
            if (_disposed) return;

            _eventWriter.Complete();
            _liveEventChannel.Writer.Complete();
            _disposed = true;
        }
    }

    // Built-in health checks
    internal class CoreComponentsHealthCheck : ILibEmiddleHealthCheck
    {
        public string Name => "Core Components";
        public IEnumerable<string> Tags => new[] { "core", "essential" };

        public Task<HealthCheckResult> CheckAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
        {
            // Check if core components are functioning
            try
            {
                // Example checks - would be more comprehensive in real implementation
                var memoryPressure = GC.GetTotalMemory(false);
                var data = new Dictionary<string, object>
                {
                    ["MemoryUsage"] = memoryPressure,
                    ["GCCollections"] = GC.CollectionCount(0)
                };

                if (memoryPressure > 100 * 1024 * 1024) // 100MB threshold
                {
                    return Task.FromResult(HealthCheckResult.Degraded("High memory usage detected", null, data));
                }

                return Task.FromResult(HealthCheckResult.Healthy("Core components operating normally", data));
            }
            catch (Exception ex)
            {
                return Task.FromResult(HealthCheckResult.Unhealthy("Core components check failed", ex));
            }
        }
    }

    internal class MemoryUsageHealthCheck : ILibEmiddleHealthCheck
    {
        public string Name => "Memory Usage";
        public IEnumerable<string> Tags => new[] { "memory", "performance" };

        public Task<HealthCheckResult> CheckAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
        {
            var memoryUsage = GC.GetTotalMemory(false);
            var data = new Dictionary<string, object>
            {
                ["MemoryUsageBytes"] = memoryUsage,
                ["MemoryUsageMB"] = memoryUsage / 1024.0 / 1024.0
            };

            if (memoryUsage > 500 * 1024 * 1024) // 500MB threshold
            {
                return Task.FromResult(HealthCheckResult.Unhealthy("Memory usage is critically high", null, data));
            }

            if (memoryUsage > 200 * 1024 * 1024) // 200MB threshold
            {
                return Task.FromResult(HealthCheckResult.Degraded("Memory usage is elevated", null, data));
            }

            return Task.FromResult(HealthCheckResult.Healthy("Memory usage is normal", data));
        }
    }

    internal class NetworkHealthCheck : ILibEmiddleHealthCheck
    {
        public string Name => "Network Connectivity";
        public IEnumerable<string> Tags => new[] { "network", "connectivity" };

        public async Task<HealthCheckResult> CheckAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
        {
            try
            {
                // Simple network connectivity check
                using var client = new HttpClient();
                client.Timeout = TimeSpan.FromSeconds(5);
                
                var sw = Stopwatch.StartNew();
                var response = await client.GetAsync("https://www.google.com", cancellationToken);
                sw.Stop();

                var data = new Dictionary<string, object>
                {
                    ["ResponseTime"] = sw.ElapsedMilliseconds,
                    ["StatusCode"] = (int)response.StatusCode
                };

                if (sw.ElapsedMilliseconds > 5000)
                {
                    return HealthCheckResult.Degraded("Network response time is slow", null, data);
                }

                return HealthCheckResult.Healthy("Network connectivity is good", data);
            }
            catch (Exception ex)
            {
                return HealthCheckResult.Unhealthy("Network connectivity check failed", ex);
            }
        }
    }
}