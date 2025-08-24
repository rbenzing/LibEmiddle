using LibEmiddle.Domain.Enums;

namespace LibEmiddle.API.Builders
{
    /// <summary>
    /// Static factory for creating LibEmiddle client builders (v2.5).
    /// Provides entry points for fluent client configuration.
    /// </summary>
    public static class LibEmiddleClientBuilder
    {
        /// <summary>
        /// Creates a new fluent client builder.
        /// </summary>
        /// <returns>A new client builder instance.</returns>
        public static ILibEmiddleClientBuilder Create()
        {
            return new LibEmiddleClientBuilderInternal();
        }

        /// <summary>
        /// Creates a client from existing options (compatibility method).
        /// This method maintains backward compatibility with the existing constructor pattern.
        /// </summary>
        /// <param name="options">Pre-configured client options.</param>
        /// <returns>A new LibEmiddle client instance.</returns>
        public static LibEmiddleClient CreateFromOptions(LibEmiddleClientOptions options)
        {
            return new LibEmiddleClient(options);
        }

        /// <summary>
        /// Creates a client with default options (development convenience).
        /// </summary>
        /// <returns>A new LibEmiddle client with default settings.</returns>
        public static LibEmiddleClient CreateDefault()
        {
            var options = new LibEmiddleClientOptions();
            return new LibEmiddleClient(options);
        }

        /// <summary>
        /// Creates a client optimized for development and testing.
        /// </summary>
        /// <returns>A new LibEmiddle client with development-friendly settings.</returns>
        public static LibEmiddleClient CreateForDevelopment()
        {
            return Create()
                .WithTransport(TransportType.InMemory)
                .WithLogging(logging => logging
                    .SetLogLevel(LogLevel.Debug)
                    .EnableDebugLogging()
                    .EnablePerformanceMetrics())
                .WithStorage(storage => storage
                    .DisableSessionPersistence()
                    .SetMaxMessageHistory(100))
                .EnableStableBeta()
                .Build();
        }

        /// <summary>
        /// Creates a client optimized for production use.
        /// </summary>
        /// <param name="endpoint">The production endpoint URL.</param>
        /// <returns>A new LibEmiddle client with production-optimized settings.</returns>
        public static ILibEmiddleClientBuilder CreateForProduction(string endpoint)
        {
            return Create()
                .WithTransport(TransportType.Http, endpoint)
                .WithSecurity(security => security
                    .RequirePerfectForwardSecrecy()
                    .RequireMessageAuthentication()
                    .SetMinimumProtocolVersion("2.5"))
                .WithLogging(logging => logging
                    .SetLogLevel(LogLevel.Warning))
                .WithPerformance(perf => perf
                    .EnableCompression()
                    .WithConnectionPooling(pool => pool
                        .UseHighPerformancePreset())
                    .WithBatching(batch => batch
                        .UseHighThroughputPreset()));
        }
    }
}