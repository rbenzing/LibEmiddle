using LibEmiddle.Domain.Enums;
using Microsoft.Extensions.Logging;

namespace LibEmiddle.API.Builders
{
    /// <summary>
    /// Fluent builder interface for creating LibEmiddle clients (v2.5).
    /// Provides a modern, discoverable API for client configuration.
    /// </summary>
    public interface ILibEmiddleClientBuilder
    {
        /// <summary>
        /// Configures the identity key storage path.
        /// </summary>
        /// <param name="keyPath">Path where the identity key will be stored.</param>
        /// <returns>The builder instance for method chaining.</returns>
        ILibEmiddleClientBuilder WithIdentity(string keyPath);

        /// <summary>
        /// Configures the transport type to use.
        /// </summary>
        /// <typeparam name="T">The transport implementation type.</typeparam>
        /// <returns>The builder instance for method chaining.</returns>
        ILibEmiddleClientBuilder WithTransport<T>() where T : class;

        /// <summary>
        /// Configures the transport type and endpoint.
        /// </summary>
        /// <param name="transportType">The transport type to use.</param>
        /// <param name="endpoint">The endpoint URL for HTTP/WebSocket transports.</param>
        /// <returns>The builder instance for method chaining.</returns>
        ILibEmiddleClientBuilder WithTransport(TransportType transportType, string? endpoint = null);

        /// <summary>
        /// Configures security settings.
        /// </summary>
        /// <param name="configure">Action to configure security options.</param>
        /// <returns>The builder instance for method chaining.</returns>
        ILibEmiddleClientBuilder WithSecurity(Action<ISecurityOptionsBuilder> configure);

        /// <summary>
        /// Configures multi-device settings.
        /// </summary>
        /// <param name="configure">Action to configure multi-device options.</param>
        /// <returns>The builder instance for method chaining.</returns>
        ILibEmiddleClientBuilder WithMultiDevice(Action<IMultiDeviceOptionsBuilder> configure);

        /// <summary>
        /// Configures storage settings.
        /// </summary>
        /// <param name="configure">Action to configure storage options.</param>
        /// <returns>The builder instance for method chaining.</returns>
        ILibEmiddleClientBuilder WithStorage(Action<IStorageOptionsBuilder> configure);

        /// <summary>
        /// Configures logging settings.
        /// </summary>
        /// <param name="logger">The logger instance to use.</param>
        /// <returns>The builder instance for method chaining.</returns>
        ILibEmiddleClientBuilder WithLogging(ILogger logger);

        /// <summary>
        /// Configures logging settings.
        /// </summary>
        /// <param name="configure">Action to configure logging options.</param>
        /// <returns>The builder instance for method chaining.</returns>
        ILibEmiddleClientBuilder WithLogging(Action<ILoggingOptionsBuilder> configure);

        /// <summary>
        /// Configures performance settings.
        /// </summary>
        /// <param name="configure">Action to configure performance options.</param>
        /// <returns>The builder instance for method chaining.</returns>
        ILibEmiddleClientBuilder WithPerformance(Action<IPerformanceOptionsBuilder> configure);

        /// <summary>
        /// Enables v2.5 features.
        /// </summary>
        /// <param name="configure">Action to configure v2.5 features.</param>
        /// <returns>The builder instance for method chaining.</returns>
        ILibEmiddleClientBuilder WithV25Features(Action<IV25FeaturesBuilder> configure);

        /// <summary>
        /// Enables all stable v2.5 features for beta testing.
        /// </summary>
        /// <returns>The builder instance for method chaining.</returns>
        ILibEmiddleClientBuilder EnableStableBeta();

        /// <summary>
        /// Configures custom options directly.
        /// </summary>
        /// <param name="configure">Action to configure the options object.</param>
        /// <returns>The builder instance for method chaining.</returns>
        ILibEmiddleClientBuilder WithCustomOptions(Action<LibEmiddleClientOptions> configure);

        /// <summary>
        /// Builds the LibEmiddle client with the configured options.
        /// </summary>
        /// <returns>A new LibEmiddle client instance.</returns>
        LibEmiddleClient Build();

        /// <summary>
        /// Builds the client options without creating a client instance.
        /// Useful for validation or creating multiple clients with the same configuration.
        /// </summary>
        /// <returns>The configured client options.</returns>
        LibEmiddleClientOptions BuildOptions();
    }
}