using Microsoft.Extensions.DependencyInjection;

namespace LibEmiddle.API;

/// <summary>
/// Extension methods for registering LibEmiddle services with Microsoft DI.
/// </summary>
public static class LibEmiddleServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="LibEmiddleClient"/> as <see cref="ILibEmiddleClient"/> with a singleton lifetime.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Delegate to configure <see cref="LibEmiddleClientOptions"/>.</param>
    /// <returns>The same <see cref="IServiceCollection"/> for chaining.</returns>
    public static IServiceCollection AddLibEmiddle(
        this IServiceCollection services,
        Action<LibEmiddleClientOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        var options = new LibEmiddleClientOptions();
        configure(options);

        services.AddSingleton<ILibEmiddleClient>(_ => new LibEmiddleClient(options));
        return services;
    }

    /// <summary>
    /// Registers <see cref="LibEmiddleClient"/> as <see cref="ILibEmiddleClient"/> with a singleton lifetime,
    /// using a pre-built <see cref="LibEmiddleClientOptions"/> instance.
    /// </summary>
    public static IServiceCollection AddLibEmiddle(
        this IServiceCollection services,
        LibEmiddleClientOptions options)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(options);

        services.AddSingleton<ILibEmiddleClient>(_ => new LibEmiddleClient(options));
        return services;
    }
}
