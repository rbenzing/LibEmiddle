using LibEmiddle.Domain.Enums;
using LibEmiddle.Domain;

namespace LibEmiddle.Abstractions
{
    /// <summary>
    /// Defines the base interface for all types of cryptographic sessions.
    /// </summary>
    public interface ISession
    {
        /// <summary>
        /// Gets the unique identifier for this session.
        /// </summary>
        string SessionId { get; }

        /// <summary>
        /// Gets the type of this session.
        /// </summary>
        SessionType Type { get; }

        /// <summary>
        /// Gets the current state of this session.
        /// </summary>
        SessionState State { get; }

        /// <summary>
        /// Event raised when the session state changes.
        /// </summary>
        event EventHandler<SessionStateChangedEventArgs>? StateChanged;

        /// <summary>
        /// Activates the session, enabling it to send and receive messages.
        /// </summary>
        /// <returns>True if the session was activated, false if it was already active.</returns>
        Task<bool> ActivateAsync();

        /// <summary>
        /// Suspends the session, temporarily preventing it from sending and receiving messages.
        /// </summary>
        /// <param name="reason">Optional reason for suspension.</param>
        /// <returns>True if the session was suspended, false if it was already suspended.</returns>
        Task<bool> SuspendAsync(string? reason = null);

        /// <summary>
        /// Terminates the session permanently, preventing any further communication.
        /// </summary>
        /// <returns>True if the session was terminated, false if it was already terminated.</returns>
        Task<bool> TerminateAsync();
    }
}
