using LibEmiddle.Domain.Enums;

namespace LibEmiddle.Domain
{
    /// <summary>
    /// Event arguments for session state changes.
    /// </summary>
    public class SessionStateChangedEventArgs : EventArgs
    {
        /// <summary>
        /// Gets the previous state of the session.
        /// </summary>
        public SessionState PreviousState { get; }

        /// <summary>
        /// Gets the new state of the session.
        /// </summary>
        public SessionState NewState { get; }

        /// <summary>
        /// Gets the timestamp when the state change occurred.
        /// </summary>
        public DateTime Timestamp { get; }

        /// <summary>
        /// Initializes a new instance of the SessionStateChangedEventArgs class.
        /// </summary>
        /// <param name="previousState">The previous state.</param>
        /// <param name="newState">The new state.</param>
        public SessionStateChangedEventArgs(SessionState previousState, SessionState newState)
        {
            PreviousState = previousState;
            NewState = newState;
            Timestamp = DateTime.UtcNow;
        }
    }
}