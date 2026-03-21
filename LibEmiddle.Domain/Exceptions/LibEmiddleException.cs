namespace LibEmiddle.Domain.Exceptions
{
    /// <summary>
    /// The base exception type for LibEmiddle. Carries a <see cref="LibEmiddleErrorCode"/>
    /// so callers can distinguish transient failures (e.g. <see cref="LibEmiddleErrorCode.TransportError"/>)
    /// from permanent ones (e.g. <see cref="LibEmiddleErrorCode.InvalidKey"/>).
    /// </summary>
    public class LibEmiddleException : Exception
    {
        /// <summary>Gets the structured error code that describes the failure.</summary>
        public LibEmiddleErrorCode ErrorCode { get; }

        /// <summary>
        /// Initialises a new instance of <see cref="LibEmiddleException"/>.
        /// </summary>
        /// <param name="message">A human-readable description of the error.</param>
        /// <param name="code">The structured error code.</param>
        /// <param name="innerException">An optional inner exception that caused this error.</param>
        public LibEmiddleException(
            string message,
            LibEmiddleErrorCode code,
            Exception? innerException = null)
            : base(message, innerException)
        {
            ErrorCode = code;
        }
    }
}
