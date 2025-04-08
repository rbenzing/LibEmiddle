using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace E2EELibrary.Core
{
    /// <summary>
    /// Centralized logging manager for the E2EE library
    /// </summary>
    public static class LoggingManager
    {
        // Default to NullLogger if no logger is provided
        private static ILogger _defaultLogger = NullLogger.Instance;

        /// <summary>
        /// Configures the default logger to use throughout the library
        /// </summary>
        /// <param name="logger">The logger to use as default</param>
        public static void SetDefaultLogger(ILogger logger)
        {
            _defaultLogger = logger ?? NullLogger.Instance;
        }

        /// <summary>
        /// Logs an error message with optional exception details
        /// </summary>
        /// <param name="category">The category name for the log</param>
        /// <param name="message">The message to log</param>
        /// <param name="exception">Optional exception</param>
        public static void LogError(string category, string message, Exception? exception = null)
        {
            // Log to default logger if available
            if (_defaultLogger != NullLogger.Instance)
            {
                if (exception != null)
                {
                    _defaultLogger.LogError(exception, message);
                }
                else
                {
                    _defaultLogger.LogError(message);
                }
            }

            // Always fall back to Trace
            if (exception != null)
            {
                Trace.TraceError($"[{category}] {message} - Exception: {exception.Message}");
            }
            else
            {
                Trace.TraceError($"[{category}] {message}");
            }
        }

        /// <summary>
        /// Logs a warning message
        /// </summary>
        /// <param name="category">The category name for the log</param>
        /// <param name="message">The message to log</param>
        public static void LogWarning(string category, string message)
        {
            // Log to default logger if available
            if (_defaultLogger != NullLogger.Instance)
            {
                _defaultLogger.LogWarning(message);
            }

            // Always fall back to Trace
            Trace.TraceWarning($"[{category}] {message}");
        }

        /// <summary>
        /// Logs an information message
        /// </summary>
        /// <param name="category">The category name for the log</param>
        /// <param name="message">The message to log</param>
        public static void LogInformation(string category, string message)
        {
            // Log to default logger if available
            if (_defaultLogger != NullLogger.Instance)
            {
                _defaultLogger.LogInformation(message);
            }

            // Always fall back to Trace
            Trace.TraceInformation($"[{category}] {message}");
        }

        /// <summary>
        /// Logs a security-related message with increased visibility
        /// </summary>
        /// <param name="category">The category name for the log</param>
        /// <param name="message">The message to log</param>
        /// <param name="isAlert">If true, logs as error level; otherwise, logs as warning</param>
        public static void LogSecurityEvent(string category, string message, bool isAlert = false)
        {
            if (isAlert)
            {
                // Log to default logger if available
                if (_defaultLogger != NullLogger.Instance)
                {
                    _defaultLogger.LogError("[SECURITY ALERT] {Message}", message);
                }

                Trace.TraceError($"[{category}] [SECURITY ALERT] {message}");
            }
            else
            {
                // Log to default logger if available
                if (_defaultLogger != NullLogger.Instance)
                {
                    _defaultLogger.LogWarning("[SECURITY WARNING] {Message}", message);
                }

                Trace.TraceWarning($"[{category}] [SECURITY WARNING] {message}");
            }
        }
    }
}