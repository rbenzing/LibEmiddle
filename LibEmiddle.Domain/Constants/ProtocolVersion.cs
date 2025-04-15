#pragma warning disable IDE0130 // Namespace does not match folder structure
namespace LibEmiddle.Domain
#pragma warning restore IDE0130 // Namespace does not match folder structure
{
    /// <summary>
    /// Versioning strategy
    /// </summary>
    public static class ProtocolVersion
    {
        /// <summary>
        /// Major version changes indicate breaking protocol changes
        /// </summary>
        public const int MAJOR_VERSION = 1;

        /// <summary>
        /// Minor version changes indicate non-breaking enhancements
        /// </summary>
        public const int MINOR_VERSION = 2;

        /// <summary>
        /// The legacy version
        /// </summary>
        public const string? LEGACY_VERSION = null;

        /// <summary>
        /// Protocol identifier string
        /// </summary>
        public const string PROTOCOL_ID = "LibEmiddle";

        /// <summary>
        /// Full version string
        /// </summary>
        public static readonly string FULL_VERSION = $"{PROTOCOL_ID}/v{MAJOR_VERSION}.{MINOR_VERSION}";

        /// <summary>
        /// Minimum supported version for compatibility
        /// </summary>
        public const int MIN_SUPPORTED_MAJOR_VERSION = 1;

        /// <summary>
        /// Helper method to check compatibility
        /// </summary>
        /// <param name="otherMajorVersion"></param>
        /// <param name="otherMinorVersion"></param>
        /// <returns></returns>
        public static bool IsCompatible(int otherMajorVersion, int otherMinorVersion)
        {
            // Same major version is compatible
            if (otherMajorVersion == MAJOR_VERSION)
                return true;

            // Older versions are compatible if they're at or above the minimum
            return otherMajorVersion >= MIN_SUPPORTED_MAJOR_VERSION;
        }
    }
}
