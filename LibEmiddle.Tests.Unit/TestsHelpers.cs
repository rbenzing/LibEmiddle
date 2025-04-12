using LibEmiddle.Core;

namespace LibEmiddle.Tests.Unit
{
    public static class TestsHelpers
    {
        /// <summary>
        /// Helper method for byte array comparison
        /// </summary>
        public static bool AreByteArraysEqual(byte[] a, byte[] b)
        {
            // Use the secure comparison for consistent behavior
            return SecureMemory.SecureCompare(a, b);
        }
    }
}
