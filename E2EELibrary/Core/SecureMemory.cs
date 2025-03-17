using System.Buffers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace E2EELibrary.Core
{
    /// <summary>
    /// Provides utilities for securely handling sensitive data in memory.
    /// Ensures that cryptographic materials are properly cleared when no longer needed.
    /// </summary>
    public static class SecureMemory
    {
        /// <summary>
        /// Securely clears sensitive data from memory.
        /// </summary>
        /// <param name="data">Data to clear</param>
        public static void SecureClear(byte[] data)
        {
            if (data == null || data.Length == 0)
                return;

            // Use CryptographicOperations.ZeroMemory where available
            try
            {
                CryptographicOperations.ZeroMemory(data.AsSpan());
            }
            catch (PlatformNotSupportedException)
            {
                // Fallback for platforms that don't support CryptographicOperations
                var span = data.AsSpan();
                for (int i = 0; i < span.Length; i++)
                {
                    span[i] = 0;
                }

                // Add a memory barrier to prevent reordering
                Thread.MemoryBarrier();
            }

            // Additional protection against optimizations
            GC.KeepAlive(data);

            // Inform runtime that the following code is in a constrained execution region
            RuntimeHelpers.PrepareConstrainedRegions();
        }

        /// <summary>
        /// Compares two byte arrays for equality in constant time to prevent timing attacks.
        /// The time taken is proportional to the length of the arrays being compared,
        /// not to how many bytes match.
        /// </summary>
        /// <param name="a">First byte array</param>
        /// <param name="b">Second byte array</param>
        /// <returns>True if arrays are equal</returns>
        public static bool SecureCompare(byte[] a, byte[] b)
        {
            // Handle null cases
            if (a == null && b == null)
                return true;
            if (a == null || b == null)
                return false;

            int lengthA = a.Length;
            int lengthB = b.Length;

            // Calculate the maximum length
            int maxLength = Math.Max(lengthA, lengthB);

            // Start with a non-zero value if lengths differ
            uint result = (uint)(lengthA ^ lengthB);

            // Iterate through all positions up to the maximum length
            for (int i = 0; i < maxLength; i++)
            {
                // For indices beyond the actual array length, use 0
                byte valueA = i < lengthA ? a[i] : (byte)0;
                byte valueB = i < lengthB ? b[i] : (byte)0;

                // XOR the bytes and OR into result
                result |= (uint)(valueA ^ valueB);
            }

            // Return true only if all comparisons were equal
            return result == 0;
        }

        /// <summary>
        /// Creates a secure copy of a byte array to prevent modification of the original data.
        /// </summary>
        /// <param name="source">The source array to copy</param>
        /// <returns>A new array containing a copy of the source data</returns>
        public static byte[]? SecureCopy(byte[] source)
        {
            ArgumentNullException.ThrowIfNull(source, nameof(source));

            byte[] copy = new byte[source.Length];
            source.AsSpan().CopyTo(copy.AsSpan());
            return copy;
        }

        /// <summary>
        /// Creates a secure buffer for sensitive cryptographic operations.
        /// </summary>
        /// <param name="size">Size of the buffer in bytes</param>
        /// <param name="usePool">Whether to use buffer pooling for better performance</param>
        /// <returns>A new secure buffer</returns>
        public static byte[] CreateSecureBuffer(int size, bool usePool = true)
        {
            return CreateBuffer(size, usePool, isSecure: true);
        }

        /// <summary>
        /// Returns a buffer to the pool, securely clearing it if needed.
        /// </summary>
        /// <param name="buffer">Buffer to return</param>
        /// <param name="isSecure">Whether the buffer contains sensitive data to clear</param>
        public static void ReturnBuffer(byte[] buffer, bool isSecure = false)
        {
            if (buffer == null) return;

            // Only process buffers that are likely from the pool
            if (buffer.Length > 1024 * 16) return;

            // Clear sensitive data if needed
            if (isSecure)
            {
                SecureClear(buffer);
            }

            // Return to the pool
            ArrayPool<byte>.Shared.Return(buffer);
        }

        /// <summary>
        /// Creates a buffer of the specified size, optionally using the array pool 
        /// with secure handling for sensitive data.
        /// </summary>
        /// <param name="size">Size of the buffer in bytes</param>
        /// <param name="usePool">Whether to use the shared buffer pool</param>
        /// <param name="isSecure">Whether this buffer will contain sensitive data</param>
        /// <returns>A new byte array of the requested size</returns>
        public static byte[] CreateBuffer(int size, bool usePool = true, bool isSecure = false)
        {
            if (size <= 0)
                throw new ArgumentException("Buffer size must be positive", nameof(size));

            // For very large buffers, avoid the pool to prevent impact on other operations
            if (!usePool || size > 1024 * 16)
            {
                return new byte[size];
            }

            // For smaller buffers, rent from the pool
            byte[] rentedBuffer = ArrayPool<byte>.Shared.Rent(size);
            try
            {
                // For secure buffers, clear the rented buffer first to avoid data leakage
                if (isSecure)
                {
                    SecureClear(rentedBuffer);
                }

                // Create a properly sized result buffer
                byte[] result = new byte[size];

                // Only copy data from the rental buffer if needed (if we're reusing a larger buffer)
                if (rentedBuffer.Length > size)
                {
                    rentedBuffer.AsSpan(0, size).CopyTo(result.AsSpan());
                }
                else
                {
                    // Direct buffer usage - optimization to avoid unnecessary copying
                    // This is safe because we've ensured the exact size above
                    return rentedBuffer;
                }

                return result;
            }
            catch
            {
                // Clear sensitive data on exceptions
                if (isSecure)
                {
                    SecureClear(rentedBuffer);
                }

                // Return the buffer to the pool
                ArrayPool<byte>.Shared.Return(rentedBuffer);
                throw;
            }
            finally
            {
                // Only return the buffer if we made a copy (we didn't return the rented buffer directly)
                if (rentedBuffer.Length > size)
                {
                    // Clear rented buffer before returning it if it might contain sensitive data
                    if (isSecure)
                    {
                        SecureClear(rentedBuffer);
                    }

                    ArrayPool<byte>.Shared.Return(rentedBuffer);
                }
            }
        }
    }
}