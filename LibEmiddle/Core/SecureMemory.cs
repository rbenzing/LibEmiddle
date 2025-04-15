using System.Buffers;
using System.Runtime.InteropServices;

namespace LibEmiddle.Core
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
        public static void SecureClear(byte[]? data)
        {
            if (data == null || data.Length == 0)
                return;

            // Pin memory so GC doesn't move it during operation
            GCHandle handle = GCHandle.Alloc(data, GCHandleType.Pinned);
            try
            {
                // Use libsodium's native sodium_memzero
                Sodium.sodium_memzero(handle.AddrOfPinnedObject(), (UIntPtr)data.Length);
            }
            finally
            {
                handle.Free();
            }

            GC.KeepAlive(data);
        }

        /// <summary>
        /// Compares two byte arrays in constant time to prevent timing attacks.
        /// </summary>
        /// <param name="a">First byte array</param>
        /// <param name="b">Second byte array</param>
        /// <returns>True if arrays are equal, false otherwise</returns>
        public static bool SecureCompare(byte[] a, byte[] b)
        {
            // Handle null cases
            if (a == null && b == null)
                return true;
            if (a == null || b == null)
                return false;

            // If lengths differ, return false but still do a comparison with the shared length
            // to ensure constant-time operation regardless of where arrays differ
            int minLength = Math.Min(a.Length, b.Length);
            int result;

            // Pin both arrays to get stable memory addresses
            GCHandle handleA = GCHandle.Alloc(a, GCHandleType.Pinned);
            GCHandle handleB = GCHandle.Alloc(b, GCHandleType.Pinned);

            try
            {
                // Compare only up to the minimum length to avoid buffer overruns
                IntPtr ptrA = handleA.AddrOfPinnedObject();
                IntPtr ptrB = handleB.AddrOfPinnedObject();

                result = Sodium.sodium_memcmp(ptrA, ptrB, (UIntPtr)minLength);
            }
            finally
            {
                // Always release handles to avoid memory leaks
                if (handleA.IsAllocated)
                    handleA.Free();
                if (handleB.IsAllocated)
                    handleB.Free();
            }

            // Return true only if the comparison succeeds AND lengths are identical
            return result == 0 && a.Length == b.Length;
        }

        /// <summary>
        /// Creates a secure copy of a byte array to prevent modification of the original data.
        /// </summary>
        /// <param name="source">The source array to copy</param>
        /// <returns>A new array containing a copy of the source data</returns>
        public static byte[] SecureCopy(byte[] source)
        {
            ArgumentNullException.ThrowIfNull(source, nameof(source));

            byte[] copy = Sodium.GenerateRandomBytes(source.Length);
            source.AsSpan().CopyTo(copy.AsSpan());
            return copy;
        }

        /// <summary>
        /// Creates a secure buffer using libsodium's protected memory allocation.
        /// </summary>
        /// <param name="size">Size of the buffer in bytes</param>
        /// <returns>A new secure buffer</returns>
        public static byte[] CreateSecureBuffer(int size)
        {
            if (size <= 0)
                throw new ArgumentException("Buffer size must be positive", nameof(size));

            // Allocate memory using sodium_malloc
            IntPtr ptr = Sodium.sodium_malloc((UIntPtr)size);
            if (ptr == IntPtr.Zero)
                throw new OutOfMemoryException("Failed to allocate secure memory");

            // Create a byte array from this memory
            byte[] buffer = Sodium.GenerateRandomBytes(size);

            // Copy the allocated memory to the managed array
            Marshal.Copy(ptr, buffer, 0, size);

            // Free the sodium_malloc memory - this is separate from the managed buffer
            Sodium.sodium_free(ptr);

            return buffer;
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
                return Sodium.GenerateRandomBytes(size);
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

        /// <summary>
        /// Secure array implementation
        /// </summary>
        /// <typeparam name="T"></typeparam>
        public sealed class SecureArray<T> : IDisposable where T : struct
        {
            private readonly T[] _array;
            private bool _disposed = false;
            private bool _isLocked = false;

            /// <summary>
            /// Secure array by length
            /// </summary>
            /// <param name="length"></param>
            public SecureArray(int length)
            {
                _array = new T[length];
                LockArray();
            }

            /// <summary>
            /// Secure array from existing
            /// </summary>
            /// <param name="existingArray"></param>
            public SecureArray(T[] existingArray)
            {
                _array = new T[existingArray.Length];
                existingArray.CopyTo(_array, 0);
                LockArray();
            }

            private void LockArray()
            {
                if (typeof(T) == typeof(byte) && !_isLocked)
                {
                    // Pin the array to get a stable memory address
                    GCHandle handle = GCHandle.Alloc(_array, GCHandleType.Pinned);
                    try
                    {
                        // Get address of pinned array and call sodium_mlock
                        IntPtr ptr = handle.AddrOfPinnedObject();
                        Sodium.sodium_mlock(ptr, (UIntPtr)(_array.Length * Marshal.SizeOf<T>()));
                        _isLocked = true;
                    }
                    finally
                    {
                        // Important: Free the handle when done
                        handle.Free();
                    }
                }
            }

            /// <summary>
            /// Check if value is disposed
            /// </summary>
            public T[] Value => _disposed ? throw new ObjectDisposedException(nameof(SecureArray<T>)) : _array;

            /// <summary>
            /// Memory cleanup
            /// </summary>
            public void Dispose()
            {
                if (!_disposed)
                {
                    if (typeof(T) == typeof(byte))
                    {
                        if (_isLocked)
                        {
                            // Pin the array to get a stable memory address
                            GCHandle handle = GCHandle.Alloc(_array, GCHandleType.Pinned);
                            try
                            {
                                // Get address of pinned array and call sodium_munlock
                                IntPtr ptr = handle.AddrOfPinnedObject();
                                Sodium.sodium_munlock(ptr, (UIntPtr)(_array.Length * Marshal.SizeOf<T>()));
                            }
                            finally
                            {
                                // Important: Free the handle when done
                                handle.Free();
                            }
                        }
                        else
                        {
                            SecureClear((byte[])(object)_array);
                        }
                    }
                    else
                    {
                        Array.Clear(_array, 0, _array.Length);
                    }
                    _disposed = true;
                }
            }
        }
    }
}