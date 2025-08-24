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
        /// Securely clears a managed heap byte array.
        /// </summary>
        /// <param name="data">The byte array to securely clear.</param>
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
        /// Securely clears a span of sensitive data.
        /// </summary>
        /// <param name="data">The span to clear.</param>
        public static void SecureClear(Span<byte> data)
        {
            if (data.IsEmpty)
                return;

            unsafe
            {
                fixed (byte* ptr = data)
                {
                    if (ptr != null)
                    {
                        Sodium.sodium_memzero((IntPtr)ptr, (UIntPtr)data.Length);
                    }
                }
            }
        }

        /// <summary>
        /// Securely compares two byte spans using constant-time comparison.
        /// </summary>
        /// <param name="a">First byte span.</param>
        /// <param name="b">Second byte span.</param>
        /// <returns>True if the contents are equal and the lengths match; false otherwise.</returns>
        public static bool SecureCompare(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
        {
            // For constant-time comparison, we need to compare equal-length buffers
            // If lengths differ, we still need to do work proportional to the longer buffer
            int maxLength = Math.Max(a.Length, b.Length);

            if (maxLength == 0)
                return a.Length == b.Length;

            // Allocate buffers of equal size
            Span<byte> paddedA = stackalloc byte[maxLength];
            Span<byte> paddedB = stackalloc byte[maxLength];

            // Clear the buffers first
            paddedA.Clear();
            paddedB.Clear();

            // Copy the actual data
            if (a.Length > 0)
                a.CopyTo(paddedA);
            if (b.Length > 0)
                b.CopyTo(paddedB);

            unsafe
            {
                fixed (byte* ptrA = paddedA)
                fixed (byte* ptrB = paddedB)
                {
                    int cmpResult = Sodium.sodium_memcmp((IntPtr)ptrA, (IntPtr)ptrB, (nuint)maxLength);

                    // Also need to constant-time compare the lengths
                    int lengthDiff = a.Length - b.Length;

                    // Return true only if both comparison and lengths match
                    return (cmpResult | lengthDiff) == 0;
                }
            }
        }

        /// <summary>
        /// Performs a secure copy of the source byte array into a new byte array.
        /// </summary>
        /// <param name="source">The byte array to copy.</param>
        /// <returns>A new byte array containing a copy of the source.</returns>
        /// <exception cref="ArgumentNullException">If the source array is null.</exception>
        /// <exception cref="ArgumentException">If the source array is empty.</exception>
        public static byte[] SecureCopy(byte[]? source)
        {
            if (source == null)
                throw new ArgumentNullException(nameof(source), "Source array cannot be null.");

            if (source.Length == 0)
                throw new ArgumentException("Source array must not be empty.", nameof(source));

            byte[] copy = CreateSecureBuffer((uint)source.Length);
            source.CopyTo(copy, 0);
            return copy;
        }

        /// <summary>
        /// Performs a secure copy of the source span into a new byte array.
        /// </summary>
        /// <param name="source">The span to copy.</param>
        /// <returns>A new byte array containing a copy of the source.</returns>
        /// <exception cref="ArgumentException">If the span is empty.</exception>
        public static byte[] SecureCopy(ReadOnlySpan<byte> source)
        {
            if (source.Length == 0)
                throw new ArgumentException("Source span must not be empty.", nameof(source));

            byte[] copy = CreateSecureBuffer((uint)source.Length);
            source.CopyTo(copy);
            return copy;
        }

        /// <summary>
        /// Creates a secure buffer using libsodium's protected memory allocation.
        /// </summary>
        /// <param name="size">Size of the buffer in bytes</param>
        /// <returns>A new secure buffer</returns>
        public static byte[] CreateSecureBuffer(uint size)
        {
            if (size == 0)
                throw new ArgumentException("Buffer size must be positive", nameof(size));

            // Allocate secure memory using libsodium
            IntPtr securePtr = Sodium.SecureAlloc(size);
            if (securePtr == IntPtr.Zero)
                throw new OutOfMemoryException("Failed to allocate secure memory");

            try
            {
                // Create managed array and copy from secure memory
                byte[] buffer = new byte[size];
                Marshal.Copy(securePtr, buffer, 0, (int)size);

                // Fill with random data
                Sodium.RandomFill(buffer);

                return buffer;
            }
            finally
            {
                // Always free the secure memory
                Sodium.SecureFree(securePtr);
            }
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

        /// <summary>
        /// Custom secure buffer wrapper
        /// </summary>
        public sealed class SecureBuffer : IDisposable
        {
            private readonly IntPtr _ptr;
            private readonly int _length;
            private bool _disposed;

            public SecureBuffer(int length)
            {
                _length = length;
                _ptr = Sodium.SecureAlloc((uint)length);
                if (_ptr == IntPtr.Zero)
                    throw new OutOfMemoryException("Failed to allocate secure memory");
            }

            public unsafe Span<byte> AsSpan()
            {
                ThrowIfDisposed();
                return new Span<byte>(_ptr.ToPointer(), _length);
            }

            public void Dispose()
            {
                if (!_disposed)
                {
                    Sodium.SecureFree(_ptr);
                    _disposed = true;
                }
            }

            /// <summary> Checks if disposed and throws. </summary>
            private void ThrowIfDisposed()
            {
                if (_disposed)
                {
                    throw new ObjectDisposedException(nameof(SecureBuffer));
                }
            }
        }
    }
}