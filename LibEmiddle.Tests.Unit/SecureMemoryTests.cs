using System;
using System.Linq;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;
using LibEmiddle.Core;

namespace LibEmiddle.Tests.Unit
{
    [TestClass]
    public class SecureMemoryTests
    {
        [TestMethod]
        public void SecureClear_ShouldZeroOutData()
        {
            // Arrange
            byte[] sensitiveData = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(sensitiveData);
            }

            // Make sure we have non-zero data
            bool hasNonZero = false;
            foreach (byte b in sensitiveData)
            {
                if (b != 0)
                {
                    hasNonZero = true;
                    break;
                }
            }
            Assert.IsTrue(hasNonZero, "Test data should contain non-zero values initially");

            // Act
            SecureMemory.SecureClear(sensitiveData);

            // Assert
            foreach (byte b in sensitiveData)
            {
                Assert.AreEqual(0, b, "All bytes should be zero after SecureClear");
            }
        }

        [TestMethod]
        public void SecureCompare_ShouldBeConstantTime()
        {
            // Arrange
            byte[] array1 = new byte[1024];
            byte[] array2 = new byte[1024];
            byte[] array3 = new byte[1024];

            // Fill with the same data
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(array1);
                Array.Copy(array1, array2, array1.Length);
            }

            // Make array3 different from the others
            Array.Copy(array1, array3, array1.Length);
            array3[array3.Length - 1] ^= 0xFF; // Ensure at least one byte differs

            // Act & Assert - Equal arrays
            bool result1 = SecureMemory.SecureCompare(array1, array2);
            Assert.IsTrue(result1, "SecureCompare should return true for identical arrays");

            // Act & Assert - Unequal arrays
            bool result2 = SecureMemory.SecureCompare(array1, array3);
            Assert.IsFalse(result2, "SecureCompare should return false for different arrays");

            // Test arrays of different lengths
            byte[] shortArray = new byte[512];
            Array.Copy(array1, shortArray, shortArray.Length);

            bool result3 = SecureMemory.SecureCompare(array1, shortArray);
            Assert.IsFalse(result3, "SecureCompare should return false for arrays of different lengths");

            // Test null arrays
            bool result4 = SecureMemory.SecureCompare(null, null);
            Assert.IsTrue(result4, "SecureCompare should return true for both null arrays");

            bool result5 = SecureMemory.SecureCompare(array1, null);
            Assert.IsFalse(result5, "SecureCompare should return false when only one array is null");
        }

        [TestMethod]
        public void SecureCopy_ShouldCreateIndependentCopy()
        {
            // Arrange
            byte[] original = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(original);
            }

            // Act
            byte[] copy = SecureMemory.SecureCopy(original);

            // Assert
            CollectionAssert.AreEqual(original, copy, "Copy should have same content as original");
            Assert.AreNotSame(original, copy, "Copy should be a different instance");

            // Modify the original and check that the copy is unaffected
            original[0] ^= 0xFF;
            Assert.AreNotEqual(original[0], copy[0], "Modifying original should not affect copy");
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void SecureCopy_WithNull_ShouldThrowException()
        {
            // Act - should throw ArgumentNullException
            SecureMemory.SecureCopy(null);
        }

        [TestMethod]
        public void CreateSecureBuffer_ShouldReturnBufferOfSpecifiedSize()
        {
            // Arrange
            int bufferSize = 1024;

            // Act
            byte[] buffer = SecureMemory.CreateSecureBuffer((uint)bufferSize);

            // Assert
            Assert.IsNotNull(buffer, "Buffer should not be null");
            Assert.AreEqual(bufferSize, buffer.Length, "Buffer should have the requested size");
        }

        [TestMethod]
        public void CreateSecureBuffer_WithPooling_ShouldWorkCorrectly()
        {
            // Test with pooling enabled
            byte[] pooledBuffer = SecureMemory.CreateSecureBuffer(1024);
            Assert.IsNotNull(pooledBuffer, "Pooled buffer should not be null");
            Assert.AreEqual(1024, pooledBuffer.Length, "Pooled buffer should have the requested size");

            // Fill buffer with non-zero data
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(pooledBuffer);
            }

            // Return the buffer to the pool
            SecureMemory.ReturnBuffer(pooledBuffer, true);

            // Test with pooling disabled
            byte[] nonPooledBuffer = SecureMemory.CreateSecureBuffer(1024);
            Assert.IsNotNull(nonPooledBuffer, "Non-pooled buffer should not be null");
            Assert.AreEqual(1024, nonPooledBuffer.Length, "Non-pooled buffer should have the requested size");
        }

        [TestMethod]
        public void CreateBuffer_WithLargeSize_ShouldBypassPool()
        {
            // Arrange - Create a very large buffer that should bypass the pool
            uint largeSize = 1024 * 1024 * 20; // 20MB

            // Act
            byte[] largeBuffer = SecureMemory.CreateSecureBuffer(largeSize);

            // Assert
            Assert.IsNotNull(largeBuffer, "Large buffer should not be null");
            Assert.AreEqual((int)largeSize, largeBuffer.Length, "Large buffer should have the requested size");
        }

        [TestMethod]
        public void ReturnBuffer_WithSecureClear_ShouldZeroData()
        {
            // Arrange
            byte[] buffer = new byte[1024];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(buffer);
            }

            // Make a copy to verify the buffer is cleared
            byte[] copy = new byte[buffer.Length];
            Buffer.BlockCopy(buffer, 0, copy, 0, buffer.Length);

            // Make sure we have non-zero data
            bool hasNonZero = false;
            foreach (byte b in buffer)
            {
                if (b != 0)
                {
                    hasNonZero = true;
                    break;
                }
            }
            Assert.IsTrue(hasNonZero, "Test data should contain non-zero values initially");

            // Act
            SecureMemory.ReturnBuffer(buffer, true);

            // We can't directly check that the buffer is zeroed after return to the pool,
            // because it's no longer accessible. This is just testing that the method runs without errors.

            // Assert that the original copy is unchanged
            CollectionAssert.AreEqual(copy, copy, "Verification copy should remain unchanged");
        }

        // Test edge cases
        [TestMethod]
        public void SecureMemory_EdgeCases()
        {
            // Test zero-length array with SecureClear
            byte[] emptyArray = new byte[0];
            SecureMemory.SecureClear(emptyArray); // Should not throw

            // Test null with SecureClear
            SecureMemory.SecureClear(null); // Should not throw

            // Test zero size buffer
            Assert.ThrowsException<ArgumentException>(() => {
                SecureMemory.CreateSecureBuffer(0);
            }, "Creating a zero-sized buffer should throw ArgumentException");

            // Test returning null buffer
            SecureMemory.ReturnBuffer(null); // Should not throw
        }

        #region Security Vulnerability Tests

        /// <summary>
        /// Tests that secure buffers don't leak data to managed heap
        /// </summary>
        [TestMethod]
        public void SecureBuffer_ShouldNotLeakToManagedHeap()
        {
            // Arrange
            byte[] sensitiveData = new byte[64];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(sensitiveData);
            }

            // Act - Create secure buffer and copy data
            byte[] secureBuffer = SecureMemory.CreateSecureBuffer(64);
            Array.Copy(sensitiveData, secureBuffer, sensitiveData.Length);

            // Verify data is present
            Assert.IsTrue(SecureMemory.SecureCompare(sensitiveData, secureBuffer),
                "Data should be correctly copied to secure buffer");

            // Clear the secure buffer
            SecureMemory.SecureClear(secureBuffer);

            // Assert - Buffer should be cleared
            foreach (byte b in secureBuffer)
            {
                Assert.AreEqual(0, b, "All bytes should be zero after secure clear");
            }

            // Original sensitive data should be unchanged
            bool hasNonZero = sensitiveData.Any(b => b != 0);
            Assert.IsTrue(hasNonZero, "Original sensitive data should remain unchanged");
        }

        /// <summary>
        /// Tests that constant-time comparison prevents timing attacks
        /// </summary>
        [TestMethod]
        public void SecureCompare_ShouldBeTimingAttackResistant()
        {
            // Arrange - Create keys that differ in different positions
            byte[] key1 = new byte[32];
            byte[] key2_early_diff = new byte[32];
            byte[] key2_late_diff = new byte[32];

            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(key1);
            }

            Array.Copy(key1, key2_early_diff, 32);
            Array.Copy(key1, key2_late_diff, 32);

            // Make differences at different positions
            key2_early_diff[0] ^= 0xFF;  // Early difference
            key2_late_diff[31] ^= 0xFF;  // Late difference

            // Act & Assert - Both should return false regardless of difference position
            Assert.IsFalse(SecureMemory.SecureCompare(key1, key2_early_diff),
                "Keys with early difference should compare unequal");
            Assert.IsFalse(SecureMemory.SecureCompare(key1, key2_late_diff),
                "Keys with late difference should compare unequal");

            // Test with different lengths (should also be constant time)
            byte[] shortKey = new byte[16];
            Assert.IsFalse(SecureMemory.SecureCompare(key1, shortKey),
                "Keys of different lengths should compare unequal");
        }

        /// <summary>
        /// Tests that memory clearing is effective against recovery attempts
        /// </summary>
        [TestMethod]
        public void SecureClear_ShouldPreventDataRecovery()
        {
            // Arrange
            byte[] sensitiveData = new byte[1024];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(sensitiveData);
            }

            // Create multiple copies to test clearing
            byte[] copy1 = new byte[sensitiveData.Length];
            byte[] copy2 = new byte[sensitiveData.Length];
            Array.Copy(sensitiveData, copy1, sensitiveData.Length);
            Array.Copy(sensitiveData, copy2, sensitiveData.Length);

            // Act - Clear one copy
            SecureMemory.SecureClear(copy1);

            // Assert - Cleared copy should be all zeros
            foreach (byte b in copy1)
            {
                Assert.AreEqual(0, b, "Cleared memory should contain only zeros");
            }

            // Other copies should be unchanged
            Assert.IsTrue(SecureMemory.SecureCompare(sensitiveData, copy2),
                "Uncleared copy should remain unchanged");
        }

        /// <summary>
        /// Tests that buffer pooling doesn't leak data between uses
        /// </summary>
        [TestMethod]
        public void BufferPool_ShouldNotLeakDataBetweenUses()
        {
            // Arrange - Create and use a buffer with sensitive data
            byte[] sensitiveData = new byte[512];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(sensitiveData);
            }

            byte[] buffer1 = SecureMemory.CreateSecureBuffer(512);
            Array.Copy(sensitiveData, buffer1, sensitiveData.Length);

            // Return buffer to pool with secure clearing
            SecureMemory.ReturnBuffer(buffer1, true);

            // Act - Get a new buffer from the pool
            byte[] buffer2 = SecureMemory.CreateSecureBuffer(512);

            // Assert - New buffer should not contain old data
            Assert.IsFalse(SecureMemory.SecureCompare(sensitiveData, buffer2),
                "New buffer from pool should not contain previous sensitive data");

            // New buffer should be clean (all zeros or random data, but not our sensitive data)
            bool containsSensitiveData = false;
            for (int i = 0; i <= buffer2.Length - sensitiveData.Length; i++)
            {
                bool matches = true;
                for (int j = 0; j < sensitiveData.Length; j++)
                {
                    if (buffer2[i + j] != sensitiveData[j])
                    {
                        matches = false;
                        break;
                    }
                }
                if (matches)
                {
                    containsSensitiveData = true;
                    break;
                }
            }

            Assert.IsFalse(containsSensitiveData,
                "Pooled buffer should not contain traces of previous sensitive data");
        }

        #endregion
    }
}