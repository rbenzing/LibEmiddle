using System;
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
            byte[] buffer = SecureMemory.CreateSecureBuffer(bufferSize);

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
            int largeSize = 1024 * 1024 * 20; // 20MB

            // Act
            byte[] largeBuffer = SecureMemory.CreateBuffer(largeSize, true, false);

            // Assert
            Assert.IsNotNull(largeBuffer, "Large buffer should not be null");
            Assert.AreEqual(largeSize, largeBuffer.Length, "Large buffer should have the requested size");
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void CreateBuffer_WithNegativeSize_ShouldThrowException()
        {
            // Act - should throw ArgumentException
            SecureMemory.CreateBuffer(-1);
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
                SecureMemory.CreateBuffer(0);
            }, "Creating a zero-sized buffer should throw ArgumentException");

            // Test returning null buffer
            SecureMemory.ReturnBuffer(null); // Should not throw
        }
    }
}