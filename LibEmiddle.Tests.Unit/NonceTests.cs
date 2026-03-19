using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;

namespace LibEmiddle.Tests.Unit
{
    /// <summary>
    /// Unit tests for nonce generation: uniqueness, thread-safety, and length guarantees.
    /// The internal Nonce class is accessed through the public CryptoProvider facade, which
    /// delegates directly to Nonce.GenerateNonce.
    /// </summary>
    [TestClass]
    public class NonceTests
    {
        private CryptoProvider _cryptoProvider;

        [TestInitialize]
        public void Setup()
        {
            _cryptoProvider = new CryptoProvider();
        }

        // ---------------------------------------------------------------
        // Length / size tests
        // ---------------------------------------------------------------

        [TestMethod]
        public void GenerateNonce_DefaultSize_ReturnsExpectedLength()
        {
            // Arrange / Act
            byte[] nonce = _cryptoProvider.GenerateNonce();

            // Assert
            Assert.IsNotNull(nonce, "Nonce must not be null");
            Assert.AreEqual(Constants.NONCE_SIZE, nonce.Length,
                $"Default nonce length must equal Constants.NONCE_SIZE ({Constants.NONCE_SIZE})");
        }

        [TestMethod]
        public void GenerateNonce_CustomSize_ReturnsRequestedLength()
        {
            // Arrange
            const uint customSize = 24; // XChaCha20 nonce size

            // Act
            byte[] nonce = _cryptoProvider.GenerateNonce(customSize);

            // Assert
            Assert.IsNotNull(nonce);
            Assert.AreEqual((int)customSize, nonce.Length,
                $"Nonce length must equal the requested size ({customSize})");
        }

        [TestMethod]
        public void GenerateNonce_MinimumSize_ReturnsOneByte()
        {
            // The implementation requires size > 0; size == 1 should succeed.
            byte[] nonce = _cryptoProvider.GenerateNonce(1);
            Assert.IsNotNull(nonce);
            Assert.AreEqual(1, nonce.Length);
        }

        // ---------------------------------------------------------------
        // Uniqueness – sequential calls
        // ---------------------------------------------------------------

        [TestMethod]
        public void GenerateNonce_SequentialCalls_ProduceUniqueNonces()
        {
            // Arrange
            const int count = 10_000;
            var seen = new HashSet<string>(count);

            // Act
            for (int i = 0; i < count; i++)
            {
                string key = Convert.ToBase64String(_cryptoProvider.GenerateNonce());
                bool added = seen.Add(key);
                Assert.IsTrue(added, $"Duplicate nonce detected at iteration {i}");
            }

            // Assert (implicit above)
            Assert.AreEqual(count, seen.Count, "Every nonce in the sequential batch must be unique");
        }

        [TestMethod]
        public void GenerateNonce_SequentialCalls_NoncesAreNotAllZero()
        {
            // A nonce that is all-zero bytes indicates the CSPRNG was not called.
            byte[] nonce = _cryptoProvider.GenerateNonce();
            bool allZero = true;
            foreach (byte b in nonce)
            {
                if (b != 0) { allZero = false; break; }
            }
            Assert.IsFalse(allZero, "A freshly generated nonce must not be all-zero bytes");
        }

        // ---------------------------------------------------------------
        // Uniqueness – concurrent calls (thread-safety)
        // ---------------------------------------------------------------

        [TestMethod]
        public void GenerateNonce_ConcurrentCalls_ProduceUniqueNonces()
        {
            // Arrange
            const int threadCount = 16;
            const int noncesPerThread = 500;
            const int total = threadCount * noncesPerThread;

            var bag = new ConcurrentBag<string>();

            // Act: generate nonces from many threads simultaneously
            Parallel.For(0, threadCount, _ =>
            {
                // Each thread uses its own CryptoProvider to avoid per-instance state
                // interference, but shares the static nonce counter inside Nonce.
                var provider = new CryptoProvider();
                for (int i = 0; i < noncesPerThread; i++)
                {
                    bag.Add(Convert.ToBase64String(provider.GenerateNonce()));
                }
            });

            // Assert: collect into a HashSet to detect any duplicates
            var all = bag.ToArray();
            Assert.AreEqual(total, all.Length, "Total nonce count must match");

            var distinct = new HashSet<string>(all);
            Assert.AreEqual(total, distinct.Count,
                $"All {total} nonces from {threadCount} concurrent threads must be unique. " +
                $"Detected {total - distinct.Count} duplicate(s).");
        }

        [TestMethod]
        public void GenerateNonce_ConcurrentCalls_NoDeadlocks()
        {
            // Verify the nonce lock does not cause deadlocks under contention.
            const int threadCount = 32;
            const int noncesPerThread = 200;

            var barrier = new Barrier(threadCount);
            var threads = new Thread[threadCount];
            var exceptions = new ConcurrentBag<Exception>();

            for (int t = 0; t < threadCount; t++)
            {
                threads[t] = new Thread(() =>
                {
                    try
                    {
                        // All threads start at the same time to maximise contention.
                        barrier.SignalAndWait(TimeSpan.FromSeconds(10));
                        var provider = new CryptoProvider();
                        for (int i = 0; i < noncesPerThread; i++)
                        {
                            _ = provider.GenerateNonce();
                        }
                    }
                    catch (Exception ex)
                    {
                        exceptions.Add(ex);
                    }
                });
            }

            foreach (var thread in threads) thread.Start();

            bool allFinished = true;
            foreach (var thread in threads)
            {
                allFinished &= thread.Join(TimeSpan.FromSeconds(30));
            }

            Assert.IsTrue(allFinished, "All threads must complete within 30 seconds (no deadlock)");
            Assert.AreEqual(0, exceptions.Count,
                $"No exceptions should be thrown. Got: {string.Join("; ", exceptions)}");
        }

        // ---------------------------------------------------------------
        // Counter-increment uniqueness guarantee
        // ---------------------------------------------------------------

        [TestMethod]
        public void GenerateNonce_CounterIncrement_EachCallYieldsDistinctNonce()
        {
            // Even if the underlying CSPRNG somehow repeated a value (theoretically impossible
            // but guarded against), the counter XOR ensures uniqueness.  We can verify the
            // practical guarantee by checking 1,000 rapid successive calls differ.
            const int count = 1_000;
            string previous = Convert.ToBase64String(_cryptoProvider.GenerateNonce());

            for (int i = 0; i < count - 1; i++)
            {
                string current = Convert.ToBase64String(_cryptoProvider.GenerateNonce());
                Assert.AreNotEqual(previous, current,
                    $"Two consecutive nonces must differ (iteration {i})");
                previous = current;
            }
        }

        // ---------------------------------------------------------------
        // Input validation
        // ---------------------------------------------------------------

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void GenerateNonce_ZeroSize_ThrowsArgumentException()
        {
            // The Nonce implementation explicitly requires size > 0.
            _cryptoProvider.GenerateNonce(0);
        }

        // ---------------------------------------------------------------
        // XChaCha20 nonce size
        // ---------------------------------------------------------------

        [TestMethod]
        public void GenerateNonce_XChaCha20Size_Returns24Bytes()
        {
            // XChaCha20-Poly1305 requires a 24-byte nonce.
            const uint xchacha20NonceSize = 24;
            byte[] nonce = _cryptoProvider.GenerateNonce(xchacha20NonceSize);

            Assert.IsNotNull(nonce);
            Assert.AreEqual(24, nonce.Length,
                "XChaCha20-Poly1305 nonce must be 24 bytes");
        }

        // ---------------------------------------------------------------
        // Large-batch uniqueness (stress test)
        // ---------------------------------------------------------------

        [TestMethod]
        public void GenerateNonce_LargeBatch_AllUnique()
        {
            // 50 000 nonces: the probability of a random collision is negligible
            // (~1 in 2^82 for 12-byte nonces). The counter further ensures uniqueness.
            const int count = 50_000;
            var seen = new HashSet<string>(count);

            for (int i = 0; i < count; i++)
            {
                string key = Convert.ToBase64String(_cryptoProvider.GenerateNonce());
                Assert.IsTrue(seen.Add(key), $"Duplicate nonce at index {i} in large batch");
            }
        }
    }
}
