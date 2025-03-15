using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using E2EELibrary;

namespace E2EELibraryTests
{
    /// <summary>
    /// Test class initialization and cleanup
    /// </summary>
    [TestClass]
    public class E2EETestFixture
    {
        /// <summary>
        /// Assemblies require initialization before tests can run
        /// </summary>
        [AssemblyInitialize]
        public static void AssemblyInit(TestContext context)
        {
            // Initialize any resources needed for all tests
            Console.WriteLine("E2EE Test Suite Initialization Started");

            // Make sure Sodium library is properly initialized if needed
            try
            {
                // Simple test to verify library operation
                var keyPair = E2EE2.GenerateX25519KeyPair();
                if (keyPair.publicKey != null && keyPair.privateKey != null)
                {
                    Console.WriteLine("Sodium library initialized successfully");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to initialize Sodium library: {ex.Message}");
                throw;
            }

            Console.WriteLine("E2EE Test Suite Initialization Completed");
        }

        /// <summary>
        /// Clean up after all tests have run
        /// </summary>
        [AssemblyCleanup]
        public static void AssemblyCleanup()
        {
            // Perform any global cleanup
        }
    }
}