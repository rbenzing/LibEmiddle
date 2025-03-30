using System;
using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using E2EELibrary;
using E2EELibrary.Core;

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
            Console.WriteLine("E2EE Test Suite Initialization Started");

            try
            {
                // First ensure the Sodium library is initialized from our Core class
                Sodium.Initialize();

                // Then verify key generation works via E2EEClient
                var keyPair = E2EEClient.GenerateKeyExchangeKeyPair();
                if (keyPair.publicKey != null && keyPair.privateKey != null)
                {
                    Console.WriteLine($"Sodium library initialized successfully. Generated key sizes: Public={keyPair.publicKey.Length}, Private={keyPair.privateKey.Length}");
                }
                else
                {
                    throw new InvalidOperationException("Key generation succeeded but returned null keys");
                }
            }
            catch (PlatformNotSupportedException ex)
            {
                Console.WriteLine($"Sodium library not available on this platform: {ex.Message}");
                Console.WriteLine("You may need to install libsodium for your platform.");

                string runtimeDir = Path.GetDirectoryName(typeof(E2EEClient).Assembly.Location) ?? "";
                Console.WriteLine($"Runtime directory: {runtimeDir}");
                Console.WriteLine("Available files:");
                foreach (var file in Directory.GetFiles(runtimeDir, "*.dll"))
                {
                    Console.WriteLine($"  {Path.GetFileName(file)}");
                }

                throw;
            }
            catch (DllNotFoundException ex)
            {
                Console.WriteLine($"Sodium library not found: {ex.Message}");
                Console.WriteLine("Make sure libsodium.dll is available in your application directory or PATH.");

                string runtimeDir = Path.GetDirectoryName(typeof(E2EEClient).Assembly.Location) ?? "";
                string path = Environment.GetEnvironmentVariable("PATH") ?? "";

                Console.WriteLine($"Runtime directory: {runtimeDir}");
                Console.WriteLine($"PATH: {path}");

                throw;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to initialize Sodium library: {ex.Message}");
                Console.WriteLine($"Exception type: {ex.GetType().FullName}");
                Console.WriteLine($"Stack trace: {ex.StackTrace}");

                if (ex.InnerException != null)
                {
                    Console.WriteLine($"Inner exception: {ex.InnerException.Message}");
                    Console.WriteLine($"Inner exception type: {ex.InnerException.GetType().FullName}");
                }

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
            Console.WriteLine("E2EE Test Suite Cleanup Completed");
        }
    }
}