using System;
using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using E2EELibrary;
using E2EELibrary.Core;
using System.Diagnostics;

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
            Trace.TraceWarning("E2EE Test Suite Initialization Started");

            try
            {
                // First ensure the Sodium library is initialized from our Core class
                Sodium.Initialize();

                // Then verify key generation works via E2EEClient
                var keyPair = LibEmiddleClient.GenerateKeyExchangeKeyPair();
                if (keyPair.publicKey != null && keyPair.privateKey != null)
                {
                    Trace.TraceWarning($"Sodium library initialized successfully. Generated key sizes: Public={keyPair.publicKey.Length}, Private={keyPair.privateKey.Length}");
                }
                else
                {
                    throw new InvalidOperationException("Key generation succeeded but returned null keys");
                }
            }
            catch (PlatformNotSupportedException ex)
            {
                Trace.TraceWarning($"Sodium library not available on this platform: {ex.Message}");
                Trace.TraceWarning("You may need to install libsodium for your platform.");

                string runtimeDir = Path.GetDirectoryName(typeof(LibEmiddleClient).Assembly.Location) ?? "";
                Trace.TraceWarning($"Runtime directory: {runtimeDir}");
                Trace.TraceWarning("Available files:");
                foreach (var file in Directory.GetFiles(runtimeDir, "*.dll"))
                {
                    Trace.TraceWarning($"  {Path.GetFileName(file)}");
                }

                throw;
            }
            catch (DllNotFoundException ex)
            {
                Trace.TraceWarning($"Sodium library not found: {ex.Message}");
                Trace.TraceWarning("Make sure libsodium.dll is available in your application directory or PATH.");

                string runtimeDir = Path.GetDirectoryName(typeof(LibEmiddleClient).Assembly.Location) ?? "";
                string path = Environment.GetEnvironmentVariable("PATH") ?? "";

                Trace.TraceWarning($"Runtime directory: {runtimeDir}");
                Trace.TraceWarning($"PATH: {path}");

                throw;
            }
            catch (Exception ex)
            {
                Trace.TraceWarning($"Failed to initialize Sodium library: {ex.Message}");
                Trace.TraceWarning($"Exception type: {ex.GetType().FullName}");
                Trace.TraceWarning($"Stack trace: {ex.StackTrace}");

                if (ex.InnerException != null)
                {
                    Trace.TraceWarning($"Inner exception: {ex.InnerException.Message}");
                    Trace.TraceWarning($"Inner exception type: {ex.InnerException.GetType().FullName}");
                }

                throw;
            }

            Trace.TraceWarning("E2EE Test Suite Initialization Completed");
        }

        /// <summary>
        /// Clean up after all tests have run
        /// </summary>
        [AssemblyCleanup]
        public static void AssemblyCleanup()
        {
            // Perform any global cleanup
            Trace.TraceWarning("E2EE Test Suite Cleanup Completed");
        }
    }
}