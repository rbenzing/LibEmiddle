using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Diagnostics;
using LibEmiddle.Abstractions;
using LibEmiddle.API;
using LibEmiddle.Core;
using LibEmiddle.Crypto;

namespace LibEmiddle.Tests.Unit
{
    /// <summary>
    /// Test class initialization and cleanup
    /// </summary>
    [TestClass]
    public class E2EETestFixture
    {
        public readonly ICryptoProvider _cryptoProvider;

        /// <summary>
        /// Assemblies require initialization before tests can run
        /// </summary>
        [AssemblyInitialize]
        public static void AssemblyInit(TestContext context)
        {
            Trace.TraceInformation("E2EE Test Suite Initialization Started");

            try
            {
                // First ensure the Sodium library is initialized from our Core class
                Sodium.Initialize();

                // initialize crypto
                var _cryptoProvider = new CryptoProvider();

                // Then verify key generation works via E2EEClient
                var keyPair = _cryptoProvider.GenerateKeyPair(KeyType.X25519);
                if (keyPair.PublicKey != null && keyPair.PrivateKey != null)
                {
                    Trace.TraceInformation($"Sodium library initialized successfully. Generated key sizes: Public={keyPair.PublicKey.Length}, Private={keyPair.PrivateKey.Length}");
                }
                else
                {
                    throw new InvalidOperationException("Key generation succeeded but returned null keys");
                }
            }
            catch (PlatformNotSupportedException ex)
            {
                Trace.TraceError($"Sodium library not available on this platform: {ex.Message}");
                Trace.TraceError("You may need to install libsodium for your platform.");

                string runtimeDir = Path.GetDirectoryName(typeof(LibEmiddleClient).Assembly.Location) ?? "";
                Trace.TraceError($"Runtime directory: {runtimeDir}");
                Trace.TraceError("Available files:");
                foreach (var file in Directory.GetFiles(runtimeDir, "*.dll"))
                {
                    Trace.TraceError($"  {Path.GetFileName(file)}");
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
                Trace.TraceError($"Failed to initialize Sodium library: {ex.Message}");
                Trace.TraceError($"Exception type: {ex.GetType().FullName}");
                Trace.TraceError($"Stack trace: {ex.StackTrace}");

                if (ex.InnerException != null)
                {
                    Trace.TraceError($"Inner exception: {ex.InnerException.Message}");
                    Trace.TraceError($"Inner exception type: {ex.InnerException.GetType().FullName}");
                }

                throw;
            }

            Trace.TraceInformation("E2EE Test Suite Initialization Completed");
        }

        /// <summary>
        /// Clean up after all tests have run
        /// </summary>
        [AssemblyCleanup]
        public static void AssemblyCleanup()
        {
            // Perform any global cleanup
            Trace.TraceInformation("E2EE Test Suite Cleanup Completed");
        }
    }
}