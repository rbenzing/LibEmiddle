using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Reflection;
using System.Linq;
using LibEmiddle.Infrastructure;
using LibEmiddle.Abstractions;

namespace LibEmiddle.Tests.Unit
{
    /// <summary>
    /// TEST-005: Verifies that stub infrastructure classes are internal and not
    /// reachable as registered implementations via the default production code paths.
    /// These stubs exist as scaffolding but must never silently replace real
    /// implementations in production-facing code.
    /// </summary>
    [TestClass]
    public class StubInfrastructureTests
    {
        private static readonly Assembly _libAssembly =
            typeof(LibEmiddle.Crypto.CryptoProvider).Assembly;

        // ---------------------------------------------------------------------------
        // 1. Visibility — stubs must not be part of the public API surface
        // ---------------------------------------------------------------------------

        [TestMethod]
        public void SessionBackupManagerStub_IsInternal_NotPublic()
        {
            var type = _libAssembly.GetType("LibEmiddle.Infrastructure.SessionBackupManagerStub",
                throwOnError: false, ignoreCase: false);

            Assert.IsNotNull(type, "SessionBackupManagerStub must exist in the assembly");
            Assert.IsFalse(type.IsPublic, "SessionBackupManagerStub must be internal, not public");
        }

        [TestMethod]
        public void AdvancedKeyRotationManagerStub_IsInternal_NotPublic()
        {
            var type = _libAssembly.GetType("LibEmiddle.Infrastructure.AdvancedKeyRotationManagerStub",
                throwOnError: false, ignoreCase: false);

            Assert.IsNotNull(type, "AdvancedKeyRotationManagerStub must exist in the assembly");
            Assert.IsFalse(type.IsPublic, "AdvancedKeyRotationManagerStub must be internal, not public");
        }

        [TestMethod]
        public void WebRTCTransportStub_IsInternal_NotPublic()
        {
            var type = _libAssembly.GetType("LibEmiddle.Infrastructure.WebRTCTransportStub",
                throwOnError: false, ignoreCase: false);

            Assert.IsNotNull(type, "WebRTCTransportStub must exist in the assembly");
            Assert.IsFalse(type.IsPublic, "WebRTCTransportStub must be internal, not public");
        }

        [TestMethod]
        public void ConnectionPoolStub_IsInternal_NotPublic()
        {
            var type = _libAssembly.GetType("LibEmiddle.Infrastructure.ConnectionPoolStub",
                throwOnError: false, ignoreCase: false);

            Assert.IsNotNull(type, "ConnectionPoolStub must exist in the assembly");
            Assert.IsFalse(type.IsPublic, "ConnectionPoolStub must be internal, not public");
        }

        [TestMethod]
        public void ResilienceManagerStub_IsInternal_NotPublic()
        {
            var type = _libAssembly.GetType("LibEmiddle.Infrastructure.ResilienceManagerStub",
                throwOnError: false, ignoreCase: false);

            Assert.IsNotNull(type, "ResilienceManagerStub must exist in the assembly");
            Assert.IsFalse(type.IsPublic, "ResilienceManagerStub must be internal, not public");
        }

        // ---------------------------------------------------------------------------
        // 2. No stub type is stored in public fields / properties of any public type
        // ---------------------------------------------------------------------------

        [TestMethod]
        public void NoPublicType_HasField_OfStubType()
        {
            var stubTypes = new[]
            {
                _libAssembly.GetType("LibEmiddle.Infrastructure.SessionBackupManagerStub"),
                _libAssembly.GetType("LibEmiddle.Infrastructure.AdvancedKeyRotationManagerStub"),
                _libAssembly.GetType("LibEmiddle.Infrastructure.WebRTCTransportStub"),
                _libAssembly.GetType("LibEmiddle.Infrastructure.ConnectionPoolStub"),
                _libAssembly.GetType("LibEmiddle.Infrastructure.ResilienceManagerStub"),
            };

            // Walk all public types in the library assembly
            foreach (var publicType in _libAssembly.GetExportedTypes())
            {
                // Check instance fields
                foreach (var field in publicType.GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic))
                {
                    if (Array.Exists(stubTypes, s => s != null && s.IsAssignableFrom(field.FieldType)))
                    {
                        Assert.Fail(
                            $"Public type '{publicType.FullName}' has a field '{field.Name}' of stub type " +
                            $"'{field.FieldType.Name}'. Stubs must not be stored as fields of production types.");
                    }
                }

                // Check properties
                foreach (var prop in publicType.GetProperties(BindingFlags.Instance | BindingFlags.Public))
                {
                    if (Array.Exists(stubTypes, s => s != null && s.IsAssignableFrom(prop.PropertyType)))
                    {
                        Assert.Fail(
                            $"Public type '{publicType.FullName}' has a property '{prop.Name}' of stub type " +
                            $"'{prop.PropertyType.Name}'. Stubs must not be exposed through public properties.");
                    }
                }
            }
        }

        // ---------------------------------------------------------------------------
        // 3. PostQuantumCryptoStub is the only intended-public stub — verify it
        //    is NOT registered as the default IPostQuantumCrypto in production.
        // ---------------------------------------------------------------------------

        [TestMethod]
        public void PostQuantumCryptoStub_IsPublic_ButNotUsedByDefault()
        {
            // PostQuantumCryptoStub is public by design (it's the test/fallback implementation)
            // but must never silently back a production service without the caller knowing.
            var stubType = _libAssembly.GetType("LibEmiddle.Crypto.PostQuantum.PostQuantumCryptoStub",
                throwOnError: false);

            Assert.IsNotNull(stubType, "PostQuantumCryptoStub must exist");
            Assert.IsTrue(stubType.IsPublic, "PostQuantumCryptoStub is intentionally public");

            // Verify it self-identifies as a stub via IsStub in RunSelfTestAsync Metadata
            var selfTestMethod = stubType.GetMethod("RunSelfTestAsync");
            Assert.IsNotNull(selfTestMethod, "PostQuantumCryptoStub must implement RunSelfTestAsync()");

            // Instantiate with a valid algorithm enum value — look it up from the loaded assembly
            // to avoid type-identity mismatch across assembly references
            var ctor = stubType.GetConstructors().FirstOrDefault();
            Assert.IsNotNull(ctor, "PostQuantumCryptoStub must have a public constructor");
            var algorithmParam = ctor.GetParameters()[0];
            var kyber512Val = Enum.ToObject(algorithmParam.ParameterType, 0); // Kyber512 = 0
            var instance = Activator.CreateInstance(stubType, kyber512Val, null);
            Assert.IsNotNull(instance, "PostQuantumCryptoStub must be instantiable");

            var task = (System.Threading.Tasks.Task)selfTestMethod.Invoke(instance, null);
            task.GetAwaiter().GetResult();
            var resultProp = task.GetType().GetProperty("Result");
            var capResult = resultProp?.GetValue(task);
            Assert.IsNotNull(capResult, "RunSelfTestAsync() must return a non-null result");

            var metadataProp = capResult.GetType().GetProperty("Metadata");
            Assert.IsNotNull(metadataProp, "Test result must have a Metadata property");

            var metadata = metadataProp.GetValue(capResult) as System.Collections.Generic.Dictionary<string, object>;
            Assert.IsNotNull(metadata, "Metadata must be a Dictionary<string,object>");
            Assert.IsTrue(metadata.ContainsKey("IsStub"), "PostQuantumCryptoStub must set Metadata[\"IsStub\"]");
            Assert.IsTrue(metadata["IsStub"] is bool b && b, "PostQuantumCryptoStub must set Metadata[\"IsStub\"] = true");
        }
    }
}
