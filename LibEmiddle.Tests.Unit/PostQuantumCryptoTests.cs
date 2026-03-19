#pragma warning disable CS8632 // nullable annotation outside #nullable context
#pragma warning disable CS8600 // Converting null literal or possible null value to non-nullable type
#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using LibEmiddle.Abstractions;
using LibEmiddle.Crypto.PostQuantum;
using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;

namespace LibEmiddle.Tests.Unit
{
    /// <summary>
    /// Unit tests for PostQuantumCryptoFactory and PostQuantumCryptoStub.
    ///
    /// The stub implementation uses randomly generated placeholder data for every
    /// operation. Key encapsulation (KEM) is simulated: the stub does NOT perform
    /// real KEM, so decapsulation with the "correct" private key returns a freshly
    /// generated random secret rather than the one produced during encapsulation.
    /// The tests below accurately reflect this stub behaviour.
    /// </summary>
    [TestClass]
    public class PostQuantumCryptoFactoryTests
    {
        private PostQuantumCryptoFactory _factory;

        [TestInitialize]
        public void Setup()
        {
            _factory = new PostQuantumCryptoFactory();
        }

        // ---------------------------------------------------------------
        // Factory creation
        // ---------------------------------------------------------------

        [TestMethod]
        public void Factory_Instantiation_DoesNotThrow()
        {
            // Arrange / Act / Assert
            var factory = new PostQuantumCryptoFactory();
            Assert.IsNotNull(factory, "Factory must be constructable without errors");
        }

        [TestMethod]
        public async Task CreateAsync_KyberAlgorithm_ReturnsProvider()
        {
            // Arrange
            var options = new PostQuantumOptions { RunSelfTests = false };

            // Act
            IPostQuantumCrypto provider = await _factory.CreateAsync(PostQuantumAlgorithm.Kyber768, options);

            // Assert
            Assert.IsNotNull(provider, "Factory must return a non-null provider for Kyber768");
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public async Task CreateAsync_NoneAlgorithm_ThrowsArgumentException()
        {
            await _factory.CreateAsync(PostQuantumAlgorithm.None);
        }

        [TestMethod]
        public void GetAvailableAlgorithms_ReturnsNonEmptyList()
        {
            var algorithms = _factory.GetAvailableAlgorithms().ToList();
            Assert.IsTrue(algorithms.Count > 0, "At least one algorithm must be available");
        }

        [TestMethod]
        public void GetAvailableAlgorithms_ContainsAllKyberVariants()
        {
            var algorithms = _factory.GetAvailableAlgorithms();
            Assert.IsTrue(algorithms.Contains(PostQuantumAlgorithm.Kyber512));
            Assert.IsTrue(algorithms.Contains(PostQuantumAlgorithm.Kyber768));
            Assert.IsTrue(algorithms.Contains(PostQuantumAlgorithm.Kyber1024));
        }

        [TestMethod]
        public void IsAlgorithmAvailable_Kyber768_ReturnsTrue()
        {
            Assert.IsTrue(_factory.IsAlgorithmAvailable(PostQuantumAlgorithm.Kyber768));
        }

        [TestMethod]
        public void IsAlgorithmAvailable_NoneAlgorithm_ReturnsFalse()
        {
            Assert.IsFalse(_factory.IsAlgorithmAvailable(PostQuantumAlgorithm.None));
        }

        [TestMethod]
        public void GetRecommendedAlgorithm_128BitSecurity_ReturnsKyberVariant()
        {
            PostQuantumAlgorithm algo = _factory.GetRecommendedAlgorithm(128, PostQuantumPerformance.Balanced);
            Assert.AreEqual(PostQuantumAlgorithm.Kyber512, algo);
        }

        [TestMethod]
        public void GetAlgorithmInfo_Kyber512_ReturnCorrectMetadata()
        {
            PostQuantumAlgorithmInfo info = _factory.GetAlgorithmInfo(PostQuantumAlgorithm.Kyber512);
            Assert.IsNotNull(info);
            Assert.AreEqual(PostQuantumAlgorithm.Kyber512, info.Algorithm);
            Assert.IsTrue(info.IsNistApproved, "Kyber512 must be NIST-approved");
            Assert.AreEqual(128, info.SecurityLevel);
            Assert.IsTrue(info.KeySizes.PublicKeyBytes > 0, "Public key size must be positive");
            Assert.IsTrue(info.KeySizes.PrivateKeyBytes > 0, "Private key size must be positive");
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void GetAlgorithmInfo_UnknownAlgorithm_ThrowsArgumentException()
        {
            _factory.GetAlgorithmInfo(PostQuantumAlgorithm.None);
        }
    }

    // -------------------------------------------------------------------

    [TestClass]
    public class PostQuantumCryptoStubTests
    {
        // Use Kyber768 (KEM algorithm) as the default test algorithm.
        private const PostQuantumAlgorithm KemAlgorithm = PostQuantumAlgorithm.Kyber768;
        private const PostQuantumAlgorithm SignAlgorithm = PostQuantumAlgorithm.Dilithium2;

        private static PostQuantumOptions NoSelfTestOptions()
            => new PostQuantumOptions { RunSelfTests = false };

        // ---------------------------------------------------------------
        // Stub construction
        // ---------------------------------------------------------------

        [TestMethod]
        public void Stub_Construction_DoesNotThrow()
        {
            using var stub = new PostQuantumCryptoStub(KemAlgorithm, NoSelfTestOptions());
            Assert.IsNotNull(stub);
        }

        [TestMethod]
        public void Stub_Algorithm_ReflectsConstructorArgument()
        {
            using var stub = new PostQuantumCryptoStub(PostQuantumAlgorithm.Kyber512, NoSelfTestOptions());
            Assert.AreEqual(PostQuantumAlgorithm.Kyber512, stub.Algorithm);
        }

        [TestMethod]
        public void Stub_IsNistApproved_TrueForKyber()
        {
            using var stub = new PostQuantumCryptoStub(KemAlgorithm, NoSelfTestOptions());
            Assert.IsTrue(stub.IsNistApproved, "Kyber768 must be NIST-approved");
        }

        [TestMethod]
        public void Stub_SecurityLevel_MatchesAlgorithm()
        {
            using var stub = new PostQuantumCryptoStub(KemAlgorithm, NoSelfTestOptions());
            Assert.AreEqual(192, stub.SecurityLevel, "Kyber768 provides 192-bit security");
        }

        // ---------------------------------------------------------------
        // Key generation
        // ---------------------------------------------------------------

        [TestMethod]
        public async Task GenerateKeyPairAsync_ReturnsNonNullKeyPair()
        {
            using var stub = new PostQuantumCryptoStub(KemAlgorithm, NoSelfTestOptions());
            PostQuantumKeyPair keyPair = await stub.GenerateKeyPairAsync();

            Assert.IsNotNull(keyPair, "GenerateKeyPairAsync must return a non-null key pair");
        }

        [TestMethod]
        public async Task GenerateKeyPairAsync_PublicKey_HasExpectedLength()
        {
            // Kyber768 public key: 1184 bytes
            using var stub = new PostQuantumCryptoStub(PostQuantumAlgorithm.Kyber768, NoSelfTestOptions());
            PostQuantumKeyPair keyPair = await stub.GenerateKeyPairAsync();

            Assert.IsNotNull(keyPair.PublicKey);
            Assert.AreEqual(1184, keyPair.PublicKey.KeyData.Length,
                "Kyber768 public key must be 1184 bytes");
        }

        [TestMethod]
        public async Task GenerateKeyPairAsync_PrivateKey_HasExpectedLength()
        {
            // Kyber768 private key: 2400 bytes
            using var stub = new PostQuantumCryptoStub(PostQuantumAlgorithm.Kyber768, NoSelfTestOptions());
            PostQuantumKeyPair keyPair = await stub.GenerateKeyPairAsync();

            Assert.IsNotNull(keyPair.PrivateKey);
            Assert.AreEqual(2400, keyPair.PrivateKey.KeyData.Length,
                "Kyber768 private key must be 2400 bytes");
        }

        [TestMethod]
        public async Task GenerateKeyPairAsync_KeyPairAlgorithmMatchesStub()
        {
            using var stub = new PostQuantumCryptoStub(PostQuantumAlgorithm.Kyber512, NoSelfTestOptions());
            PostQuantumKeyPair keyPair = await stub.GenerateKeyPairAsync();

            Assert.AreEqual(PostQuantumAlgorithm.Kyber512, keyPair.Algorithm);
            Assert.AreEqual(PostQuantumAlgorithm.Kyber512, keyPair.PublicKey.Algorithm);
            Assert.AreEqual(PostQuantumAlgorithm.Kyber512, keyPair.PrivateKey.Algorithm);
        }

        [TestMethod]
        public async Task GenerateKeyPairAsync_PublicAndPrivateKey_ShareSameKeyId()
        {
            using var stub = new PostQuantumCryptoStub(KemAlgorithm, NoSelfTestOptions());
            PostQuantumKeyPair keyPair = await stub.GenerateKeyPairAsync();

            Assert.IsFalse(string.IsNullOrEmpty(keyPair.PublicKey.KeyId),
                "Public key ID must not be empty");
            Assert.AreEqual(keyPair.PublicKey.KeyId, keyPair.PrivateKey.KeyId,
                "Public and private key must share the same key ID");
        }

        [TestMethod]
        public async Task GenerateKeyPairAsync_CalledTwice_ProducesDifferentPublicKeys()
        {
            using var stub = new PostQuantumCryptoStub(KemAlgorithm, NoSelfTestOptions());
            PostQuantumKeyPair first = await stub.GenerateKeyPairAsync();
            PostQuantumKeyPair second = await stub.GenerateKeyPairAsync();

            CollectionAssert.AreNotEqual(first.PublicKey.KeyData, second.PublicKey.KeyData,
                "Two independently generated key pairs must have different public keys");
        }

        // ---------------------------------------------------------------
        // Encapsulation (KEM)
        // ---------------------------------------------------------------

        [TestMethod]
        public async Task EncapsulateAsync_ValidPublicKey_ReturnsCiphertext()
        {
            using var stub = new PostQuantumCryptoStub(PostQuantumAlgorithm.Kyber768, NoSelfTestOptions());
            PostQuantumKeyPair keyPair = await stub.GenerateKeyPairAsync();

            KemResult result = await stub.EncapsulateAsync(keyPair.PublicKey);

            Assert.IsNotNull(result, "EncapsulateAsync must return a non-null result");
            Assert.IsNotNull(result.Ciphertext, "Ciphertext must not be null");
            Assert.IsTrue(result.Ciphertext.Length > 0, "Ciphertext must be non-empty");
        }

        [TestMethod]
        public async Task EncapsulateAsync_ValidPublicKey_ReturnsSharedSecret()
        {
            using var stub = new PostQuantumCryptoStub(PostQuantumAlgorithm.Kyber768, NoSelfTestOptions());
            PostQuantumKeyPair keyPair = await stub.GenerateKeyPairAsync();

            KemResult result = await stub.EncapsulateAsync(keyPair.PublicKey);

            Assert.IsNotNull(result.SharedSecret, "SharedSecret must not be null");
            Assert.IsTrue(result.SharedSecret.Length > 0, "SharedSecret must be non-empty");
        }

        [TestMethod]
        public async Task EncapsulateAsync_Kyber768_CiphertextHasExpectedLength()
        {
            // Kyber768 ciphertext: 1088 bytes
            using var stub = new PostQuantumCryptoStub(PostQuantumAlgorithm.Kyber768, NoSelfTestOptions());
            PostQuantumKeyPair keyPair = await stub.GenerateKeyPairAsync();

            KemResult result = await stub.EncapsulateAsync(keyPair.PublicKey);

            Assert.AreEqual(1088, result.Ciphertext.Length,
                "Kyber768 ciphertext must be 1088 bytes");
        }

        [TestMethod]
        public async Task EncapsulateAsync_Kyber768_SharedSecretHasExpectedLength()
        {
            // Kyber768 shared secret: 32 bytes
            using var stub = new PostQuantumCryptoStub(PostQuantumAlgorithm.Kyber768, NoSelfTestOptions());
            PostQuantumKeyPair keyPair = await stub.GenerateKeyPairAsync();

            KemResult result = await stub.EncapsulateAsync(keyPair.PublicKey);

            Assert.AreEqual(32, result.SharedSecret.Length,
                "Kyber768 shared secret must be 32 bytes");
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public async Task EncapsulateAsync_WrongAlgorithmPublicKey_ThrowsArgumentException()
        {
            using var stub768 = new PostQuantumCryptoStub(PostQuantumAlgorithm.Kyber768, NoSelfTestOptions());
            using var stub512 = new PostQuantumCryptoStub(PostQuantumAlgorithm.Kyber512, NoSelfTestOptions());

            PostQuantumKeyPair keyPair512 = await stub512.GenerateKeyPairAsync();

            // Pass a Kyber512 public key to a Kyber768 stub — must throw.
            await stub768.EncapsulateAsync(keyPair512.PublicKey);
        }

        [TestMethod]
        public async Task EncapsulateAsync_ContainsIsStubMetadata()
        {
            using var stub = new PostQuantumCryptoStub(KemAlgorithm, NoSelfTestOptions());
            PostQuantumKeyPair keyPair = await stub.GenerateKeyPairAsync();

            KemResult result = await stub.EncapsulateAsync(keyPair.PublicKey);

            Assert.IsTrue(result.Metadata.ContainsKey("IsStub"),
                "KemResult metadata must include 'IsStub' flag");
            Assert.AreEqual(true, result.Metadata["IsStub"]);
        }

        // ---------------------------------------------------------------
        // Decapsulation (KEM) — stub behaviour
        //
        // IMPORTANT: This is a stub. DecapsulateAsync generates a fresh random
        // shared secret; it does NOT recover the encapsulated secret. Tests
        // therefore validate shape (non-null, correct length, non-zero) rather
        // than semantic equivalence with the encapsulated secret.
        // ---------------------------------------------------------------

        [TestMethod]
        public async Task DecapsulateAsync_CorrectLengthCiphertext_ReturnsNonNullSecret()
        {
            using var stub = new PostQuantumCryptoStub(PostQuantumAlgorithm.Kyber768, NoSelfTestOptions());
            PostQuantumKeyPair keyPair = await stub.GenerateKeyPairAsync();
            KemResult encResult = await stub.EncapsulateAsync(keyPair.PublicKey);

            byte[] sharedSecret = await stub.DecapsulateAsync(keyPair.PrivateKey, encResult.Ciphertext);

            Assert.IsNotNull(sharedSecret, "DecapsulateAsync must return a non-null value for valid ciphertext length");
        }

        [TestMethod]
        public async Task DecapsulateAsync_CorrectLengthCiphertext_ReturnsExpectedSecretLength()
        {
            // Kyber768 shared secret: 32 bytes
            using var stub = new PostQuantumCryptoStub(PostQuantumAlgorithm.Kyber768, NoSelfTestOptions());
            PostQuantumKeyPair keyPair = await stub.GenerateKeyPairAsync();
            KemResult encResult = await stub.EncapsulateAsync(keyPair.PublicKey);

            byte[] sharedSecret = await stub.DecapsulateAsync(keyPair.PrivateKey, encResult.Ciphertext);

            Assert.IsNotNull(sharedSecret);
            Assert.AreEqual(32, sharedSecret.Length,
                "Kyber768 decapsulated shared secret must be 32 bytes");
        }

        [TestMethod]
        public async Task DecapsulateAsync_InvalidCiphertextLength_ReturnsNull()
        {
            // A ciphertext with the wrong length must cause the stub to return null.
            using var stub = new PostQuantumCryptoStub(PostQuantumAlgorithm.Kyber768, NoSelfTestOptions());
            PostQuantumKeyPair keyPair = await stub.GenerateKeyPairAsync();

            byte[] wrongLengthCiphertext = new byte[100]; // Kyber768 expects 1088 bytes

            byte[] result = await stub.DecapsulateAsync(keyPair.PrivateKey, wrongLengthCiphertext);

            Assert.IsNull(result, "Decapsulation with wrong-length ciphertext must return null");
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public async Task DecapsulateAsync_WrongAlgorithmPrivateKey_ThrowsArgumentException()
        {
            using var stub768 = new PostQuantumCryptoStub(PostQuantumAlgorithm.Kyber768, NoSelfTestOptions());
            using var stub512 = new PostQuantumCryptoStub(PostQuantumAlgorithm.Kyber512, NoSelfTestOptions());

            PostQuantumKeyPair keyPair512 = await stub512.GenerateKeyPairAsync();
            PostQuantumKeyPair keyPair768 = await stub768.GenerateKeyPairAsync();
            KemResult enc = await stub768.EncapsulateAsync(keyPair768.PublicKey);

            // Pass a Kyber512 private key to a Kyber768 stub — must throw.
            await stub768.DecapsulateAsync(keyPair512.PrivateKey, enc.Ciphertext);
        }

        [TestMethod]
        public async Task DecapsulateAsync_StubNote_TwoCallsReturnDifferentSecrets()
        {
            // The stub generates a fresh random secret on every call. This test documents
            // and verifies that known-stub behaviour: two decapsulation calls on the same
            // ciphertext produce different outputs. Real KEM implementations would always
            // return the same shared secret.
            using var stub = new PostQuantumCryptoStub(PostQuantumAlgorithm.Kyber768, NoSelfTestOptions());
            PostQuantumKeyPair keyPair = await stub.GenerateKeyPairAsync();
            KemResult enc = await stub.EncapsulateAsync(keyPair.PublicKey);

            byte[] secret1 = await stub.DecapsulateAsync(keyPair.PrivateKey, enc.Ciphertext);
            byte[] secret2 = await stub.DecapsulateAsync(keyPair.PrivateKey, enc.Ciphertext);

            Assert.IsNotNull(secret1);
            Assert.IsNotNull(secret2);

            // The stub returns random bytes each time — the two results should differ.
            bool areSame = secret1.Length == secret2.Length &&
                           System.Linq.Enumerable.SequenceEqual(secret1, secret2);
            // Statistically impossible for two independent 32-byte CSPRNG outputs to match.
            Assert.IsFalse(areSame,
                "Stub decapsulation returns fresh random bytes each call — results must differ");
        }

        // ---------------------------------------------------------------
        // Signature operations (Dilithium)
        // ---------------------------------------------------------------

        [TestMethod]
        public async Task SignAsync_ValidPrivateKey_ReturnsNonEmptySignature()
        {
            using var stub = new PostQuantumCryptoStub(SignAlgorithm, NoSelfTestOptions());
            PostQuantumKeyPair keyPair = await stub.GenerateKeyPairAsync();
            byte[] message = System.Text.Encoding.UTF8.GetBytes("Hello, post-quantum world!");

            byte[] signature = await stub.SignAsync(keyPair.PrivateKey, message);

            Assert.IsNotNull(signature, "Signature must not be null");
            Assert.IsTrue(signature.Length > 0, "Signature must be non-empty");
        }

        [TestMethod]
        public async Task SignAsync_Dilithium2_SignatureHasExpectedLength()
        {
            // Dilithium2 signature: 2420 bytes
            using var stub = new PostQuantumCryptoStub(PostQuantumAlgorithm.Dilithium2, NoSelfTestOptions());
            PostQuantumKeyPair keyPair = await stub.GenerateKeyPairAsync();
            byte[] message = System.Text.Encoding.UTF8.GetBytes("Test message");

            byte[] signature = await stub.SignAsync(keyPair.PrivateKey, message);

            Assert.AreEqual(2420, signature.Length, "Dilithium2 signature must be 2420 bytes");
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public async Task SignAsync_WrongAlgorithmPrivateKey_ThrowsArgumentException()
        {
            using var stubDil = new PostQuantumCryptoStub(PostQuantumAlgorithm.Dilithium2, NoSelfTestOptions());
            using var stubFal = new PostQuantumCryptoStub(PostQuantumAlgorithm.Falcon512, NoSelfTestOptions());

            PostQuantumKeyPair keyPairFal = await stubFal.GenerateKeyPairAsync();
            byte[] message = System.Text.Encoding.UTF8.GetBytes("message");

            await stubDil.SignAsync(keyPairFal.PrivateKey, message);
        }

        [TestMethod]
        public async Task VerifyAsync_ValidSignatureAndMessage_ReturnsTrue()
        {
            using var stub = new PostQuantumCryptoStub(SignAlgorithm, NoSelfTestOptions());
            PostQuantumKeyPair keyPair = await stub.GenerateKeyPairAsync();
            byte[] message = System.Text.Encoding.UTF8.GetBytes("Verify me");
            byte[] signature = await stub.SignAsync(keyPair.PrivateKey, message);

            bool isValid = await stub.VerifyAsync(keyPair.PublicKey, message, signature);

            Assert.IsTrue(isValid, "Stub must return true for a valid-length signature over a non-empty message");
        }

        [TestMethod]
        public async Task VerifyAsync_WrongLengthSignature_ReturnsFalse()
        {
            using var stub = new PostQuantumCryptoStub(SignAlgorithm, NoSelfTestOptions());
            PostQuantumKeyPair keyPair = await stub.GenerateKeyPairAsync();
            byte[] message = System.Text.Encoding.UTF8.GetBytes("Verify me");
            byte[] wrongSignature = new byte[10]; // Dilithium2 expects 2420 bytes

            bool isValid = await stub.VerifyAsync(keyPair.PublicKey, message, wrongSignature);

            Assert.IsFalse(isValid, "Verify must return false for a signature with wrong length");
        }

        // ---------------------------------------------------------------
        // Self-test
        // ---------------------------------------------------------------

        [TestMethod]
        public async Task RunSelfTestAsync_ReturnsSuccessResult()
        {
            var options = new PostQuantumOptions { RunSelfTests = false };
            using var stub = new PostQuantumCryptoStub(KemAlgorithm, options);

            PostQuantumTestResults results = await stub.RunSelfTestAsync();

            Assert.IsNotNull(results, "Self-test must return a non-null result");
            Assert.IsTrue(results.Success, "Stub self-test must succeed");
        }

        [TestMethod]
        public async Task RunSelfTestAsync_ContainsWarningMessages()
        {
            using var stub = new PostQuantumCryptoStub(KemAlgorithm, NoSelfTestOptions());
            PostQuantumTestResults results = await stub.RunSelfTestAsync();

            Assert.IsTrue(results.Messages != null && results.Messages.Count > 0,
                "Self-test results must contain at least one warning message");
        }

        [TestMethod]
        public async Task RunSelfTestAsync_MetadataContainsIsStubFlag()
        {
            using var stub = new PostQuantumCryptoStub(KemAlgorithm, NoSelfTestOptions());
            PostQuantumTestResults results = await stub.RunSelfTestAsync();

            Assert.IsTrue(results.Metadata.ContainsKey("IsStub"),
                "Self-test metadata must contain 'IsStub' key");
            Assert.AreEqual(true, results.Metadata["IsStub"]);
        }

        // ---------------------------------------------------------------
        // Performance estimation
        // ---------------------------------------------------------------

        [TestMethod]
        public async Task EstimatePerformanceAsync_KeyGeneration_ReturnsMetrics()
        {
            using var stub = new PostQuantumCryptoStub(KemAlgorithm, NoSelfTestOptions());
            OperationMetrics metrics = await stub.EstimatePerformanceAsync(PostQuantumOperation.KeyGeneration);

            Assert.IsNotNull(metrics, "EstimatePerformanceAsync must return non-null metrics");
            Assert.IsTrue(metrics.EstimatedDuration > TimeSpan.Zero,
                "Estimated duration for key generation must be positive");
        }

        [TestMethod]
        public async Task EstimatePerformanceAsync_AllOperations_DoNotThrow()
        {
            using var stub = new PostQuantumCryptoStub(KemAlgorithm, NoSelfTestOptions());

            foreach (PostQuantumOperation op in Enum.GetValues<PostQuantumOperation>())
            {
                OperationMetrics metrics = await stub.EstimatePerformanceAsync(op);
                Assert.IsNotNull(metrics, $"Metrics must not be null for operation {op}");
            }
        }

        // ---------------------------------------------------------------
        // Dispose
        // ---------------------------------------------------------------

        [TestMethod]
        public void Dispose_CalledTwice_DoesNotThrow()
        {
            var stub = new PostQuantumCryptoStub(KemAlgorithm, NoSelfTestOptions());
            stub.Dispose();
            // Second dispose must not throw.
            stub.Dispose();
        }

        // ---------------------------------------------------------------
        // All Kyber variants — key size matrix
        // ---------------------------------------------------------------

        [TestMethod]
        [DataRow(PostQuantumAlgorithm.Kyber512,  800, 1632, 768,  32)]
        [DataRow(PostQuantumAlgorithm.Kyber768,  1184, 2400, 1088, 32)]
        [DataRow(PostQuantumAlgorithm.Kyber1024, 1568, 3168, 1568, 32)]
        public async Task KyberVariants_KeyAndCiphertextSizes_MatchSpec(
            PostQuantumAlgorithm algorithm,
            int expectedPubKeyBytes,
            int expectedPrivKeyBytes,
            int expectedCiphertextBytes,
            int expectedSharedSecretBytes)
        {
            var options = new PostQuantumOptions { RunSelfTests = false };
            using var stub = new PostQuantumCryptoStub(algorithm, options);

            PostQuantumKeyPair keyPair = await stub.GenerateKeyPairAsync();
            Assert.AreEqual(expectedPubKeyBytes, keyPair.PublicKey.KeyData.Length,
                $"{algorithm} public key size");
            Assert.AreEqual(expectedPrivKeyBytes, keyPair.PrivateKey.KeyData.Length,
                $"{algorithm} private key size");

            KemResult enc = await stub.EncapsulateAsync(keyPair.PublicKey);
            Assert.AreEqual(expectedCiphertextBytes, enc.Ciphertext.Length,
                $"{algorithm} ciphertext size");
            Assert.AreEqual(expectedSharedSecretBytes, enc.SharedSecret.Length,
                $"{algorithm} shared secret size");

            byte[] decSecret = await stub.DecapsulateAsync(keyPair.PrivateKey, enc.Ciphertext);
            Assert.IsNotNull(decSecret);
            Assert.AreEqual(expectedSharedSecretBytes, decSecret.Length,
                $"{algorithm} decapsulated shared secret size");
        }
    }
}
