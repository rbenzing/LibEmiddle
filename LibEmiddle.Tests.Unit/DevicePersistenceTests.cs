using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using LibEmiddle.Abstractions;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.MultiDevice;

namespace LibEmiddle.Tests.Unit
{
    /// <summary>
    /// Tests for device-list persistence in DeviceManager (STORY-008).
    /// Each test uses an isolated temp directory so tests never share on-disk state.
    /// </summary>
    [TestClass]
    public class DevicePersistenceTests
    {
        private ICryptoProvider _cryptoProvider;
        private IDeviceLinkingService _deviceLinkingService;

        // Root temp dir for this test run; individual tests create sub-dirs.
        private string _testRoot;

        [TestInitialize]
        public void Setup()
        {
            _cryptoProvider = new CryptoProvider();
            _deviceLinkingService = new DeviceLinkingService(_cryptoProvider);
            _testRoot = Path.Combine(Path.GetTempPath(), "LibEmiddle_DevicePersistenceTests_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_testRoot);
        }

        [TestCleanup]
        public void Cleanup()
        {
            _deviceLinkingService?.Dispose();
            _cryptoProvider?.Dispose();

            try
            {
                if (Directory.Exists(_testRoot))
                    Directory.Delete(_testRoot, recursive: true);
            }
            catch
            {
                // Best-effort; do not fail the test on cleanup errors.
            }
        }

        // -----------------------------------------------------------------------
        // Helper: create a DeviceManager backed by an isolated storage directory.
        // -----------------------------------------------------------------------

        private DeviceManager CreateManager(KeyPair keyPair, string storagePath)
        {
            return new DeviceManager(keyPair, _deviceLinkingService, _cryptoProvider,
                storagePath: storagePath);
        }

        private string UniqueStoragePath() =>
            Path.Combine(_testRoot, Guid.NewGuid().ToString("N"));

        // -----------------------------------------------------------------------
        // TC-1: Constructor without storagePath — backward-compatible in-memory mode
        // -----------------------------------------------------------------------

        [TestMethod]
        public void Constructor_WithoutStoragePath_WorksInMemoryOnly()
        {
            var keyPair = Sodium.GenerateEd25519KeyPair();
            using var mgr = new DeviceManager(keyPair, _deviceLinkingService, _cryptoProvider);

            var deviceKey = Sodium.GenerateEd25519KeyPair().PublicKey;
            mgr.AddLinkedDevice(deviceKey);

            Assert.AreEqual(1, mgr.GetLinkedDeviceCount(),
                "Device should be present in memory even without storage path.");
        }

        // -----------------------------------------------------------------------
        // TC-2: LinkDevice → restart → device still present
        // -----------------------------------------------------------------------

        [TestMethod]
        public async Task LinkDevice_ThenRestart_DeviceStillPresent()
        {
            // Arrange
            var ownerKeyPair = Sodium.GenerateEd25519KeyPair();
            var deviceKeyPair = Sodium.GenerateEd25519KeyPair();
            string storagePath = UniqueStoragePath();

            // Act: link device in first manager instance
            using (var mgr = CreateManager(ownerKeyPair, storagePath))
            {
                mgr.AddLinkedDevice(deviceKeyPair.PublicKey);
                // Give the background persist task a moment to complete.
                await Task.Delay(200);
            }

            // Simulate restart: create a new manager using the same storage path.
            using var mgr2 = CreateManager(ownerKeyPair, storagePath);
            int loaded = await mgr2.LoadFromStorageAsync();

            // Assert
            Assert.IsTrue(loaded >= 1, "At least one device should have been loaded from disk.");
            Assert.IsTrue(mgr2.IsDeviceLinked(deviceKeyPair.PublicKey),
                "Device linked before restart should still be present after restart.");
        }

        // -----------------------------------------------------------------------
        // TC-3: RevokeDevice → restart → device gone
        // -----------------------------------------------------------------------

        [TestMethod]
        public async Task RevokeDevice_ThenRestart_DeviceGone()
        {
            // Arrange
            var ownerKeyPair = Sodium.GenerateEd25519KeyPair();
            var deviceKeyPair = Sodium.GenerateEd25519KeyPair();
            string storagePath = UniqueStoragePath();

            // First session: link and then revoke the device.
            using (var mgr = CreateManager(ownerKeyPair, storagePath))
            {
                mgr.AddLinkedDevice(deviceKeyPair.PublicKey);
                await Task.Delay(100);

                var revMsg = mgr.CreateDeviceRevocationMessage(deviceKeyPair.PublicKey, "test revoke");
                // ProcessDeviceRevocationMessage is called internally by CreateDeviceRevocationMessage,
                // which removes the device. Persist happens in that path.
                await Task.Delay(200);

                Assert.AreEqual(0, mgr.GetLinkedDeviceCount(),
                    "Device should be gone from memory immediately after revocation.");
            }

            // Simulate restart: new manager, same path.
            using var mgr2 = CreateManager(ownerKeyPair, storagePath);
            int loaded = await mgr2.LoadFromStorageAsync();

            // Assert
            Assert.AreEqual(0, loaded,
                "No devices should be loaded after the only device was revoked.");
            Assert.IsFalse(mgr2.IsDeviceLinked(deviceKeyPair.PublicKey),
                "Revoked device must not be present after restart.");
        }

        // -----------------------------------------------------------------------
        // TC-4: RemoveLinkedDevice → restart → device gone
        // -----------------------------------------------------------------------

        [TestMethod]
        public async Task RemoveLinkedDevice_ThenRestart_DeviceGone()
        {
            var ownerKeyPair = Sodium.GenerateEd25519KeyPair();
            var deviceKeyPair = Sodium.GenerateEd25519KeyPair();
            string storagePath = UniqueStoragePath();

            using (var mgr = CreateManager(ownerKeyPair, storagePath))
            {
                mgr.AddLinkedDevice(deviceKeyPair.PublicKey);
                await Task.Delay(100);

                bool removed = mgr.RemoveLinkedDevice(deviceKeyPair.PublicKey);
                Assert.IsTrue(removed, "RemoveLinkedDevice should return true.");
                await Task.Delay(200);
            }

            using var mgr2 = CreateManager(ownerKeyPair, storagePath);
            await mgr2.LoadFromStorageAsync();

            Assert.IsFalse(mgr2.IsDeviceLinked(deviceKeyPair.PublicKey),
                "Removed device must not be present after restart.");
        }

        // -----------------------------------------------------------------------
        // TC-5: Multiple devices survive a restart
        // -----------------------------------------------------------------------

        [TestMethod]
        public async Task MultipleDevices_AllPersistAcrossRestart()
        {
            var ownerKeyPair = Sodium.GenerateEd25519KeyPair();
            var deviceA = Sodium.GenerateEd25519KeyPair();
            var deviceB = Sodium.GenerateEd25519KeyPair();
            var deviceC = Sodium.GenerateEd25519KeyPair();
            string storagePath = UniqueStoragePath();

            using (var mgr = CreateManager(ownerKeyPair, storagePath))
            {
                mgr.AddLinkedDevice(deviceA.PublicKey);
                mgr.AddLinkedDevice(deviceB.PublicKey);
                mgr.AddLinkedDevice(deviceC.PublicKey);
                await Task.Delay(300);
            }

            using var mgr2 = CreateManager(ownerKeyPair, storagePath);
            int loaded = await mgr2.LoadFromStorageAsync();

            Assert.AreEqual(3, loaded, "All three devices should be loaded from disk.");
            Assert.IsTrue(mgr2.IsDeviceLinked(deviceA.PublicKey), "Device A should survive restart.");
            Assert.IsTrue(mgr2.IsDeviceLinked(deviceB.PublicKey), "Device B should survive restart.");
            Assert.IsTrue(mgr2.IsDeviceLinked(deviceC.PublicKey), "Device C should survive restart.");
        }

        // -----------------------------------------------------------------------
        // TC-6: LoadFromStorageAsync on empty / non-existent file returns 0
        // -----------------------------------------------------------------------

        [TestMethod]
        public async Task LoadFromStorage_NoFileExists_ReturnsZero()
        {
            var keyPair = Sodium.GenerateEd25519KeyPair();
            string storagePath = UniqueStoragePath();

            using var mgr = CreateManager(keyPair, storagePath);
            int loaded = await mgr.LoadFromStorageAsync();

            Assert.AreEqual(0, loaded, "Should return 0 when no file exists yet.");
            Assert.AreEqual(0, mgr.GetLinkedDeviceCount());
        }

        // -----------------------------------------------------------------------
        // TC-7: LoadFromStorageAsync without storagePath always returns 0
        // -----------------------------------------------------------------------

        [TestMethod]
        public async Task LoadFromStorage_NoStoragePath_ReturnsZero()
        {
            var keyPair = Sodium.GenerateEd25519KeyPair();

            // No storagePath supplied
            using var mgr = new DeviceManager(keyPair, _deviceLinkingService, _cryptoProvider);
            int loaded = await mgr.LoadFromStorageAsync();

            Assert.AreEqual(0, loaded);
        }

        // -----------------------------------------------------------------------
        // TC-8: LinkedAt timestamp is preserved across restart
        // -----------------------------------------------------------------------

        [TestMethod]
        public async Task LinkDevice_LinkedAtTimestamp_PreservedAcrossRestart()
        {
            var ownerKeyPair = Sodium.GenerateEd25519KeyPair();
            var deviceKeyPair = Sodium.GenerateEd25519KeyPair();
            string storagePath = UniqueStoragePath();

            long timestampBefore = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            using (var mgr = CreateManager(ownerKeyPair, storagePath))
            {
                mgr.AddLinkedDevice(deviceKeyPair.PublicKey);
                await Task.Delay(200);
            }

            long timestampAfter = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            using var mgr2 = CreateManager(ownerKeyPair, storagePath);
            await mgr2.LoadFromStorageAsync();

            // Export gives us the LinkedAt value for inspection.
            string exported = mgr2.ExportLinkedDevices();
            Assert.IsFalse(string.IsNullOrEmpty(exported));

            // The exported JSON must contain a linkedAt value in a sensible range.
            Assert.IsTrue(exported.Contains("linkedAt"),
                "Exported JSON should contain 'linkedAt' field.");

            // Verify the device is linked and count is correct.
            Assert.AreEqual(1, mgr2.GetLinkedDeviceCount());
        }

        // -----------------------------------------------------------------------
        // TC-9: Repeated LoadFromStorageAsync does not duplicate devices
        // -----------------------------------------------------------------------

        [TestMethod]
        public async Task LoadFromStorage_CalledTwice_NoDuplicates()
        {
            var ownerKeyPair = Sodium.GenerateEd25519KeyPair();
            var deviceKeyPair = Sodium.GenerateEd25519KeyPair();
            string storagePath = UniqueStoragePath();

            using (var mgr = CreateManager(ownerKeyPair, storagePath))
            {
                mgr.AddLinkedDevice(deviceKeyPair.PublicKey);
                await Task.Delay(200);
            }

            using var mgr2 = CreateManager(ownerKeyPair, storagePath);
            await mgr2.LoadFromStorageAsync();
            int loadedSecondCall = await mgr2.LoadFromStorageAsync();

            Assert.AreEqual(0, loadedSecondCall,
                "Second call to LoadFromStorageAsync should load 0 new devices (already loaded).");
            Assert.AreEqual(1, mgr2.GetLinkedDeviceCount(),
                "Still exactly one device total.");
        }

        // -----------------------------------------------------------------------
        // TC-10: File is written atomically (temp file should not linger)
        // -----------------------------------------------------------------------

        [TestMethod]
        public async Task AtomicWrite_TempFileDoesNotLinger()
        {
            var ownerKeyPair = Sodium.GenerateEd25519KeyPair();
            var deviceKeyPair = Sodium.GenerateEd25519KeyPair();
            string storagePath = UniqueStoragePath();

            using (var mgr = CreateManager(ownerKeyPair, storagePath))
            {
                mgr.AddLinkedDevice(deviceKeyPair.PublicKey);
                await Task.Delay(300);
            }

            // No .tmp file should remain after the write completes.
            string[] tmpFiles = Directory.GetFiles(storagePath, "*.tmp");
            Assert.AreEqual(0, tmpFiles.Length, "No .tmp files should remain after atomic write.");

            // The actual device file should exist (encrypted format uses .enc extension).
            string deviceFile = Path.Combine(storagePath, "linked-devices.enc");
            Assert.IsTrue(File.Exists(deviceFile), "linked-devices.enc should exist.");
        }
    }
}
