using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using LibEmiddle.Core;
using LibEmiddle.Domain;
using LibEmiddle.Abstractions;
using LibEmiddle.Crypto;
using System.Security;

namespace LibEmiddle.MultiDevice;

/// <summary>
/// Manages multi-device sessions for securely synchronizing cryptographic state across
/// multiple devices belonging to the same user identity.
///
/// <para>
/// Provides functionality for linking, unlinking, and synchronizing data between devices,
/// as well as managing device revocation to ensure security across a user's device ecosystem.
/// Implements RFC-compliant procedures for the Signal protocol's multi-device specification.
/// </para>
/// </summary>
public partial class DeviceManager : IDeviceManager, IDisposable
{
    private readonly KeyPair _deviceKeyPair;
    private readonly IDeviceLinkingService _deviceLinkingService;
    private readonly ICryptoProvider _cryptoProvider;
    private readonly ISyncMessageValidator _syncMessageValidator;

    // Optional persistence layer; null when no storage path is provided.
    private readonly DeviceStorage? _deviceStorage;

    // Device storage with thread-safe dictionaries
    private readonly ConcurrentDictionary<string, DeviceInfo> _linkedDevices =
        new(StringComparer.Ordinal);

    // Store revocation messages we've processed for replay protection
    private readonly ConcurrentDictionary<string, DeviceRevocationMessage> _processedRevocations =
        new();

    // Use a separate sync lock for import/export operations
    private readonly SemaphoreSlim _stateLock = new(1, 1);

    // Track if we're disposed
    private volatile bool _disposed = false;

    // Lazy-load guard: once true, LoadFromStorageAsync has already populated _linkedDevices.
    // CS0414: volatile bool read in double-checked locking is not recognized by the Roslyn analyzer.
#pragma warning disable CS0414
    private volatile bool _storageLoaded = false;
#pragma warning restore CS0414
    private readonly SemaphoreSlim _loadLock = new(1, 1);

    /// <summary>
    /// Creates a new multi-device manager with the specified dependencies.
    /// </summary>
    /// <param name="deviceKeyPair">This device's Ed25519 identity key pair</param>
    /// <param name="deviceLinkingService">Service for handling device linking operations</param>
    /// <param name="cryptoProvider">Cryptographic provider implementation</param>
    /// <param name="syncMessageValidator">Optional validator for sync messages</param>
    /// <param name="storagePath">
    /// Optional directory path for persisting the device list.  When provided the device list is
    /// saved to disk after every add / remove operation and can be restored via
    /// <see cref="LoadFromStorageAsync"/>.  When <c>null</c> the manager operates in-memory only
    /// (backward-compatible default).
    /// </param>
    /// <exception cref="ArgumentNullException">Thrown when required parameters are null</exception>
    /// <exception cref="ArgumentException">Thrown when device key pair is invalid</exception>
    public DeviceManager(
        KeyPair deviceKeyPair,
        IDeviceLinkingService deviceLinkingService,
        ICryptoProvider cryptoProvider,
        ISyncMessageValidator? syncMessageValidator = null,
        string? storagePath = null)
    {
        if (deviceKeyPair.PublicKey == null || deviceKeyPair.PublicKey.Length == 0)
            throw new ArgumentException("Device public key cannot be null or empty", nameof(deviceKeyPair));

        if (deviceKeyPair.PrivateKey == null || deviceKeyPair.PrivateKey.Length == 0)
            throw new ArgumentException("Device private key cannot be null or empty", nameof(deviceKeyPair));

        // Create a deep copy of the key pair to prevent external modification
        _deviceKeyPair = new KeyPair(
            SecureMemory.SecureCopy(deviceKeyPair.PublicKey) ?? throw new ArgumentNullException(nameof(deviceKeyPair.PublicKey)),
            SecureMemory.SecureCopy(deviceKeyPair.PrivateKey) ?? throw new ArgumentNullException(nameof(deviceKeyPair.PrivateKey))
        );

        _deviceLinkingService = deviceLinkingService ?? throw new ArgumentNullException(nameof(deviceLinkingService));
        _cryptoProvider = cryptoProvider ?? throw new ArgumentNullException(nameof(cryptoProvider));
        _syncMessageValidator = syncMessageValidator ?? new SyncMessageValidator(cryptoProvider);

        if (storagePath != null)
        {
            _deviceStorage = new DeviceStorage(_cryptoProvider, storagePath);
        }
    }

    /// <summary>
    /// Ensures the persisted device list has been loaded at most once.
    /// Subsequent calls after the first successful load are no-ops.
    /// Safe to call concurrently — only one load will actually run.
    /// </summary>
    private async Task EnsureStorageLoadedAsync()
    {
        if (_storageLoaded || _deviceStorage == null)
            return;

        await _loadLock.WaitAsync().ConfigureAwait(false);
        try
        {
            // Double-check after acquiring the lock.
            if (_storageLoaded)
                return;

            await LoadFromStorageAsync().ConfigureAwait(false);
            _storageLoaded = true;
        }
        finally
        {
            _loadLock.Release();
        }
    }

    /// <summary>
    /// Loads the previously persisted device list from disk into memory.
    /// Call this once after construction when a <c>storagePath</c> was provided.
    /// Has no effect when no storage path was configured.
    /// </summary>
    /// <returns>The number of devices loaded from disk.</returns>
    public async Task<int> LoadFromStorageAsync()
    {
        ThrowIfDisposed();

        if (_deviceStorage == null)
            return 0;

        try
        {
            var stored = await _deviceStorage.LoadAsync().ConfigureAwait(false);
            int count = 0;

            foreach (var info in stored)
            {
                if (string.IsNullOrEmpty(info.Id) || string.IsNullOrEmpty(info.PublicKey))
                    continue;

                // Skip already-present entries to avoid duplicates on repeated calls.
                if (_linkedDevices.ContainsKey(info.Id))
                    continue;

                try
                {
                    byte[] publicKey = Convert.FromBase64String(info.PublicKey);

                    // Do not re-import revoked devices.
                    if (IsDeviceRevoked(publicKey))
                        continue;

                    var deviceInfo = new DeviceInfo
                    {
                        PublicKey = publicKey,
                        LinkedAt = info.LinkedAt
                    };

                    if (_linkedDevices.TryAdd(info.Id, deviceInfo))
                        count++;
                }
                catch (Exception ex)
                {
                    LoggingManager.LogWarning(nameof(DeviceManager),
                        $"Skipping corrupt device entry '{info.Id}' during load: {ex.Message}");
                }
            }

            LoggingManager.LogInformation(nameof(DeviceManager),
                $"Loaded {count} device(s) from persistent storage.");

            // Mark storage as loaded so lazy callers know not to re-load.
            _storageLoaded = true;
            return count;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(DeviceManager),
                $"Failed to load devices from storage: {ex.Message}");
            return 0;
        }
    }

    /// <summary>
    /// Persists the current in-memory device list to disk.
    /// Does nothing when no storage path was configured.
    /// </summary>
    private void PersistDevicesFireAndForget()
    {
        if (_deviceStorage == null || _disposed)
            return;

        // Snapshot the current list before handing it to the background task so
        // that later mutations do not affect what we write.
        var snapshot = _linkedDevices
            .Select(kvp => new LinkedDeviceInfo
            {
                Id = kvp.Key,
                PublicKey = Convert.ToBase64String(kvp.Value.PublicKey),
                LinkedAt = kvp.Value.LinkedAt
            })
            .ToList();

        _ = _deviceStorage.SaveAsync(snapshot).ContinueWith(t =>
        {
            if (t.IsFaulted)
            {
                LoggingManager.LogError(nameof(DeviceManager),
                    $"Background device persistence failed: {t.Exception?.GetBaseException().Message}");
            }
        }, TaskScheduler.Default);
    }

    /// <summary>
    /// Throws an ObjectDisposedException if this object has been disposed.
    /// </summary>
    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(DeviceManager));
        }
    }

    /// <summary>
    /// Disposes of resources used by the DeviceManager.
    /// </summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Disposes of resources used by the DeviceManager.
    /// </summary>
    /// <param name="disposing">True if disposing, false if finalizing</param>
    protected virtual void Dispose(bool disposing)
    {
        if (_disposed) return;

        if (disposing)
        {
            // Dispose of managed resources
            _stateLock.Dispose();
            _loadLock.Dispose();
            _deviceStorage?.Dispose();

            // Clear any sensitive data
            foreach (var device in _linkedDevices.Values)
            {
                if (device.PublicKey != null)
                {
                    SecureMemory.SecureClear(device.PublicKey);
                }
            }

            // Clear collections
            _linkedDevices.Clear();
            _processedRevocations.Clear();

            // Clear device key pair
            if (_deviceKeyPair.PublicKey != null)
                SecureMemory.SecureClear(_deviceKeyPair.PublicKey);
            if (_deviceKeyPair.PrivateKey != null)
                SecureMemory.SecureClear(_deviceKeyPair.PrivateKey);
        }

        _disposed = true;
    }
}
