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

    /// <summary>
    /// Creates a new multi-device manager with the specified dependencies.
    /// </summary>
    /// <param name="deviceKeyPair">This device's Ed25519 identity key pair</param>
    /// <param name="deviceLinkingService">Service for handling device linking operations</param>
    /// <param name="cryptoProvider">Cryptographic provider implementation</param>
    /// <param name="syncMessageValidator">Optional validator for sync messages</param>
    /// <exception cref="ArgumentNullException">Thrown when required parameters are null</exception>
    /// <exception cref="ArgumentException">Thrown when device key pair is invalid</exception>
    public DeviceManager(
        KeyPair deviceKeyPair,
        IDeviceLinkingService deviceLinkingService,
        ICryptoProvider cryptoProvider,
        ISyncMessageValidator? syncMessageValidator = null)
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
