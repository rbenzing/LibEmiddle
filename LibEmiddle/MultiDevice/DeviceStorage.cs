using System.Text;
using System.Text.Json;
using LibEmiddle.Abstractions;
using LibEmiddle.Core;
using LibEmiddle.Domain;

namespace LibEmiddle.MultiDevice;

/// <summary>
/// Provides atomic, thread-safe persistence of a device list to disk using AES-GCM encryption.
///
/// <para>
/// Writes are performed atomically via a temp-file-then-rename pattern so that a
/// crash mid-write never leaves a partially-written or corrupted file on disk.
/// All file content is encrypted using the same pattern as <c>SessionPersistenceManager</c>:
/// a per-write random AES-256 key is generated, used to encrypt the JSON payload, and
/// then stored in the platform's secure key storage via <see cref="ICryptoProvider.StoreKeyAsync"/>.
/// All public methods are safe to call from multiple threads concurrently.
/// </para>
/// </summary>
internal sealed class DeviceStorage : IDisposable
{
    private const string StorageKeyId = "devices:linked-devices";

    private readonly string _filePath;
    private readonly ICryptoProvider _cryptoProvider;
    private readonly SemaphoreSlim _ioLock = new(1, 1);
    private volatile bool _disposed;

    private static readonly JsonSerializerOptions _jsonOptions = new()
    {
        WriteIndented = false,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    /// <summary>
    /// Initialises a new instance and ensures the storage directory exists.
    /// </summary>
    /// <param name="cryptoProvider">
    /// Cryptographic provider used to encrypt/decrypt the device file and to persist the
    /// per-write encryption key in the platform's secure key storage.
    /// </param>
    /// <param name="storagePath">
    /// Directory that will hold the devices file.  When <c>null</c> the default
    /// <c>%LocalAppData%\LibEmiddle\Devices</c> path is used.
    /// </param>
    public DeviceStorage(ICryptoProvider cryptoProvider, string? storagePath = null)
    {
        _cryptoProvider = cryptoProvider ?? throw new ArgumentNullException(nameof(cryptoProvider));

        string directory = storagePath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "LibEmiddle",
            "Devices");

        Directory.CreateDirectory(directory);
        _filePath = Path.Combine(directory, "linked-devices.enc");
    }

    /// <summary>
    /// Encrypts and persists <paramref name="devices"/> to disk atomically.
    /// Replaces any previously saved list.
    /// </summary>
    /// <param name="devices">The full current device list to save.</param>
    /// <returns><c>true</c> on success, <c>false</c> on failure (error is logged).</returns>
    public async Task<bool> SaveAsync(IEnumerable<LinkedDeviceInfo> devices)
    {
        ThrowIfDisposed();

        byte[]? key = null;
        try
        {
            // Serialize to JSON then encode as UTF-8 bytes.
            string json = JsonSerializer.Serialize(devices.ToList(), _jsonOptions);
            byte[] plaintext = Encoding.UTF8.GetBytes(json);

            // Generate a fresh random key and nonce for this write.
            key = _cryptoProvider.GenerateRandomBytes(Constants.AES_KEY_SIZE);
            byte[] nonce = _cryptoProvider.GenerateRandomBytes((uint)Constants.NONCE_SIZE);

            // Encrypt the payload.
            byte[] ciphertext = _cryptoProvider.Encrypt(plaintext, key, nonce, null);

            // Build the file header: nonce length (4 bytes) + nonce + ciphertext.
            // This embeds the nonce directly in the file so it is available at load time.
            byte[] fileContent = BuildFileContent(nonce, ciphertext);

            await _ioLock.WaitAsync().ConfigureAwait(false);
            try
            {
                if (!AtomicWrite(_filePath, fileContent))
                    return false;

                // Persist the encryption key in secure storage so it can be retrieved on load.
                bool keyStored = await _cryptoProvider.StoreKeyAsync(StorageKeyId, key).ConfigureAwait(false);
                if (!keyStored)
                {
                    // If we cannot store the key the file is unreadable — remove it.
                    try { if (File.Exists(_filePath)) File.Delete(_filePath); } catch { /* best-effort */ }
                    LoggingManager.LogError(nameof(DeviceStorage),
                        "Failed to store encryption key for device list; file removed.");
                    return false;
                }

                return true;
            }
            finally
            {
                _ioLock.Release();
            }
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(DeviceStorage), $"Failed to save device list: {ex.Message}");
            return false;
        }
        finally
        {
            if (key != null)
                SecureMemory.SecureClear(key);
        }
    }

    /// <summary>
    /// Decrypts and loads the persisted device list from disk.
    /// Returns an empty list if no file exists, if the file is corrupt, or if the
    /// encryption key cannot be retrieved from secure storage.
    /// </summary>
    public async Task<List<LinkedDeviceInfo>> LoadAsync()
    {
        ThrowIfDisposed();

        byte[]? key = null;
        await _ioLock.WaitAsync().ConfigureAwait(false);
        try
        {
            if (!File.Exists(_filePath))
                return new List<LinkedDeviceInfo>();

            byte[] fileContent = await File.ReadAllBytesAsync(_filePath).ConfigureAwait(false);

            // Parse the nonce and ciphertext out of the stored file content.
            if (!TryParseFileContent(fileContent, out byte[] nonce, out byte[] ciphertext))
            {
                LoggingManager.LogError(nameof(DeviceStorage),
                    "Device list file is malformed — starting with empty list.");
                return new List<LinkedDeviceInfo>();
            }

            // Retrieve the encryption key from secure storage.
            key = await _cryptoProvider.RetrieveKeyAsync(StorageKeyId).ConfigureAwait(false);
            if (key == null)
            {
                LoggingManager.LogError(nameof(DeviceStorage),
                    "Encryption key for device list not found in secure storage — starting with empty list.");
                return new List<LinkedDeviceInfo>();
            }

            // Decrypt and deserialize.
            byte[] plaintext = _cryptoProvider.Decrypt(ciphertext, key, nonce, null);
            string json = Encoding.UTF8.GetString(plaintext);

            var result = JsonSerializer.Deserialize<List<LinkedDeviceInfo>>(json, _jsonOptions);
            return result ?? new List<LinkedDeviceInfo>();
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(DeviceStorage),
                $"Failed to load device list — starting with empty list: {ex.Message}");
            return new List<LinkedDeviceInfo>();
        }
        finally
        {
            if (key != null)
                SecureMemory.SecureClear(key);
            _ioLock.Release();
        }
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /// <summary>
    /// Packs nonce and ciphertext into the binary file format:
    /// [4-byte nonce length (little-endian)][nonce bytes][ciphertext bytes].
    /// </summary>
    private static byte[] BuildFileContent(byte[] nonce, byte[] ciphertext)
    {
        byte[] result = new byte[4 + nonce.Length + ciphertext.Length];
        BitConverter.TryWriteBytes(result.AsSpan(0, 4), nonce.Length);
        nonce.CopyTo(result.AsSpan(4));
        ciphertext.CopyTo(result.AsSpan(4 + nonce.Length));
        return result;
    }

    /// <summary>
    /// Parses the binary file format written by <see cref="BuildFileContent"/>.
    /// Returns <c>false</c> if the buffer is too short or otherwise malformed.
    /// </summary>
    private static bool TryParseFileContent(byte[] fileContent, out byte[] nonce, out byte[] ciphertext)
    {
        nonce = Array.Empty<byte>();
        ciphertext = Array.Empty<byte>();

        if (fileContent.Length < 4)
            return false;

        int nonceLength = BitConverter.ToInt32(fileContent, 0);
        if (nonceLength <= 0 || nonceLength > fileContent.Length - 4)
            return false;

        nonce = new byte[nonceLength];
        Buffer.BlockCopy(fileContent, 4, nonce, 0, nonceLength);

        int ciphertextStart = 4 + nonceLength;
        int ciphertextLength = fileContent.Length - ciphertextStart;
        if (ciphertextLength <= 0)
            return false;

        ciphertext = new byte[ciphertextLength];
        Buffer.BlockCopy(fileContent, ciphertextStart, ciphertext, 0, ciphertextLength);
        return true;
    }

    /// <summary>
    /// Writes <paramref name="data"/> to a temp file alongside <paramref name="targetPath"/>
    /// and then atomically renames it to replace the target.
    /// </summary>
    private static bool AtomicWrite(string targetPath, byte[] data)
    {
        // Place the temp file in the same directory so rename is atomic on the same volume.
        string tempPath = targetPath + ".tmp";

        try
        {
            File.WriteAllBytes(tempPath, data);

            // On all supported platforms File.Move with overwrite=true is atomic
            // as long as source and destination are on the same filesystem volume.
            File.Move(tempPath, targetPath, overwrite: true);
            return true;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(DeviceStorage),
                $"Atomic write failed for {targetPath}: {ex.Message}");

            // Best-effort cleanup of the temp file.
            try { if (File.Exists(tempPath)) File.Delete(tempPath); } catch { /* ignore */ }
            return false;
        }
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(DeviceStorage));
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _ioLock.Dispose();
    }
}
