namespace LibEmiddle.Abstractions
{
    /// <summary>
    /// Defines an interface for storage providers to persist and retrieve data.
    /// Implementations can store data in various backends such as filesystem, 
    /// secure key stores, databases, or cloud storage.
    /// </summary>
    public interface IStorageProvider
    {
        /// <summary>
        /// Stores data in the storage backend.
        /// </summary>
        /// <param name="key">The unique key to identify the data.</param>
        /// <param name="data">The data to store.</param>
        /// <returns>A task that represents the asynchronous operation.</returns>
        Task StoreAsync(string key, string data);

        /// <summary>
        /// Stores binary data in the storage backend.
        /// </summary>
        /// <param name="key">The unique key to identify the data.</param>
        /// <param name="data">The binary data to store.</param>
        /// <returns>A task that represents the asynchronous operation.</returns>
        Task StoreBinaryAsync(string key, byte[] data);

        /// <summary>
        /// Retrieves data from the storage backend.
        /// </summary>
        /// <param name="key">The unique key to identify the data.</param>
        /// <returns>The stored data, or null if the key doesn't exist.</returns>
        Task<string> RetrieveAsync(string key);

        /// <summary>
        /// Retrieves binary data from the storage backend.
        /// </summary>
        /// <param name="key">The unique key to identify the data.</param>
        /// <returns>The stored binary data, or null if the key doesn't exist.</returns>
        Task<byte[]?> RetrieveBinaryAsync(string key);

        /// <summary>
        /// Deletes data from the storage backend.
        /// </summary>
        /// <param name="key">The unique key to identify the data.</param>
        /// <returns>True if the data was deleted, false if the key doesn't exist.</returns>
        Task<bool> DeleteAsync(string key);

        /// <summary>
        /// Checks if a key exists in the storage backend.
        /// </summary>
        /// <param name="key">The unique key to check.</param>
        /// <returns>True if the key exists, false otherwise.</returns>
        Task<bool> ExistsAsync(string key);

        /// <summary>
        /// Lists all keys in the storage backend that match a prefix.
        /// </summary>
        /// <param name="keyPrefix">The prefix to match keys against.</param>
        /// <returns>A list of keys that match the prefix.</returns>
        Task<List<string>> ListKeysAsync(string keyPrefix);

        /// <summary>
        /// Securely clears all data from the storage backend.
        /// </summary>
        /// <returns>A task that represents the asynchronous operation.</returns>
        Task ClearAllAsync();
    }
}