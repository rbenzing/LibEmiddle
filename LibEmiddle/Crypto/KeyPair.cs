namespace LibEmiddle.Crypto
{
    /// <summary>
    /// Provides key pair import/export management.
    /// </summary>
    public static class KeyPair
    {
        /// <summary>
        /// Exports a key to a secure Base64 string representation
        /// </summary>
        /// <param name="key">The key to export</param>
        /// <returns>Base64 encoded string representation of the key</returns>
        public static string ExportKeyToBase64(byte[] key)
        {
            return Convert.ToBase64String(key);
        }

        /// <summary>
        /// Imports a key from a Base64 string representation
        /// </summary>
        /// <param name="base64Key">Base64 encoded key</param>
        /// <returns>Byte array representation of the key</returns>
        public static byte[] ImportKeyFromBase64(string base64Key)
        {
            return Convert.FromBase64String(base64Key);
        }
    }
}