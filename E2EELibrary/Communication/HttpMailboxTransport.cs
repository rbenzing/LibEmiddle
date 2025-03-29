using System.Text;
using System.Text.Json;
using E2EELibrary.Communication.Abstract;
using E2EELibrary.Models;

namespace E2EELibrary.Communication
{
    /// <summary>
    /// Implements the mailbox transport using HTTP requests to a mailbox server.
    /// </summary>
    public class HttpMailboxTransport : IMailboxTransport
    {
        private readonly HttpClient _httpClient;
        private readonly string _baseUrl;
        private readonly JsonSerializerOptions _jsonOptions;

        /// <summary>
        /// Creates a new HTTP-based mailbox transport.
        /// </summary>
        /// <param name="baseUrl">Base URL of the mailbox server</param>
        /// <param name="httpClient">Optional HTTP client (for testing or custom configuration)</param>
        public HttpMailboxTransport(string baseUrl, HttpClient httpClient = null)
        {
            _baseUrl = baseUrl.TrimEnd('/');
            _httpClient = httpClient ?? new HttpClient();
            _jsonOptions = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                WriteIndented = false
            };
        }

        /// <summary>
        /// Sends a message to the mailbox server.
        /// </summary>
        /// <param name="message">The message to send</param>
        /// <returns>True if the send operation was successful</returns>
        public async Task<bool> SendMessageAsync(MailboxMessage message)
        {
            try
            {
                string json = JsonSerializer.Serialize(message, _jsonOptions);
                var content = new StringContent(json, Encoding.UTF8, "application/json");

                var response = await _httpClient.PostAsync($"{_baseUrl}/messages", content);

                return response.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                // Log the error - in production this would use a proper logging framework
                Console.WriteLine($"Error sending message: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Fetches messages from the mailbox server.
        /// </summary>
        /// <param name="recipientKey">The recipient's public key</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>List of mailbox messages for the recipient</returns>
        public async Task<List<MailboxMessage>> FetchMessagesAsync(byte[] recipientKey, CancellationToken cancellationToken)
        {
            try
            {
                // Convert recipient key to base64 for use in URL
                string recipientKeyBase64 = Convert.ToBase64String(recipientKey);

                var response = await _httpClient.GetAsync(
                    $"{_baseUrl}/messages?recipient={Uri.EscapeDataString(recipientKeyBase64)}",
                    cancellationToken);

                if (!response.IsSuccessStatusCode)
                {
                    return new List<MailboxMessage>();
                }

                string json = await response.Content.ReadAsStringAsync();
                var messages = JsonSerializer.Deserialize<List<MailboxMessage>>(json, _jsonOptions);

                return messages ?? new List<MailboxMessage>();
            }
            catch (OperationCanceledException)
            {
                // Rethrow cancellation exceptions
                throw;
            }
            catch (Exception ex)
            {
                // Log the error - in production this would use a proper logging framework
                Console.WriteLine($"Error fetching messages: {ex.Message}");
                return new List<MailboxMessage>();
            }
        }

        /// <summary>
        /// Deletes a message from the server.
        /// </summary>
        /// <param name="messageId">The message ID to delete</param>
        /// <returns>True if the deletion was successful</returns>
        public async Task<bool> DeleteMessageAsync(string messageId)
        {
            try
            {
                var response = await _httpClient.DeleteAsync($"{_baseUrl}/messages/{Uri.EscapeDataString(messageId)}");
                return response.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                // Log the error - in production this would use a proper logging framework
                Console.WriteLine($"Error deleting message: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Marks a message as read on the server.
        /// </summary>
        /// <param name="messageId">The message ID to mark as read</param>
        /// <returns>True if the operation was successful</returns>
        public async Task<bool> MarkMessageAsReadAsync(string messageId)
        {
            try
            {
                var content = new StringContent("{\"read\": true}", Encoding.UTF8, "application/json");
                var response = await _httpClient.PatchAsync($"{_baseUrl}/messages/{Uri.EscapeDataString(messageId)}", content);
                return response.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                // Log the error - in production this would use a proper logging framework
                Console.WriteLine($"Error marking message as read: {ex.Message}");
                return false;
            }
        }
    }
}