using System.Net.WebSockets;

namespace E2EELibrary.Communication
{
    /// <summary>
    /// Interface for WebSocket client operations, designed to be mockable for testing
    /// </summary>
    public interface IWebSocketClient
    {
        /// <summary>
        /// Gets the current state of the WebSocket connection
        /// </summary>
        WebSocketState State { get; }

        /// <summary>
        /// Connects to a WebSocket server as an asynchronous operation
        /// </summary>
        /// <param name="uri">The URI of the WebSocket server to connect to</param>
        /// <param name="cancellationToken">A cancellation token used to propagate notification that the operation should be canceled</param>
        /// <returns>A task that represents the asynchronous operation</returns>
        Task ConnectAsync(Uri uri, CancellationToken cancellationToken);

        /// <summary>
        /// Sends data over the WebSocket connection as an asynchronous operation
        /// </summary>
        /// <param name="buffer">The buffer containing the message to send</param>
        /// <param name="messageType">The type of message being sent</param>
        /// <param name="endOfMessage">True if this message is a standalone message or the end of a fragmented message, false if it's part of a fragmented message and more fragments will follow</param>
        /// <param name="cancellationToken">A cancellation token used to propagate notification that the operation should be canceled</param>
        /// <returns>A task that represents the asynchronous operation</returns>
        Task SendAsync(ArraySegment<byte> buffer, WebSocketMessageType messageType, bool endOfMessage, CancellationToken cancellationToken);

        /// <summary>
        /// Receives data from the WebSocket connection as an asynchronous operation
        /// </summary>
        /// <param name="buffer">The buffer to receive the message into</param>
        /// <param name="cancellationToken">A cancellation token used to propagate notification that the operation should be canceled</param>
        /// <returns>A task that represents the asynchronous receive operation. The Result property of the task contains information on the received message</returns>
        Task<WebSocketReceiveResult> ReceiveAsync(ArraySegment<byte> buffer, CancellationToken cancellationToken);

        /// <summary>
        /// Closes the WebSocket connection as an asynchronous operation
        /// </summary>
        /// <param name="closeStatus">The WebSocket close status</param>
        /// <param name="statusDescription">The WebSocket close status description</param>
        /// <param name="cancellationToken">A cancellation token used to propagate notification that the operation should be canceled</param>
        /// <returns>A task that represents the asynchronous operation</returns>
        Task CloseAsync(WebSocketCloseStatus closeStatus, string statusDescription, CancellationToken cancellationToken);
    }
}