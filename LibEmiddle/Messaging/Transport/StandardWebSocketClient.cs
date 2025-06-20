﻿using LibEmiddle.Abstractions;
using System.Net.WebSockets;

namespace LibEmiddle.Messaging.Transport
{
    /// <summary>
    /// Standard implementation of IWebSocketClient using System.Net.WebSockets.ClientWebSocket
    /// </summary>
    /// <remarks>
    /// Initializes a new instance of the StandardWebSocketClient class
    /// </remarks>
    public class StandardWebSocketClient(Uri endpoint) : IWebSocketClient
    {
        private readonly ClientWebSocket _clientWebSocket = new();
        private Uri _endpoint = endpoint;

        /// <summary>
        /// Gets the current state of the WebSocket connection
        /// </summary>
        public WebSocketState State => _clientWebSocket.State;

        /// <summary>
        /// Connects to a WebSocket server as an asynchronous operation
        /// </summary>
        /// <param name="cancellationToken">A cancellation token used to propagate notification that the operation should be canceled</param>
        /// <returns>A task that represents the asynchronous operation</returns>
        public Task ConnectAsync(CancellationToken cancellationToken)
        {
            return _clientWebSocket.ConnectAsync(_endpoint, cancellationToken);
        }

        /// <summary>
        /// Sends data over the WebSocket connection as an asynchronous operation
        /// </summary>
        /// <param name="buffer">The buffer containing the message to send</param>
        /// <param name="messageType">The type of message being sent</param>
        /// <param name="endOfMessage">True if this message is a standalone message or the end of a fragmented message, false if it's part of a fragmented message and more fragments will follow</param>
        /// <param name="cancellationToken">A cancellation token used to propagate notification that the operation should be canceled</param>
        /// <returns>A task that represents the asynchronous operation</returns>
        public Task SendAsync(ArraySegment<byte> buffer, WebSocketMessageType messageType, bool endOfMessage, CancellationToken cancellationToken)
        {
            return _clientWebSocket.SendAsync(buffer, messageType, endOfMessage, cancellationToken);
        }

        /// <summary>
        /// Receives data from the WebSocket connection as an asynchronous operation
        /// </summary>
        /// <param name="buffer">The buffer to receive the message into</param>
        /// <param name="cancellationToken">A cancellation token used to propagate notification that the operation should be canceled</param>
        /// <returns>A task that represents the asynchronous receive operation. The Result property of the task contains information on the received message</returns>
        public Task<WebSocketReceiveResult> ReceiveAsync(ArraySegment<byte> buffer, CancellationToken cancellationToken)
        {
            return _clientWebSocket.ReceiveAsync(buffer, cancellationToken);
        }

        /// <summary>
        /// Closes the WebSocket connection as an asynchronous operation
        /// </summary>
        /// <param name="closeStatus">The WebSocket close status</param>
        /// <param name="statusDescription">The WebSocket close status description</param>
        /// <param name="cancellationToken">A cancellation token used to propagate notification that the operation should be canceled</param>
        /// <returns>A task that represents the asynchronous operation</returns>
        public Task CloseAsync(WebSocketCloseStatus closeStatus, string statusDescription, CancellationToken cancellationToken)
        {
            return _clientWebSocket.CloseAsync(closeStatus, statusDescription, cancellationToken);
        }
    }
}