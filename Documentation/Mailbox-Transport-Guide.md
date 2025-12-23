# Mailbox Transport System - Complete Guide

## Table of Contents
1. [Overview](#overview)
2. [Architecture](#architecture)
3. [How It Works](#how-it-works)
4. [Transport Types](#transport-types)
5. [Usage Examples](#usage-examples)
6. [Message Flow](#message-flow)
7. [Best Practices](#best-practices)
8. [Troubleshooting](#troubleshooting)

---

## Overview

The **Mailbox Transport System** is LibEmiddle's asynchronous message delivery layer, providing a flexible abstraction for sending and receiving encrypted messages. Think of it as a "post office" for encrypted messages - it handles message routing, delivery, and polling while the encryption/decryption is handled by the protocol layers above it.

### Key Characteristics

- **Asynchronous**: Messages are queued and delivered when recipients are ready
- **Transport-Agnostic**: Switch between HTTP, WebSocket, or in-memory implementations
- **Encrypted Payloads**: Transports messages that are already encrypted by Double Ratchet
- **Event-Driven**: Receive notifications when new messages arrive
- **Reliable**: Built-in retry logic and delivery receipts

---

## Architecture

The mailbox transport system follows a layered architecture with clear separation of concerns:

```
┌─────────────────────────────────────────────────────────┐
│                  LibEmiddleClient                        │
│              (High-level unified API)                    │
└───────────────────────┬─────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────┐
│                   ChatSession                            │
│            (Per-conversation management)                 │
└───────────────────────┬─────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────┐
│                 MailboxManager                           │
│   (Orchestrates Double Ratchet + Transport)             │
│   - Manages encryption/decryption sessions              │
│   - Queues outgoing messages                            │
│   - Processes incoming messages                         │
│   - Handles delivery/read receipts                      │
└───────────────────────┬─────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────┐
│               IMailboxTransport                          │
│           (Transport abstraction layer)                  │
└───────────────────────┬─────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────┐
│             BaseMailboxTransport                         │
│        (Common functionality & validation)               │
│   - Message validation                                   │
│   - Logging and events                                   │
│   - Disposal pattern                                     │
└───────────────────────┬─────────────────────────────────┘
                        │
           ┌────────────┴────────────┐
           ▼                         ▼
┌──────────────────────┐  ┌──────────────────────┐
│ HttpMailboxTransport │  │InMemoryMailboxTransport│
│  (HTTP REST API)     │  │   (Testing/Local)     │
└──────────────────────┘  └──────────────────────┘
```

### Layer Responsibilities

| Layer | Responsibility | Handles Encryption? |
|-------|---------------|---------------------|
| **LibEmiddleClient** | Unified API for all operations | No |
| **ChatSession** | Per-conversation session management | No |
| **MailboxManager** | Orchestrates Double Ratchet + Transport | **Yes** (encrypts/decrypts) |
| **IMailboxTransport** | Transport abstraction contract | No |
| **BaseMailboxTransport** | Common transport functionality | No |
| **Concrete Transports** | Actual message delivery mechanism | No |

**Important**: Only `MailboxManager` handles encryption/decryption using the Double Ratchet protocol. All transport layers work with already-encrypted `MailboxMessage` objects.

---

## How It Works

### The Journey of a Message

#### Sending a Message

```
1. User calls client.SendChatMessageAsync("Hello!")
         ↓
2. LibEmiddleClient creates/retrieves ChatSession
         ↓
3. ChatSession.EncryptAsync() delegates to MailboxManager
         ↓
4. MailboxManager encrypts plaintext using DoubleRatchet
         ↓
5. MailboxManager creates MailboxMessage with encrypted payload
         ↓
6. Message added to outgoing queue
         ↓
7. Background sending task dequeues and sends via IMailboxTransport
         ↓
8. BaseMailboxTransport validates message
         ↓
9. Concrete transport (Http/InMemory) sends to server/storage
         ↓
10. Server stores message in recipient's mailbox
```

#### Receiving a Message

```
1. Transport polling loop fetches messages from server
         ↓
2. BaseMailboxTransport validates each message
         ↓
3. OnMessageReceived event raises to MailboxManager
         ↓
4. MailboxManager adds to incoming message dictionary
         ↓
5. MessageReceived event fires to ChatSession
         ↓
6. ChatSession decrypts using DoubleRatchet
         ↓
7. LibEmiddleClient.MessageReceived event fires to application
         ↓
8. Application displays decrypted message to user
```

### Key Concepts

**MailboxMessage**: A container that wraps an encrypted message with metadata:
- `RecipientKey`: Who should receive this message
- `SenderKey`: Who sent this message
- `EncryptedPayload`: The actual encrypted content (from Double Ratchet)
- `Timestamp`, `ExpiresAt`, `IsDelivered`, `IsRead`: Metadata

**Polling**: Transports periodically check for new messages:
- Default interval: 5 seconds (configurable)
- Runs in background task
- Automatic retry on errors

**Sessions**: MailboxManager maintains Double Ratchet sessions per contact:
- Each contact has a unique session ID
- Sessions persist across restarts
- Support encryption/decryption with forward secrecy

---

## Transport Types

### 1. InMemoryMailboxTransport

**Purpose**: Local testing and development

**When to Use**:
- Unit tests
- Integration tests
- Local development without a server
- Demo applications

**Characteristics**:
- ✅ Thread-safe with semaphore locking
- ✅ Zero network dependencies
- ✅ Fast and simple
- ❌ Messages lost on restart
- ❌ Not suitable for production

**Configuration**:
```csharp
var options = new LibEmiddleClientOptions
{
    TransportType = TransportType.InMemory
};
```

**Use Case Example**:
```csharp
// Perfect for testing two users on the same machine
var alice = new LibEmiddleClient(new LibEmiddleClientOptions
{
    TransportType = TransportType.InMemory
});

var bob = new LibEmiddleClient(new LibEmiddleClientOptions
{
    TransportType = TransportType.InMemory
});

await alice.InitializeAsync();
await bob.InitializeAsync();

// Alice sends to Bob - both use the same in-memory storage
await alice.SendChatMessageAsync(bobPublicKey, "Hello Bob!");
```

---

### 2. HttpMailboxTransport

**Purpose**: Production use with HTTP REST API

**When to Use**:
- Production deployments
- Remote users
- Reliable message delivery required
- Server-based message storage

**Characteristics**:
- ✅ Production-ready
- ✅ Works with remote servers
- ✅ Supports authentication headers
- ✅ Configurable timeouts
- ✅ Automatic retry logic
- ❌ Requires server endpoint

**Configuration**:
```csharp
var options = new LibEmiddleClientOptions
{
    TransportType = TransportType.Http,
    ServerEndpoint = "https://your-messaging-server.com/api",
    NetworkTimeoutMs = 30000,
    CustomHeaders = new Dictionary<string, string>
    {
        ["Authorization"] = "Bearer your-jwt-token",
        ["X-Client-Version"] = "2.5.0"
    }
};
```

**Server API Requirements**:

Your server must implement these REST endpoints:

| Method | Endpoint | Purpose | Request Body | Response |
|--------|----------|---------|--------------|----------|
| POST | `/messages` | Send message | `MailboxMessage` JSON | 200 OK |
| GET | `/messages/{recipientKey}` | Fetch messages | None | Array of `MailboxMessage` |
| DELETE | `/messages/{messageId}` | Delete message | None | 200 OK |
| PATCH | `/messages/{messageId}/read` | Mark as read | None | 200 OK |
| PATCH | `/messages/{messageId}/delivery-status` | Update delivery | `{ isDelivered: bool }` | 200 OK |

**Example Server Endpoints** (pseudocode):
```csharp
// POST /messages
[HttpPost("messages")]
public IActionResult SendMessage([FromBody] MailboxMessage message)
{
    // Store message in database keyed by recipientKey
    _messageStore.Save(message);
    return Ok();
}

// GET /messages/{recipientKey}
[HttpGet("messages/{recipientKey}")]
public IActionResult GetMessages(string recipientKey)
{
    var messages = _messageStore.GetUnreadMessages(recipientKey);
    return Ok(messages);
}
```

---

## Usage Examples

### Example 1: Basic Chat with InMemory Transport

```csharp
using LibEmiddle.API;
using LibEmiddle.Domain.Enums;

// Setup
var aliceOptions = new LibEmiddleClientOptions
{
    TransportType = TransportType.InMemory,
    EnableMessageHistory = true
};

var bobOptions = new LibEmiddleClientOptions
{
    TransportType = TransportType.InMemory,
    EnableMessageHistory = true
};

using var alice = new LibEmiddleClient(aliceOptions);
using var bob = new LibEmiddleClient(bobOptions);

await alice.InitializeAsync();
await bob.InitializeAsync();

// Get public keys for addressing
var alicePublicKey = alice.GetIdentityPublicKey();
var bobPublicKey = bob.GetIdentityPublicKey();

// Bob listens for messages
bob.MessageReceived += async (sender, args) =>
{
    Console.WriteLine($"Bob received: {args.DecryptedContent}");
    Console.WriteLine($"From: {Convert.ToBase64String(args.Message.SenderKey)[..8]}...");
};

// Start listening
await bob.StartListeningAsync();

// Alice sends to Bob
var chatSession = await alice.CreateChatSessionAsync(bobPublicKey, "bob@example.com");
await alice.SendChatMessageAsync(bobPublicKey, "Hello Bob!");

// Wait for delivery
await Task.Delay(2000);

// Stop listening
await bob.StopListeningAsync();
```

---

### Example 2: Production HTTP Transport

```csharp
using LibEmiddle.API;
using LibEmiddle.Domain.Enums;

var options = new LibEmiddleClientOptions
{
    TransportType = TransportType.Http,
    ServerEndpoint = "https://messaging.yourcompany.com/api",
    NetworkTimeoutMs = 30000,
    EnableStrictCertificateValidation = true,

    CustomHeaders = new Dictionary<string, string>
    {
        ["Authorization"] = $"Bearer {await GetAuthToken()}",
        ["X-Device-Id"] = deviceId
    },

    // Configure retry behavior
    RetryOptions = new RetryOptions
    {
        MaxRetries = 3,
        BaseDelayMs = 1000,
        MaxDelayMs = 10000,
        BackoffMultiplier = 2.0
    }
};

using var client = new LibEmiddleClient(options);
await client.InitializeAsync();

// Listen for incoming messages
client.MessageReceived += async (sender, args) =>
{
    // Process message
    await ProcessIncomingMessage(args.Message, args.DecryptedContent);

    // Optionally mark as read
    await client.MarkMessageAsReadAsync(args.Message.Id);
};

// Start listening with custom polling interval
await client.StartListeningAsync(); // Default 5 second polling

// Send a message
await client.SendChatMessageAsync(recipientPublicKey, "Hello from production!");
```

---

### Example 3: Custom Polling Interval

```csharp
// For low-latency applications (more network traffic)
var lowLatencyOptions = new LibEmiddleClientOptions
{
    TransportType = TransportType.Http,
    ServerEndpoint = "https://messaging.example.com/api",
    // Note: Polling interval is configured when starting to listen
};

using var client = new LibEmiddleClient(lowLatencyOptions);
await client.InitializeAsync();

// Start listening with 1-second polling (more responsive, higher load)
await client.StartListeningAsync(pollingInterval: 1000);
```

---

### Example 4: Delivery and Read Receipts

```csharp
var options = new LibEmiddleClientOptions
{
    TransportType = TransportType.Http,
    ServerEndpoint = "https://messaging.example.com/api"
};

using var client = new LibEmiddleClient(options);
await client.InitializeAsync();

// Enable automatic receipt sending (enabled by default)
// Client automatically sends delivery receipts when messages are received
// and read receipts when MarkMessageAsReadAsync is called

client.MessageReceived += async (sender, args) =>
{
    var message = args.Message;

    Console.WriteLine($"Message delivered: {message.IsDelivered}");
    Console.WriteLine($"Delivered at: {DateTimeOffset.FromUnixTimeMilliseconds(message.DeliveredAt ?? 0)}");

    // Process message...

    // Mark as read (triggers automatic read receipt)
    await client.MarkMessageAsReadAsync(message.Id);
};

await client.StartListeningAsync();
```

---

### Example 5: Session Import/Export

```csharp
// Export session for backup or multi-device sync
var sessionData = mailboxManager.ExportSession(
    recipientId: Convert.ToBase64String(recipientPublicKey),
    encryptionKey: myEncryptionKey // Optional: encrypt the export
);

// Save to secure storage
await SecureStorage.SaveAsync("session_backup.dat", sessionData);

// Later, on another device or after crash...

// Import session
var importedData = await SecureStorage.LoadAsync("session_backup.dat");
bool success = mailboxManager.ImportSession(
    recipientId: Convert.ToBase64String(recipientPublicKey),
    sessionData: importedData,
    decryptionKey: myEncryptionKey // Must match encryption key
);

if (success)
{
    Console.WriteLine("Session restored successfully!");
}
```

---

## Message Flow

### Detailed Sequence Diagram

See [Message-Flow-Sequence.md](./Message-Flow-Sequence.md) for the complete Mermaid diagram showing:
- Complete message sending flow
- Complete message receiving flow
- Encryption/decryption at each layer
- Event propagation
- Error handling

---

## Best Practices

### 1. Choose the Right Transport

| Scenario | Recommended Transport |
|----------|----------------------|
| Unit testing | `InMemory` |
| Integration testing | `InMemory` |
| Local development | `InMemory` |
| Production single-server | `Http` |
| Production distributed | `Http` |
| Real-time requirements | `Http` with low polling interval |

### 2. Configure Polling Intervals Appropriately

```csharp
// Conservative (low server load, higher latency)
await client.StartListeningAsync(pollingInterval: 30000); // 30 seconds

// Balanced (recommended for most apps)
await client.StartListeningAsync(pollingInterval: 5000); // 5 seconds (default)

// Aggressive (higher server load, lower latency)
await client.StartListeningAsync(pollingInterval: 1000); // 1 second
```

**Rule of Thumb**:
- Chat apps: 2-5 seconds
- Notification systems: 10-30 seconds
- Background sync: 60+ seconds

### 3. Handle Message Received Events Efficiently

```csharp
client.MessageReceived += async (sender, args) =>
{
    try
    {
        // Process quickly - don't block the event handler
        await ProcessMessageAsync(args.Message, args.DecryptedContent);
    }
    catch (Exception ex)
    {
        // Always catch exceptions in event handlers
        logger.LogError(ex, "Error processing message {MessageId}", args.Message.Id);
    }
};
```

### 4. Always Dispose Clients Properly

```csharp
// Use 'using' statements
using var client = new LibEmiddleClient(options);
await client.InitializeAsync();
// ... use client ...
// Automatically disposed at end of scope

// Or explicit disposal
var client = new LibEmiddleClient(options);
try
{
    await client.InitializeAsync();
    // ... use client ...
}
finally
{
    client.Dispose(); // Stops listening and cleans up
}
```

### 5. Configure Appropriate Timeouts

```csharp
var options = new LibEmiddleClientOptions
{
    NetworkTimeoutMs = 30000, // 30 seconds for network operations

    RetryOptions = new RetryOptions
    {
        MaxRetries = 3,        // Try up to 3 times
        BaseDelayMs = 1000,    // Start with 1 second delay
        MaxDelayMs = 30000,    // Cap at 30 seconds
        BackoffMultiplier = 2.0 // Double delay each retry
    }
};
```

### 6. Implement Server-Side Message Expiration

```csharp
// When sending, optionally set expiration
var message = new MailboxMessage(recipientKey, senderKey, encryptedPayload)
{
    ExpiresAt = DateTimeOffset.UtcNow.AddDays(7).ToUnixTimeMilliseconds() // 7 day expiration
};
```

Server should clean up expired messages:
```csharp
// Pseudocode for server cleanup
async Task CleanupExpiredMessages()
{
    var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
    await _messageStore.DeleteWhere(m => m.ExpiresAt > 0 && m.ExpiresAt < now);
}
```

---

## Troubleshooting

### Problem: Messages Not Being Received

**Symptoms**: `MessageReceived` event never fires

**Solutions**:

1. **Check if listening started**:
```csharp
// Make sure you called StartListeningAsync
await client.StartListeningAsync();
```

2. **Verify recipient key matches**:
```csharp
// Sender must use recipient's PUBLIC key
var bobPublicKey = bob.GetIdentityPublicKey();
await alice.SendChatMessageAsync(bobPublicKey, "message");

// NOT the private key!
```

3. **Check transport configuration**:
```csharp
// For HTTP: ensure server endpoint is correct and reachable
var options = new LibEmiddleClientOptions
{
    TransportType = TransportType.Http,
    ServerEndpoint = "https://your-server.com/api" // Must be valid
};
```

4. **Enable debug logging**:
```csharp
var options = new LibEmiddleClientOptions
{
    EnableDebugLogging = true,
    LogLevel = LogLevel.Debug
};
```

---

### Problem: High Network Traffic

**Symptoms**: Excessive bandwidth usage, server overload

**Solutions**:

1. **Increase polling interval**:
```csharp
await client.StartListeningAsync(pollingInterval: 10000); // 10 seconds instead of 5
```

2. **Use message batching** (v2.5+):
```csharp
var options = new LibEmiddleClientOptions
{
    FeatureFlags = new FeatureFlags
    {
        EnableMessageBatching = true
    },
    BatchingOptions = new BatchingOptions
    {
        MaxBatchSize = 50,
        BatchTimeoutMs = 1000
    }
};
```

3. **Implement server-side push** (future):
Consider using WebSockets or SSE for server-initiated pushes instead of polling.

---

### Problem: Message Delivery Failures

**Symptoms**: `SendMessageAsync` fails, messages never arrive

**Solutions**:

1. **Check retry configuration**:
```csharp
var options = new LibEmiddleClientOptions
{
    RetryOptions = new RetryOptions
    {
        MaxRetries = 5,        // Increase retries
        BaseDelayMs = 2000,    // Longer initial delay
        MaxDelayMs = 60000     // Allow longer max delay
    }
};
```

2. **Verify server is running**:
```bash
# Test HTTP endpoint manually
curl -X GET https://your-server.com/api/messages/test-key
```

3. **Check authentication**:
```csharp
// Ensure auth token is valid and not expired
CustomHeaders = new Dictionary<string, string>
{
    ["Authorization"] = $"Bearer {await GetFreshAuthToken()}"
}
```

4. **Monitor network errors**:
```csharp
// Add error logging
try
{
    await client.SendChatMessageAsync(recipientKey, message);
}
catch (HttpRequestException ex)
{
    logger.LogError(ex, "Network error sending message");
}
```

---

### Problem: Session Corruption

**Symptoms**: Decryption fails, "Invalid session" errors

**Solutions**:

1. **Export and backup sessions regularly**:
```csharp
// Backup after successful message exchange
var sessionData = mailboxManager.ExportSession(recipientId, encryptionKey);
await BackupStorage.SaveAsync($"session_{recipientId}.dat", sessionData);
```

2. **Re-establish session with key exchange**:
```csharp
// If session is corrupted, create a new one
await client.CreateChatSessionAsync(recipientPublicKey, userId);
```

3. **Check for concurrent access**:
```csharp
// Avoid using the same session from multiple threads
// Each client instance maintains its own sessions
```

---

### Problem: Memory Leaks

**Symptoms**: Memory usage grows over time

**Solutions**:

1. **Always dispose clients**:
```csharp
using var client = new LibEmiddleClient(options);
// Automatic disposal
```

2. **Unsubscribe from events**:
```csharp
void Cleanup()
{
    client.MessageReceived -= OnMessageReceived;
    client.Dispose();
}
```

3. **Configure message history limits**:
```csharp
var options = new LibEmiddleClientOptions
{
    EnableMessageHistory = true,
    MaxMessageHistoryPerSession = 100 // Limit stored messages
};
```

4. **Regularly clean up old sessions**:
```csharp
// Delete old or unused sessions
var oldSessions = await client.GetInactiveSessionsAsync(olderThan: TimeSpan.FromDays(30));
foreach (var session in oldSessions)
{
    await client.DeleteSessionAsync(session.SessionId);
}
```

---

## Advanced Topics

### Custom Transport Implementation

If you need to implement a custom transport (e.g., for RabbitMQ, Redis, Azure Service Bus), inherit from `BaseMailboxTransport`:

```csharp
public class CustomMailboxTransport : BaseMailboxTransport
{
    public CustomMailboxTransport(ICryptoProvider cryptoProvider)
        : base(cryptoProvider)
    {
    }

    protected override async Task<bool> SendMessageInternalAsync(MailboxMessage message)
    {
        // Your custom send logic
        // Return true if successful, false otherwise
    }

    protected override async Task<List<MailboxMessage>> FetchMessagesInternalAsync(
        byte[] recipientKey,
        CancellationToken cancellationToken)
    {
        // Your custom fetch logic
        // Return list of messages for recipient
    }

    protected override async Task<bool> DeleteMessageInternalAsync(string messageId)
    {
        // Your custom delete logic
    }

    protected override async Task<bool> MarkMessageAsReadInternalAsync(string messageId)
    {
        // Your custom mark-as-read logic
    }

    protected override async Task StartListeningInternalAsync(
        byte[] localIdentityKey,
        int pollingInterval,
        CancellationToken cancellationToken)
    {
        // Your custom listening logic
        // Call OnMessageReceived(message) when messages arrive
    }

    protected override async Task StopListeningInternalAsync()
    {
        // Your custom stop logic
    }

    protected override async Task<bool> UpdateDeliveryStatusInternalAsync(
        string messageId,
        bool isDelivered)
    {
        // Your custom delivery status update logic
    }
}
```

---

## Summary

The **Mailbox Transport System** provides a clean, flexible abstraction for asynchronous encrypted messaging:

- ✅ **Transport-agnostic**: Switch between implementations without changing application code
- ✅ **Protocol separation**: Encryption handled separately from transport
- ✅ **Production-ready**: Battle-tested with HTTP transport
- ✅ **Developer-friendly**: InMemory transport for testing
- ✅ **Event-driven**: React to messages asynchronously
- ✅ **Reliable**: Built-in retry and receipt mechanisms

Choose `InMemory` for development/testing, use `Http` for production, and implement custom transports when needed.

For more details, see:
- [Full System Architecture](./Full-System-Architecture.md)
- [Message Flow Sequence Diagram](./Message-Flow-Sequence.md)
- [1-to-1 Chat Sequence](./1-to-1-Chat-Sequence.md)
