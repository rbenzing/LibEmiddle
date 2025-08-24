# LibEmiddle - Secure End-to-End Encryption for .NET

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![Coverage](https://img.shields.io/badge/coverage-90%25-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)
![.NET](https://img.shields.io/badge/.NET-8.0-purple)
![Version](https://img.shields.io/badge/version-2.5.0-blue)

A comprehensive, production-ready end-to-end encryption library for .NET applications implementing modern cryptographic protocols with a focus on security, privacy, and usability. Now with advanced features including post-quantum cryptography preparation, WebRTC transport, message batching, and enterprise-grade monitoring capabilities.

## 🚀 Quick Start

```csharp
// Install via NuGet
// dotnet add package LibEmiddle --version 2.5.0

using LibEmiddle.API;
using LibEmiddle.Domain.Enums;

// Configure the client
var options = new LibEmiddleClientOptions
{
    TransportType = TransportType.Http,
    ServerEndpoint = "https://your-server.com",
    EnableMultiDevice = true,
    EnableMessageHistory = true
};

// Create and initialize the client
using var client = new LibEmiddleClient(options);
await client.InitializeAsync();

// Start a secure conversation
var chatSession = await client.CreateChatSessionAsync(recipientPublicKey, "user123");
var encryptedMessage = await chatSession.EncryptAsync("Hello, secure world!");
```

## ✨ Core Features

### 🔒 Advanced Cryptographic Protocols
- **X3DH Key Exchange** - Extended Triple Diffie-Hellman for secure initial key agreement
- **Double Ratchet Algorithm** - Continuous key rotation for forward secrecy
- **AES-GCM Encryption** - Authenticated encryption with strong integrity guarantees
- **Ed25519 & X25519** - Modern elliptic curve cryptography for digital signatures and key exchange
- **Post-Quantum Cryptography** - Preparation for quantum-resistant algorithms (v2.5)
- **Advanced Key Rotation** - Sophisticated key rotation policies and monitoring

### 💬 Communication Patterns
- **One-to-One Messaging** - Secure private conversations with forward secrecy
- **Group Messaging** - Efficient encrypted group chats with advanced member management
- **Multi-Device Support** - Seamless synchronization and device linking
- **Asynchronous Communication** - Robust mailbox system with delivery and read receipts
- **WebRTC Transport** - Peer-to-peer encrypted communication (v2.5)
- **Message Batching** - Efficient bulk messaging with compression support (v2.5)

### 🏗️ Architecture Highlights
- **Unified Client API** - Single `LibEmiddleClient` for all operations
- **Modular Design** - Pluggable transport, storage, and crypto providers
- **Session Management** - Automatic session persistence and recovery with backup capabilities
- **Event-Driven** - Real-time message handling with comprehensive events
- **Feature Flags** - Gradual rollout and configuration of new capabilities (v2.5)
- **Enterprise Monitoring** - Built-in diagnostics and resilience management (v2.5)
- **Connection Pooling** - Optimized connection management for high throughput (v2.5)

## 💬 Individual Chat Sessions

```csharp
// Create a chat session with a specific user
var chatSession = await client.CreateChatSessionAsync(
    recipientPublicKey,
    recipientUserId: "alice@example.com",
    options: new ChatSessionOptions
    {
        RotationStrategy = KeyRotationStrategy.Aggressive,
        EnableMessageHistory = true
    });

// Send encrypted messages
var encryptedMessage = await chatSession.EncryptAsync("Hello Alice!");

// Receive and decrypt messages
var decryptedMessage = await chatSession.DecryptAsync(incomingEncryptedMessage);
Console.WriteLine($"Received: {decryptedMessage}");

// Send message directly by recipient key (creates session if needed)
var directMessage = await client.SendChatMessageAsync(
    recipientPublicKey,
    "Direct message without explicit session creation");

// Handle incoming messages with events
chatSession.MessageReceived += (sender, args) =>
{
    Console.WriteLine($"New message: {args.DecryptedContent}");
};
```

## 🚀 Multi-Device Management

```csharp
// Enable multi-device support in client options
var options = new LibEmiddleClientOptions
{
    EnableMultiDevice = true,
    MaxLinkedDevices = 5
};

using var client = new LibEmiddleClient(options);
await client.InitializeAsync();

// Link a new device
var linkMessage = client.CreateDeviceLinkMessage(newDevicePublicKey);

// Process device link on the new device
var success = await client.ProcessDeviceLinkMessageAsync(linkMessage);

// Synchronize data across devices
var syncData = Encoding.UTF8.GetBytes("Session data to sync");
var syncMessages = client.CreateSyncMessages(syncData);

// Send sync messages to all linked devices
foreach (var (deviceId, message) in syncMessages)
{
    await client.SendToDeviceAsync(deviceId, message);
}

// Revoke a compromised device
await client.RevokeDeviceAsync(compromisedDevicePublicKey, "Device lost");
```

## 🔐 Enhanced Group Messaging

```csharp
// Create a new group
var groupSession = await client.CreateGroupAsync(
    groupId: "team-secure-chat",
    groupName: "Development Team",
    options: new GroupSessionOptions
    {
        RotationStrategy = KeyRotationStrategy.Standard,
        MaxMembers = 50
    });

// Add members to the group
await groupSession.AddMemberAsync(member1PublicKey, MemberRole.Admin);
await groupSession.AddMemberAsync(member2PublicKey, MemberRole.Member);

// Send encrypted group messages
var encryptedGroupMessage = await client.SendGroupMessageAsync(
    "team-secure-chat",
    "Confidential team discussion");

// Join an existing group using distribution message
var joinedGroup = await client.JoinGroupAsync(distributionMessage);

// Handle group events
groupSession.MemberAdded += (sender, args) =>
{
    Console.WriteLine($"Member {args.MemberPublicKey} joined the group");
};

groupSession.MessageReceived += (sender, args) =>
{
    Console.WriteLine($"Group message: {args.DecryptedContent}");
};

// Rotate group keys (admin only)
await groupSession.RotateKeysAsync();

// Leave the group
await client.LeaveGroupAsync("team-secure-chat");
```

## 📬 Transport and Messaging

```csharp
// Configure different transport types
var httpOptions = new LibEmiddleClientOptions
{
    TransportType = TransportType.Http,
    ServerEndpoint = "https://secure-messaging.example.com",
    NetworkTimeoutMs = 30000,
    EnableStrictCertificateValidation = true
};

var webSocketOptions = new LibEmiddleClientOptions
{
    TransportType = TransportType.WebSocket,
    ServerEndpoint = "wss://realtime.example.com/ws",
    CustomHeaders = new Dictionary<string, string>
    {
        ["Authorization"] = "Bearer your-token"
    }
};

// In-memory transport for testing
var testOptions = new LibEmiddleClientOptions
{
    TransportType = TransportType.InMemory
};

// Start listening for incoming messages
await client.StartListeningAsync();

// Handle all incoming messages
client.MessageReceived += async (sender, args) =>
{
    var message = args.Message;
    Console.WriteLine($"Received message: {message.MessageId}");

    // Process based on message type
    switch (message.MessageType)
    {
        case MessageType.Chat:
            await ProcessChatMessage(message);
            break;
        case MessageType.GroupMessage:
            await ProcessGroupMessage(message);
            break;
        case MessageType.DeviceSync:
            await ProcessDeviceSync(message);
            break;
    }
};

// Stop listening when done
await client.StopListeningAsync();
```

## 🔒 Advanced Configuration

```csharp
// Comprehensive client configuration
var options = new LibEmiddleClientOptions
{
    // Storage configuration
    IdentityKeyPath = "keys/identity.key",
    SessionStoragePath = "data/sessions",
    KeyStoragePath = "data/keys",

    // Transport settings
    TransportType = TransportType.Http,
    ServerEndpoint = "https://api.example.com",
    NetworkTimeoutMs = 30000,

    // Security policies
    SecurityPolicy = new SecurityPolicyOptions
    {
        RequirePerfectForwardSecrecy = true,
        RequireMessageAuthentication = true,
        MinimumProtocolVersion = "2.0",
        AllowInsecureConnections = false
    },

    // Key management
    DefaultRotationStrategy = KeyRotationStrategy.Aggressive,
    MaxOneTimePreKeys = 100,
    MaxSkippedMessageKeys = 1000,
    EnableAutomaticKeyRotation = true,

    // Multi-device support
    EnableMultiDevice = true,
    MaxLinkedDevices = 10,

    // Performance and reliability
    EnableMessageHistory = true,
    MaxMessageHistoryPerSession = 1000,
    EnableSecureMemory = true,
    EnableSessionPersistence = true,

    // Retry configuration
    RetryOptions = new RetryOptions
    {
        MaxRetries = 3,
        BaseDelayMs = 1000,
        MaxDelayMs = 30000,
        BackoffMultiplier = 2.0
    }
};

using var client = new LibEmiddleClient(options);
```

## 🔍 Session Management

```csharp
// Get all active sessions
var activeSessions = await client.GetActiveSessionsAsync();

// Get specific session by ID
var session = await client.GetSessionAsync(sessionId);

// Get chat sessions with a specific user
var userSessions = await client.GetChatSessionsAsync(userPublicKey);

// Session lifecycle management
await session.ActivateAsync();
await session.SuspendAsync("Temporary suspension");
await session.ResumeAsync();
await session.TerminateAsync();

// Session persistence and recovery
await client.SaveSessionAsync(session);
var recoveredSession = await client.LoadSessionAsync(sessionId);

// Session metadata and history
session.Metadata["custom_field"] = "value";
var messageHistory = session.GetMessageHistory();

// Session events
session.StateChanged += (sender, args) =>
{
    Console.WriteLine($"Session {args.SessionId} state changed to {args.NewState}");
};
```

## 🆕 Advanced Features (v2.5)

### 🌐 WebRTC Transport
```csharp
// Configure WebRTC transport for peer-to-peer communication
var webRtcOptions = new LibEmiddleClientOptions
{
    TransportType = TransportType.WebRTC,
    WebRTCOptions = new WebRTCOptions
    {
        ICEServers = new[] { "stun:stun.l.google.com:19302" },
        NetworkQualityThreshold = WebRTCNetworkQualityLevel.Good,
        EnableAdaptiveBitrate = true
    }
};

using var client = new LibEmiddleClient(webRtcOptions);
await client.InitializeAsync();

// Establish direct peer connection
var peerSession = await client.CreateWebRTCSessionAsync(targetPeerKey);
```

### 📦 Message Batching
```csharp
// Enable message batching for improved throughput
var options = new LibEmiddleClientOptions
{
    FeatureFlags = new FeatureFlags
    {
        EnableMessageBatching = true
    },
    BatchingOptions = new BatchingOptions
    {
        MaxBatchSize = 50,
        BatchTimeoutMs = 1000,
        CompressionLevel = CompressionLevel.Balanced
    }
};

// Messages are automatically batched and compressed
await client.SendChatMessageAsync(recipientKey, "Message 1");
await client.SendChatMessageAsync(recipientKey, "Message 2");
await client.SendChatMessageAsync(recipientKey, "Message 3");
// All three messages sent in a single compressed batch
```

### 🔐 Post-Quantum Cryptography Preparation
```csharp
// Configure post-quantum crypto algorithms (preparation for future)
var options = new LibEmiddleClientOptions
{
    PostQuantumOptions = new PostQuantumOptions
    {
        Algorithm = PostQuantumAlgorithm.Kyber1024,
        EnableHybridMode = true, // Classical + Post-quantum
        KeyExchangeMode = KeyExchangeMode.Hybrid
    }
};

// The system will use hybrid classical+PQ when available
using var client = new LibEmiddleClient(options);
```

### 📊 Enterprise Monitoring & Diagnostics
```csharp
// Enable comprehensive monitoring and diagnostics
var options = new LibEmiddleClientOptions
{
    FeatureFlags = new FeatureFlags
    {
        EnableDiagnostics = true,
        EnableResilienceManager = true
    },
    ResilienceOptions = new ResilienceOptions
    {
        RetryPolicy = RetryPolicy.ExponentialBackoff,
        HealthCheckIntervalMs = 30000,
        EnableFailover = true
    }
};

using var client = new LibEmiddleClient(options);

// Access diagnostics information
var diagnostics = client.GetDiagnostics();
Console.WriteLine($"Active Sessions: {diagnostics.ActiveSessions}");
Console.WriteLine($"Messages Sent: {diagnostics.MessagesSent}");
Console.WriteLine($"Network Quality: {diagnostics.NetworkQuality}");

// Monitor resilience events
client.ResilienceManager.ConnectionRestored += (sender, args) =>
{
    Console.WriteLine($"Connection restored after {args.DowntimeMs}ms");
};
```

### 🏊‍♂️ Connection Pooling
```csharp
// Configure connection pooling for high-throughput scenarios
var options = new LibEmiddleClientOptions
{
    ConnectionPoolOptions = new ConnectionPoolOptions
    {
        MinPoolSize = 5,
        MaxPoolSize = 20,
        ConnectionTimeoutMs = 30000,
        IdleTimeoutMs = 300000,
        EnableLoadBalancing = true
    }
};

// Connections are automatically managed and reused
using var client = new LibEmiddleClient(options);
```

### 🔄 Advanced Key Rotation
```csharp
// Configure sophisticated key rotation policies
var rotationPolicy = new KeyRotationPolicy
{
    Strategy = KeyRotationStrategy.Adaptive,
    TimeBasedRotationIntervalHours = 24,
    MessageCountThreshold = 10000,
    RiskBasedRotation = true,
    BackupKeyCount = 3
};

await client.SetAdvancedKeyRotationPolicyAsync(sessionId, rotationPolicy);

// Monitor key rotation events
client.KeyRotated += (sender, args) =>
{
    Console.WriteLine($"Keys rotated for session {args.SessionId}: {args.RotationReason}");
};
```

## 🛡️ Security Features

### Forward Secrecy & Post-Compromise Security
- **Automatic Key Rotation** - Configurable rotation strategies
- **Perfect Forward Secrecy** - Past messages remain secure even if keys are compromised
- **Post-Compromise Security** - Future messages are secure after key compromise recovery

### Authentication & Integrity
- **Message Authentication** - Every message is cryptographically authenticated
- **Replay Protection** - Built-in protection against message replay attacks
- **Tampering Detection** - Immediate detection of message modification attempts

### Memory Security
- **Secure Memory Handling** - Sensitive data is properly cleared from memory
- **Key Derivation** - Strong key derivation functions (HKDF, Argon2)
- **Constant-Time Operations** - Protection against timing attacks

## 📦 Installation

### NuGet Package
```bash
dotnet add package LibEmiddle --version 2.5.0
```

### Package Manager Console
```powershell
Install-Package LibEmiddle -Version 2.5.0
```

### Requirements
- .NET 8.0 or later
- Windows, Linux, or macOS
- libsodium native library (included in package)

## 🔄 Migration Guide

### From v2.0 to v2.5
Version 2.5 is backward compatible with v2.0. New features are opt-in via `FeatureFlags`:

```csharp
var options = new LibEmiddleClientOptions
{
    FeatureFlags = new FeatureFlags
    {
        EnableMessageBatching = true,      // Opt-in to batching
        EnableDiagnostics = true,          // Opt-in to monitoring
        EnableAdvancedGroupManagement = true // Opt-in to enhanced groups
    }
};
```

### From v1.x to v2.x
Version 2.x introduces breaking changes. See [CHANGELOG.md](CHANGELOG.md) for detailed migration instructions.

### Key Changes in v2.5:
- **Feature Flags System** - Gradual rollout of new capabilities
- **WebRTC Transport** - Peer-to-peer encrypted communication
- **Message Batching** - Improved performance with compression
- **Post-Quantum Preparation** - Future-ready cryptographic interfaces
- **Enterprise Monitoring** - Built-in diagnostics and resilience management
- **Advanced Key Rotation** - Sophisticated rotation policies

### Migration Example:
```csharp
// v1.x (deprecated)
var oldClient = new LibEmiddleManager();
await oldClient.InitializeAsync();

// v2.x (current)
var options = new LibEmiddleClientOptions { /* configuration */ };
var newClient = new LibEmiddleClient(options);
await newClient.InitializeAsync();
```

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details.

## 🤝 Contributing

We welcome contributions! Please see our [contributing guidelines](CONTRIBUTING.md) and:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## 📚 Documentation

The [Documentation/](Documentation/) folder contains comprehensive technical documentation including:

- **Architecture Diagrams**: Full system architecture and component interactions
- **Sequence Diagrams**: Detailed protocol flows for all major operations
  - 1-to-1 Chat establishment and messaging
  - Group Chat creation and management
  - Device linking and revocation processes
  - Advanced key rotation workflows
  - Post-quantum key exchange preparation
  - Message batching and compression flows
- **Technical Specifications**: In-depth coverage of cryptographic protocols and security features

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/rbenzing/LibEmiddle/issues)
- **Security**: For security concerns, email Russell Benzing at [me@russellbenzing.com]
- **Documentation**: See [Documentation/](Documentation/) folder for detailed technical documentation and sequence diagrams

## 🔗 References

- [libsodium Library](https://doc.libsodium.org/)
- [Signal Protocol Specifications](https://signal.org/docs/)
- [The X3DH Key Agreement Protocol](https://signal.org/docs/specifications/x3dh/)
- [The Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/)
- [NIST Recommendations for Key Management](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf)
- [RFC 7748 - Elliptic Curves for Security](https://www.rfc-editor.org/rfc/rfc7748)
