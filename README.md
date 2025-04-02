# E2EELibrary - Secure End-to-End Encryption for .NET

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![Coverage](https://img.shields.io/badge/coverage-90%25-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)
![.NET](https://img.shields.io/badge/.NET-8.0-purple)

A comprehensive, production-ready end-to-end encryption library for .NET applications implementing modern cryptographic protocols with a focus on security, privacy, and usability.

## ✨ Core Features

### 🔒 Advanced Cryptographic Protocols
- **X3DH Key Exchange** - Extended Triple Diffie-Hellman for secure initial key agreement
- **Double Ratchet Algorithm** - Continuous key rotation for forward secrecy
- **AES-GCM Encryption** - Authenticated encryption with strong integrity guarantees
- **Ed25519 & X25519** - Modern elliptic curve cryptography for digital signatures and key exchange

### 💬 Communication Patterns
- **One-to-One Messaging** - Secure private conversations with forward secrecy
- **Group Messaging** - Efficient encrypted group chats with advanced member management
- **Multi-Device Support** - Seamless synchronization and device linking
- **Asynchronous Communication** - Robust mailbox system with delivery and read receipts

## 🚀 Multi-Device Management

```csharp
// Main device setup
var mainDeviceManager = new DeviceManager(mainDeviceKeyPair);

// Add a new device with comprehensive security checks
try 
{
    // Generate keys for the new device
    var newDeviceKeyPair = KeyGenerator.GenerateX25519KeyPair();

    // Create a secure device link message
    var linkMessage = DeviceLinking.CreateDeviceLinkMessage(
        mainDeviceKeyPair, 
        newDeviceKeyPair.publicKey
    );

    // Process the link message on the new device
    byte[] mainDevicePublicKey = DeviceLinking.ProcessDeviceLinkMessage(
        linkMessage, 
        newDeviceKeyPair, 
        mainDeviceKeyPair.publicKey
    );

    // Add the new device with validation
    mainDeviceManager.AddLinkedDevice(newDeviceKeyPair.publicKey);

    // Create sync messages for the new device
    byte[] syncData = Encoding.UTF8.GetBytes("Secure device synchronization data");
    var syncMessages = mainDeviceManager.CreateSyncMessages(syncData);

    // Process sync messages across devices
    foreach (var message in syncMessages.Values)
    {
        byte[] processedData = mainDeviceManager.ProcessSyncMessage(message);
        // Handle synchronized data
    }
}
catch (Exception ex)
{
    // Comprehensive error handling for device linking
    Console.WriteLine($"Device linking failed: {ex.Message}");
}
```

## 🔐 Enhanced Group Messaging

```csharp
// Create a group with role-based access control
var groupManager = new GroupChatManager(userIdentityKeyPair);
string groupId = "secure-team-chat";

// Create the group with the current user as owner
groupManager.CreateGroup(groupId);

// Add members with specific roles
groupManager.AddGroupMember(groupId, member1PublicKey, MemberRole.Admin);
groupManager.AddGroupMember(groupId, member2PublicKey, MemberRole.Member);

// Distribute sender keys securely
var distributionMessage = groupManager.CreateDistributionMessage(groupId);

// Process distribution message across members
foreach (var memberManager in memberManagers)
{
    memberManager.ProcessSenderKeyDistribution(distributionMessage);
}

// Encrypt a group message with sender authentication
var encryptedMessage = groupManager.EncryptGroupMessage(
    groupId, 
    "Confidential team discussion"
);

// Decrypt with role-based access validation
string decryptedMessage = groupManager.DecryptGroupMessage(encryptedMessage);

// Rotate group key (requires admin privileges)
byte[] newSenderKey = groupManager.RotateGroupKey(groupId);
```

## 📬 Advanced Mailbox Communication

```csharp
// Create a mailbox manager with custom transport
var mailboxManager = new MailboxManager(
    userIdentityKeyPair, 
    new HttpMailboxTransport("https://mailbox.example.com")
);

// Configure advanced mailbox settings
mailboxManager.SetPollingInterval(TimeSpan.FromMinutes(1));
mailboxManager.SetAutoSendReceipts(true);

// Start background message processing
mailboxManager.Start();

// Event-driven message handling
mailboxManager.MessageReceived += (sender, args) => 
{
    var message = args.Message;
    Console.WriteLine($"New message received: {message.MessageId}");
    
    // Automatically mark as read and send read receipt
    await mailboxManager.MarkMessageAsReadAsync(message.MessageId);
};

// Send a message with expiration
string messageId = mailboxManager.SendMessage(
    recipientPublicKey, 
    "Time-sensitive information", 
    MessageType.Chat,
    timeToLive: 24 * 60 * 60 * 1000 // 24 hours
);

// Stop mailbox operations when done
mailboxManager.Stop();
```

## 🔒 Secure Key Management

```csharp
// Advanced key generation with enhanced security
var keyPair = KeyGenerator.GenerateEd25519KeyPair();

// Derive X25519 keys for different purposes
byte[] x25519PublicKey = KeyConversion.DeriveX25519PublicKeyFromEd25519(keyPair.privateKey);

// Secure key storage with password and salt rotation
KeyStorage.StoreKeyToFile(
    sensitiveKey, 
    "secure_key.dat", 
    password: "strongPassword", 
    saltRotationDays: 30
);

// Load key with automatic salt rotation
byte[] loadedKey = KeyStorage.LoadKeyFromFile(
    "secure_key.dat", 
    password: "strongPassword", 
    forceRotation: false
);
```

## 🛡️ WebSocket Secure Communication

```csharp
var webSocketClient = new SecureWebSocketClient("wss://secure.example.com/ws");

try 
{
    // Establish secure session
    await webSocketClient.ConnectAsync();
    webSocketClient.SetSession(secureDoubleRatchetSession);

    // Send encrypted messages with retry logic
    await webSocketClient.SendEncryptedMessageAsync("Secure communication");

    // Receive messages with comprehensive error handling
    string receivedMessage = await webSocketClient.ReceiveEncryptedMessageAsync(
        cancellationToken: CancellationTokenSource.CreateLinkedTokenSource(
            new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token
        ).Token
    );
}
catch (WebSocketException ex)
{
    // Robust error handling
    Console.WriteLine($"Secure WebSocket communication failed: {ex.Message}");
}
finally
{
    await webSocketClient.CloseAsync();
}
```

## 🔍 Key Enhancements

- Enhanced role-based access control
- Comprehensive device synchronization
- Advanced key rotation mechanisms
- Improved error handling and logging
- Stronger replay and replay attack protections

## 🛡️ Security Guarantees

- **Forward Secrecy** - Automatic key rotation
- **Post-Compromise Security** - Resilient against potential key compromises
- **Granular Access Control** - Role-based permissions
- **Secure Memory Handling** - Protection of sensitive cryptographic material

## 📦 Installation

```bash
dotnet add package E2EELibrary
```

## 📄 License

MIT License - See LICENSE file for details.

## 🤝 Contributing

Contributions welcome! Please submit pull requests or open issues.

## 📞 Support

For security concerns: Russell Benzing [me@russellbenzing.com]

## 🔗 References

- [Signal Protocol Specifications](https://signal.org/docs/)
- [The X3DH Key Agreement Protocol](https://signal.org/docs/specifications/x3dh/)
- [The Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/)
- [NIST Recommendations for Key Management](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf)
- [Cryptographic Standards](https://www.rfc-editor.org/rfc/rfc7748)
