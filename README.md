# E2EELibrary - Secure End-to-End Encryption for .NET

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![Coverage](https://img.shields.io/badge/coverage-95%25-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)
![.NET](https://img.shields.io/badge/.NET-Standard%202.1-purple)

A comprehensive, production-ready end-to-end encryption library for .NET applications implementing modern cryptographic protocols with a focus on security, privacy, and usability.

## ✨ Core Features

### 🔒 Advanced Cryptographic Protocols
- **X3DH Key Exchange** - Extended Triple Diffie-Hellman for secure initial key agreement
- **Double Ratchet Algorithm** - Continuous key rotation for forward secrecy
- **AES-GCM Encryption** - Authenticated encryption with strong integrity guarantees
- **Ed25519 & X25519** - Modern elliptic curve cryptography for digital signatures and key exchange

### 💬 Communication Patterns
- **One-to-One Messaging** - Secure private conversations with forward secrecy
- **Group Messaging** - Efficient encrypted group chats with sender key distribution
- **Multi-Device Support** - Seamless synchronization between user devices
- **Asynchronous Communication** - Support for offline message delivery via mailbox system

### 🛡️ Security Guarantees
- **Forward Secrecy** - Compromise of current keys doesn't expose past messages
- **Post-Compromise Security** - Automatic recovery from potential compromise
- **Message Integrity** - Tamper-evident messaging with authentication
- **Replay Protection** - Prevents message replay attacks
- **Secure Memory Handling** - Protection of sensitive data in memory

## 📦 Installation

```
// Package manager
Install-Package E2EELibrary

// .NET CLI
dotnet add package E2EELibrary
```

## 🚀 Quick Start

### Key Generation

```csharp
// Generate a signature key pair (Ed25519)
var signatureKeyPair = E2EEClient.GenerateSignatureKeyPair();

// Generate a key exchange key pair (X25519)
var keyExchangeKeyPair = E2EEClient.GenerateKeyExchangeKeyPair();

// Generate a sender key for group messaging
byte[] senderKey = E2EEClient.GenerateSenderKey();
```

### Basic Encryption/Decryption

```csharp
// Simple encryption with a shared key
string message = "Secret message";
byte[] key = new byte[32]; // Generate a proper random key in production
RandomNumberGenerator.Fill(key);

// Encrypt
var encryptedMessage = E2EEClient.EncryptMessage(message, key);

// Decrypt
string decryptedMessage = E2EEClient.DecryptMessage(encryptedMessage, key);
```

### Digital Signatures

```csharp
// Sign a message
byte[] messageBytes = Encoding.UTF8.GetBytes("Message to sign");
byte[] signature = E2EEClient.SignMessage(messageBytes, signatureKeyPair.privateKey);

// Verify signature
bool isValid = E2EEClient.VerifySignature(messageBytes, signature, signatureKeyPair.publicKey);

// Text message signing (Base64 signature)
string textSignature = E2EEClient.SignTextMessage("Text message", signatureKeyPair.privateKey);
bool textValid = E2EEClient.VerifyTextMessage("Text message", textSignature, signatureKeyPair.publicKey);
```

### Secure Key Storage

```csharp
// Store a key securely (with optional password protection)
E2EEClient.StoreKeyToFile(keyData, "key.dat", "optional-password");

// Load a key
byte[] loadedKey = E2EEClient.LoadKeyFromFile("key.dat", "optional-password");
```

### One-to-One Secure Messaging

```csharp
// 1. Initialize key bundles for both parties
X3DHKeyBundle aliceBundle = E2EEClient.CreateKeyBundle();
X3DHKeyBundle bobBundle = E2EEClient.CreateKeyBundle();

// 2. Convert Bob's bundle to public bundle (for sharing)
var bobPublicBundle = new X3DHPublicBundle {
    IdentityKey = bobBundle.IdentityKey,
    SignedPreKey = bobBundle.SignedPreKey,
    SignedPreKeySignature = bobBundle.SignedPreKeySignature,
    OneTimePreKeys = bobBundle.OneTimePreKeys
};

// 3. Alice initiates a session with Bob
var aliceIdentityKeyPair = (aliceBundle.IdentityKey, aliceBundle.GetIdentityKeyPrivate());
var session = E2EEClient.InitiateSession(bobPublicBundle, aliceIdentityKeyPair);

// 4. Create a DoubleRatchet session
var aliceSession = new DoubleRatchetSession(
    dhRatchetKeyPair: aliceIdentityKeyPair,
    remoteDHRatchetKey: bobPublicBundle.SignedPreKey,
    rootKey: session.RootKey,
    sendingChainKey: session.ChainKey,
    receivingChainKey: session.ChainKey,
    messageNumber: 0,
    sessionId: Guid.NewGuid().ToString()
);

// 5. Encrypt a message
string message = "Hello Bob, this is Alice!";
var (updatedSession, encryptedMessage) = E2EEClient.EncryptWithSession(aliceSession, message);

// 6. Decrypt a message
var (updatedReceiverSession, decryptedMessage) = E2EEClient.DecryptWithSession(bobSession, encryptedMessage);
```

### Group Messaging

```csharp
// Create a group chat manager for each participant
var aliceManager = new GroupChatManager(aliceKeyPair);
var bobManager = new GroupChatManager(bobKeyPair);
var charlieManager = new GroupChatManager(charlieKeyPair);

// Alice creates a group
string groupId = "friends-group";
aliceManager.CreateGroup(groupId);

// Alice creates a distribution message
var aliceDistribution = aliceManager.CreateDistributionMessage(groupId);

// Bob and Charlie process Alice's distribution
bobManager.ProcessSenderKeyDistribution(aliceDistribution);
charlieManager.ProcessSenderKeyDistribution(aliceDistribution);

// Bob and Charlie create their distributions and share with everyone
var bobDistribution = bobManager.CreateDistributionMessage(groupId);
var charlieDistribution = charlieManager.CreateDistributionMessage(groupId);

aliceManager.ProcessSenderKeyDistribution(bobDistribution);
aliceManager.ProcessSenderKeyDistribution(charlieDistribution);
// ...and so on for all combinations

// Now anyone can send encrypted messages to the group
var aliceMessage = aliceManager.EncryptGroupMessage(groupId, "Hello group!");

// Everyone can decrypt
string bobsDecryption = bobManager.DecryptGroupMessage(aliceMessage);
string charliesDecryption = charlieManager.DecryptGroupMessage(aliceMessage);
```

### Multi-Device Support

```csharp
// Link a new device to a main device
var mainDeviceKeyPair = E2EEClient.GenerateSignatureKeyPair();
var newDeviceKeyPair = E2EEClient.GenerateSignatureKeyPair();

// Create a device link message
var encryptedLinkMessage = E2EEClient.CreateDeviceLinkMessage(
    mainDeviceKeyPair,
    newDeviceKeyPair.publicKey
);

// Set up device managers
var mainDeviceManager = new DeviceManager(mainDeviceKeyPair);
var newDeviceManager = new DeviceManager(newDeviceKeyPair);

// Link the devices
mainDeviceManager.AddLinkedDevice(newDeviceKeyPair.publicKey);
newDeviceManager.AddLinkedDevice(mainDeviceKeyPair.publicKey);

// Sync data between devices
byte[] dataToSync = Encoding.UTF8.GetBytes("Sync data");
var syncMessages = mainDeviceManager.CreateSyncMessages(dataToSync);

// Process sync messages on the other device
foreach (var message in syncMessages.Values)
{
    byte[] receivedData = newDeviceManager.ProcessSyncMessage(message);
    // Use the synced data
}
```

### Mailbox Communication

```csharp
// Create a transport implementation (needs to implement IMailboxTransport)
var transport = new MyMailboxTransport();

// Create a mailbox manager
var mailboxManager = E2EEClient.CreateMailboxManager(userKeyPair, transport);

// Start mailbox operations
mailboxManager.Start();

// Send a message to a recipient
string messageId = mailboxManager.SendMessage(
    recipientKey, 
    "Secure message", 
    MessageType.Chat
);

// Get received messages
var messages = mailboxManager.GetMessages();

// Mark a message as read
await mailboxManager.MarkMessageAsReadAsync(messageId);

// Delete a message
await mailboxManager.DeleteMessageAsync(messageId);

// Stop the mailbox when done
mailboxManager.Stop();
```

### WebSocket Secure Communication

```csharp
// Create a secure WebSocket client
var client = new SecureWebSocketClient("wss://example.com/ws");

// Set up a session (from previous key exchange)
client.SetSession(doubleRatchetSession);

// Connect to the server
await client.ConnectAsync();

// Send an encrypted message
await client.SendEncryptedMessageAsync("Secret message");

// Receive and decrypt a message
string receivedMessage = await client.ReceiveEncryptedMessageAsync();

// Close the connection when done
await client.CloseAsync();
```

## 📋 Architecture

The library is structured into several key components:

- **Core** - Constants, utilities, and secure memory handling
- **Encryption** - AES implementation, Double Ratchet, and nonce generation
- **KeyManagement** - Key generation, storage, validation, and conversion
- **KeyExchange** - X3DH protocol implementation and session management
- **Models** - Data structures for messages, sessions, and key bundles
- **Communication** - WebSocket clients, message signing, and mailbox system
- **GroupMessaging** - Group chat management and message distribution
- **MultiDevice** - Device linking and synchronization

## 🛡️ Security Design Principles

- **Defense in Depth** - Multiple layers of security controls
- **Least Privilege** - Minimal access to sensitive cryptographic material
- **Secure Defaults** - Conservative default settings for maximum security
- **Immutable Data Structures** - Thread-safe operation with no side effects
- **Fail Secure** - Errors result in messages being rejected, not compromised

## 🧪 Testing and Validation

The library includes comprehensive tests:

- Unit tests for individual components
- Integration tests for end-to-end workflows
- Security tests for cryptographic properties
- Performance tests for efficiency
- Edge case handling

## 📚 Documentation

For more detailed documentation, please refer to the XML documentation comments in the code.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📞 Support

For security issues, please contact Russell Benzing [me@russellbenzing.com]

## 🔗 References

- [Signal Protocol Specifications](https://signal.org/docs/)
- [The X3DH Key Agreement Protocol](https://signal.org/docs/specifications/x3dh/)
- [The Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/)
- [NIST Recommendations for Key Management](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf)
- [Cryptographic Standards](https://www.rfc-editor.org/rfc/rfc7748)
