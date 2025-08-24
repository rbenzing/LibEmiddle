# Device Linking Sequence Diagram

This diagram shows the complete flow of linking a secondary device to a primary device in LibEmiddle's multi-device architecture.

```mermaid
sequenceDiagram
    participant UserPrimary as User (Primary Device)
    participant PrimaryLib as LibEmiddle (Primary Device)
    participant Server as Transport Server
    participant SecondaryLib as LibEmiddle (Secondary Device)
    participant UserSecondary as User (Secondary Device)
    participant Bob as Bob (Contact)
    participant BobLib as LibEmiddle (Bob)

    Note over UserPrimary, BobLib: Device Linking Process

    UserPrimary->>PrimaryLib: Add new device
    PrimaryLib->>PrimaryLib: DeviceManager.CreateDeviceLinkMessage()
    
    UserPrimary->>UserSecondary: Share linking code (out-of-band)
    UserSecondary->>SecondaryLib: Enter linking code
    SecondaryLib->>SecondaryLib: DeviceLinkingService.ProcessDeviceLinkMessage()
    SecondaryLib->>SecondaryLib: DeviceManager.AddLinkedDevice()
    PrimaryLib->>PrimaryLib: DeviceManager.AddLinkedDevice()

    Note over UserPrimary, BobLib: Multi-Device Session Synchronization

    UserPrimary->>PrimaryLib: Send message to Bob
    PrimaryLib->>PrimaryLib: ChatSession.EncryptAsync()
    PrimaryLib->>Server: Send encrypted message to Bob
    
    PrimaryLib->>PrimaryLib: DeviceManager.CreateSyncMessages()
    PrimaryLib->>Server: Send session sync to secondary device
    Server->>SecondaryLib: Deliver sync message
    SecondaryLib->>SecondaryLib: DeviceManager.ProcessSyncMessage()
    SecondaryLib->>SecondaryLib: Update local sessions

    Note over UserPrimary, BobLib: Secondary Device Can Now Send Messages

    UserSecondary->>SecondaryLib: Send message to Bob
    SecondaryLib->>SecondaryLib: ChatSession.EncryptAsync()
    SecondaryLib->>Server: Send encrypted message to Bob
    
    SecondaryLib->>SecondaryLib: DeviceManager.CreateSyncMessages()
    SecondaryLib->>Server: Send session sync to primary device
    Server->>PrimaryLib: Deliver sync message
    PrimaryLib->>PrimaryLib: DeviceManager.ProcessSyncMessage()
    PrimaryLib->>UserPrimary: Update message history

    Note over UserPrimary, BobLib: Bob's Response Delivered to Both Devices

    Bob->>BobLib: Send message to User
    BobLib->>Server: Send encrypted message
    Server->>PrimaryLib: Deliver to primary device
    Server->>SecondaryLib: Deliver to secondary device
    
    PrimaryLib->>PrimaryLib: ChatSession.DecryptAsync()
    PrimaryLib->>UserPrimary: Show decrypted message
    
    SecondaryLib->>SecondaryLib: ChatSession.DecryptAsync()
    SecondaryLib->>UserSecondary: Show decrypted message
```

## Key Components

### Device Management
- **DeviceManager**: Central coordinator for multi-device operations
- **DeviceLinkingService**: Handles secure device pairing process
- **SyncMessageValidator**: Ensures sync message integrity across devices

### Linking Process
1. **Link Code Generation**: Primary device creates secure linking message
2. **Out-of-Band Sharing**: Linking code shared through secure external channel
3. **Device Registration**: Secondary device processes link and registers with primary
4. **Mutual Recognition**: Both devices add each other to their device lists

### Session Synchronization
- **Automatic Sync**: All session state changes are automatically synchronized
- **Bidirectional Updates**: Both devices can initiate and receive sync messages
- **Consistent State**: All linked devices maintain identical session state

### Security Features
- **Secure Linking**: Device linking uses cryptographic proof of possession
- **Session Isolation**: Each device maintains independent encryption keys
- **Synchronized Forward Secrecy**: Key rotation is coordinated across devices
- **Message Consistency**: All devices receive and can decrypt the same messages

### Multi-Device Benefits
- **Seamless Experience**: Users can switch between devices transparently
- **Message History**: Full conversation history available on all linked devices
- **Real-time Sync**: Messages and session updates propagated immediately
- **Device Independence**: Each device can operate independently when needed