# 1-to-1 Chat Sequence Diagram

This diagram shows the complete flow of establishing a 1-to-1 encrypted chat session between Alice and Bob using LibEmiddle.

```mermaid
sequenceDiagram
    participant Alice as Alice (Sender)
    participant AliceLib as LibEmiddle (Alice)
    participant Server as Transport Server
    participant BobLib as LibEmiddle (Bob)
    participant Bob as Bob (Receiver)

    Note over Alice, Bob: Initial Setup and Key Exchange

    Alice->>AliceLib: Initialize Library
    AliceLib->>AliceLib: Generate Identity KeyPair
    
    Bob->>BobLib: Initialize Library
    BobLib->>BobLib: Generate Identity KeyPair
    BobLib->>BobLib: CreateKeyBundleAsync()
    BobLib->>Server: Upload key bundle (X3DHPublicBundle)

    Note over Alice, Bob: Session Establishment

    Alice->>AliceLib: Request session with Bob
    AliceLib->>Server: Fetch Bob's key bundle
    Server->>AliceLib: Return Bob's X3DHPublicBundle
    
    AliceLib->>AliceLib: SessionManager.CreateSessionAsync()
    AliceLib->>AliceLib: ProtocolAdapter.PrepareSenderSessionAsync()
    AliceLib->>AliceLib: X3DHProtocol.InitiateSessionAsSenderAsync()
    AliceLib->>AliceLib: DoubleRatchetProtocol.InitializeSessionAsSenderAsync()
    AliceLib->>AliceLib: Create ChatSession

    AliceLib->>Server: Send InitialMessageData + first message
    Server->>BobLib: Deliver message to Bob

    BobLib->>BobLib: ProtocolAdapter.ProcessKeyExchangeMessageAsync()
    BobLib->>BobLib: X3DHProtocol.EstablishSessionAsReceiverAsync()
    BobLib->>BobLib: DoubleRatchetProtocol.InitializeSessionAsReceiverAsync()
    BobLib->>BobLib: Create ChatSession
    BobLib->>Bob: Deliver decrypted message

    Note over Alice, Bob: Ongoing Encrypted Communication

    Alice->>AliceLib: Send message to Bob
    AliceLib->>AliceLib: ChatSession.EncryptAsync()
    AliceLib->>AliceLib: DoubleRatchetProtocol.EncryptAsync()
    AliceLib->>Server: Send encrypted message
    Server->>BobLib: Deliver message to Bob
    
    BobLib->>BobLib: ChatSession.DecryptAsync()
    BobLib->>BobLib: DoubleRatchetProtocol.DecryptAsync()
    BobLib->>Bob: Deliver decrypted message

    Bob->>BobLib: Send reply to Alice
    BobLib->>BobLib: ChatSession.EncryptAsync()
    BobLib->>Server: Send encrypted message
    Server->>AliceLib: Deliver message to Alice
    AliceLib->>AliceLib: ChatSession.DecryptAsync()
    AliceLib->>Alice: Deliver decrypted message
```

## Key Components

### Protocol Stack
- **X3DH Protocol**: Extended Triple Diffie-Hellman for initial key agreement
- **Double Ratchet Protocol**: Provides forward secrecy and post-compromise security
- **SessionManager**: Manages chat session lifecycle
- **ProtocolAdapter**: Coordinates between protocol layers

### Security Features
- **Perfect Forward Secrecy**: Each message uses unique encryption keys
- **Post-Compromise Security**: Future messages remain secure even if past keys are compromised
- **Authenticated Encryption**: Messages are both encrypted and authenticated
- **Key Rotation**: Continuous key evolution through Double Ratchet

### Flow Summary
1. **Initialization**: Both parties initialize LibEmiddle and generate identity keys
2. **Key Bundle Upload**: Bob uploads his public key bundle to the server
3. **Session Initiation**: Alice fetches Bob's keys and initiates X3DH key exchange
4. **Message Delivery**: First message includes key exchange data for Bob to establish session
5. **Session Established**: Both parties now have a shared ChatSession for ongoing communication
6. **Encrypted Messaging**: All subsequent messages use Double Ratchet encryption