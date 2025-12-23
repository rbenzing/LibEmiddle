# Message Flow Sequence Diagram

This document provides detailed Mermaid sequence diagrams showing the complete message flow through the LibEmiddle mailbox transport system.

## Complete Message Sending Flow

```mermaid
sequenceDiagram
    participant App as Application
    participant Client as LibEmiddleClient
    participant Chat as ChatSession
    participant MB as MailboxManager
    participant DR as DoubleRatchetProtocol
    participant Trans as IMailboxTransport
    participant Base as BaseMailboxTransport
    participant Http as HttpMailboxTransport
    participant Server as Message Server

    Note over App,Server: Message Sending Flow

    App->>Client: SendChatMessageAsync(recipientKey, "Hello!")
    activate Client

    Client->>Client: Get or create ChatSession
    Client->>Chat: EncryptAsync("Hello!")
    activate Chat

    Chat->>MB: SendMessage(recipientKey, "Hello!", session)
    activate MB

    Note over MB: Encrypt plaintext with Double Ratchet
    MB->>DR: EncryptAsync(session, "Hello!")
    activate DR
    DR->>DR: Generate message keys
    DR->>DR: Encrypt plaintext
    DR-->>MB: (updatedSession, encryptedPayload)
    deactivate DR

    MB->>MB: Update session
    MB->>MB: Create MailboxMessage
    Note over MB: MailboxMessage contains:<br/>- RecipientKey<br/>- SenderKey<br/>- EncryptedPayload<br/>- Timestamp
    MB->>MB: Add to outgoing queue

    MB-->>Chat: messageId
    deactivate MB
    Chat-->>Client: EncryptedMessage
    deactivate Chat
    Client-->>App: messageId
    deactivate Client

    Note over MB,Server: Background Sending Task

    MB->>MB: ProcessOutgoingMessagesAsync (background)
    activate MB
    MB->>MB: Dequeue message from queue
    MB->>MB: Check if expired

    MB->>Trans: SendMessageAsync(mailboxMessage)
    activate Trans

    Trans->>Base: SendMessageAsync(mailboxMessage)
    activate Base
    Base->>Base: ThrowIfDisposed()
    Base->>Base: Validate message not null
    Base->>Base: Log debug info

    Base->>Http: SendMessageInternalAsync(mailboxMessage)
    activate Http

    Http->>Server: POST /messages<br/>{mailboxMessage as JSON}
    activate Server
    Server->>Server: Store message in recipient's mailbox
    Server-->>Http: 200 OK
    deactivate Server

    Http-->>Base: true (success)
    deactivate Http
    Base-->>Trans: true
    deactivate Base
    Trans-->>MB: true
    deactivate Trans

    MB->>MB: Remove from queue (success)
    deactivate MB

    Note over App,Server: Message successfully delivered to server
```

## Complete Message Receiving Flow

```mermaid
sequenceDiagram
    participant Server as Message Server
    participant Http as HttpMailboxTransport
    participant Base as BaseMailboxTransport
    participant Trans as IMailboxTransport
    participant MB as MailboxManager
    participant DR as DoubleRatchetProtocol
    participant Chat as ChatSession
    participant Client as LibEmiddleClient
    participant App as Application

    Note over Server,App: Message Receiving Flow

    Note over Http,Server: Background Polling Task

    Http->>Http: StartListeningInternalAsync<br/>(polling loop)
    activate Http

    loop Every pollingInterval (default 5s)
        Http->>Base: FetchMessagesAsync(localIdentityKey)
        activate Base

        Base->>Base: ThrowIfDisposed()
        Base->>Base: Validate recipientKey

        Base->>Http: FetchMessagesInternalAsync(recipientKey)
        activate Http

        Http->>Server: GET /messages/{base64RecipientKey}
        activate Server
        Server->>Server: Retrieve unread messages<br/>for recipient
        Server-->>Http: Array of MailboxMessage JSON
        deactivate Server

        Http->>Http: Deserialize JSON to List<MailboxMessage>
        Http-->>Base: List<MailboxMessage>
        deactivate Http

        Note over Base: Validate each message
        loop For each message
            Base->>Base: ValidateMessageAsync(message)
            Base->>Base: Check sender key not null
            Base->>Base: Check recipient key not null
            Base->>Base: Check encrypted payload valid
            Base->>Base: Check not expired
            Base->>Base: Filter valid messages only
        end

        Base-->>Http: List<MailboxMessage> (validated)
        deactivate Base

        loop For each validated message
            Http->>Base: OnMessageReceived(message)
            activate Base
            Base->>Trans: Raise MessageReceived event
            deactivate Base
            activate Trans

            Trans->>MB: MessageReceived event handler
            activate MB

            MB->>MB: ValidateIncomingMessage(message)
            Note over MB: Check recipient is us,<br/>not expired, not too old

            MB->>MB: Add to _incomingMessages dictionary
            MB->>MB: Mark IsDelivered = true
            MB->>MB: Set DeliveredAt timestamp

            opt Auto-send receipts enabled
                MB->>MB: SendReceipt(message, isDeliveryReceipt: true)
                Note over MB: Encrypts receipt and queues
            end

            MB->>Chat: OnMessageReceived(message)
            activate Chat

            Note over Chat: Decrypt message
            Chat->>MB: Get session for sender
            MB-->>Chat: DoubleRatchetSession

            Chat->>DR: DecryptAsync(session, encryptedPayload)
            activate DR
            DR->>DR: Verify message authentication
            DR->>DR: Derive message key
            DR->>DR: Decrypt ciphertext
            DR->>DR: Update session state
            DR-->>Chat: (updatedSession, "Hello!")
            deactivate DR

            Chat->>MB: Update session
            deactivate MB

            Chat->>Client: Raise MessageReceived event
            activate Client
            Client->>App: MessageReceived event<br/>(message, decryptedContent)
            deactivate Chat
            deactivate Client
            deactivate Trans

            activate App
            App->>App: Display "Hello!" to user
            deactivate App

            Http->>Base: MarkMessageAsReadAsync(messageId)
            activate Base
            Base->>Http: MarkMessageAsReadInternalAsync(messageId)
            activate Http
            Http->>Server: PATCH /messages/{messageId}/read
            activate Server
            Server->>Server: Update message.IsRead = true
            Server-->>Http: 200 OK
            deactivate Server
            Http-->>Base: true
            deactivate Http
            Base-->>Http: true
            deactivate Base
        end

        Http->>Http: await Task.Delay(pollingInterval)
    end

    deactivate Http

    Note over Server,App: Message successfully delivered to app
```

## Simplified Layer View

```mermaid
graph TD
    A[Application Layer] -->|Uses| B[LibEmiddleClient]
    B -->|Manages| C[ChatSession]
    C -->|Delegates to| D[MailboxManager]

    D -->|Encrypts with| E[DoubleRatchetProtocol]
    D -->|Sends via| F[IMailboxTransport]

    F -->|Implements| G[BaseMailboxTransport]
    G -->|Extended by| H[HttpMailboxTransport]
    G -->|Extended by| I[InMemoryMailboxTransport]

    H -->|Communicates with| J[HTTP Server]
    I -->|Stores in| K[In-Memory Dictionary]

    style D fill:#e1f5ff
    style E fill:#ffe1e1
    style F fill:#e1ffe1

    classDef encrypt fill:#ffe1e1,stroke:#ff0000
    classDef transport fill:#e1ffe1,stroke:#00ff00
    class E encrypt
    class F,G,H,I transport
```

## Message State Transitions

```mermaid
stateDiagram-v2
    [*] --> Created: App sends message
    Created --> Encrypted: DoubleRatchet encrypts
    Encrypted --> Queued: Added to outgoing queue
    Queued --> Sending: Background task dequeues
    Sending --> SentToServer: HTTP POST succeeds
    Sending --> Queued: HTTP POST fails (retry)
    SentToServer --> InRecipientMailbox: Server stores
    InRecipientMailbox --> Fetched: Recipient polls
    Fetched --> Validated: BaseMailboxTransport validates
    Validated --> Delivered: MailboxManager processes
    Delivered --> Decrypted: DoubleRatchet decrypts
    Decrypted --> Displayed: App shows to user
    Displayed --> Read: User reads message
    Read --> [*]: Message lifecycle complete

    note right of Encrypted
        Only MailboxManager
        handles encryption
    end note

    note right of Validated
        BaseMailboxTransport
        validates messages
    end note

    note right of Decrypted
        ChatSession coordinates
        decryption
    end note
```

## Component Responsibilities

```mermaid
graph LR
    subgraph "Application Code"
        A1[Your App]
    end

    subgraph "LibEmiddle Client API"
        B1[LibEmiddleClient]
        B2[ChatSession]
    end

    subgraph "Orchestration Layer"
        C1[MailboxManager]
    end

    subgraph "Protocol Layer - ENCRYPTION HAPPENS HERE"
        D1[DoubleRatchetProtocol]
        D2[X3DHProtocol]
    end

    subgraph "Transport Abstraction"
        E1[IMailboxTransport]
        E2[BaseMailboxTransport]
    end

    subgraph "Concrete Transports - NO ENCRYPTION"
        F1[HttpMailboxTransport]
        F2[InMemoryMailboxTransport]
    end

    A1 --> B1
    B1 --> B2
    B2 --> C1
    C1 --> D1
    C1 --> D2
    C1 --> E1
    E1 --> E2
    E2 --> F1
    E2 --> F2

    style D1 fill:#ffe1e1,stroke:#ff0000,stroke-width:3px
    style D2 fill:#ffe1e1,stroke:#ff0000,stroke-width:3px
    style C1 fill:#e1f5ff,stroke:#0000ff,stroke-width:2px
    style F1 fill:#e1ffe1
    style F2 fill:#e1ffe1
```

## Key Takeaways

### Encryption Happens Once
- ✅ **MailboxManager** encrypts messages using **DoubleRatchetProtocol**
- ❌ Transport layers never see plaintext
- ❌ Transport layers never perform encryption/decryption

### Message Flow Layers
1. **Application**: Sends plaintext "Hello!"
2. **LibEmiddleClient**: Routes to appropriate ChatSession
3. **ChatSession**: Coordinates encryption
4. **MailboxManager**: Performs encryption, creates MailboxMessage
5. **IMailboxTransport**: Abstract transport interface
6. **BaseMailboxTransport**: Common validation and logging
7. **Concrete Transport**: Actual delivery (HTTP, InMemory, etc.)
8. **Server/Storage**: Stores encrypted MailboxMessage

### Receiving is the Reverse
1. **Server/Storage**: Stores encrypted messages
2. **Concrete Transport**: Polls for new messages
3. **BaseMailboxTransport**: Validates messages
4. **IMailboxTransport**: Raises events
5. **MailboxManager**: Decrypts using DoubleRatchet
6. **ChatSession**: Coordinates decryption
7. **LibEmiddleClient**: Forwards to application
8. **Application**: Receives plaintext "Hello!"

### Important Architecture Notes

- **Single Responsibility**: Each layer has one clear job
- **Separation of Concerns**: Transport ≠ Encryption
- **Event-Driven**: Messages flow through events
- **Async Throughout**: All operations are async
- **Validation at Boundaries**: BaseMailboxTransport validates before processing
