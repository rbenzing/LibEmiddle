```mermaid
graph TD
    %% Client Layer
    ClientApp[Client Application] 
    
    %% API Layer  
    subgraph API["LibEmiddle API Layer"]
        LibClient[LibEmiddleClient]
        ClientBuilder[LibEmiddleClientBuilder]
        Diagnostics[LibEmiddleDiagnostics]
        ResilienceMgr[ResilienceManager]
        FeatureFlags[FeatureFlags]
    end
    
    %% Session Management Layer
    subgraph SessionMgmt["Session Management"]
        SessionManager[SessionManager]
        ChatSession[ChatSession]
        GroupSession[GroupSession]
        SessionPersistence[SessionPersistenceManager]
        SessionBackup[SessionBackupManager]
        ConnectionPool[ConnectionPool]
    end
    
    %% Multi-Device and Messaging Layer
    subgraph MultiDevice["Multi-Device & Messaging"]
        DeviceManager[DeviceManager]
        DeviceLinking[DeviceLinkingService]
        SyncValidator[SyncMessageValidator]
        MessageBatcher[MessageBatcher]
        MailboxManager[MailboxManager]
        AdvancedKeyRotation[AdvancedKeyRotationManager]
    end
    
    %% Protocol Layer
    subgraph ProtocolLayer["Protocol Layer"]
        X3DHProtocol[X3DHProtocol]
        DoubleRatchet[DoubleRatchetProtocol]
        ProtocolAdapter[ProtocolAdapter]
    end
    
    %% Transport Layer
    subgraph TransportLayer["Transport Layer"]
        HttpTransport[HttpMailboxTransport]
        WebSocketClient[SecureWebSocketClient]
        WebRTCTransport[WebRTCTransport]
        InMemoryTransport[InMemoryMailboxTransport]
        MessageSigning[MessageSigning]
    end
    
    %% Cryptography Layer
    subgraph CryptoLayer["Cryptography"]
        CryptoProvider[CryptoProvider]
        PostQuantumCrypto[PostQuantumCrypto]
        KeyManager[KeyManager]
        SecureMemory[SecureMemory]
        KeyStorage[KeyStorage]
        SodiumCore[Sodium.Core]
    end
    
    %% Storage Layer
    subgraph StorageLayer["Storage Layer"]
        FileStorageProvider[EnhancedFileStorageProvider]
        MemoryStorageProvider[InMemoryStorageProvider]
        BackupStorage[BackupStorage]
        Compression[Compression]
    end
    
    %% External/Server Layer
    subgraph ExternalLayer["External/Server Interface"]
        TransportServer[Transport/Server]
        KeyDistribution[Key Distribution Service]
        MessageRelay[Message Relay]
        WebRTCSignaling[WebRTC Signaling]
    end
    
    %% Connections
    ClientApp --> LibClient
    
    LibClient --> SessionManager
    ClientBuilder --> ChatSession
    ClientBuilder --> GroupSession
    Diagnostics --> ResilienceMgr
    
    SessionManager --> DeviceManager
    ChatSession --> DeviceLinking  
    GroupSession --> SyncValidator
    SessionPersistence --> SessionBackup
    ConnectionPool --> AdvancedKeyRotation
    
    DeviceManager --> X3DHProtocol
    ChatSession --> X3DHProtocol
    GroupSession --> DoubleRatchet
    ProtocolAdapter --> CryptoProvider
    
    MailboxManager --> HttpTransport
    MailboxManager --> WebSocketClient
    MessageBatcher --> WebRTCTransport
    
    X3DHProtocol --> CryptoProvider
    DoubleRatchet --> PostQuantumCrypto
    CryptoProvider --> KeyManager
    KeyManager --> KeyStorage
    PostQuantumCrypto --> SecureMemory
    KeyStorage --> SodiumCore
    
    SessionPersistence --> FileStorageProvider
    SessionBackup --> MemoryStorageProvider
    BackupStorage --> Compression
    
    HttpTransport --> TransportServer
    WebRTCTransport --> KeyDistribution
    WebSocketClient --> MessageRelay
    WebRTCTransport --> WebRTCSignaling
    
    %% Styling
    classDef clientStyle fill:#e6f3ff,stroke:#4169e1,stroke-width:2px
    classDef apiStyle fill:#e6ffe6,stroke:#32cd32,stroke-width:2px
    classDef sessionStyle fill:#fffacd,stroke:#daa520,stroke-width:2px
    classDef messagingStyle fill:#ffeedd,stroke:#ff8c00,stroke-width:2px
    classDef protocolStyle fill:#dda0dd,stroke:#9370db,stroke-width:2px
    classDef transportStyle fill:#e8e8e8,stroke:#696969,stroke-width:2px
    classDef cryptoStyle fill:#ffc0cb,stroke:#dc143c,stroke-width:2px
    classDef storageStyle fill:#f0e68c,stroke:#8b4513,stroke-width:2px
    classDef externalStyle fill:#fff8dc,stroke:#cd853f,stroke-width:2px
    
    class ClientApp clientStyle
    class LibClient,ClientBuilder,Diagnostics,ResilienceMgr,FeatureFlags apiStyle
    class SessionManager,ChatSession,GroupSession,SessionPersistence,SessionBackup,ConnectionPool sessionStyle
    class DeviceManager,DeviceLinking,SyncValidator,MessageBatcher,MailboxManager,AdvancedKeyRotation messagingStyle
    class X3DHProtocol,DoubleRatchet,ProtocolAdapter protocolStyle
    class HttpTransport,WebSocketClient,WebRTCTransport,InMemoryTransport,MessageSigning transportStyle
    class CryptoProvider,PostQuantumCrypto,KeyManager,SecureMemory,KeyStorage,SodiumCore cryptoStyle
    class FileStorageProvider,MemoryStorageProvider,BackupStorage,Compression storageStyle
    class TransportServer,KeyDistribution,MessageRelay,WebRTCSignaling externalStyle
    ```