```mermaid
sequenceDiagram
    participant User as User
    participant LibClient as LibEmiddleClient
    participant KeyManager as KeyManager
    participant AdvancedKeyMgr as AdvancedKeyRotationManager
    participant Server as Transport Server
    participant Contacts as User Contacts

    Note over User, Contacts: Advanced Key Rotation Policy - Automatic: Time-based, Event-based, Risk-based

    User->>LibClient: Configure key rotation policy
    LibClient->>AdvancedKeyMgr: InitializeAdvancedRotation(policy)
    AdvancedKeyMgr->>AdvancedKeyMgr: SetRotationSchedule(automatic)

    AdvancedKeyMgr->>AdvancedKeyMgr: MonitorKeyHealth()
    AdvancedKeyMgr->>AdvancedKeyMgr: AssessRotationRisk()

    Note over AdvancedKeyMgr: Rotation trigger: Risk threshold exceeded

    AdvancedKeyMgr->>AdvancedKeyMgr: TriggerAdvancedRotation()
    AdvancedKeyMgr->>AdvancedKeyMgr: AnalyzeKeyUsagePatterns()
    AdvancedKeyMgr->>AdvancedKeyMgr: DetermineOptimalRotationOrder()

    AdvancedKeyMgr->>KeyManager: InitiateSmartRotation(keys_list)
    KeyManager->>KeyManager: RotateKeysInSequence(optimized_order)
    KeyManager->>KeyManager: GenerateNewKeyMaterial()

    KeyManager->>Server: DistributeNewKeys()
    Server->>Contacts: NotifyContactsOfKeyRotation()

    AdvancedKeyMgr->>AdvancedKeyMgr: VerifyRotationComplete()
    AdvancedKeyMgr->>AdvancedKeyMgr: UpdateRotationMetrics()

    LibClient->>User: Key rotation completed successfully

    Note over User, Contacts: Smart rotation with minimal impact on ongoing sessions and performance
    ```