## AST Branch Map & Production Readiness

### Branch classification

Every code path in this library falls into one of four AST branch classes. An agent must identify which class it is modifying before writing code.

**Class A — Production-ready core** (trust and extend)
- `LibEmiddle/Protocol/` — X3DH + Double Ratchet; real crypto, real state machines
- `LibEmiddle/Crypto/` — CryptoProvider, AES, Nonce; P/Invoke wrappers over libsodium
- `LibEmiddle/Core/SecureMemory.cs` — pinned GC memory, sodium_memzero; do not touch without understanding unsafe pinning
- `LibEmiddle/Messaging/Chat/ChatSession.cs` — SemaphoreSlim state machine, bounded replay buffer
- `LibEmiddle/KeyManagement/` — KeyManager, OPKManager, KeyStorage; real TTL caching and OPK lifecycle
- `LibEmiddle/Sessions/SessionManager.cs` — real session orchestration
- `LibEmiddle.Domain/` — all models, DTOs, enums; no logic, safe to read freely

**Class B — Structurally sound, async contracts complete as of v2.6.1**
- `LibEmiddle/Sessions/SessionPersistenceManager.cs` — all 9 public methods accept `CancellationToken`; `_ioLock.WaitAsync(ct)` with `lockAcquired` guard; path traversal fixed with base64 encoding + `Path.GetFullPath` containment assertion
- `LibEmiddle/Protocol/DoubleRatchetProtocol.cs` — renamed to sync `Encrypt`/`Decrypt`; all `(null, null)` failure paths replaced with typed `LibEmiddleException(LibEmiddleErrorCode.*)`
- `LibEmiddle/Infrastructure/ResilienceManager.cs` — real implementation: exponential backoff retry, Closed/HalfOpen/Open circuit breaker, per-call timeout via linked `CancellationTokenSource`, lock-free `Interlocked` stats

**Class C — Stub: interface only, zero implementation** (deferred to v3.0 — do not ship)
These files compile and pass the interface contract but perform no real work. They are wired into the DI builder and will silently succeed in production:

| File | What the stub does instead of real work | v3.0 target |
|------|----------------------------------------|-------------|
| `Infrastructure/AdvancedKeyRotationManagerStub.cs` | Sleeps with `Task.Delay`, returns fake `KeyRotationResult`; no keys are ever rotated | v3.0 |
| `Infrastructure/ConnectionPoolStub.cs` | Returns a `PooledConnectionStub` that echoes sends back as receives; `#pragma warning disable 67` suppresses unused event warnings | v3.0 |
| `Infrastructure/SessionBackupManagerStub.cs` | Creates `BackupInfo` objects with hardcoded `"stub-checksum-*"` and simulated file sizes; nothing is written to disk | v3.0 |
| `Infrastructure/WebRTCTransportStub.cs` | Echoes sent bytes back as received bytes; `Random` (non-cryptographic) used for stats simulation | v3.0 |
| `Crypto/PostQuantum/PostQuantumCryptoStub.cs` | `GenerateRandomBytes` used as placeholder for all Kyber/Dilithium/Falcon operations; `VerifyAsync` returns `true` for any non-empty signature | v3.0 |

**Class D — Dead API surface** (deferred to v3.0)
- `PostQuantumOptions` — stored, validated, stub instantiated; no actual PQ crypto path exists
- `BatchingOptions.IsValid()` — checked at construction, not enforced at encryption time

---

### v2.6.x completed (Class A+B fixes)

1. ✅ **CancellationToken propagation** — added `ct = default` to all async methods in `SessionPersistenceManager`; all `SemaphoreSlim.WaitAsync()` → `WaitAsync(ct)` with `lockAcquired` guard; `when (ex is not OperationCanceledException)` on all catch blocks
2. ✅ **Path traversal** — `GetSessionFilePath` now base64-encodes session IDs (URL-safe variant); `Path.GetFullPath` + prefix assertion provides defense-in-depth; `ListSessionsAsync` decodes back to original IDs
3. ✅ **Silent tuple failure** — `DoubleRatchetProtocol.Encrypt/Decrypt` now throw `LibEmiddleException` with `LibEmiddleErrorCode.InvalidMessage` / `DecryptionFailed` instead of returning `(null, null)`; callers wrap in `catch (LibEmiddleException)` to preserve their own null-on-failure contracts
4. ✅ **ResilienceManagerStub replaced** — `ResilienceManager` (real) implements full retry/circuit-breaker/timeout; stub deleted
5. ✅ **CLAUDE.md violations** — Array.Clear → SecureClear, SequenceEqual on secrets → sodium_memcmp, lock() in async → SemaphoreSlim, swallowed exceptions → logged warnings, Task.FromResult no-ops removed, unsafe blocks outside permitted files removed

### v3.0 backlog (Class C stubs → real implementations)

- WebRTC transport (real ICE/STUN/TURN, DataChannel framing)
- Post-quantum crypto (Kyber, Dilithium, Falcon via liboqs or similar)
- Session backup manager (real encrypted backup/restore, checksum verification)
- Connection pool (real pooling with health checks, eviction policy)
- Advanced key rotation manager (real rotation schedules, key ceremony support)
