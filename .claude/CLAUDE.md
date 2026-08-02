# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build, Test & Lint Commands

```bash
# Restore dependencies
dotnet restore

# Build (Debug or Release)
dotnet build --configuration Release
dotnet build --configuration Debug

# Run all tests
dotnet test --configuration Release --verbosity detailed

# Run a single test class
dotnet test --configuration Release --filter "ClassName=ChatSessionTests"

# Run a single test method
dotnet test --configuration Release --filter "FullyQualifiedName~ChatSessionTests.SomeTestMethod"

# Run tests with coverage
dotnet test --configuration Release --collect:"XPlat Code Coverage"

# Pack NuGet package
dotnet pack --configuration Release --output ./packages
```

Build settings enforce `TreatWarningsAsErrors=true` and `EnforceCodeStyleInBuild=true`, so all analyzer warnings must be resolved before a build succeeds. CS1591 (missing XML doc comments) is suppressed.

## Architecture Overview

LibEmiddle is a .NET 8 end-to-end encryption library implementing X3DH + Double Ratchet protocols via libsodium. The solution has four projects:

| Project | Role |
|---------|------|
| **LibEmiddle** | Main library — all cryptographic logic, sessions, transport |
| **LibEmiddle.Abstractions** | Interface contracts only; no implementations |
| **LibEmiddle.Domain** | Domain models, DTOs, enums, constants — no external dependencies |
| **LibEmiddle.Tests.Unit** | MSTest test suite with Moq for mocking |

### Layered dependency flow
```
LibEmiddle → LibEmiddle.Abstractions → LibEmiddle.Domain
```
`LibEmiddle.Tests.Unit` references only `LibEmiddle` (internals are exposed via `InternalsVisibleTo`).

### Main library layout (`LibEmiddle/`)

- **API/** — `LibEmiddleClient` is the single public entry point. `LibEmiddleClientOptions` controls all configuration. Client implements `IAsyncDisposable`.
- **Protocol/** — `X3DHProtocol` (initial key agreement) and `DoubleRatchetProtocol` (continuous ratcheting). `ProtocolAdapter` bridges them.
- **Crypto/** — `CryptoProvider` wraps libsodium via `Sodium.cs` P/Invoke bindings. `AES.cs` handles AES-256-GCM. `SecureMemory.cs` manages zeroing of sensitive data.
- **KeyManagement/** — `KeyManager` handles key lifecycle; `KeyStorage` persists keys encrypted with AES-GCM.
- **Sessions/** — `SessionManager` manages session lifecycle; `SessionPersistenceManager` handles bundle caching and recovery (Argon2id KDF for password-derived keys since v2.6.0).
- **Messaging/Chat/** — `ChatSession` handles 1-to-1 encrypted sessions with 500-entry replay-protection FIFO buffer.
- **Messaging/Group/** — `GroupSession` manages multi-party sessions with per-sender message IDs for replay protection.
- **Messaging/Transport/** — `MailboxManager` encrypts/decrypts; `HttpMailboxTransport` and `InMemoryMailboxTransport` implement `IMailboxTransport`. `SecureWebSocketClient` wraps TLS WebSocket.
- **MultiDevice/** — `DeviceManager`, `DeviceLinkingService`, and `SyncMessageValidator` implement device linking and revocation.

### Domain layer (`LibEmiddle.Domain/`)

- **Constants/ProtocolVersion.cs** — `MAJOR_VERSION`/`MINOR_VERSION` constants; updated only on major releases.
- **Enums/** — `KeyRotationStrategy` (Aggressive/Standard/Conservative/Adaptive), `SessionState`, `MemberRole`, `MessageType`, `SessionType`.
- **DTO/** — Serializable snapshots for all session types (used for persistence, never for wire format directly).
- **`LibEmiddleException`** — Typed exception with `LibEmiddleErrorCode` enum; always throw this instead of raw exceptions in library code.

### Abstractions layer (`LibEmiddle.Abstractions/`)

All public-facing interfaces live here: `IChatSession`, `IGroupSession`, `IDoubleRatchetProtocol`, `IX3DHProtocol`, `IMailboxTransport`, `IKeyManager`, `ISessionManager`, `IStorageProvider`, `IDeviceManager`, `ICryptoProvider`, etc. Implement these interfaces in `LibEmiddle`; never let implementations leak into Abstractions.

## Patterns & Anti-Patterns

**Core patterns — always apply:**
- Clone session state before mutating: `DeepCloneSession()` at entry of every encrypt/decrypt, return the clone, never modify the input object
- Semaphore over lock: `SemaphoreSlim(1,1)` for all async-safe state mutations; never use `lock()` in async paths
- Volatile + Interlocked disposal: `private volatile bool _disposed` checked via `ThrowIfDisposed()` on every public entry; set with `Interlocked.Exchange(ref _disposedFlag, 1)`
- Null-before-return for owned keys: when returning key material to a caller, set the local variable to `null` before the `finally` block so the finally doesn't clear what the caller now owns
- Secure-clear in finally: every method that produces intermediate key bytes wraps the work in try/finally and calls `SecureMemory.SecureClear()` on all temporaries — even on the success path
- Tuple returns for paired state: protocol methods return `(UpdatedSession?, ResultData?)` — never mutate session in-place and return a side-channel result
- Bounded eviction collections: replay-protection sets use a parallel Queue for FIFO eviction when the HashSet exceeds its cap; do the same for any unbounded accumulator
- Fire-and-forget events: raise domain events via `Task.Run(() => handler(...))` so event handlers can't hold the session lock
- Boolean validators, not throwing validators: key-validation helpers return `false` on bad input; only the caller that has context throws
- Constant-time ops: use `CryptographicOperations.FixedTimeEquals()` for key comparison, `Sodium.sodium_memcmp()` for raw byte comparison — never `==` or `SequenceEqual` on secrets

**Anti-patterns — never do:**
- Never call `Array.Clear()` on key material — use `SecureMemory.SecureClear()` which pins and calls `sodium_memzero`
- Never use `System.Security.Cryptography` asymmetric primitives — all asymmetric ops go through `CryptoProvider` → `Sodium`
- Never add unsafe blocks outside `Core/SecureMemory.cs` and `Core/Sodium.cs`
- Never swallow exceptions in catch — log and rethrow with context; `(null, null)` tuple returns are the only silent failure allowed and only in protocol decrypt paths
- Never share the cached key array — `GetKeyCopy()` returns a fresh copy; the cache retains the original
- Never use `Task.FromResult` to wrap genuinely async work — only for operations that are provably synchronous
- Never skip timestamp validation on incoming messages — reject anything negative or more than 1 hour in the future before touching crypto

## Key Conventions

- **Cryptography**: All crypto operations go through `CryptoProvider` → `Sodium` P/Invoke. Never use `System.Security.Cryptography` directly for asymmetric operations; libsodium is the source of truth.
- **Unsafe code**: Enabled in `LibEmiddle.csproj` solely for libsodium P/Invoke and `SecureMemory` zeroing. Do not add unsafe blocks elsewhere.
- **Nullable**: Nullable reference types are enabled project-wide (`Nullable=enable`). All public APIs must be null-annotated.
- **Async**: All I/O and session operations are async/await. Use `IAsyncDisposable` for resources that hold crypto state.
- **Events**: State changes (message received, member added, key rotated, session state changed) are surfaced via typed `EventArgs` subclasses in Domain.
- **Version bumps**: Update `Directory.Build.props` (`VersionPrefix`) and for major releases also `ProtocolVersion.cs`.
- **Native binaries**: libsodium DLLs live in `runtimes/win-x64/native/` and `runtimes/win-x86/native/`. Linux/macOS builds rely on the system-installed libsodium.

## CI/CD Notes

- `dotnet.yml` runs matrix builds (Debug + Release) on push/PR to `main`, `legacy-1.0`, and `experimental`. Tests must pass in both configurations.
- Version tags (`v*`) trigger a GitHub Release with attached `.nupkg` files and auto-extracted changelog notes.
- `release.yml` is a manual workflow for triggering versioned releases; it validates branch/version compatibility before committing the version bump and creating the tag.
- Branch → version mapping: `main` = v2.x.x, `legacy-1.0` = v1.x.x, `experimental` = v3.x.x-alpha.
