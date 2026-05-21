# Class A+B Async Contract Completion Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate every Class B defect so all Class A and Class B code has complete async contracts, typed exceptions, and no silent failure paths — making the library production-ready for callers that need cancellation, error differentiation, and safe file access.

**Architecture:** Four independent fix areas executed as separate tasks: (1) `CancellationToken` threading through `SessionPersistenceManager` + its `_ioLock`; (2) `DoubleRatchetProtocol.EncryptAsync/DecryptAsync` replaced with throwing `LibEmiddleException`; (3) path traversal fix in `GetSessionFilePath`; (4) `ResilienceManager` real implementation replacing the stub. Tasks 1–3 are surgical modifications to existing files; Task 4 replaces one internal class with no public-API change.

**Tech Stack:** C# 12, .NET 8, MSTest, `SemaphoreSlim.WaitAsync(CancellationToken)`, `LibEmiddleException(LibEmiddleErrorCode)`, `Path.GetFullPath` canonicalization, no new NuGet packages (Polly is not used — resilience is implemented from scratch using `SemaphoreSlim`, `Stopwatch`, and `Interlocked`).

---

## File Map

| File | Change |
|------|--------|
| `LibEmiddle/Sessions/SessionPersistenceManager.cs` | Add `ct` to all 8 public async methods; thread into `_ioLock.WaitAsync(ct)` and all `await` calls |
| `LibEmiddle/Sessions/SessionPersistenceManager.cs:507-511` | Replace char-filter path sanitizer with `Path.GetFullPath` + prefix assertion |
| `LibEmiddle/Protocol/DoubleRatchetProtocol.cs:188,298` | Remove `(null,null)` catch-all returns; throw `LibEmiddleException` with typed error code |
| `LibEmiddle.Abstractions/IDoubleRatchetProtocol.cs:38,46` | Update interface signatures — `EncryptAsync`/`DecryptAsync` become `Encrypt`/`Decrypt` (these are not async; names are misleading) |
| `LibEmiddle/Infrastructure/ResilienceManager.cs` | **New file** — real implementation replacing `ResilienceManagerStub.cs` |
| `LibEmiddle/Infrastructure/ResilienceManagerStub.cs` | Delete (replaced by `ResilienceManager.cs`) |
| `LibEmiddle.Tests.Unit/SessionPersistenceTests.cs` | New tests for CT propagation and path traversal |
| `LibEmiddle.Tests.Unit/DoubleRatchetTests.cs` | New tests for typed exception paths |
| `LibEmiddle.Tests.Unit/ResilienceManagerTests.cs` | New tests for retry, circuit breaker, timeout |

---

## Task 1 — Thread `CancellationToken` through `SessionPersistenceManager`

**Files:**
- Modify: `LibEmiddle/Sessions/SessionPersistenceManager.cs` (all public async methods + `EncryptAndSaveSessionAsync` + `LoadAndDecryptSessionAsync`)
- Test: `LibEmiddle.Tests.Unit/SessionPersistenceTests.cs`

- [ ] **Step 1: Write failing tests for CT propagation**

Add to `LibEmiddle.Tests.Unit/SessionPersistenceTests.cs` (create file if it doesn't exist — check with `Get-ChildItem LibEmiddle.Tests.Unit\SessionPersistenceTests.cs`):

```csharp
using LibEmiddle.Core;
using LibEmiddle.Sessions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace LibEmiddle.Tests.Unit;

[TestClass]
public class SessionPersistenceTests
{
    [TestMethod]
    public async Task DeleteSessionAsync_CancelledToken_ThrowsOperationCanceled()
    {
        var crypto = new CryptoProvider();
        var spm = new SessionPersistenceManager(crypto, Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString()));
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsExceptionAsync<OperationCanceledException>(
            () => spm.DeleteSessionAsync("test-session-id", cts.Token));
    }

    [TestMethod]
    public async Task ListSessionsAsync_CancelledToken_ThrowsOperationCanceled()
    {
        var crypto = new CryptoProvider();
        var spm = new SessionPersistenceManager(crypto, Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString()));
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsExceptionAsync<OperationCanceledException>(
            () => spm.ListSessionsAsync(cts.Token));
    }

    [TestMethod]
    public async Task SaveKeyBundleAsync_CancelledToken_ThrowsOperationCanceled()
    {
        var crypto = new CryptoProvider();
        var spm = new SessionPersistenceManager(crypto, Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString()));
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var bundle = new LibEmiddle.Domain.X3DHPublicBundle
        {
            IdentityKey = new byte[32]
        };
        RandomNumberGenerator.Fill(bundle.IdentityKey);

        await Assert.ThrowsExceptionAsync<OperationCanceledException>(
            () => spm.SaveKeyBundleAsync(bundle, cts.Token));
    }
}
```

Run: `dotnet test --configuration Release --filter "ClassName=SessionPersistenceTests" --verbosity detailed`
Expected: FAIL — method signatures don't accept `CancellationToken` yet.

- [ ] **Step 2: Add `CancellationToken ct = default` to all 8 public async methods**

In `LibEmiddle/Sessions/SessionPersistenceManager.cs`, update every public async method signature:

```csharp
// Line 41
public async Task<bool> SaveChatSessionAsync(IChatSession session, CancellationToken ct = default)

// Line 75
public async Task<bool> SaveGroupSessionAsync(IGroupSession session, CancellationToken ct = default)

// Line 121
public async Task<ChatSession?> LoadChatSessionAsync(
    string sessionId,
    IDoubleRatchetProtocol doubleRatchetProtocol,
    CancellationToken ct = default)

// Line 175
public async Task<string?> LoadGroupSessionStateAsync(string sessionId, CancellationToken ct = default)

// Line 204
public async Task<IGroupSession?> LoadGroupSessionAsync(
    string sessionId,
    KeyPair identityKeyPair,
    CancellationToken ct = default)

// Line 252
public async Task<bool> DeleteSessionAsync(string sessionId, CancellationToken ct = default)

// Line 281
public async Task<string?[]> ListSessionsAsync(CancellationToken ct = default)

// Line 457
public async Task SaveKeyBundleAsync(X3DHPublicBundle bundle, CancellationToken ct = default)

// Line 481
public async Task<X3DHPublicBundle?> LoadKeyBundleByIdentityKeyAsync(byte[] identityKey, CancellationToken ct = default)
```

Also update the private helpers:
```csharp
// Line 310
private async Task<bool> EncryptAndSaveSessionAsync(SerializedSessionData dto, CancellationToken ct = default)

// Line 386
private async Task<SerializedSessionData?> LoadAndDecryptSessionAsync(string sessionId, CancellationToken ct = default)
```

- [ ] **Step 3: Thread `ct` into every `_ioLock.WaitAsync()` call and every delegating `await`**

Every call to `_ioLock.WaitAsync()` in the file (lines 258, 283, 340, 390, 466, 487) becomes:
```csharp
await _ioLock.WaitAsync(ct).ConfigureAwait(false);
```

Every `await` that delegates to another async method in this file passes `ct` through:
```csharp
// SaveChatSessionAsync delegates to EncryptAndSaveSessionAsync:
return await EncryptAndSaveSessionAsync(dto, ct);

// SaveGroupSessionAsync:
string groupState = await groupSession.GetSerializedStateAsync();  // no ct — GroupSession doesn't expose one yet
return await EncryptAndSaveSessionAsync(dto, ct);

// LoadChatSessionAsync delegates to LoadAndDecryptSessionAsync:
var dto = await LoadAndDecryptSessionAsync(sessionId, ct);

// LoadGroupSessionStateAsync:
var dto = await LoadAndDecryptSessionAsync(sessionId, ct);

// LoadGroupSessionAsync:
string? groupState = await LoadGroupSessionStateAsync(sessionId, ct);
bool restored = await groupSession.RestoreSerializedStateAsync(groupState);  // no ct available — leave as-is

// SaveKeyBundleAsync:
await File.WriteAllTextAsync(filePath, json, System.Text.Encoding.UTF8, ct);

// LoadKeyBundleByIdentityKeyAsync:
string json = await File.ReadAllTextAsync(filePath, System.Text.Encoding.UTF8, ct);
```

`_cryptoProvider.StoreKeyAsync` and `_cryptoProvider.RetrieveKeyAsync` do not accept `CancellationToken` — leave those calls unchanged (they are in-memory or file operations that complete quickly).

- [ ] **Step 4: Build**

```
dotnet build LibEmiddle.sln --configuration Release
```
Expected: 0 errors. If callers of `SessionPersistenceManager` in `SessionManager.cs` break, they use `default` implicitly — all callers will still compile since `ct = default` is optional.

- [ ] **Step 5: Run failing tests — expect PASS now**

```
dotnet test --configuration Release --filter "ClassName=SessionPersistenceTests" --verbosity detailed
```
Expected: all 3 new tests PASS.

- [ ] **Step 6: Run full suite**

```
dotnet test --configuration Release
```
Expected: all existing tests still pass.

- [ ] **Step 7: Commit**

```
git add LibEmiddle/Sessions/SessionPersistenceManager.cs LibEmiddle.Tests.Unit/SessionPersistenceTests.cs
git commit -m "feat: add CancellationToken propagation to SessionPersistenceManager"
```

---

## Task 2 — Fix path traversal in `GetSessionFilePath`

**Files:**
- Modify: `LibEmiddle/Sessions/SessionPersistenceManager.cs:507-511`
- Test: `LibEmiddle.Tests.Unit/SessionPersistenceTests.cs`

- [ ] **Step 1: Write a failing test for path traversal**

Add to `LibEmiddle.Tests.Unit/SessionPersistenceTests.cs`:

```csharp
[TestMethod]
public async Task DeleteSessionAsync_TraversalSessionId_ThrowsArgumentException()
{
    var crypto = new CryptoProvider();
    var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
    Directory.CreateDirectory(tempDir);
    var spm = new SessionPersistenceManager(crypto, tempDir);

    // A session ID containing ".." must not be allowed to escape the storage directory
    await Assert.ThrowsExceptionAsync<ArgumentException>(
        () => spm.DeleteSessionAsync("../../etc/passwd"));
}
```

Run: `dotnet test --configuration Release --filter "DeleteSessionAsync_TraversalSessionId_ThrowsArgumentException" --verbosity detailed`
Expected: FAIL — currently the char-filter allows `..` through.

- [ ] **Step 2: Replace the sanitizer with `Path.GetFullPath` + prefix guard**

In `LibEmiddle/Sessions/SessionPersistenceManager.cs`, replace `GetSessionFilePath` (lines 507–511):

```csharp
private string GetSessionFilePath(string sessionId)
{
    // Use URL-safe base64 encoding of the UTF-8 bytes to guarantee filename safety.
    // This prevents any path traversal regardless of what characters sessionId contains.
    string encoded = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(sessionId))
        .Replace('+', '-').Replace('/', '_').Replace("=", "");
    string candidate = Path.Combine(_storagePath, $"{encoded}.session");

    // Canonicalize and assert containment — defense in depth.
    string canonical = Path.GetFullPath(candidate);
    string storageCanonical = Path.GetFullPath(_storagePath);
    if (!canonical.StartsWith(storageCanonical + Path.DirectorySeparatorChar, StringComparison.Ordinal)
        && canonical != storageCanonical)
    {
        throw new ArgumentException($"Session ID '{sessionId}' resolves outside storage path.", nameof(sessionId));
    }

    return canonical;
}
```

Note: the base64 encoding means old session files stored under the old char-filter names will no longer be found. This is acceptable — this library has no migration story for beta session files. If backward compatibility is required in the future, a migration helper can be added.

- [ ] **Step 3: Build**

```
dotnet build LibEmiddle.sln --configuration Release
```
Expected: 0 errors.

- [ ] **Step 4: Run failing test — expect PASS**

```
dotnet test --configuration Release --filter "DeleteSessionAsync_TraversalSessionId_ThrowsArgumentException" --verbosity detailed
```
Expected: PASS.

- [ ] **Step 5: Run full suite**

```
dotnet test --configuration Release
```
Expected: all pass. (Integration tests that create sessions will now write under the new base64 filenames — verify no test compares raw file paths.)

- [ ] **Step 6: Commit**

```
git add LibEmiddle/Sessions/SessionPersistenceManager.cs LibEmiddle.Tests.Unit/SessionPersistenceTests.cs
git commit -m "fix: replace path-traversal-vulnerable session filename sanitizer with base64 encoding"
```

---

## Task 3 — Replace `(null, null)` silent failure in `DoubleRatchetProtocol` with typed exceptions

**Files:**
- Modify: `LibEmiddle.Abstractions/IDoubleRatchetProtocol.cs:38,46`
- Modify: `LibEmiddle/Protocol/DoubleRatchetProtocol.cs:188,298`
- Modify: `LibEmiddle/Messaging/Chat/ChatSession.cs` — callers of `EncryptAsync`/`DecryptAsync` that check for `(null, null)`
- Test: `LibEmiddle.Tests.Unit/DoubleRatchetTests.cs`

**Context:** `EncryptAsync` and `DecryptAsync` are misnamed — they are synchronous methods (`(Session?, Message?)` tuple return, no `await` inside). This task also renames them to `Encrypt`/`Decrypt` in the interface and implementation to eliminate the misleading `Async` suffix.

- [ ] **Step 1: Identify all callers of `EncryptAsync` and `DecryptAsync`**

```
grep -rn "\.EncryptAsync\|\.DecryptAsync" LibEmiddle/ LibEmiddle.Tests.Unit/
```

Expected files: `ChatSession.cs` and possibly test files. Record each call site before changing anything.

- [ ] **Step 2: Write failing tests for typed exceptions**

Add to `LibEmiddle.Tests.Unit/DoubleRatchetTests.cs` (create if absent):

```csharp
using LibEmiddle.Domain;
using LibEmiddle.Domain.Exceptions;
using LibEmiddle.Domain.Enums;
using LibEmiddle.Protocol;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace LibEmiddle.Tests.Unit;

[TestClass]
public class DoubleRatchetExceptionTests
{
    [TestMethod]
    public void Encrypt_SessionIdMismatch_ThrowsLibEmiddleException()
    {
        var protocol = new DoubleRatchetProtocol();
        var session = MakeInitializedSession("session-A");

        // Create a message with a different session ID to trigger the mismatch path
        // We encrypt normally first to produce a valid ciphertext, then tamper the session ID
        var (updatedSession, msg) = protocol.Encrypt(session, "hello");
        Assert.IsNotNull(updatedSession);
        Assert.IsNotNull(msg);

        // Now decrypt with a session whose ID doesn't match the message's session ID
        var wrongSession = MakeInitializedSession("session-B");
        var ex = Assert.ThrowsException<LibEmiddleException>(
            () => protocol.Decrypt(wrongSession, msg!));
        Assert.AreEqual(LibEmiddleErrorCode.InvalidMessage, ex.ErrorCode);
    }

    [TestMethod]
    public void Decrypt_TamperedCiphertext_ThrowsLibEmiddleException()
    {
        var protocol = new DoubleRatchetProtocol();
        // Need a sender and receiver session pair. Use InitializeSessionAsSender/AsReceiver.
        var senderKeyPair = LibEmiddle.Core.Sodium.GenerateX25519KeyPair();
        var receiverKeyPair = LibEmiddle.Core.Sodium.GenerateX25519KeyPair();
        byte[] sharedKey = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(sharedKey);

        var sender = protocol.InitializeSessionAsSender(sharedKey, receiverKeyPair.PublicKey, "s1");
        var receiver = protocol.InitializeSessionAsReceiver(sharedKey, receiverKeyPair, senderKeyPair.PublicKey, "s1");

        var (_, msg) = protocol.Encrypt(sender, "hello");
        Assert.IsNotNull(msg);

        // Tamper the ciphertext
        msg!.Ciphertext![0] ^= 0xFF;

        var ex = Assert.ThrowsException<LibEmiddleException>(
            () => protocol.Decrypt(receiver, msg));
        Assert.AreEqual(LibEmiddleErrorCode.DecryptionFailed, ex.ErrorCode);
    }
}

// Helper — creates a minimally initialized session (sender side) for testing
file static class DoubleRatchetTestHelper
{
    internal static DoubleRatchetSession MakeInitializedSession(string sessionId)
    {
        var protocol = new DoubleRatchetProtocol();
        var recipientKey = LibEmiddle.Core.Sodium.GenerateX25519KeyPair();
        byte[] sharedKey = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(sharedKey);
        return protocol.InitializeSessionAsSender(sharedKey, recipientKey.PublicKey, sessionId);
    }
}
```

Run: `dotnet test --configuration Release --filter "ClassName=DoubleRatchetExceptionTests" --verbosity detailed`
Expected: FAIL — methods are still called `EncryptAsync`/`DecryptAsync` and return `(null,null)`.

- [ ] **Step 3: Rename interface methods and update return types**

In `LibEmiddle.Abstractions/IDoubleRatchetProtocol.cs`, rename lines 38 and 46:

```csharp
/// <summary>
/// Encrypts a message using the Double Ratchet protocol.
/// Throws <see cref="LibEmiddle.Domain.Exceptions.LibEmiddleException"/> on failure.
/// </summary>
(DoubleRatchetSession, EncryptedMessage) Encrypt(
    DoubleRatchetSession session,
    string message,
    KeyRotationStrategy rotationStrategy = KeyRotationStrategy.Standard);

/// <summary>
/// Decrypts a message using the Double Ratchet protocol.
/// Throws <see cref="LibEmiddle.Domain.Exceptions.LibEmiddleException"/> on failure.
/// </summary>
(DoubleRatchetSession, string) Decrypt(
    DoubleRatchetSession session,
    EncryptedMessage encryptedMessage);
```

Note: return types are now non-nullable tuples — the contract is "return a valid result or throw; never return null."

- [ ] **Step 4: Update `DoubleRatchetProtocol.cs` — rename methods and replace `(null,null)` returns with throws**

In `LibEmiddle/Protocol/DoubleRatchetProtocol.cs`:

**Rename** `EncryptAsync` → `Encrypt` (line 188). Change the catch block at line 285–289:

```csharp
// BEFORE
catch (Exception ex)
{
    LoggingManager.LogError(nameof(DoubleRatchetProtocol), $"Encryption failed: {ex.Message}");
    return (null, null);
}

// AFTER
catch (Exception ex) when (ex is not LibEmiddleException)
{
    LoggingManager.LogError(nameof(DoubleRatchetProtocol), $"Encryption failed: {ex.Message}");
    throw new LibEmiddleException(
        $"Message encryption failed: {ex.Message}",
        LibEmiddleErrorCode.DecryptionFailed,
        ex);
}
```

Add `using LibEmiddle.Domain.Exceptions;` at top of file if not present.

**Rename** `DecryptAsync` → `Decrypt` (line 298). Replace the session-ID mismatch `(null,null)` return at line ~319:

```csharp
// BEFORE
if (encryptedMessage.SessionId != session.SessionId)
{
    LoggingManager.LogWarning(nameof(DoubleRatchetProtocol), "Message session ID does not match current session");
    return (null, null);
}

// AFTER
if (encryptedMessage.SessionId != session.SessionId)
{
    throw new LibEmiddleException(
        $"Message session ID '{encryptedMessage.SessionId}' does not match session '{session.SessionId}'.",
        LibEmiddleErrorCode.InvalidMessage);
}
```

Replace the timestamp-rejection `(null,null)` returns (lines ~324 and ~334):

```csharp
// BEFORE — negative timestamp
return (null, null);
// AFTER
throw new LibEmiddleException(
    "Message has a negative timestamp and was rejected.",
    LibEmiddleErrorCode.InvalidMessage);

// BEFORE — future timestamp
return (null, null);
// AFTER
throw new LibEmiddleException(
    "Message timestamp is more than 1 hour in the future and was rejected.",
    LibEmiddleErrorCode.InvalidMessage);
```

Replace the outer catch block (lines 442–446):

```csharp
// BEFORE
catch (Exception ex)
{
    LoggingManager.LogError(nameof(DoubleRatchetProtocol), $"Decryption failed: {ex.Message}");
    return (null, null);
}

// AFTER
catch (Exception ex) when (ex is not LibEmiddleException)
{
    LoggingManager.LogError(nameof(DoubleRatchetProtocol), $"Decryption failed: {ex.Message}");
    throw new LibEmiddleException(
        $"Message decryption failed: {ex.Message}",
        LibEmiddleErrorCode.DecryptionFailed,
        ex);
}
```

Change method return types from `(DoubleRatchetSession?, EncryptedMessage?)` and `(DoubleRatchetSession?, string?)` to the non-nullable variants `(DoubleRatchetSession, EncryptedMessage)` and `(DoubleRatchetSession, string)`.

- [ ] **Step 5: Update all callers of `EncryptAsync`/`DecryptAsync`**

From the grep in Step 1, update each call site. In `LibEmiddle/Messaging/Chat/ChatSession.cs`:

```csharp
// BEFORE
var (updatedSession, encryptedMessage) = _doubleRatchetProtocol.EncryptAsync(currentSession, message, _rotationStrategy);
if (updatedSession == null || encryptedMessage == null)
    throw new InvalidOperationException("Encryption failed");

// AFTER — EncryptAsync renamed to Encrypt; throws on failure so no null check needed
var (updatedSession, encryptedMessage) = _doubleRatchetProtocol.Encrypt(currentSession, message, _rotationStrategy);
```

```csharp
// BEFORE
var (updatedSession, decryptedMessage) = _doubleRatchetProtocol.DecryptAsync(currentSession, encryptedMessage);
if (updatedSession == null || decryptedMessage == null)
    return null;

// AFTER — Decrypt throws LibEmiddleException on failure; caller handles or propagates
var (updatedSession, decryptedMessage) = _doubleRatchetProtocol.Decrypt(currentSession, encryptedMessage);
```

The `LibEmiddleException` will propagate through `ChatSession` to `LibEmiddleClient.Chat.cs`, where it should be logged and re-thrown (or caught and wrapped). Verify the caller chain handles the exception appropriately — if it currently catches `Exception` and returns `null`, it will still handle it correctly since `LibEmiddleException` is an `Exception`.

- [ ] **Step 6: Build**

```
dotnet build LibEmiddle.sln --configuration Release
```
Expected: 0 errors. Fix any remaining callers the compiler reports.

- [ ] **Step 7: Run failing tests — expect PASS**

```
dotnet test --configuration Release --filter "ClassName=DoubleRatchetExceptionTests" --verbosity detailed
```
Expected: both tests PASS.

- [ ] **Step 8: Run full suite**

```
dotnet test --configuration Release
```
Expected: all tests pass. Any test that previously checked for `null` returns from `EncryptAsync`/`DecryptAsync` will need updating to expect `LibEmiddleException` instead.

- [ ] **Step 9: Commit**

```
git add LibEmiddle.Abstractions/IDoubleRatchetProtocol.cs LibEmiddle/Protocol/DoubleRatchetProtocol.cs LibEmiddle/Messaging/Chat/ChatSession.cs LibEmiddle.Tests.Unit/DoubleRatchetTests.cs
git commit -m "feat: replace (null,null) silent failure in DoubleRatchetProtocol with typed LibEmiddleException"
```

---

## Task 4 — Replace `ResilienceManagerStub` with a real implementation

**Files:**
- Create: `LibEmiddle/Infrastructure/ResilienceManager.cs`
- Delete: `LibEmiddle/Infrastructure/ResilienceManagerStub.cs`
- Test: `LibEmiddle.Tests.Unit/ResilienceManagerTests.cs`

**Architecture:** Implement retry with exponential backoff + jitter, circuit breaker (Closed/HalfOpen/Open), and per-call timeout enforcement — all from scratch using `SemaphoreSlim`, `Stopwatch`, `Interlocked`, and `Task.WhenAny`. No new NuGet packages. `ResilienceStats` is tracked in a `ConcurrentDictionary<ResilienceOperationType, OperationStats>` (a private internal type). The class is `internal` like the stub it replaces.

- [ ] **Step 1: Write failing tests for resilience behavior**

Create `LibEmiddle.Tests.Unit/ResilienceManagerTests.cs`:

```csharp
using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;
using LibEmiddle.Infrastructure;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace LibEmiddle.Tests.Unit;

[TestClass]
public class ResilienceManagerTests
{
    private static ResilienceOptions DefaultOptions() => new()
    {
        RetryPolicy = new RetryPolicy
        {
            MaxRetries = 2,
            BaseDelay = TimeSpan.FromMilliseconds(10),
            MaxDelay = TimeSpan.FromMilliseconds(100),
            BackoffMultiplier = 2.0,
            UseExponentialBackoff = true
        },
        CircuitBreakerPolicy = new CircuitBreakerPolicy
        {
            FailureThreshold = 3,
            RecoveryTimeout = TimeSpan.FromMilliseconds(200),
            MinimumThroughput = 1,
            SamplingPeriod = TimeSpan.FromSeconds(10)
        },
        TimeoutPolicy = new TimeoutPolicy
        {
            DefaultTimeout = TimeSpan.FromSeconds(5),
            ConnectionTimeout = TimeSpan.FromSeconds(5),
            SendTimeout = TimeSpan.FromSeconds(5),
            ReceiveTimeout = TimeSpan.FromSeconds(5)
        },
        EnableJitter = false // Disable jitter for deterministic tests
    };

    [TestMethod]
    public async Task ExecuteAsync_SuccessOnFirstAttempt_ReturnsResult()
    {
        using var mgr = new ResilienceManager(DefaultOptions());
        int result = await mgr.ExecuteAsync(
            _ => Task.FromResult(42),
            ResilienceOperationType.MessageSend);
        Assert.AreEqual(42, result);
    }

    [TestMethod]
    public async Task ExecuteAsync_TransientFailure_RetriesAndSucceeds()
    {
        using var mgr = new ResilienceManager(DefaultOptions());
        int attempts = 0;
        int result = await mgr.ExecuteAsync<int>(
            _ =>
            {
                attempts++;
                if (attempts < 2) throw new InvalidOperationException("transient");
                return Task.FromResult(99);
            },
            ResilienceOperationType.MessageSend);

        Assert.AreEqual(99, result);
        Assert.AreEqual(2, attempts);
    }

    [TestMethod]
    public async Task ExecuteAsync_ExceedsRetries_ThrowsOriginalException()
    {
        using var mgr = new ResilienceManager(DefaultOptions());
        await Assert.ThrowsExceptionAsync<InvalidOperationException>(
            () => mgr.ExecuteAsync<int>(
                _ => throw new InvalidOperationException("permanent"),
                ResilienceOperationType.MessageSend));
    }

    [TestMethod]
    public async Task ExecuteAsync_CircuitOpensAfterThreshold_ThrowsImmediately()
    {
        var options = DefaultOptions();
        options.CircuitBreakerPolicy.FailureThreshold = 2;
        options.CircuitBreakerPolicy.MinimumThroughput = 1;
        using var mgr = new ResilienceManager(options);

        // Exhaust retries twice to trip the circuit
        for (int i = 0; i < 2; i++)
        {
            try
            {
                await mgr.ExecuteAsync<int>(
                    _ => throw new InvalidOperationException("fail"),
                    ResilienceOperationType.MessageSend);
            }
            catch { }
        }

        var stats = await mgr.GetStatisticsAsync(ResilienceOperationType.MessageSend);
        Assert.AreEqual(CircuitBreakerState.Open, stats.CircuitBreakerState);

        // Next call should be blocked immediately without executing the operation
        await Assert.ThrowsExceptionAsync<InvalidOperationException>(
            () => mgr.ExecuteAsync<int>(
                _ => Task.FromResult(0),
                ResilienceOperationType.MessageSend));
    }

    [TestMethod]
    public async Task GetStatisticsAsync_AfterMixedRuns_ReportsCorrectCounts()
    {
        using var mgr = new ResilienceManager(DefaultOptions());
        await mgr.ExecuteAsync(_ => Task.FromResult(1), ResilienceOperationType.KeyExchange);
        try { await mgr.ExecuteAsync<int>(_ => throw new Exception("e"), ResilienceOperationType.KeyExchange); } catch { }

        var stats = await mgr.GetStatisticsAsync(ResilienceOperationType.KeyExchange);
        Assert.IsTrue(stats.TotalExecutions >= 2);
        Assert.IsTrue(stats.SuccessfulExecutions >= 1);
        Assert.IsTrue(stats.FailedExecutions >= 1);
    }
}
```

Run: `dotnet test --configuration Release --filter "ClassName=ResilienceManagerTests" --verbosity detailed`
Expected: FAIL — `ResilienceManager` class doesn't exist yet (only `ResilienceManagerStub`).

- [ ] **Step 2: Create `LibEmiddle/Infrastructure/ResilienceManager.cs`**

```csharp
using System.Collections.Concurrent;
using System.Diagnostics;
using LibEmiddle.Abstractions;
using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;

namespace LibEmiddle.Infrastructure;

/// <summary>
/// Real implementation of <see cref="IResilienceManager"/> providing retry with
/// exponential backoff, circuit breaker (Closed/HalfOpen/Open), and per-call timeout.
/// </summary>
internal sealed class ResilienceManager : IResilienceManager
{
    private readonly ResilienceOptions _options;
    private readonly ConcurrentDictionary<ResilienceOperationType, OperationState> _state = new();

    public ResilienceManager(ResilienceOptions options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    // ── Public interface ────────────────────────────────────────────────────

    public async Task<T> ExecuteAsync<T>(
        Func<CancellationToken, Task<T>> operation,
        ResilienceOperationType operationType,
        CancellationToken cancellationToken = default)
    {
        var state = _state.GetOrAdd(operationType, _ => new OperationState());
        ThrowIfOpen(state, operationType);

        int attempt = 0;
        Exception? lastException = null;

        while (attempt <= _options.RetryPolicy.MaxRetries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var sw = Stopwatch.StartNew();
            try
            {
                T result = await ExecuteWithTimeoutAsync(operation, cancellationToken)
                    .ConfigureAwait(false);
                sw.Stop();
                RecordSuccess(state, sw.Elapsed);
                return result;
            }
            catch (OperationCanceledException)
            {
                throw; // never retry cancellation
            }
            catch (Exception ex)
            {
                sw.Stop();
                lastException = ex;
                RecordFailure(state, ex, sw.Elapsed);
                attempt++;
                if (attempt <= _options.RetryPolicy.MaxRetries)
                    await DelayAsync(attempt, cancellationToken).ConfigureAwait(false);
            }
        }

        throw lastException!;
    }

    public async Task ExecuteAsync(
        Func<CancellationToken, Task> operation,
        ResilienceOperationType operationType,
        CancellationToken cancellationToken = default)
    {
        await ExecuteAsync<bool>(async ct =>
        {
            await operation(ct).ConfigureAwait(false);
            return true;
        }, operationType, cancellationToken).ConfigureAwait(false);
    }

    public Task<ResilienceStats> GetStatisticsAsync(ResilienceOperationType operationType)
    {
        var state = _state.GetOrAdd(operationType, _ => new OperationState());
        return Task.FromResult(state.ToStats(operationType));
    }

    public Task<Dictionary<ResilienceOperationType, ResilienceStats>> GetAllStatisticsAsync()
    {
        var result = new Dictionary<ResilienceOperationType, ResilienceStats>();
        foreach (var kvp in _state)
            result[kvp.Key] = kvp.Value.ToStats(kvp.Key);
        return Task.FromResult(result);
    }

    public Task ResetStatisticsAsync(ResilienceOperationType? operationType = null)
    {
        if (operationType.HasValue)
        {
            if (_state.TryGetValue(operationType.Value, out var s)) s.Reset();
        }
        else
        {
            foreach (var s in _state.Values) s.Reset();
        }
        return Task.CompletedTask;
    }

    public void Dispose() { /* no unmanaged resources */ }

    // ── Private helpers ─────────────────────────────────────────────────────

    private async Task<T> ExecuteWithTimeoutAsync<T>(
        Func<CancellationToken, Task<T>> operation,
        CancellationToken cancellationToken)
    {
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(_options.TimeoutPolicy.DefaultTimeout);
        return await operation(timeoutCts.Token).ConfigureAwait(false);
    }

    private void ThrowIfOpen(OperationState state, ResilienceOperationType operationType)
    {
        if (state.CircuitState != CircuitBreakerState.Open) return;

        // Check if recovery window has elapsed → transition to HalfOpen
        if (DateTime.UtcNow - state.CircuitOpenedAt >= _options.CircuitBreakerPolicy.RecoveryTimeout)
        {
            state.CircuitState = CircuitBreakerState.HalfOpen;
            return;
        }

        throw new InvalidOperationException(
            $"Circuit breaker is Open for operation type {operationType}. Recovery in " +
            $"{(_options.CircuitBreakerPolicy.RecoveryTimeout - (DateTime.UtcNow - state.CircuitOpenedAt)).TotalSeconds:F1}s.");
    }

    private void RecordSuccess(OperationState state, TimeSpan elapsed)
    {
        Interlocked.Increment(ref state.TotalExecutions);
        Interlocked.Increment(ref state.SuccessfulExecutions);
        state.UpdateAverageTime(elapsed);
        state.LastExecutionTime = DateTime.UtcNow;
        // Close circuit on success (handles HalfOpen probe succeeded)
        state.CircuitState = CircuitBreakerState.Closed;
        Interlocked.Exchange(ref state.ConsecutiveFailures, 0);
    }

    private void RecordFailure(OperationState state, Exception ex, TimeSpan elapsed)
    {
        Interlocked.Increment(ref state.TotalExecutions);
        Interlocked.Increment(ref state.FailedExecutions);
        state.UpdateAverageTime(elapsed);
        state.LastExecutionTime = DateTime.UtcNow;
        state.LastException = ex;

        long failures = Interlocked.Increment(ref state.ConsecutiveFailures);
        if (state.TotalExecutions >= _options.CircuitBreakerPolicy.MinimumThroughput
            && failures >= _options.CircuitBreakerPolicy.FailureThreshold
            && state.CircuitState != CircuitBreakerState.Open)
        {
            state.CircuitState = CircuitBreakerState.Open;
            state.CircuitOpenedAt = DateTime.UtcNow;
        }
    }

    private async Task DelayAsync(int attempt, CancellationToken ct)
    {
        TimeSpan delay = _options.RetryPolicy.UseExponentialBackoff
            ? TimeSpan.FromMilliseconds(
                Math.Min(
                    _options.RetryPolicy.BaseDelay.TotalMilliseconds
                        * Math.Pow(_options.RetryPolicy.BackoffMultiplier, attempt - 1),
                    _options.RetryPolicy.MaxDelay.TotalMilliseconds))
            : _options.RetryPolicy.BaseDelay;

        if (_options.EnableJitter)
        {
            double jitter = Random.Shared.NextDouble() * delay.TotalMilliseconds * 0.2;
            delay = TimeSpan.FromMilliseconds(delay.TotalMilliseconds + jitter);
        }

        await Task.Delay(delay, ct).ConfigureAwait(false);
    }

    // ── Per-operation mutable state (not thread-safe for reads, only for atomic increments) ─
    private sealed class OperationState
    {
        public long TotalExecutions;
        public long SuccessfulExecutions;
        public long FailedExecutions;
        public long ConsecutiveFailures;
        public volatile CircuitBreakerState CircuitState = CircuitBreakerState.Closed;
        public DateTime CircuitOpenedAt;
        public DateTime? LastExecutionTime;
        public Exception? LastException;

        private long _totalElapsedMs;
        private readonly object _timeLock = new();

        public void UpdateAverageTime(TimeSpan elapsed)
        {
            Interlocked.Add(ref _totalElapsedMs, (long)elapsed.TotalMilliseconds);
        }

        public void Reset()
        {
            Interlocked.Exchange(ref TotalExecutions, 0);
            Interlocked.Exchange(ref SuccessfulExecutions, 0);
            Interlocked.Exchange(ref FailedExecutions, 0);
            Interlocked.Exchange(ref ConsecutiveFailures, 0);
            Interlocked.Exchange(ref _totalElapsedMs, 0);
            CircuitState = CircuitBreakerState.Closed;
            LastExecutionTime = null;
            LastException = null;
        }

        public ResilienceStats ToStats(ResilienceOperationType operationType)
        {
            long total = Interlocked.Read(ref TotalExecutions);
            return new ResilienceStats
            {
                OperationType = operationType,
                TotalExecutions = total,
                SuccessfulExecutions = Interlocked.Read(ref SuccessfulExecutions),
                FailedExecutions = Interlocked.Read(ref FailedExecutions),
                CircuitBreakerState = CircuitState,
                AverageExecutionTime = total > 0
                    ? TimeSpan.FromMilliseconds(Interlocked.Read(ref _totalElapsedMs) / (double)total)
                    : TimeSpan.Zero,
                LastExecutionTime = LastExecutionTime,
                LastException = LastException
            };
        }
    }
}
```

- [ ] **Step 3: Delete `ResilienceManagerStub.cs`**

```
Remove-Item LibEmiddle\Infrastructure\ResilienceManagerStub.cs
```

- [ ] **Step 4: Update `StubInfrastructureTests.cs` to reference `ResilienceManager`**

Open `LibEmiddle.Tests.Unit/StubInfrastructureTests.cs`. Any test that instantiates `ResilienceManagerStub` must be updated to use `ResilienceManager`. If those tests tested stub-specific behavior (e.g., "executes directly with no retry"), update expectations to match real behavior (which also executes directly on success).

Search: `grep -n "ResilienceManagerStub" LibEmiddle.Tests.Unit/StubInfrastructureTests.cs`

Replace each `new ResilienceManagerStub(options)` with `new ResilienceManager(options)`. The interface is identical so no other changes are needed.

- [ ] **Step 5: Build**

```
dotnet build LibEmiddle.sln --configuration Release
```
Expected: 0 errors.

- [ ] **Step 6: Run new resilience tests — expect PASS**

```
dotnet test --configuration Release --filter "ClassName=ResilienceManagerTests" --verbosity detailed
```
Expected: all 5 tests PASS.

- [ ] **Step 7: Run full suite**

```
dotnet test --configuration Release
```
Expected: all tests pass.

- [ ] **Step 8: Commit**

```
git add LibEmiddle/Infrastructure/ResilienceManager.cs LibEmiddle.Tests.Unit/ResilienceManagerTests.cs LibEmiddle.Tests.Unit/StubInfrastructureTests.cs
git commit -m "feat: replace ResilienceManagerStub with real retry/circuit-breaker/timeout implementation"
```

---

## Task 5 — Update `TODO.md` to reflect v3.0 deferrals and completed work

**Files:**
- Modify: `TODO.md`

- [ ] **Step 1: Rewrite `TODO.md`**

Replace the entire `TODO.md` with the following to reflect what's done, what's deferred, and what remains:

```markdown
## AST Branch Map & Production Readiness

### Branch classification

Every code path in this library falls into one of four AST branch classes.

**Class A — Production-ready core** (trust and extend)
- `LibEmiddle/Protocol/` — X3DH + Double Ratchet; real crypto, real state machines
- `LibEmiddle/Crypto/` — CryptoProvider, AES, Nonce; P/Invoke wrappers over libsodium
- `LibEmiddle/Core/SecureMemory.cs` — pinned GC memory, sodium_memzero
- `LibEmiddle/Messaging/Chat/ChatSession.cs` — SemaphoreSlim state machine, bounded replay buffer
- `LibEmiddle/KeyManagement/` — KeyManager, OPKManager, KeyStorage; TTL caching and OPK lifecycle
- `LibEmiddle/Sessions/SessionManager.cs` — real session orchestration
- `LibEmiddle.Domain/` — all models, DTOs, enums; no logic

**Class B — Structurally sound, async contracts complete** (ship-ready)
- All Class A code: `CancellationToken` is now threaded through `SessionPersistenceManager`
- `LibEmiddle/Sessions/SessionPersistenceManager.cs` — persistence with CT propagation and base64 path safety
- `LibEmiddle/Protocol/DoubleRatchetProtocol.cs` — throws typed `LibEmiddleException` on failure; no silent (null,null) returns
- `LibEmiddle/Infrastructure/ResilienceManager.cs` — real retry/circuit-breaker/timeout; no longer a stub

**Class C — Deferred to v3.0** (do not ship, must replace before v3.0)

| File | Deferred because |
|------|-----------------|
| `Infrastructure/AdvancedKeyRotationManagerStub.cs` | Requires protocol-layer integration; v3.0 roadmap |
| `Infrastructure/ConnectionPoolStub.cs` | Requires transport layer design decisions; v3.0 roadmap |
| `Infrastructure/SessionBackupManagerStub.cs` | Requires backup file format design + encryption; v3.0 roadmap |
| `Infrastructure/WebRTCTransportStub.cs` | Requires WebRTC library bindings; v3.0 roadmap |
| `Crypto/PostQuantum/PostQuantumCryptoStub.cs` | Requires liboqs bindings; v3.0 roadmap |

**Class D — Dead API surface** (accepted by builder, silently ignored at runtime)
- `ResilienceOptions` in `LibEmiddleClientOptions` — now wired to real `ResilienceManager`
- `PostQuantumOptions` — stored and validated; stub instantiated; no actual PQ crypto path
- `BatchingOptions.IsValid()` — checked at construction, not enforced at encryption time

### Known structural defects remaining

1. **Class C stubs** — must be replaced with real implementations before v3.0; the builder wires them in silently with no runtime warning
2. **Class D BatchingOptions** — validated but not enforced at encrypt time
3. **`CancellationToken` not yet threaded into `ICryptoProvider`, `IMailboxTransport`** — these interfaces predate CT and will require a breaking change for full CT support
```

- [ ] **Step 2: Commit**

```
git add TODO.md
git commit -m "docs: update TODO.md — mark Class B complete, document v3.0 deferrals"
```

---

## Self-Review

**Spec coverage check:**

| Requirement from TODO.md | Task |
|--------------------------|------|
| CancellationToken on every async method in SessionPersistenceManager | Task 1 ✓ |
| `_ioLock.WaitAsync()` has no CT — blocks indefinitely | Task 1 ✓ (`WaitAsync(ct)`) |
| Path traversal in `GetSessionFilePath` | Task 2 ✓ (base64 + `Path.GetFullPath` guard) |
| `DoubleRatchetProtocol` `(null,null)` silent failure | Task 3 ✓ (throws `LibEmiddleException`) |
| Misleading `Async` suffix on sync methods | Task 3 ✓ (renamed to `Encrypt`/`Decrypt`) |
| Class C stubs — Resilience | Task 4 ✓ |
| Class C stubs — SessionBackup, ConnectionPool, WebRTC, PostQuantum | Explicitly deferred to v3.0 per user decision |
| TODO.md updated to reflect changes | Task 5 ✓ |

**Placeholder scan:** No TBD/TODO/similar. All code blocks are complete and self-contained.

**Type consistency:**
- `LibEmiddleException(string, LibEmiddleErrorCode, Exception?)` — used consistently across Tasks 3 and 4 error paths
- `ResilienceManager` constructor takes `ResilienceOptions` — matches `ResilienceManagerStub` constructor, so wiring sites are drop-in
- `SessionPersistenceManager` method signatures: `ct = default` added as last parameter in all 9 methods — all existing callers compile without change
- `IDoubleRatchetProtocol.Encrypt/Decrypt` return non-nullable tuples — all callers updated in Task 3 Step 5
