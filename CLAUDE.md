# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Development Commands

### Building the Solution
```cmd
# Restore dependencies
dotnet restore

# Build the entire solution
dotnet build

# Build specific configuration
dotnet build --configuration Release
dotnet build --configuration Debug

# Build specific project
dotnet build LibEmiddle/LibEmiddle.csproj
```

### Running Tests
```cmd
# Run all tests
dotnet test

# Run tests with specific configuration
dotnet test --configuration Release

# Run tests with code coverage
dotnet test --collect:"XPlat Code Coverage"

# Run a specific test file
dotnet test LibEmiddle.Tests.Unit/ChatSessionTests.cs

# Run tests with verbosity for debugging
dotnet test --verbosity normal
```

### Creating NuGet Packages
```cmd
# Create package from main project
dotnet pack --configuration Release

# Create package with specific version
dotnet pack --configuration Release -p:Version=2.0.1
```

### Code Analysis and Quality
The project uses:
- **TreatWarningsAsErrors**: All warnings are treated as errors
- **Microsoft.CodeAnalysis.NetAnalyzers**: Static code analysis
- **SecurityCodeScan.VS2019**: Security analysis
- **Nullable reference types**: Enabled for null safety

## High-Level Architecture

### Project Structure
This is a .NET 8.0 C# solution with a layered architecture implementing end-to-end encryption protocols using Sodium Library as a DLL

**Core Projects:**
- **LibEmiddle** - Main library with unified `LibEmiddleClient` API
- **LibEmiddle.Abstractions** - Interfaces and contracts  
- **LibEmiddle.Domain** - Domain models, DTOs, and enums
- **LibEmiddle.Tests.Unit** - MSTest-based unit tests

### Key Architectural Components

#### 1. Unified Client API (`LibEmiddle.API.LibEmiddleClient`)
The main entry point providing:
- Individual chat sessions via `CreateChatSessionAsync()`
- Group messaging via `CreateGroupAsync()` and `JoinGroupAsync()`
- Multi-device support via `DeviceManager`
- Transport abstraction (HTTP, WebSocket, InMemory)

#### 2. Cryptographic Protocols (`LibEmiddle.Protocol`)
- **X3DHProtocol** - Extended Triple Diffie-Hellman for initial key exchange
- **DoubleRatchetProtocol** - Continuous key rotation with forward secrecy
- **CryptoProvider** - libsodium-based crypto operations (AES-GCM, Ed25519, X25519)

#### 3. Session Management (`LibEmiddle.Sessions`)
- **SessionManager** - Lifecycle management for all session types
- **SessionPersistenceManager** - Secure session storage and recovery
- **ChatSession** - Individual encrypted conversations
- **GroupSession** - Encrypted group messaging with member management

#### 4. Multi-Device Architecture (`LibEmiddle.MultiDevice`)
- **DeviceManager** - Device linking and revocation
- **DeviceLinkingService** - Secure device pairing protocol
- **SyncMessageValidator** - Cross-device state synchronization

#### 5. Transport Layer (`LibEmiddle.Messaging.Transport`)
- **MailboxManager** - Message routing and delivery
- **HttpMailboxTransport** - REST API transport
- **SecureWebSocketClient** - Real-time messaging transport
- **InMemoryMailboxTransport** - Testing transport

#### 6. Key Management (`LibEmiddle.KeyManagement`)
- **KeyManager** - Cryptographic key lifecycle
- **KeyStorage** - Secure key persistence
- Automatic key rotation with configurable strategies

### Security Design Principles

#### Protocol Implementation
- **X3DH + Double Ratchet**: Industry-standard Signal Protocol implementation
- **Perfect Forward Secrecy**: Past messages remain secure if keys are compromised
- **Post-Compromise Security**: Future messages are secure after key recovery
- **Deniable Authentication**: Messages cannot be proven authentic to third parties

#### Key Security Features
- **libsodium Integration**: Uses battle-tested cryptographic primitives
- **Secure Memory Handling**: Sensitive data cleared from memory (`SecureMemory` class)
- **Replay Protection**: Message timestamps and unique IDs prevent replay attacks
- **Constant-Time Operations**: Protection against timing attacks

#### Configuration-Based Security
Security policies configured via `LibEmiddleClientOptions.SecurityPolicy`:
- `RequirePerfectForwardSecrecy`
- `RequireMessageAuthentication` 
- `MinimumProtocolVersion`
- `AllowInsecureConnections`

## Development Guidelines

### Cryptographic Constants
All crypto parameters centralized in `LibEmiddle.Domain.Constants`:
- Key sizes (AES-256, X25519, Ed25519)
- Security timeouts and limits
- Protocol version information

### Error Handling Patterns
- Use specific exception types for different error categories
- Always validate input parameters, especially cryptographic material
- Log security events appropriately (without exposing sensitive data)

### Testing Strategy
- MSTest framework with Moq for mocking
- Separate test classes for each major component
- Integration tests cover end-to-end encryption flows
- Performance tests for cryptographic operations
- Unit tests are needed for all implementations
- Unit tests are located in `LibEmiddle.Tests.Unit`

### Version Management
- **v2.x.x**: Current main branch (modern architecture)
- **v1.x.x**: Legacy branch (deprecated)

## Common Development Tasks

### Adding New Message Types
1. Define enum in `LibEmiddle.Domain.Enums.MessageType`
2. Create corresponding DTO in `LibEmiddle.Domain.DTO`
3. Update `MailboxManager` message routing
4. Add serialization/deserialization logic
5. Update transport implementations

### Implementing New Transport
1. Inherit from `BaseMailboxTransport`
2. Implement required abstract methods
3. Add transport type to `TransportType` enum
4. Update `LibEmiddleClient` transport factory
5. Add integration tests

### Adding Cryptographic Operations
1. Extend `ICryptoProvider` interface
2. Implement in `CryptoProvider` using libsodium
3. Add security constants to `Constants` class
4. Update `SecureMemory` for proper cleanup
5. Add comprehensive unit tests

### Multi-Device Features
1. Extend `IDeviceManager` interface
2. Implement in `DeviceManager`
3. Update sync message protocols
4. Add device validation logic
5. Test cross-device scenarios

### Adding new code paths
1. Check for existing code paths to see if it makes more sense to extend existing code paths before creating new ones.
2. Looks for existing related methods before creating new ones to see if they will work for the task requested.