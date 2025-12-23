# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Nothing yet

### Changed
- Nothing yet

### Deprecated
- Nothing yet

### Removed
- Nothing yet

### Fixed
- Nothing yet

### Security
- Nothing yet

## [2.5.1] - 2025-12-22

### Added
- **Comprehensive Mailbox Transport Documentation**: New complete guide explaining the mailbox transport system architecture, usage patterns, and integration (Documentation/Mailbox-Transport-Guide.md)
- **Detailed Message Flow Diagrams**: Mermaid sequence diagrams showing complete message sending and receiving flows through all layers (Documentation/Message-Flow-Sequence.md)
- **Enhanced XML Documentation**: Improved code documentation for transport implementations with implementation guidance and usage examples

### Changed
- **Refactored Transport Polling Logic**: Extracted duplicate polling code from HttpMailboxTransport and InMemoryMailboxTransport into BaseMailboxTransport helper method, reducing code duplication by ~120 lines
- **Clarified WebRTC Status**: Updated README and CHANGELOG to clearly indicate WebRTC is under development (stub only) and planned for v3.0, not production-ready in v2.5
- **Improved README**: Added dedicated "Mailbox Transport System" section with practical code examples and architecture overview

### Documentation
- Added complete mailbox transport system guide with architecture overview, usage examples, best practices, and troubleshooting
- Added Mermaid sequence diagrams for complete message flow visualization
- Enhanced transport implementation XML documentation with guidance for custom transport development
- Clarified WebRTC transport status across all documentation
- Added "Future Roadmap" section to README with planned features

### Fixed
- Eliminated duplicate polling logic between transport implementations (DRY principle)
- Improved code maintainability through shared helper methods

## [2.5.0] - 2025-8-24

### Added
- **Feature Flags System**: Gradual rollout and configuration of new capabilities
- **Message Batching**: Efficient bulk messaging with configurable compression levels
- **Post-Quantum Cryptography Preparation**: Interface definitions and hybrid mode support for quantum-resistant algorithms (Kyber1024, Dilithium)
- **Enterprise Monitoring & Diagnostics**: Built-in health monitoring, metrics collection, and diagnostic capabilities
- **Connection Pooling**: Optimized connection management with configurable pool sizes and load balancing
- **Advanced Key Rotation**: Sophisticated rotation policies with time-based, usage-based, and risk-based triggers
- **Session Backup Management**: Automated backup and recovery capabilities for session data
- **Resilience Manager**: Automatic failover, retry policies, and connection restoration
- **Async Message Streams**: IAsyncEnumerable support for reactive programming patterns
- **Advanced Group Management**: Granular permissions system with fine-grained member control
- **Compression Support**: Multiple compression levels (None, Fast, Balanced, Maximum) for message batching
- **Network Quality Monitoring**: Real-time network quality assessment for WebRTC connections
- **Group Statistics**: Comprehensive analytics and statistics for group sessions
- **Group Invitations**: Enhanced invitation system with expiration and validation
- **Message Priority System**: Priority-based message handling and delivery
- **Enhanced Security Policies**: Expanded security policy options with quantum-readiness preparation

### Changed
- Enhanced `LibEmiddleClientOptions` with new configuration sections for advanced features
- Improved `TransportType` enum to include WebRTC support
- Extended `MemberRole` and `GroupMember` with advanced permission capabilities
- Updated session management to support backup and recovery operations
- Enhanced error handling and logging throughout the system
- Improved performance optimizations for high-throughput scenarios

### Fixed
- Improved memory management in long-running sessions
- Enhanced thread safety in multi-device scenarios
- Better handling of network connectivity issues
- Optimized key rotation timing and coordination
- Improved group synchronization reliability

### Security
- **Hybrid Cryptography Support**: Preparation for classical + post-quantum cryptographic combinations
- **Enhanced Key Rotation**: More sophisticated rotation strategies with configurable policies
- **Improved Forward Secrecy**: Better key isolation and cleanup procedures
- **Quantum-Resistant Preparation**: Infrastructure for future post-quantum algorithm integration
- **Advanced Authentication**: Enhanced device and session authentication mechanisms
- **Security Monitoring**: Real-time security event monitoring and alerting capabilities

### Performance
- **Connection Pooling**: Significant performance improvements for high-throughput scenarios
- **Message Batching**: Reduced network overhead through intelligent message batching and compression
- **Optimized Memory Usage**: Better memory management and reduced allocations
- **Parallel Processing**: Enhanced parallel processing capabilities for concurrent operations
- **Efficient Serialization**: Improved serialization performance for large messages and batches

### Documentation
- Added comprehensive sequence diagrams for all major operations
- Enhanced technical documentation with detailed architecture descriptions
- Added Mermaid diagrams for visual protocol flow representation
- Expanded API documentation with v2.5 feature coverage
- Updated migration guide for v2.0 to v2.5 transition
- **NEW**: Added complete Mailbox Transport System guide (Documentation/Mailbox-Transport-Guide.md)
- **NEW**: Added detailed message flow sequence diagrams (Documentation/Message-Flow-Sequence.md)

## [2.0.0] - 2024-12-19

### Added
- Complete architectural rewrite with improved separation of concerns
- New `LibEmiddleClient` API for simplified end-to-end encryption
- Comprehensive abstractions layer with interfaces for all major components
- New domain models with better encapsulation and validation
- Advanced session management with persistence capabilities
- Multi-device support with device linking and synchronization
- Group messaging with enhanced security features
- Improved key management with rotation strategies
- Protocol adapters for X3DH and Double Ratchet
- Enhanced transport layer with multiple transport options
- Comprehensive test suite with over 90% coverage
- Advanced error recovery mechanisms
- Performance optimizations for large groups and high-throughput scenarios

### Changed
- **BREAKING**: Complete API redesign - not backward compatible with v1.x
- **BREAKING**: Protocol version updated to 2.0
- **BREAKING**: Database schema changes require migration
- Improved cryptographic implementations with better security
- Enhanced logging and debugging capabilities
- Better memory management and secure memory handling
- Modernized codebase with latest C# features and patterns

### Removed
- **BREAKING**: Legacy v1.x API methods and classes
- **BREAKING**: Old session persistence format
- **BREAKING**: Deprecated cryptographic methods

### Fixed
- Multiple security vulnerabilities identified in v1.x
- Memory leaks in long-running sessions
- Race conditions in multi-threaded scenarios
- Key rotation edge cases
- Group membership synchronization issues

### Security
- Enhanced key derivation functions
- Improved forward secrecy guarantees
- Better protection against timing attacks
- Strengthened group key management
- Enhanced device authentication mechanisms

## [1.0.0] - 2024-02-14 (Legacy)

### Added
- Initial release of LibEmiddle
- Basic X3DH key exchange implementation
- Double Ratchet protocol for forward secrecy
- Group messaging capabilities
- Device management features
- WebSocket transport support
- Basic session persistence

### Security
- End-to-end encryption for individual and group messages
- Forward secrecy through Double Ratchet
- Post-compromise security features

---

## Migration Guide

### From v2.0 to v2.5

**✅ BACKWARD COMPATIBLE**: Version 2.5 is backward compatible with v2.0.

New features in v2.5 are **opt-in** through the Feature Flags system:

```csharp
var options = new LibEmiddleClientOptions
{
    // Existing v2.0 configuration works unchanged
    TransportType = TransportType.Http,
    ServerEndpoint = "https://your-server.com",
    
    // New v2.5 features are opt-in
    FeatureFlags = new FeatureFlags
    {
        EnableMessageBatching = true,           // Opt-in to message batching
        EnableDiagnostics = true,              // Opt-in to monitoring
        EnableAdvancedGroupManagement = true,  // Opt-in to enhanced groups
        EnableAsyncMessageStreams = true,      // Opt-in to reactive streams
        EnableWebRTCTransport = true          // Opt-in to WebRTC support
    },
    
    // Configure new optional features
    WebRTCOptions = new WebRTCOptions { /* configuration */ },
    BatchingOptions = new BatchingOptions { /* configuration */ },
    PostQuantumOptions = new PostQuantumOptions { /* configuration */ }
};
```

#### Benefits of Upgrading to v2.5:
- **Performance**: Message batching and connection pooling improvements
- **Monitoring**: Built-in diagnostics and health monitoring
- **Future-Ready**: Post-quantum cryptography preparation
- **Enterprise**: Advanced features for high-scale deployments

#### Note on WebRTC Transport:
WebRTC transport was initially planned for v2.5 but remains under development. The current implementation is a stub for API development only and is **not production-ready**. Full WebRTC support is targeted for v3.0.

### From v1.x to v2.x

**⚠️ BREAKING CHANGES**: Version 2.0 is not backward compatible with v1.x.

#### Key Changes:
1. **API Redesign**: Complete rewrite of public APIs
2. **Protocol Update**: New protocol version with enhanced security
3. **Data Migration**: Existing sessions and keys need migration

#### Migration Steps:
1. **Backup existing data** before upgrading
2. **Review new API documentation** in README.md
3. **Update your code** to use new `LibEmiddleClient` API
4. **Run migration tools** (if available) for existing data
5. **Test thoroughly** in development environment

#### Code Changes Required:
```csharp
// Old v1.x API (deprecated)
var oldClient = new LibEmiddleManager();
await oldClient.InitializeAsync();

// New v2.x API
var options = new LibEmiddleClientOptions
{
    UserId = "user123",
    DeviceId = "device456"
};
var newClient = new LibEmiddleClient(options);
await newClient.InitializeAsync();
```

For detailed migration instructions, see the [Migration Guide](docs/MIGRATION.md).

## Support Policy

| Version | Status | Support Level | End of Life |
|---------|--------|---------------|-------------|
| 2.5.x   | Current | Full support | TBD |
| 2.0.x   | Maintenance | Security fixes and critical bugs | 2025-12-31 |
| 1.x.x   | Legacy  | Security fixes only | 2025-06-30 |

## Links

- [Repository](https://github.com/rbenzing/LibEmiddle)
- [Issues](https://github.com/rbenzing/LibEmiddle/issues)
- [Releases](https://github.com/rbenzing/LibEmiddle/releases)
- [Documentation](README.md)
