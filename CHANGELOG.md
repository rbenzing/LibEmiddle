# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2025-06-08

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

## [1.0.0] - 2024-05-10 (Legacy)

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
| 2.x.x   | Current | Full support | TBD |
| 1.x.x   | Legacy  | Security fixes only | 2025-12-31 |

## Links

- [Repository](https://github.com/rbenzing/LibEmiddle)
- [Issues](https://github.com/rbenzing/LibEmiddle/issues)
- [Releases](https://github.com/rbenzing/LibEmiddle/releases)
- [Documentation](README.md)
