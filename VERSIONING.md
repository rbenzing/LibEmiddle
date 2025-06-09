# LibEmiddle Versioning Strategy

## Overview

LibEmiddle follows [Semantic Versioning (SemVer)](https://semver.org/) with a structured branching strategy to maintain multiple versions and ensure backward compatibility.

## Version Format

**MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]**

- **MAJOR**: Breaking changes to the public API or protocol
- **MINOR**: New features that are backward compatible
- **PATCH**: Bug fixes that are backward compatible
- **PRERELEASE**: Optional pre-release identifiers (alpha, beta, rc)
- **BUILD**: Optional build metadata

## Branching Strategy

### Main Branches

1. **`main`** - Current stable release (v2.x.x)
   - Contains the latest stable version
   - All releases are tagged from this branch
   - Protected branch requiring PR reviews

2. **`legacy-1.0`** - Legacy version 1.x maintenance
   - Contains version 1.x.x codebase
   - Only receives critical security fixes and bug fixes
   - No new features

3. **`develop`** - Development branch (future v3.x.x)
   - Integration branch for new features
   - Base branch for feature branches
   - Merged to main when ready for release

### Supporting Branches

- **`feature/*`** - New features
- **`bugfix/*`** - Bug fixes
- **`hotfix/*`** - Critical fixes for production
- **`release/*`** - Release preparation

## Version Management

### Current Versions

- **Main Branch**: v2.0.0+ (Current stable)
- **Legacy Branch**: v1.x.x (Maintenance only)

### Protocol Versioning

The protocol version is managed separately in `LibEmiddle.Domain/Constants/ProtocolVersion.cs`:

```csharp
public static class ProtocolVersion
{
    public const int MAJOR_VERSION = 2;
    public const int MINOR_VERSION = 0;
    public const string? LEGACY_VERSION = "1.0";
}
```

### Package Versioning

Version numbers are centrally managed in:
- `Directory.Build.props` - Global version prefix
- Individual `.csproj` files - Project-specific versions

## Release Process

### Major Releases (Breaking Changes)

1. Create `release/vX.0.0` branch from `develop`
2. Update version numbers in all relevant files
3. Update protocol version if needed
4. Run full test suite
5. Create PR to `main`
6. Tag release after merge
7. Create new legacy branch for previous major version

### Minor Releases (New Features)

1. Create `release/vX.Y.0` branch from `develop`
2. Update version numbers
3. Run full test suite
4. Create PR to `main`
5. Tag release after merge

### Patch Releases (Bug Fixes)

1. Create `hotfix/vX.Y.Z` branch from `main`
2. Fix the issue
3. Update version numbers
4. Create PR to `main`
5. Tag release after merge
6. Cherry-pick to `develop` if needed

### Legacy Maintenance

1. Create `hotfix/legacy-1.0-vX.Y.Z` branch from `legacy-1.0`
2. Apply critical fixes only
3. Update version numbers
4. Create PR to `legacy-1.0`
5. Tag release after merge

## CI/CD Integration

### Automated Versioning

- Version numbers are automatically incremented based on branch patterns
- Pre-release versions for feature branches
- Stable versions for main branch releases

### Build Triggers

- **Main**: Full build, test, and package
- **Legacy-1.0**: Security and critical fixes only
- **Develop**: Continuous integration builds
- **Feature branches**: PR validation builds

## Migration Guidelines

### From v1.x to v2.x

- Review breaking changes in CHANGELOG.md
- Update protocol handling for new version
- Test compatibility with existing data
- Follow migration guide in documentation

### Backward Compatibility

- v2.x can read v1.x protocol messages (with limitations)
- v1.x cannot read v2.x protocol messages
- Data migration tools provided for major version upgrades

## Version Support Policy

| Version | Status | Support Level | End of Life |
|---------|--------|---------------|-------------|
| 2.x.x   | Current | Full support | TBD |
| 1.x.x   | Legacy  | Security fixes only | 2025-12-31 |

## Tools and Commands

### Check Current Version
```bash
git describe --tags --abbrev=0
```

### Create Release Tag
```bash
git tag -a v2.0.0 -m "Release version 2.0.0"
git push origin v2.0.0
```

### Switch to Legacy Branch
```bash
git checkout legacy-1.0
```

## References

- [Semantic Versioning](https://semver.org/)
- [Git Flow](https://nvie.com/posts/a-successful-git-branching-model/)
- [GitHub Flow](https://guides.github.com/introduction/flow/)
