# RFC-0004: Proof Bundle Schema Versioning

**Status:** Proposed
**Author:** Parwana Core Team
**Date:** 2026-05-21
**Version:** 1.0.0

## Abstract

This RFC establishes a formal schema versioning system for `ProofBundle` and all protocol data structures. It defines version compatibility rules, migration paths, and a deprecation schedule.

## Motivation

The current `ProofBundle` has a `version: u32` field but lacks:

1. **Structured versioning** — Single u32 doesn't convey major/minor/patch semantics
2. **Compatibility matrix** — No clear rules for which versions can interoperate
3. **Migration path** — No mechanism for transitioning between versions
4. **Deprecation schedule** — No timeline for phasing out old versions

## Design

### 1. Structured ProtocolVersion

```rust
pub struct ProtocolVersion {
    pub major: u32,  // Breaking changes
    pub minor: u32,  // Additive changes
    pub patch: u32,  // Non-breaking fixes
    pub hash: Hash,  // Version identity
}

impl ProtocolVersion {
    pub fn is_compatible_with(&self, other: &ProtocolVersion) -> bool {
        // Same major version = compatible
        self.major == other.major
    }
    
    pub fn supports(&self, required: &ProtocolVersion) -> bool {
        self.major == required.major && 
        (self.minor > required.minor || 
         (self.minor == required.minor && self.patch >= required.patch))
    }
}
```

### 2. ProofBundle Versioning

```rust
pub struct ProofBundle {
    pub version: ProtocolVersion,
    pub signature_scheme: SignatureScheme,
    // ... other fields
}

impl ProofBundle {
    pub fn validate_version(&self, supported: &ProtocolVersion) -> Result<(), ProtocolError> {
        if !supported.supports(&self.version) {
            return Err(ProtocolError::VersionMismatch {
                expected: supported.clone(),
                got: self.version.clone(),
            });
        }
        Ok(())
    }
}
```

### 3. Version Compatibility Matrix

| Bundle Version | Supported By | Status |
|---------------|--------------|--------|
| v1.0.0 | v1.x.x | Active |
| v2.0.0 | v2.x.x | Active |
| v1.x.x | v1.x.x | Deprecated (grace period) |

### 4. Deprecation Schedule

1. **Active** — Fully supported, new deployments recommended
2. **Maintenance** — Bug fixes only, no new features
3. **Deprecated** — 30-day grace period, migration required
4. **Removed** — No longer accepted, rejected with `VersionMismatch`

## Implementation

### Changes to `csv-core/src/protocol_version.rs`

- Add `ProtocolVersion` struct with major/minor/patch
- Add `is_compatible_with()` and `supports()` methods
- Add version hash computation

### Changes to `csv-core/src/proof.rs`

- Update `ProofBundle.version` to use `ProtocolVersion`
- Add `validate_version()` method
- Add version compatibility checks in verifier
- Require proof bundles to serialize the signature scheme used for authorizing signatures and reject mismatches against the source chain adapter

### New Module: `csv-core/src/version_registry.rs`

- Maintain registry of supported versions
- Track deprecation status
- Provide version compatibility queries

## Security Impact

- **Prevents version confusion attacks** — Clear compatibility rules prevent accepting incompatible proofs
- **Enables safe upgrades** — Deprecation schedule allows gradual migration
- **Version-bound proofs** — Each proof is cryptographically bound to its version

## References

- Protocol Constitution Section 7 — Versioning and Upgrades
- `csv-core/src/proof.rs` — Current ProofBundle
- `csv-core/src/protocol_version.rs` — Current version handling
