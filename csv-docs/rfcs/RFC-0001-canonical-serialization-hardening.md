# RFC-0001: Canonical Serialization Hardening

**Status:** Proposed
**Author:** CSV Protocol Core Team
**Date:** 2026-05-21
**Version:** 1.0.0

## Abstract

This RFC hardens the canonical CBOR serialization used throughout the CSV protocol. It defines strict rules for deterministic serialization, introduces CBOR tag enforcement, and establishes a golden corpus validation pipeline.

## Motivation

The current `canonical.rs` implementation provides basic deterministic CBOR serialization but lacks:

1. **CBOR tag enforcement** — No mechanism to tag serialized structures with semantic type identifiers
2. **Integrity checksums** — No built-in verification that serialized data hasn't been corrupted
3. **Version-aware deserialization** — No schema versioning for forward/backward compatibility
4. **Golden corpus validation** — No automated pipeline to ensure serialization consistency across implementations

Without these hardening measures, different implementations could produce non-identical byte sequences for the same logical data, breaking cross-implementation verification.

## Design

### 1. CBOR Tag Enforcement

All protocol structures MUST be serialized with a CBOR tag from the reserved range 0x1C0–0x1FF:

| Tag | Type |
|-----|------|
| 0x1C0 (448) | `ProofBundle` |
| 0x1C1 (449) | `SanadEnvelope` |
| 0x1C2 (450) | `Commitment` |
| 0x1C3 (451) | `Seal` |
| 0x1C4 (452) | `Consignment` |

### 2. Integrity Checksum

Each serialized structure includes a 4-byte CRC32 checksum appended after the CBOR bytes:

```
serialized = canonical_cbor(structure) || crc32(serialized)
```

The checksum enables fast corruption detection before expensive cryptographic verification.

### 3. Schema Versioning

Each structure includes a `version` field that is validated during deserialization:

```rust
pub fn from_canonical_cbor_with_version<T: DeserializeOwned>(
    bytes: &[u8],
    expected_version: u32,
) -> Result<T, ProtocolError>
```

Structures with unsupported versions are rejected with a `VersionMismatch` error.

### 4. Golden Corpus Pipeline

A golden corpus of canonical CBOR fixtures is maintained at `csv-core/tests/golden/`. Each fixture is:

1. Generated from a known-good runtime build
2. Hashed with SHA-256
3. Stored alongside its expected hash
4. Validated in CI on every commit

## Implementation

### Changes to `csv-core/src/canonical.rs`

```rust
// New function with tag enforcement
pub fn to_canonical_cbor_with_tag<T: Serialize>(
    value: &T,
    tag: u64,
) -> Result<Vec<u8>, ProtocolError>

// New function with version validation
pub fn from_canonical_cbor_with_version<T: DeserializeOwned>(
    bytes: &[u8],
    expected_version: u32,
) -> Result<T, ProtocolError>

// New function with integrity checksum
pub fn to_canonical_cbor_with_checksum<T: Serialize>(
    value: &T,
) -> Result<Vec<u8>, ProtocolError>

// New function with full validation
pub fn from_canonical_cbor_full<T: DeserializeOwned>(
    bytes: &[u8],
    expected_tag: Option<u64>,
    expected_version: Option<u32>,
) -> Result<T, ProtocolError>
```

### Golden Corpus Format

Each golden fixture file is accompanied by a `.sha256` file:

```
valid_proof_bundle_v1.cbor
valid_proof_bundle_v1.cbor.sha256  (contains the SHA-256 hash)
```

## Security Impact

- **Prevents serialization ambiguity** — Deterministic output ensures cross-implementation compatibility
- **Detects data corruption** — CRC32 checksum catches accidental bit flips
- **Prevents version confusion** — Schema versioning prevents accepting data from incompatible protocol versions
- **Enables CI validation** — Golden corpus ensures no accidental serialization changes slip through

## References

- RFC 8949 Section 4.2 — Canonical CBOR Encoding
- Protocol Constitution Section 2 — Serialization
- `csv-core/src/canonical.rs` — Current implementation
