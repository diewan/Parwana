# RFC-0002: HashDomain Enum and Typed Hash Wrappers

**Status:** Proposed
**Author:** CSV Protocol Core Team
**Date:** 2026-05-21
**Version:** 1.0.0

## Abstract

This RFC introduces an exhaustive `HashDomain` enum that provides compile-time guarantees for domain-separated hashing. It replaces the current string-based domain tags with a type-safe enum, preventing cross-domain hash collisions at compile time.

## Motivation

The current `domain_hash.rs` implementation uses string-based domain tags:

```rust
pub trait Domain {
    const DOMAIN: &'static [u8];
}
```

This approach has several weaknesses:

1. **String-based domains are error-prone** — Typos in domain strings are not caught at compile time
2. **No exhaustiveness checking** — New domains can be added without review
3. **No domain hierarchy** — Related domains (e.g., `csv.bitcoin.seal.v1`, `csv.bitcoin.commitment.v1`) have no structural relationship
4. **No domain capability encoding** — Domains don't encode what operations they authorize

## Design

### 1. HashDomain Enum

```rust
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum HashDomain {
    // Seal domains
    BitcoinSealV1,
    EthereumSealV1,
    SolanaSealV1,
    SuiSealV1,
    AptosSealV1,
    CelestiaSealV1,
    StarkSealV1,
    
    // Commitment domains
    TransferCommitmentV1,
    CommitmentVersion,
    CommitmentProtocolId,
    CommitmentMpcRoot,
    CommitmentContractId,
    CommitmentPrevious,
    CommitmentPayload,
    CommitmentSeal,
    CommitmentDomain,
    
    // Identity domains
    SanadId,
    Nullifier,
    ReplayIdV1,
    
    // Verification domains
    VerificationProofV1,
    VerificationResult,
    
    // Stealth domains
    StealthAddressV1,
    StealthNonceV1,
    EphemeralPointV1,
    
    // Protocol domains
    ProtocolVersion,
    MerkleCombine,
    
    // MPC domains
    MpcProof,
}
```

### 2. Domain Implementation

```rust
impl HashDomain {
    pub fn as_bytes(&self) -> &'static [u8] {
        match self {
            HashDomain::BitcoinSealV1 => b"csv.bitcoin.seal.v1",
            HashDomain::EthereumSealV1 => b"csv.ethereum.seal.v1",
            // ... etc
        }
    }
    
    pub fn category(&self) -> DomainCategory {
        match self {
            Self::BitcoinSealV1 | Self::EthereumSealV1 | Self::SolanaSealV1 |
            Self::SuiSealV1 | Self::AptosSealV1 | Self::CelestiaSealV1 | Self::StarkSealV1 => {
                DomainCategory::Seal
            }
            // ... etc
        }
    }
}
```

### 3. Typed Hash Wrappers

```rust
// Each typed hash wraps [u8; 32] with a domain marker
pub struct SealHash(Hash);
pub struct CommitmentHash(Hash);
pub struct SanadIdHash(Hash);
pub struct NullifierHash(Hash);
pub struct ReplayIdHash(Hash);
pub struct VerificationHash(Hash);
pub struct MerkleHash(Hash);

impl SealHash {
    pub fn new(data: &[u8]) -> Self {
        Self(Hash::from(csv_tagged_hash(HashDomain::BitcoinSealV1.as_bytes(), data)))
    }
}
```

### 4. Domain Category

```rust
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DomainCategory {
    Seal,
    Commitment,
    Identity,
    Verification,
    Stealth,
    Protocol,
    Mpc,
}
```

## Implementation

### Changes to `csv-core/src/hash.rs`

- Add `HashDomain` enum with all reserved domains
- Add `DomainCategory` enum
- Add typed hash wrapper types
- Add `Hash::domain_hash(domain, data)` method

### Changes to `csv-core/src/domain_hash.rs`

- Deprecate `Domain` trait in favor of `HashDomain` enum
- Add `DomainSeparatedHash<HashDomain>` implementation
- Keep `DomainSeparatedHash<D>` for backward compatibility with custom domains

### Migration Path

1. New code uses `HashDomain` enum and typed hash wrappers
2. Existing code continues to work with `Domain` trait
3. Gradual migration over 2-3 releases
4. `Domain` trait deprecated in release N+2, removed in N+3

## Security Impact

- **Compile-time domain safety** — Typos in domain strings are caught at compile time
- **Exhaustiveness checking** — Rust's match exhaustiveness ensures all domains are handled
- **Type-safe hash separation** — Typed hash wrappers prevent accidental mixing of hash types
- **Domain capability encoding** — Each domain encodes what operations it authorizes

## References

- RFC 8949 — CBOR Standard
- BIP-340 — Tagged Hashing
- Protocol Constitution Section 3 — Hashing
- Protocol Invariants Invariant 7 — Domain Separation
