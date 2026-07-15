# Parwana Layering System

## Overview

The Parwana uses a layered type system to enforce canonical encoding rules and prevent serialization bugs that could lead to hash collisions or protocol divergence. Each layer has specific encoding requirements and serde policies that must be followed.

## Layer Definitions

| Layer | Description | Serde Policy | Encoding | Example Types |
|-------|-------------|--------------|----------|---------------|
| **L0** | Hash types, SanadId, SealPoint, CommitAnchor | Serde only for non-critical integration; never as a hash preimage | canonical_cbor only for protocol paths | `Hash`, `ReplayIdHash`, `SealHash`, `SanadIdHash` |
| **L1** | Proof types, InclusionProof, FinalityProof | **SHOULD NOT use serde** | canonical_cbor only | `ProofBundle`, `InclusionProof`, `FinalityProof` |
| **L2** | Schema, Content types | MAY use serde | serde or canonical_cbor | `ContentTree`, `Schema`, `AttachmentRef` |
| **L3** | Storage types (replay, state, lease, genesis) | MAY use serde | serde preferred | `ReplayCheckpoint`, `TransferPhaseEntry` |
| **L4** | Runtime/Coordinator types (failure domains, capabilities, config) | MAY use serde | serde preferred | `ChainConfig`, `AdapterRegistry`, `CircuitBreaker` |

## Encoding Rules by Layer

### L0: Hash Types (Critical Security)

**Purpose:** Fundamental cryptographic building blocks used in hashing paths.

**Rules:**

- **MUST NOT** use serde-derived bytes in protocol-critical hashing paths
- The optional `csv-hash/serde` feature exists for non-critical persistence and transport integration
- **MUST** use `to_canonical_bytes()` / `from_canonical_bytes()` for protocol-critical hashing
- Hash types wrap the core `Hash` type with domain separation
- Direct serde usage is forbidden to prevent non-canonical encoding in hash computations

**Migration Pattern:**

```rust
// ❌ WRONG - using serde for hash
let hash_bytes = serde_json::to_string(&replay_id_hash)?;

// ✅ CORRECT - using canonical encoding
let hash_bytes = replay_id_hash.0.to_canonical_bytes()?;
```

**Location:** `csv-hash/src/hash_registry.rs`

**Examples:**

- `Hash` - Core 32-byte hash
- `ReplayIdHash` - Replay protection identifier
- `SealHash` - Seal commitment hash
- `SanadIdHash` - Sanad identifier hash
- `CommitmentHash` - Commitment identifier
- `NullifierHash` - Nullifier for double-spend protection
- `VerificationHash` - Proof verification hash
- `MerkleHash` - Merkle tree hash

### L1: Proof Types (High Importance)

**Purpose:** Cryptographic proofs that must verify consistently across all chains.

**Rules:**

- **SHOULD NOT** use serde derives directly
- **MUST** use canonical_cbor for verification to ensure deterministic encoding
- Serde derives may be present for canonical_cbor compatibility, but non-canonical formats (serde_json) are forbidden
- Manual serialization via `to_canonical_bytes()` / `from_canonical_bytes()` is preferred

**Migration Pattern:**

```rust
// ❌ WRONG - using serde_json for proof
let proof_json = serde_json::to_string(&proof_bundle)?;

// ✅ CORRECT - using canonical encoding
let proof_bytes = proof_bundle.to_canonical_bytes()?;

// ✅ CORRECT - using canonical_cbor (if serde derives exist)
let proof_bytes = csv_codec::to_canonical_cbor(&proof_bundle)?;
```

**Location:** `csv-protocol/src/proof_taxonomy.rs`, `csv-proof/src/`

**Examples:**

- `ProofBundle` - Complete proof bundle for peer-to-peer verification
- `InclusionProof` - Merkle inclusion proof
- `FinalityProof` - Chain finality proof
- `DAGSegment` - State transition DAG segment

### L2: Schema and Content Types

**Purpose:** User-facing content, schemas, and application data.

**Rules:**

- **MAY** use serde (serialization is the primary use case)
- canonical_cbor is optional but recommended for cross-chain compatibility
- No strict encoding requirements for protocol correctness

**Examples:**

- `ContentTree` - Merkleized content tree
- `Schema` - Content schema definitions
- `AttachmentRef` - External attachment references
- `Claim` - Content claims and rights

**Location:** `csv-content/src/`

### L3: Storage Types

**Purpose:** Persistence layer for runtime state (replay DB, execution journal, leases).

**Rules:**

- **MAY** use serde (persistence layer)
- Serde is preferred for database serialization
- Encoding consistency is managed by storage backends

**Examples:**

- `ReplayCheckpoint` - Crash recovery checkpoint
- `TransferPhaseEntry` - Execution journal entry
- `LeaseEntry` - Distributed coordinator lease

**Location:** `csv-runtime/src/`, `csv-storage/src/`

### L4: Runtime/Coordinator Types

**Purpose:** Operational types for failure domains, capabilities, and configuration.

**Rules:**

- **MAY** use serde (operational serialization)
- Serde is preferred for config and monitoring
- No protocol-critical encoding requirements

**Examples:**

- `ChainConfig` - Chain configuration
- `AdapterRegistry` - Chain adapter registry
- `CircuitBreaker` - Circuit breaker state
- `ExecutionCell` - Per-chain execution cell

**Location:** `csv-runtime/src/`, `csv-coordinator/src/`

## How to Identify Which Layer a Type Belongs To

### 1. Check the Crate Location

| Crate | Layer | Notes |
|-------|-------|-------|
| `csv-hash` | L0 | All hash types |
| `csv-proof` | L1 | All proof types |
| `csv-protocol` (proof_taxonomy) | L1 | Proof taxonomy |
| `csv-protocol` (sanad, seal) | L0/L1 | Hash wrappers (L0), proof types (L1) |
| `csv-content` | L2 | Content and schema types |
| `csv-runtime` (recovery, journal) | L3 | Storage types |
| `csv-runtime` (coordinator, admission) | L4 | Runtime types |
| `csv-coordinator` | L4 | Coordinator types |
| `csv-storage` | L3 | Storage backends |

### 2. Check Module-Level Documentation

Each crate should have module-level documentation indicating its layer:

```rust
//! CSV Hash - L0: Hash types and domain separation
//!
//! **Layer:** L0 (Hash types)
//! **Encoding:** MUST use canonical_cbor for protocol-critical paths
//! **Serde Policy:** Never use serde output as protocol hash preimage material
```

### 3. Check Struct-Level Comments

Critical types should have layer annotations:

```rust
/// Typed hash wrapper for replay ID hashes.
///
/// **Layer:** L0
/// **Encoding:** Use `to_canonical_bytes()` / `from_canonical_bytes()`
/// **Serde:** Non-critical integration only; forbidden as hash preimage material
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ReplayIdHash(pub Hash);
```

### 4. Check Architecture-Test Enforcement

The `csv-architecture` tests contain the forbidden edges and source-pattern
checks that enforce layer policies. `deny.toml` is reserved for cargo-deny
supply-chain checks.

## Common Pitfalls and Anti-Patterns

### ❌ Using serde_json for L0/L1 Types

```rust
// WRONG - non-canonical encoding in hash path
let hash = csv_hash::Hash::new([0u8; 32]);
let json = serde_json::to_string(&hash)?; // FORBIDDEN for L0
```

### ❌ Using serde for Hash Computations

```rust
// WRONG - serde in hash computation path
let replay_id_hash = compute_replay_id(&transfer);
let hash_input = serde_json::to_vec(&replay_id_hash)?; // FORBIDDEN
let commitment = sha256(&hash_input);
```

### ✅ Correct Pattern for L0 Types

```rust
// CORRECT - use canonical encoding
let replay_id_hash = compute_replay_id(&transfer);
let hash_input = replay_id_hash.0.to_canonical_bytes()?;
let commitment = sha256(&hash_input);
```

### ❌ Mixing Encoding Formats

```rust
// WRONG - inconsistent encoding
let proof = ProofBundle { ... };
let bytes = serde_cbor::to_vec(&proof)?; // Non-canonical
let hash = sha256(&bytes);
```

### ✅ Correct Pattern for L1 Types

```rust
// CORRECT - use canonical encoding
let proof = ProofBundle { ... };
let bytes = proof.to_canonical_bytes()?;
let hash = sha256(&bytes);
```

## Migration Guide

### Adding a New Type

1. **Determine the layer** based on the type's purpose:
   - Is it a hash or cryptographic identifier? → L0
   - Is it a proof or verification type? → L1
   - Is it user-facing content or schema? → L2
   - Is it persistence state? → L3
   - Is it runtime configuration or coordination? → L4

2. **Add appropriate documentation:**

   ```rust
   /// My new type description.
   ///
   /// **Layer:** L0
   /// **Encoding:** canonical_cbor
   /// **Serde:** Never use serde output as hash preimage material
   ```

3. **Choose the right encoding:**
   - L0: Use `to_canonical_bytes()` / `from_canonical_bytes()`
   - L1: Use `to_canonical_bytes()` / `from_canonical_bytes()` or `csv_codec::to_canonical_cbor()`
   - L2+: Use serde if appropriate

4. **Add serde derives only if allowed:**
   - L0: Only for non-critical integration; never in hashing paths
   - L1: Only if required by canonical_cbor
   - L2+: MAY

### Converting Existing Types

1. **Identify the current layer** by checking the crate and usage patterns
2. **Update documentation** with layer classification
3. **Replace serde usage** with canonical encoding if moving to L0/L1
4. **Update `csv-architecture` tests** if adding new forbidden edges
5. **Run tests** to ensure encoding compatibility

## Enforcement Mechanisms

### Dependency supply chain: deny.toml

`deny.toml` provides cargo-deny's graph selection. Cargo-deny does not model
arbitrary crate-to-crate forbidden edges; those are enforced by the
`csv-architecture` tests. Advisory policy remains the separate `cargo audit`
release/security gate documented in the operational guide.

### Run-Time: Architecture Tests

The `csv-architecture` crate contains conformance tests that verify:

- No forbidden dependencies
- Correct layer classification
- Encoding compliance

### CI/CD: Build Checks

The architecture CI pipeline runs:

- Architecture compliance tests - verifies layer rules
- Release metadata tests - verify the MSRV, workspace release version, and versioned internal paths
- Package-content checks - run `cargo package --list` for every publishable crate

## Reference Documents

- `development/PLAN.md` - Phase 7: Serde Audit and Canonical Serialization
- `csv-docs/rfcs/RFC-0001-canonical-serialization.md` - Canonical serialization specification
- `csv-docs/PROTOCOL_INVARIANTS.md` - Protocol invariants and rules
- `csv-docs/PROTOCOL_CONSTITUTION.md` - Protocol constitution
- `development/AUDIT.md` - Security audit findings

## Quick Reference

| Task | L0 | L1 | L2 | L3 | L4 |
|------|----|----|----|----|----|
| Use serde derives | ⚠️ Non-critical integration only | ⚠️ Only for canonical_cbor | ✅ OK | ✅ OK | ✅ OK |
| Use serde_json | ❌ NEVER | ❌ NEVER | ✅ OK | ✅ OK | ✅ OK |
| Use canonical_cbor | ✅ REQUIRED | ✅ REQUIRED | ✅ OK | ✅ OK | ✅ OK |
| Use to_canonical_bytes() | ✅ REQUIRED | ✅ REQUIRED | ✅ OK | ⚠️ Optional | ⚠️ Optional |
| Location | csv-hash | csv-proof, csv-protocol | csv-content | csv-runtime, csv-storage | csv-runtime, csv-coordinator |
