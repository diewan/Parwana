# Self-Expressive Architecture Plan

This plan addresses ambiguous entity naming and organization across the CSV Protocol codebase to ensure every module self-expresses its purpose, location, and architectural role.

## Ambiguous Entities Identified

### csv-protocol (Core Protocol Types)

**Proof-related ambiguity:**

- `proof.rs` - Re-exports from proof_types (redundant layer)
- `proof_types.rs` - Canonical proof taxonomy
- `canonical_proof.rs` - Canonical proof validation
- **Issue:** Three proof-related files with unclear distinction

**Verification ambiguity:**

- `verification.rs` - Verification levels enum (StructuralOnly, MerkleVerified, FullyVerified, ConsensusVerified)
- `verified.rs` - Multi-dimensional verification result types (VerificationAssurance, InclusionStrength, FinalityStrength)
- **Issue:** Similar naming, unclear which to use for what purpose

**Generic naming:**

- `backend.rs` - Chain operation traits (ChainQuery, ChainSigner, ChainBroadcaster, etc.)
- **Issue:** "backend" doesn't indicate it's chain operation traits for adapters

**Unclear domain:**

- `seal.rs` - CommitAnchor, SealPoint types
- `seal_protocol.rs` - Seal protocol operations
- **Issue:** Unclear distinction between seal types and protocol operations
- `sanad.rs` - Sanad types
- `envelope.rs` - Envelope types
- **Issue:** Domain-specific terms without context

### csv-core (Runtime-Specific Modules - Partial Migration)

**IMPORTANT:** csv-core contains future-proof cryptographic modules (zk_proof.rs, quantum proof infrastructure, advanced techniques) that should NOT be migrated. Only migrate stable, production-ready modules.

**Offchain vs Onchain ambiguity:**

- `trust_package.rs` - OFFLINE verification bootstrapping
- **Issue:** Name doesn't indicate "offchain" or "verification bootstrapping"

**Generic naming:**

- `client.rs` - Client-side validation engine
- **Issue:** "client" too generic, doesn't indicate validation
- `validator.rs` - Consignment validation pipeline
- **Issue:** "validator" doesn't indicate what it validates (consignments)
- `adapter.rs` - Chain adapter boundary
- **Issue:** "adapter" doesn't indicate it's chain data fetching boundary
- `store.rs` - Storage abstractions
- `state_store.rs` - State storage
- **Issue:** Unclear distinction between storage types

**Domain-specific jargon:**

- `consignment.rs` - Consignment wire format
- `transition.rs` - State transitions
- **Issue:** "consignment" is domain-specific jargon without context
- `certification.rs` - Proof certification
- **Issue:** Doesn't indicate it's for deterministic verification

**Acronym ambiguity:**

- `mcp.rs` - Agent-friendly types
- **Issue:** "mcp" acronym not self-expressive

**Unclear scope:**

- `performance.rs` - Performance monitoring
- **Issue:** Doesn't indicate what performance it measures
- `proof_provenance.rs` - Proof provenance metadata
- **Issue:** "provenance" doesn't indicate forensic/deterministic verification
- `runtime_health.rs` - Runtime health types
- **Issue:** Doesn't indicate degraded-mode types

**Future-proof modules (KEEP in csv-core):**

- `zk_proof.rs` - ZK proof infrastructure (quantum-resistant, advanced techniques)
- Any future quantum proof modules
- Any experimental cryptographic primitives

### csv-runtime (Orchestration Facade)

**Lease ambiguity:**

- `coordinator_lease.rs` - Distributed coordinator lease (prevents split-brain double-mints)
- `lease.rs` - User-facing and runtime leases
- **Issue:** Two lease systems with unclear distinction

**Event ambiguity:**

- `event_bus.rs` - Event bus for transfer events
- `event_store.rs` - Event persistence
- `event_envelope.rs` - Event envelope types
- **Issue:** Three event files with unclear separation of concerns

**Replay ambiguity:**

- `replay_db.rs` - Replay database trait
- `replay_record.rs` - Replay record types
- **Issue:** Unclear distinction between database and record types

**Unclear domain:**

- `failure_domain.rs` - Failure isolation
- **Issue:** "failure_domain" doesn't indicate it's for error classification
- `recovery.rs` - Recovery checkpoint management
- **Issue:** Doesn't indicate it's for crash recovery

### csv-verifier (Canonical Verification)

**Generic naming:**

- `anchor.rs` - Cryptographic anchors (block headers, inclusion proofs)
- **Issue:** "anchor" doesn't indicate it's for verification
- `chain_bundle.rs` - Chain proof bundles
- **Issue:** "bundle" too generic, doesn't indicate proof aggregation

### csv-storage (Persistence)

**Generic directory:**

- `backends/` - Storage backend implementations
- **Issue:** Generic name, doesn't indicate persistence implementations
- `coordinator_replay/` - Coordinator replay storage
- **Issue:** Doesn't indicate it's for replay database

## Naming Convention Plan

### Principle 1: Domain-Context Suffixes

Add suffixes to indicate architectural domain:

**Onchain vs Offchain:**

- `trust_package.rs` → `offchain_trust_anchor.rs`
- `client.rs` → `offchain_client_validation.rs`
- `validator.rs` → `offchain_consignment_validator.rs`

**Adapter vs Core:**

- `adapter.rs` → `chain_adapter_boundary.rs`
- `backend.rs` → `chain_adapter_traits.rs`

### Principle 2: Purpose-First Naming

Rename to indicate primary purpose:

**Proof types:**

- `proof.rs` → DELETE (redundant re-export)
- `proof_types.rs` → `proof_taxonomy.rs`
- `canonical_proof.rs` → `proof_validation.rs`

**Verification:**

- `verification.rs` → `verification_levels.rs`
- `verified.rs` → `verification_results.rs`

**Storage:**

- `store.rs` → `seal_store.rs`
- `state_store.rs` → `state_transition_store.rs`

### Principle 3: Acronym Expansion

Expand unclear acronyms:

- `mcp.rs` → `agent_types.rs` (Model Context Protocol → Agent-friendly types)

### Principle 4: Disambiguate Similar Names

**Leases:**

- `coordinator_lease.rs` → `distributed_coordinator_lease.rs` (HA coordination)
- `lease.rs` → `user_runtime_lease.rs` (user-facing + runtime)

**Events:**

- `event_bus.rs` → `event_bus.rs` (keep - clear)
- `event_store.rs` → `event_persistence.rs`
- `event_envelope.rs` → `event_envelope.rs` (keep - clear)

**Replay:**

- `replay_db.rs` → `replay_database.rs`
- `replay_record.rs` → `replay_record_types.rs`

## Architecture Reorganization Plan

### Phase 1: Domain-Based Directory Structure

Reorganize csv-protocol by architectural domain:

```
csv-protocol/src/
  onchain/
    chain_adapter_traits.rs (was backend.rs)
    seal_protocol.rs
    seal_types.rs (was seal.rs)
    sanad.rs
  offchain/
    trust_anchor.rs (move from csv-core)
    client_validation.rs (move from csv-core)
    consignment_validator.rs (move from csv-core)
  verification/
    proof_taxonomy.rs (was proof_types.rs)
    proof_validation.rs (was canonical_proof.rs)
    verification_levels.rs (was verification.rs)
    verification_results.rs (was verified.rs)
  cross_chain/
    cross_chain.rs
  types/
    envelope.rs
    state_machine/
    transfer_state/
```

### Phase 2: csv-core Partial Migration

**IMPORTANT:** Only migrate stable, production-ready modules. Keep future-proof cryptographic modules in csv-core.

**Move to csv-protocol:**

- `trust_package.rs` → `csv-protocol/src/offchain/trust_anchor.rs`
- `client.rs` → `csv-protocol/src/offchain/client_validation.rs`
- `validator.rs` → `csv-protocol/src/offchain/consignment_validator.rs`
- `adapter.rs` → `csv-protocol/src/onchain/chain_adapter_boundary.rs`

**Move to csv-runtime:**

- `recovery_engine.rs` → `csv-runtime/src/recovery_engine.rs`
- `certification.rs` → `csv-runtime/src/proof_certification.rs`

**Move to new crate csv-provenance:**

- `proof_provenance.rs`
- `performance.rs`

**KEEP in csv-core (future-proof):**

- `zk_proof.rs` - ZK proof infrastructure
- Any quantum proof modules (future)
- Any experimental cryptographic primitives (future)

**Rename csv-core to csv-advanced** (to reflect its purpose as advanced/experimental cryptographic module)

### Phase 3: csv-runtime Organization

Reorganize csv-runtime by responsibility:

```
csv-runtime/src/
  coordination/
    distributed_coordinator_lease.rs (was coordinator_lease.rs)
    user_runtime_lease.rs (was lease.rs)
    transfer_coordinator.rs
  events/
    event_bus.rs
    event_persistence.rs (was event_store.rs)
    event_envelope.rs
  recovery/
    recovery.rs
    recovery_checkpoint.rs
  replay/
    replay_database.rs (was replay_db.rs)
    replay_record_types.rs (was replay_record.rs)
  monitoring/
    failure_domain.rs → error_classification.rs
    runtime_mode.rs
    backpressure.rs
```

### Phase 4: csv-verifier Clarification

```
csv-verifier/src/
  anchors.rs (was anchor.rs) - plural for clarity
  chain_proof_bundle.rs (was chain_bundle.rs)
  verifier.rs
```

### Phase 5: csv-storage Organization

```
csv-storage/src/
  backends/
    in_memory.rs
    postgres.rs
    rocksdb.rs
  coordinator_replay/ → replay/
    coordinator_replay.rs
  traits.rs
  errors.rs
```

## Documentation Standards Plan

### Module-Level Documentation Template

Every module must include:

```rust
//! [Domain] [Purpose] for [Context]
//!
//! ## Architectural Role
//!
//! This module handles [specific responsibility] within the [architectural domain].
//! It is part of the [layer/tier] and interacts with [related modules].
//!
//! ## Onchain vs Offchain
//!
//! - **Onchain operations**: [list if applicable]
//! - **Offchain operations**: [list if applicable]
//!
//! ## Key Types
//!
//! - [`TypeName`] - [brief description]
//! - [`TypeName`] - [brief description]
//!
//! ## Related Modules
//!
//! - `related_module.rs` - [relationship]
//! - `related_module.rs` - [relationship]
```

### File Header Standards

Every file must include:

```rust
//! [Self-expressive module name]
//!
//! [One-sentence purpose]
//!
//! ## Location in Architecture
//!
//! - **Crate**: [crate-name]
//! - **Layer**: [protocol/runtime/storage/verifier]
//! - **Domain**: [onchain/offchain/cross-chain/coordination]
```

### Type Documentation Standards

Every public type must include:

```rust
/// [Type name] - [Purpose]
///
/// ## Architectural Role
///
/// [Where this type fits in the architecture]
///
/// ## Usage Context
///
/// [When to use this type vs alternatives]
///
/// ## Onchain/Offchain
///
/// [Whether this is for onchain or offchain operations]
```

### Cross-Reference Documentation

Add architecture map to each crate's lib.rs:

```rust
//! ## Crate Architecture
//!
//! ### Domain Organization
//!
//! - **Onchain**: [modules handling onchain operations]
//! - **Offchain**: [modules handling offchain operations]
//! - **Cross-chain**: [modules handling cross-chain coordination]
//!
//! ### Module Map
//!
//! See `ARCHITECTURE.md` for detailed module relationships.
```

## Implementation Priority

### High Priority (Security-Critical Ambiguity)

1. `trust_package.rs` → `offchain_trust_anchor.rs` (security-critical offchain verification)
2. `backend.rs` → `chain_adapter_traits.rs` (adapter boundary clarity)
3. `verification.rs` vs `verified.rs` disambiguation (verification correctness)

### Medium Priority (Architecture Clarity)

4. csv-core partial migration (keep future-proof modules, rename to csv-advanced)
2. Domain-based directory reorganization
3. Lease system disambiguation

### Low Priority (Documentation Polish)

7. Module documentation template application
2. Architecture map creation
3. Type documentation standards

## Migration Strategy

### Step 1: Documentation First

- Add module-level docs to all ambiguous modules
- Add architectural role annotations
- Add onchain/offchain indicators

### Step 2: Type Aliases (Backward Compatibility)

```rust
// Old name → new name with deprecation warning
#[deprecated(since = "0.2.0", note = "Use offchain_trust_anchor instead")]
pub use trust_package as offchain_trust_anchor;
```

### Step 3: Gradual Renaming

- Rename files one at a time
- Update imports incrementally
- Run tests after each rename

### Step 4: Directory Reorganization

- Create new directory structure
- Move files with updated imports
- Update lib.rs exports

### Step 5: csv-Core Partial Migration

- Move stable modules to target crates
- KEEP future-proof modules (zk_proof.rs, quantum proof, etc.)
- Rename csv-core to csv-advanced
- Update dependencies
- Update all references

## Success Criteria

1. **Self-Expression**: Every module name indicates its domain and purpose
2. **Onchain/Offchain Clarity**: Clear distinction between onchain and offchain operations
3. **No Ambiguity**: No two modules have similar names without clear distinction
4. **Documentation Coverage**: Every module has architectural role documentation
5. **Future-Proof Preservation**: csv-advanced (was csv-core) retains zk_proof.rs and future quantum/experimental modules
6. **Migration Complete**: Stable modules migrated, future-proof modules preserved in csv-advanced
