# RFC-0006: Contract ABI

## Status

Proposed

## Motivation

Current contracts are too thin semantically and lack:

- Explicit storage versioning
- Upgrade-safe layout guarantees
- Event schema guarantees
- Protocol compatibility registry
- Feature negotiation
- Deprecation framework
- Immutable verification commitments

Without ABI constitution, future protocol evolution becomes dangerous.

## Proposed Change

### 1. Create ABI Constitution

Create `/docs/contracts/ABI_CONSTITUTION.md` freezing:

- Event ordering
- Field ordering
- Event hashing
- Serialization
- Topic indexing

### 2. Define Canonical Event Schema

ALL chains emit identical semantic events:

```rust
event SanadAnchored {
    protocol_version,
    schema_id,
    content_root,
    proof_root,
    replay_nullifier,
    transition_type,
}
```

### 3. Add Contract Semantics

Contracts MUST:

- Anchor commitments
- Anchor replay nullifiers
- Anchor proof roots
- Anchor schema IDs
- Emit canonical events
- Enforce replay uniqueness
- NO business logic

### 4. Add Deployment Framework

Create `/deployment/` with:

- `manifest.json`
- `chain-configs/`
- `checksums/`
- `reproducibility/`

Deployment must verify:

- Bytecode checksum
- RPC consistency
- Chain ID
- ABI compatibility
- Deployment provenance

## Rationale

Contract ABI constitution prevents:

- Event schema drift
- Incompatible upgrades
- Ecosystem fragmentation
- Verification ambiguity

## Impact

BREAKING CHANGE: All contracts must be redesigned.

- Rewrite all contracts
- Update deployment scripts
- Update event indexing
- Update verification logic

## Alternatives

- Keep current thin contracts (REJECTED - insufficient anchoring)
- Allow contract evolution without constitution (REJECTED - dangerous)

## Unresolved Questions

- Contract upgrade strategy?
- Event schema versioning?
- Cross-chain contract equivalence testing?
