# RFC-0006: Contract ABI

## Status

Proposed — **destination-mint model superseded by [RFC-0012: Thin Registry Cross-Chain Mint](RFC-0012-thin-registry-cross-chain-mint.md)**.

> **Deprecation note.** The destination-mint model in this RFC (proof-root / `stateRoot` anchoring, "Anchor proof roots" as a contract duty, `ProofAccepted`/`ProofRejected` events) is **deprecated**. Under RFC-0012, destination mint is a **thin registry**: it authenticates a verifier-signed attestation (RFC-0012 §9), enforces `sanadId`/`nullifier`/`lockEventId` uniqueness, and emits `SanadMinted`. Proof-root installation is **no longer required for ordinary mint** and MUST NOT gate it. The uniqueness/replay-anchoring and event-schema-discipline duties below remain valid; the proof-root duties do not. See [ABI_CONSTITUTION.md](../contracts/ABI_CONSTITUTION.md) for the frozen thin-registry ABI, §9.2 attestation digest, and §10 settlement receipt.

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
- ~~Anchor proof roots~~ (**deprecated** — RFC-0012 §4 removes proof-root anchoring from the mint hot path)
- Anchor schema IDs
- Authenticate the mint via verifier-signed attestation (RFC-0012 §9)
- Enforce `sanadId` / `nullifier` / `lockEventId` uniqueness
- Emit canonical events (`SanadMinted`, `SettlementReleased`)
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
