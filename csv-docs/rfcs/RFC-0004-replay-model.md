# RFC-0004: Replay Model

## Status

Proposed

## Motivation

Replay logic exists across multiple modules without globally enforced replay invariants:

- replay registry
- replay store
- replay DB
- nullifiers
- seals

This creates risk of:

- Double consumption
- Cross-chain replay
- Proof reuse
- Stale proof resurrection
- Rollback replay
- Delayed finality replay

Replay must be protocol-central, not adapter-central.

## Proposed Change

### 1. Create Replay Constitution

Create `/docs/replay-model.md` defining:

- Replay domains
- Replay scope
- Replay invalidation
- Rollback semantics
- Chain-local replay
- Cross-chain replay

### 2. Centralize Replay Registry

Create `/crates/csv-protocol/src/replay/` with:

- ONLY protocol controls replay
- Adapters cannot override
- Canonical replay semantics
- Global replay invariants

### 3. Define Replay Semantics

```rust
pub enum ReplayDomain {
    Global,
    ChainLocal(ChainId),
    ProtocolLocal(ProtocolId),
    SealLocal(SealId),
}

pub struct ReplayPolicy {
    domain: ReplayDomain,
    scope: ReplayScope,
    invalidation: ReplayInvalidation,
}
```

### 4. Add Replay to Verification Context

All verification MUST include replay policy:

```rust
pub struct VerificationContext {
    replay_policy: ReplayPolicy,
    // ...
}
```

## Rationale

Centralized replay semantics prevent:

- Adapter-specific replay bugs
- Cross-chain replay attacks
- Inconsistent replay enforcement
- Protocol drift

## Impact

BREAKING CHANGE: All replay logic must be centralized.

- Move replay logic to csv-protocol
- Update all adapters to use centralized replay
- Update verification logic
- Add replay tests

## Alternatives

- Keep distributed replay logic (REJECTED - too risky)
- Adapter-controlled replay (REJECTED - violates protocol invariants)

## Unresolved Questions

- How to handle cross-chain replay coordination?
- Replay invalidation timing?
- Rollback replay recovery?
