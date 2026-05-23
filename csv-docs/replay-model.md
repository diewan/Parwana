# CSV Replay Model

Canonical replay semantics for testnet and production. Adapters MUST NOT override these rules.

## Replay Domains

| Domain | Scope | Identifier |
|--------|-------|------------|
| `chain_local` | Single chain, single transfer | `ReplayId` from proof material + seal consumption |
| `cross_chain` | Source lock → destination mint | Source nullifier + destination chain id |
| `proof_bundle` | Re-submission of identical proof bytes | Canonical hash of proof bundle CBOR |

## Required Pipeline Order

1. Derive deterministic `ReplayId` from canonical proof material.
2. `ReplayRegistry::check` — reject if already `Consumed` or `Pending` (CAS).
3. Execute verification and finality gates.
4. `ReplayRegistry::insert_if_absent` — atomic CAS before mint.
5. On rollback/reorg: transition replay record to `Invalidated`, never delete silently.

## Invalidation Rules

| Event | Replay state | Transfer state |
|-------|--------------|----------------|
| Deep reorg on source | `Invalidated` | `RolledBack` |
| Proof mutation detected | `Rejected` | `Compromised` |
| Duplicate mint attempt | `Consumed` (unchanged) | Hard error |

## Cross-Chain Replay

A source-chain nullifier MUST be registered on the destination chain contract before mint completes. Off-chain replay registry and on-chain nullifier map MUST agree; disagreement is a hard failure.

## Forbidden

- Feature flags that skip replay checks
- Runtime bypass of `csv-core` replay registry
- Adapter-local replay stores without reconciliation to protocol registry

See `csv-core/src/replay_registry.rs` and `PROTOCOL_INVARIANTS.md` Invariant 9.
