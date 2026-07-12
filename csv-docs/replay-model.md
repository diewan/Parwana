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
5. On rollback/reorg: transition replay record to `RolledBack` or the protocol-level invalidated state, never delete silently.

## Invalidation Rules

| Event | Replay state | Transfer state |
|-------|--------------|----------------|
| Deep reorg on source | `Invalidated` | `RolledBack` |
| Proof mutation detected | `Rejected` | `Compromised` |
| Duplicate mint attempt | `Consumed` (unchanged) | Hard error |

Runtime storage backends expose the concrete replay states `Pending`, `Consumed`, and `RolledBack`. A failed mint path after replay insertion MUST call `mark_rolled_back`; a confirmed mint MUST call `confirm_consumed` and persist the completed transfer entry.

## Retention

Nullifier and replay protection records MUST remain queryable long enough for congested multi-hop transfers and delayed finality. The default expiry is 604,800 seconds (7 days).

## Cross-Chain Replay

A source-chain nullifier MUST be registered on the destination chain contract before mint completes. Off-chain replay registry and on-chain nullifier map MUST agree; disagreement is a hard failure.

## Forbidden

- Feature flags that skip replay checks
- Runtime bypass of `csv-protocol` replay semantics or the runtime replay database
- Adapter-local replay stores without reconciliation to protocol registry

See `csv-protocol/src/replay/registry.rs`, `csv-runtime/src/replay_database.rs`, and `PROTOCOL_INVARIANTS.md` Invariant 9.
