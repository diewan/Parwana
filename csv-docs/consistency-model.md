# CSV Consistency Model

Authoritative state and rollback semantics for coordinators and operators.

## Authoritative State

| Concern | Authority |
|---------|-----------|
| Transfer legality | `csv-core` transfer state machine |
| Proof validity | `csv-core` verifier + chain capabilities |
| Replay consumption | `csv-core` replay registry (persistent in production) |
| Orchestration order | `csv-runtime` `TransferCoordinator` |
| Persisted events | `csv-store` / runtime event store (dumb persistence) |

Applications (CLI, SDK) MUST NOT mark transfers complete without runtime + verifier success.

## Transfer Finality

A transfer is **irreversible** only in `Completed`. Until then:

- Proofs may become invalid on reorg.
- Ownership on destination MUST NOT be assumed from mempool observation alone.
- `AwaitingFinality → Minting` requires chain-specific finality threshold (`ChainCapabilities::finality_threshold_met`).

## Rollback Semantics

On reorg detection (`csv-core/reorg`, `csv-runtime` adversarial path):

1. Invalidate inclusion-dependent proofs.
2. Transition active transfer → `RolledBack`.
3. Reconcile replay registry (invalidate, do not delete consumed nullifiers).
4. Emit `RollbackExecuted` event (see `csv-core/src/events.rs`).

**Winner after rollback:** last persisted transition before reorg depth exceeded `max_safe_reorg_depth`.

## Proof Invalidation

| Finality class | Invalidation trigger |
|----------------|---------------------|
| Probabilistic (BTC, SOL) | Depth rollback below confirmation threshold |
| Checkpoint (ETH) | Safe head reorg |
| BFT instant (SUI, APT) | Certified checkpoint superseded (rare) |

## Event Ordering

All indexer and coordinator ordering MUST use `(block_height, tx_index, log_index)`. Timestamp ordering is forbidden for protocol decisions.

## Stage 1 vs Stage 3

**Stage 1 (testnet):** RPC quorum evidence; mint receipt cross-check recommended but not fully enforced everywhere.

**Stage 3 (target):** Independent mint confirmation via quorum or light client — see `PROTOCOL_INVARIANTS.md` RPC trust section.
