# Thin-Registry Incident Response Runbook

**Scope:** duplicate mint attempts, replay-domain conflicts, forged
authorization, settlement anomalies, and crash recovery for RFC-0012
materialization.

## First Response

1. Stop new materialization submissions for the affected chain pair.
2. Preserve the execution journal, event store, replay DB, runtime logs, and
   destination contract events for the affected `sanadId`.
3. Check the seven operator signals:
   `verified proof built`, `mint submitted`, `mint confirmed`,
   `settlement submitted`, `settlement confirmed`, `replay rejected`,
   `authorization rejected`.
4. Compare runtime state with on-chain state. On-chain finality and canonical
   runtime verification win over local display caches.

## Incident Classes

| Symptom | Immediate classification | Required check |
|---------|--------------------------|----------------|
| Second mint accepted for same `sanadId` | Critical replay failure | Destination `sanadId` guard and runtime completed-replay short-circuit |
| Second mint accepted for same `nullifier` | Critical seal replay failure | Destination nullifier table/tombstone |
| Second mint accepted for same `lockEventId` | Critical source-lock replay failure | Destination lock-event table/tombstone |
| Mint accepted with malformed attestation payload | Critical authorization failure | Verifier-set signature path and adapter request decoding |
| Source settlement accepted without confirmed mint evidence | Critical payout failure | `SettlementReceipt` verifier binding and runtime `settlement_evidence` |
| Crash resume rebroadcasted a mint | Critical recovery failure | Journal phase and `MintSubmitted` recovery path |
| Runtime says reverted but chain shows mint | State divergence | Treat as completed only after final on-chain `SanadMinted` evidence |

## Containment

- Set the affected chain's `verified` flag to `false` in
  `deployments/deployment-manifest.json`.
- Disable operator submissions for the affected source/destination pair.
- Do not clear replay guards, tombstones, or runtime replay DB entries.
- Do not lower finality depth to reproduce faster.
- Do not introduce a proof-root or authorized-caller fallback path.

## Recovery Decisions

- If no destination mint exists and the runtime is `RolledBack`, follow the
  source escrow timeout/refund procedure. Do not re-drive the same transfer id.
- If a destination mint exists at strict finality, record or reconstruct
  settlement evidence from the canonical event and proceed only through the
  verifier-signed settlement receipt path.
- If runtime journal and chain state disagree, keep the chain pair disabled until
  an adversarial review identifies the exact failing invariant and a regression
  test is merged.

## Regression Evidence

Every incident fix must include a test that names the prevented failure:

- duplicate `sanadId`
- duplicate `nullifier`
- duplicate `lockEventId`
- forged mint authorization payload
- forged or premature settlement receipt
- retry after destination revert
- resume after crash during mint
- resume after crash during settlement
