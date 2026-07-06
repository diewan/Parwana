# TRM-HARDEN-001 Release Readiness Checklist

**Scope:** RFC-0012 thin-registry materialization, source escrow settlement, crash
recovery, and operator observability.

## Required Gates

- [ ] Duplicate `sanadId` mint attempt does not dispatch a second destination mint.
- [ ] Duplicate `nullifier` attempt is rejected by the destination replay guard.
- [ ] Duplicate `lockEventId` attempt is rejected by the destination replay guard.
- [ ] Malformed or forged mint authorization payload is rejected before state mutation.
- [ ] Forged or premature settlement receipt path is rejected before source payout.
- [ ] Resume after crash during proof/mint uses durable journal state and does not remint.
- [ ] Resume after `MintSubmitted` confirms the recorded mint transaction instead of rebroadcasting.
- [ ] Source settlement is one-shot: second release is rejected and the adapter is not invoked.
- [ ] Cross-chain event/state conformance confirms the seven canonical `SanadMinted` fields.
- [ ] Runtime operator metrics expose all seven hardening signals:
  `verified proof built`, `mint submitted`, `mint confirmed`,
  `settlement submitted`, `settlement confirmed`, `replay rejected`,
  `authorization rejected`.

## Test Commands

```bash
CXXFLAGS="-include cstdint" cargo test --workspace --all-features
cargo test -p csv-runtime
```

## End-to-End Matrix

Run the testnet matrix from `csv-docs/runbooks/OPERATOR_ROLLOUT_MULTICHAIN.md`:

| Source | Destination | Required result |
|--------|-------------|-----------------|
| Bitcoin signet | Sui testnet | one finalized lock, one `SanadMinted`, replay refused |
| Bitcoin signet | Aptos testnet | one finalized lock, one `SanadMinted`, replay refused |
| Bitcoin signet | Solana devnet | one finalized lock, one `SanadMinted`, replay refused |
| Ethereum Sepolia | Sui testnet | one finalized lock, one `SanadMinted`, replay refused |
| Sui testnet | Ethereum Sepolia | one finalized lock, one `SanadMinted`, replay refused |

Record each transfer id, source lock tx, destination mint tx, settlement evidence,
and replay-attempt result in the release evidence bundle.

## Stop-Ship Conditions

- Any chain mints without all three replay guards (`sanadId`, `nullifier`,
  `lockEventId`).
- Any settlement release can be submitted without confirmed destination mint
  evidence and verifier receipt binding.
- Any resume path can rebroadcast a mint after `MintSubmitted`.
- Any operator-facing metric is missing for a failed replay or authorization
  rejection.
- Any chain emits non-conformant canonical event/state fields.
