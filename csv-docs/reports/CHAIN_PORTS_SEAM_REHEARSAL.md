# csv-chain-ports Seam Rehearsal

**Status:** Measurement only — no extraction authorized.  
**Owner:** TBD.  
**Authority for extraction go/no-go:** maintainer.

## Contract-stability evidence

The `csv-chain-ports` seam is a workspace-local, chain-neutral contract used by
runtime and all concrete adapters. The rehearsal command is:

```bash
scripts/rehearse-chain-ports.sh
```

It records four in-place stability facts: the port crate compiles independently,
its tests and runtime consumer pass, Cargo can package its declared contents,
and its public API exactly matches the reviewed snapshot. The snapshot is an
intentional API-contract review artifact, not a publication or extraction
artifact.

No repository is created, no history is filtered, no source is moved, and no
contract is deployed. A successful rehearsal therefore supports only continued
workspace hardening; it does not authorize extraction.

## 2026-07-15 local measurement

- `cargo check -p csv-chain-ports` passed.
- `cargo test -p csv-chain-ports -p csv-runtime` passed (109 runtime unit tests,
  plus integration and constitution suites).
- `scripts/check-core-api.sh` passed against the checked-in L0-L4 snapshots.
- `cargo package --list -p csv-chain-ports` was blocked before package creation
  by an existing malformed nested Git worktree at
  `csv-contracts/ethereum/contracts/lib/buffer`. This is repository hygiene
  evidence, not a reason to bypass Cargo verification or extract anything.
