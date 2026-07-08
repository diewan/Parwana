---
id: ROADMAP-CELESTIA-001
title: "Decide fate of csv-celestia: finish wiring or archive"
theme: "Celestia DA-layer roadmap"
crate: "csv-adapters/csv-celestia"
priority: P2
security_critical: false
model_hint: sonnet
status: open
context_radius: 25
agent_md: "AGENTS.md"
target_file: "csv-adapters/csv-celestia/src/seal_protocol.rs"
target_patterns:
  - "[0u8; 32], // row_root"
  - ".with_quorum(vec![])"
target_file_2: "csv-runtime/src/transfer_coordinator.rs"
target_patterns_2:
  - "// Register celestia which cannot authorize mints (DA only)"
  - "let celestia_caps = ChainCapabilities::celestia();"
interface_files:
  - "csv-adapter-factory/src/lib.rs"
  - "csv-adapters/csv-celestia/src/da_layer.rs"
  - "csv-adapters/csv-celestia/Cargo.toml"
reference_crate: "csv-adapter-factory"
reference_file: "csv-adapter-factory/src/lib.rs"
reference_patterns:
  - "feature = \"sui\""
  - "pub use sui::SuiFactory;"
verify_commands:
  - "CXXFLAGS=\"-include cstdint\" cargo check -p csv-celestia --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo test -p csv-celestia --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo build --workspace --all-features"
forbidden_patterns:
  - "todo!"
  - "unimplemented!"
  - "panic!"
  - "unreachable!"
  - "#[allow(dead_code)]"
  - "#[allow(unused)]"
  - "vec![0u8;"
  - "Hash::new([0u8; 32])"
  - "Ok(true) // Placeholder"
  - "Ok(0) // Placeholder"
contract_files:
  - ""
cross_boundary_check: true
---

## Problem

`csv-celestia` has zero in-workspace dependents: no other crate's `Cargo.toml`
lists it as a dependency, and it has no entry in `csv-adapter-factory` (compare
`csv-adapter-factory/src/lib.rs`, which declares a `mod`/`pub use` pair per live
chain — `aptos`, `bitcoin`, `ethereum`, `solana`, `sui` — with nothing equivalent
for celestia). There is also no `chains/celestia*.toml` config file, unlike the
five live chains that each have one under `chains/`.

Internally, its `SealProtocol` implementation is not functionally real yet even
if it were wired in:

- `verify_inclusion` (`csv-adapters/csv-celestia/src/seal_protocol.rs:176`)
  builds a `CommitmentProof` with hardcoded `[0u8; 32]` values for `row_root`
  and `data_root`, with a comment noting "In production, this would verify the
  inclusion proof from Celestia."
- `verify_finality` (`csv-adapters/csv-celestia/src/seal_protocol.rs:194`)
  builds a `CelestiaFinalityProof` with a zeroed `data_root` and
  `.with_quorum(vec![])` — an empty quorum vector.

## Why it matters

`csv-runtime/src/transfer_coordinator.rs` does reference Celestia as a
capability-only, non-transfer "DA only" chain: around line 4422 it registers
`ChainCapabilities::celestia()` with the comment "Register celestia which
cannot authorize mints (DA only)". This suggests there may be partial intent to
support Celestia as a data-availability-only chain rather than a full transfer
chain, rather than the crate being simply abandoned. That distinction should be
surfaced and resolved rather than assumed.

## Task

Read any `csv-docs/` RFCs mentioning Celestia or a DA-layer, and the
capability-only reference in `transfer_coordinator.rs`, to determine which of
the following describes the intended fate of `csv-celestia`:

- **(a) Full chain adapter.** It is a future full transfer-capable chain
  adapter that needs the same finish-and-wire treatment as the other five:
  register it in `csv-adapter-factory`, add `chains/celestia*.toml`, and
  replace the zeroed-root/mock-hash inclusion and finality checks with real
  Celestia RPC-backed verification.
- **(b) DA-only, intentionally unwired for transfers.** It should stay out of
  the transfer-adapter registry, but its inclusion/finality checks should be
  replaced with real ones for whatever DA-only capability it is meant to
  support (e.g. anchoring commitments to Celestia without minting/transfer
  authority).
- **(c) Abandoned scaffolding.** It should be removed from the workspace
  members list entirely, or excluded the way `csv-explorer/*` is already
  commented out of the root `Cargo.toml` members list rather than deleted.

## Acceptance criteria

- [ ] A clear decision is recorded (in this ticket's resolution or a follow-up
      ticket) as to which of (a), (b), or (c) applies.
- If (a): csv-celestia is registered in `csv-adapter-factory`, a
  `chains/celestia*.toml` exists, and `verify_inclusion`/`verify_finality` no
  longer return zeroed roots or empty quorum vectors.
- If (b): the transfer-adapter wiring is explicitly and permanently marked out
  of scope (doc comment or ADR), and the DA-only capability path (inclusion and
  finality checks it actually needs) is implemented for real — no more zeroed
  roots or mock SHA-256 hashing standing in for chain-observed state.
- If (c): the crate is removed or excluded from the workspace `members` list,
  matching the `csv-explorer/*` precedent in the root `Cargo.toml`.
- [ ] All `verify_commands` pass for whichever path is chosen.
- [ ] Production code does not introduce `todo!`, `unimplemented!`, `unwrap`,
      `expect`, zero-hash placeholders, fake proofs, or silent fallbacks.

## Notes

This is a decision ticket. Don't guess at scope reduction without recording the
decision — a reader of this crate six months from now should be able to tell
from either the code or this ticket's resolution why csv-celestia looks the way
it does.
