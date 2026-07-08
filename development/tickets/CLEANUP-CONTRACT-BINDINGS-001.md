---
id: CLEANUP-CONTRACT-BINDINGS-001
title: "Decide fate of unreferenced csv-contract-bindings crate"
theme: "chain-binding strategy consolidation"
crate: "csv-contract-bindings"
priority: P3
security_critical: false
model_hint: sonnet
status: open
context_radius: 25
agent_md: "AGENTS.md"
target_file: "csv-contract-bindings/src/lib.rs"
target_patterns:
  - "Type-safe smart contract ABI bindings for all supported chains."
  - "pub mod csv_seal;"
target_file_2: "csv-adapters/csv-ethereum/src/bindings/mod.rs"
target_patterns_2:
  - "pub mod csv_seal;"
  - "pub mod csv_lock;"
interface_files:
  - "csv-architecture/tests/dep_graph_constitution.rs"
  - "csv-contract-bindings/Cargo.toml"
  - "Cargo.toml"
reference_crate: "csv-adapters/csv-ethereum"
reference_file: "csv-adapters/csv-ethereum/src/bindings/csv_seal.rs"
reference_patterns:
  - "csv_seal"
verify_commands:
  - "CXXFLAGS=\"-include cstdint\" cargo check -p csv-contract-bindings --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo check -p csv-ethereum --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo test -p csv-architecture --all-features"
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

`csv-contract-bindings` has zero in-workspace dependents: no crate's
`Cargo.toml` lists it as a dependency except the root workspace `Cargo.toml`
(as a member) and its own `Cargo.toml`. Its `lib.rs` docstring describes it as
providing "Type-safe smart contract ABI bindings for all supported chains,"
with modules for `csv_seal`, `mint_contract`, `sanad_contract`,
`seal_contract`, etc.

Meanwhile `csv-adapters/csv-ethereum` has grown its own parallel bindings
module at `csv-adapters/csv-ethereum/src/bindings/` (`csv_seal.rs`,
`csv_lock.rs`, both `cfg`-gated behind the `rpc` feature) — and that is what is
actually used by the Ethereum adapter. The only other reference to
`csv-contract-bindings` in the workspace is from
`csv-architecture/tests/dep_graph_constitution.rs`, which lists it in a
crate-allowlist test, not a real bindings consumer.

## Why it matters

Two parallel binding strategies — a dedicated top-level crate versus
per-adapter `bindings/` modules — is confusing for anyone trying to find "the"
Ethereum contract bindings. If `csv-contract-bindings` is fully superseded by
the per-adapter pattern, it should be removed; if it has a different intended
purpose, that purpose should be documented so the duplication reads as
deliberate rather than accidental.

## Task

Determine intent:

- **(a) Standalone published bindings package.** If `csv-contract-bindings` is
  meant to be published as a standalone external Rust bindings package, its
  existence is legitimate, but it should be documented as such (crate-level
  doc comment, README, or workspace docs), and the per-adapter duplication
  should probably be consolidated to use it instead of
  `csv-ethereum`'s separate `bindings/` module.
- **(b) Superseded scaffolding.** If it predates the per-adapter `bindings/`
  pattern and is dead scaffolding, remove it from the workspace and standardize
  on per-adapter `bindings/` modules for all chains that need typed bindings,
  not just Ethereum.

## Acceptance criteria

- [ ] A decision is recorded (in this ticket's resolution) between (a) and (b).
- If (a): `csv-contract-bindings` becomes the actual single source of truth for
  chain bindings — `csv-ethereum`'s `bindings/` module is migrated to depend on
  it (or removed in favor of it), and any of Solana/Sui/Aptos/Bitcoin that need
  typed bindings gain equivalent coverage there rather than duplicating logic
  per-adapter.
- If (b): `csv-contract-bindings` is removed from the workspace `members` list
  and deleted, and `csv-architecture/tests/dep_graph_constitution.rs` no longer
  references it.
- [ ] All `verify_commands` pass.
- [ ] A repo-wide search confirms no other crate silently assumed
      `csv-contract-bindings` existed after the decision is applied.

## Notes

This is a decision ticket. Check whether `csv-contract-bindings` has ever been
published to crates.io or referenced from outside this repository before
assuming (a); absent that evidence, (b) is the more likely correct call given
it has no in-workspace consumers today.
