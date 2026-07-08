---
id: CLEANUP-ETH-BINDINGS-001
title: "Remove orphaned legacy CSVMint contract bindings"
theme: "Ethereum adapter cleanup"
crate: "csv-adapters/csv-ethereum"
priority: P3
security_critical: false
model_hint: sonnet
status: open
context_radius: 25
agent_md: "AGENTS.md"
target_file: "csv-adapters/csv-ethereum/src/bindings/csv_mint.rs"
target_patterns:
  - "//! Generated from CSVMint.sol"
  - "contract CSVMint {"
target_file_2: "csv-adapters/csv-ethereum/src/bindings/mod.rs"
target_patterns_2:
  - "pub mod csv_seal;"
  - "pub mod csv_lock;"
interface_files:
  - "csv-adapters/csv-ethereum/src/contract_bytecode.rs"
reference_crate: ""
reference_file: ""
reference_patterns:
  - ""
verify_commands:
  - "CXXFLAGS=\"-include cstdint\" cargo check -p csv-ethereum --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo test -p csv-ethereum --all-features"
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
cross_boundary_check: false
---

## Problem

`csv-adapters/csv-ethereum/src/bindings/csv_mint.rs` (249 lines) holds legacy
`CSVMint` Solidity ABI bindings — `registerNullifier`, `mintSanad`,
`mintSanadWithMetadata`, `isSanadMinted`, `isNullifierRegistered`,
`batchMintSanads` — for a standalone mint contract that predates the move to
`csv_seal.rs`'s `mint_sanad` (VERSION 6 attestation ABI, per RFC-0012
thin-registry mint). `csv-adapters/csv-ethereum/src/bindings/mod.rs` only
declares `pub mod csv_seal;` and `pub mod csv_lock;`, both `cfg`-gated behind
the `rpc` feature — there is no `mod csv_mint;` anywhere, so this file is not
compiled. It is pure dead weight on disk.

A separate, related leftover: `csv-adapters/csv-ethereum/src/contract_bytecode.rs`
still has a `pub const CSVMINT_BYTECODE: &[u8] = &[];` (an empty placeholder,
already unused) alongside the live `CSVLOCK_BYTECODE`. This ticket's task is
scoped to deleting `csv_mint.rs`; note the bytecode constant here as a related
finding but leave it out of scope unless removing it is trivial and clearly
safe.

## Why it matters

An uncompiled legacy bindings file with a full contract interface could
confuse a future reader into thinking there are two mint contract paths on
Ethereum (there is only one — `csv_seal.rs`'s `mint_sanad`).

## Task

Delete `csv-adapters/csv-ethereum/src/bindings/csv_mint.rs`.

## Acceptance criteria

- [ ] `csv-adapters/csv-ethereum/src/bindings/csv_mint.rs` is removed.
- [ ] `csv-ethereum` builds clean.
- [ ] A repo-wide grep for `csv_mint` / `CSVMint` confirms no remaining
      references anywhere in the workspace before considering this done.
- [ ] All `verify_commands` pass.

## Notes

If the repo-wide grep in the acceptance check turns up the unused
`CSVMINT_BYTECODE` constant in `contract_bytecode.rs`, it is fine to leave it —
that is a separate, smaller piece of dead weight not part of this ticket's
scope. Mention it in the PR description if left in place so it doesn't get
lost.
