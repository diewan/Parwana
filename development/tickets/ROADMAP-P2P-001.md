---
id: ROADMAP-P2P-001
title: "Decide fate of csv-p2p: enable feature or archive"
theme: "P2P proof delivery roadmap"
crate: "csv-p2p"
priority: P3
security_critical: false
model_hint: sonnet
status: open
context_radius: 25
agent_md: "AGENTS.md"
target_file: "csv-sdk/Cargo.toml"
target_patterns:
  - "csv-p2p = { path = \"../csv-p2p\", optional = true }"
  - "p2p = [\"dep:csv-p2p\"]"
target_file_2: "csv-cli/Cargo.toml"
target_patterns_2:
  - "csv-sdk = { path = \"../csv-sdk\", features = [\"bitcoin\", \"ethereum\", \"sui\", \"aptos\", \"solana\", \"rpc\", \"runtime-coordinator\"] }"
interface_files:
  - "csv-p2p/src/lib.rs"
  - "csv-cli/src/commands/mod.rs"
reference_crate: "csv-cli"
reference_file: "csv-cli/Cargo.toml"
reference_patterns:
  - "features = [\"bitcoin\", \"ethereum\", \"sui\", \"aptos\", \"solana\", \"rpc\", \"runtime-coordinator\"]"
verify_commands:
  - "CXXFLAGS=\"-include cstdint\" cargo check -p csv-p2p --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo check -p csv-cli --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo test -p csv-p2p --all-features"
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

`csv-p2p` (roughly 2,700 lines of real Nostr/IPFS proof-delivery code) is
depended on by `csv-sdk` behind an optional `p2p` Cargo feature
(`csv-sdk/Cargo.toml`: `csv-p2p = { path = "../csv-p2p", optional = true }` and
`p2p = ["dep:csv-p2p"]`), but `csv-cli`'s `csv-sdk` dependency never enables
that feature — its feature list is
`["bitcoin", "ethereum", "sui", "aptos", "solana", "rpc", "runtime-coordinator"]`,
with no `"p2p"`. As a result, this crate never runs in the shipped `csv`
binary.

## Why it matters

Unlike `csv-celestia`, this looks like complete, real functionality that is
simply never opted into — a lower-effort decision than a rewrite. The question
is purely "should the CLI expose this," not "does this need to be built."

## Task

Determine whether P2P proof delivery (Nostr/IPFS) is an intended CLI-facing
feature:

- **If yes:** add `p2p` to `csv-cli`'s `csv-sdk` feature list (or add a
  separate `--features p2p` opt-in build profile if it shouldn't be on by
  default), add a real CLI surface (command or flag) that exercises it end to
  end, and add an integration test covering that surface.
- **If no longer relevant:** document why in this ticket's resolution, and
  decide whether to leave it opt-in-only (fine as-is, just document the
  decision near the `p2p` feature definition) or remove the crate.

## Acceptance criteria

- [ ] Either: the CLI has a real, tested way to reach `csv-p2p` functionality
      (a command/flag exists, is wired through `csv-sdk`'s `p2p` feature, and
      has a passing integration test).
- [ ] Or: a documented decision exists (in this ticket's resolution and as a
      code comment near the `p2p` feature in `csv-sdk/Cargo.toml`) explaining
      why it remains opt-in-only/unused, so the next person auditing the
      codebase does not read it as accidental dead weight.
- [ ] All `verify_commands` pass.
- [ ] Production code does not introduce `todo!`, `unimplemented!`, `unwrap`,
      `expect`, or silent fallbacks in any newly wired CLI surface.

## Notes

This is a decision ticket, but a lightly-scoped one relative to the others in
this batch — `csv-p2p` is not scaffolding, it is finished code waiting on a
decision about CLI exposure.
