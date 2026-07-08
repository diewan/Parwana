---
id: LINT-DEADCODE-HYGIENE-001
title: "Remove blanket #![allow(dead_code)] suppressions and re-baseline real warnings"
theme: "workspace lint hygiene"
crate: "workspace"
priority: P2
security_critical: false
model_hint: sonnet
status: open
context_radius: 25
agent_md: "AGENTS.md"
target_file: "csv-cli/src/main.rs"
target_patterns:
  - "#![allow(dead_code)]"
target_file_2: "csv-cli/src/config.rs"
target_patterns_2:
  - "#![allow(dead_code)]"
interface_files:
  - "csv-cli/src/commands/mod.rs"
  - "csv-hash/src/lib.rs"
  - "csv-adapters/csv-bitcoin/src/lib.rs"
  - "csv-adapters/csv-aptos/src/lib.rs"
  - "csv-adapters/csv-solana/src/lib.rs"
  - "csv-adapters/csv-sui/src/lib.rs"
  - "csv-adapters/csv-bitcoin/src/seal_protocol.rs"
  - "csv-adapters/csv-ethereum/src/seal_protocol.rs"
  - "csv-adapters/csv-sui/src/seal_protocol.rs"
  - "csv-adapters/csv-aptos/src/seal_protocol.rs"
  - "csv-adapters/csv-ethereum/src/seal.rs"
  - "csv-adapters/csv-ethereum/src/ops.rs"
reference_crate: ""
reference_file: ""
reference_patterns:
  - ""
verify_commands:
  - "CXXFLAGS=\"-include cstdint\" cargo clippy --workspace --all-features -- -D warnings"
  - "CXXFLAGS=\"-include cstdint\" cargo build --workspace --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo test --workspace --all-features"
forbidden_patterns:
  - "todo!"
  - "unimplemented!"
  - "panic!"
  - "unreachable!"
  - "#![allow(dead_code)]"
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

Twelve files carry a blanket, unexplained `#![allow(dead_code)]` at file or
crate root scope: `csv-cli/src/main.rs`, `csv-cli/src/commands/mod.rs`,
`csv-cli/src/config.rs`, `csv-hash/src/lib.rs`,
`csv-adapters/csv-bitcoin/src/lib.rs`, `csv-adapters/csv-aptos/src/lib.rs`,
`csv-adapters/csv-solana/src/lib.rs`, `csv-adapters/csv-sui/src/lib.rs`, each
adapter's `seal_protocol.rs` (bitcoin/ethereum/sui/aptos), and
`csv-adapters/csv-ethereum/src/seal.rs` / `ops.rs`. None of the twelve carry an
explanatory comment — they are bare `#![allow(dead_code)]` lines, sometimes
alongside `#![allow(deprecated)]` or `#![allow(missing_docs)]`.

This means a plain `cargo clippy --workspace --all-features` currently reports
zero `dead_code` warnings, even though real dead code exists underneath:
running `RUSTFLAGS="--force-warn dead_code" cargo check --workspace
--all-features` (which overrides the in-source allows) surfaces genuine
`dead_code`-class warnings in multiple workspace crates, including csv-cli,
csv-bitcoin, csv-sui, csv-aptos, csv-solana, csv-ethereum, csv-sdk, csv-runtime,
csv-store, csv-protocol, csv-hash, and csv-coordinator. (Third-party dependency
crates also emit a large number of unrelated `dead_code` warnings under that
override — those are not in scope here and should be ignored; only warnings
inside `csv-*` crates matter for this ticket.)

## Why it matters

This defeats the compiler's own dead-code detection workspace-wide, meaning
future dead code accumulates invisibly — exactly the class of problem this
whole dead-code audit had to work around with a `RUSTFLAGS` override to see
past. It is a standing hygiene gap, and `.agents/AGENT.md`'s CI Enforcement
Requirements section implies dead/unused code should be caught, not suppressed
wholesale.

## Task

For each of the twelve listed files: remove the blanket `#![allow(dead_code)]`
and see what `dead_code` warnings surface for that crate under
`RUSTFLAGS="--force-warn dead_code" cargo check -p <crate> --all-features` (or
simply removing the allow and running normal `cargo check`/`clippy`, once the
suppression is gone). For each real warning that surfaces:

- **(a) Genuinely dead.** Remove it. Cross-reference against the specific
  dead-code cleanup tickets already filed in this batch —
  `CLEANUP-LEGACY-CONFIG-001` for `csv-cli/src/config.rs`,
  `CLEANUP-ETH-BINDINGS-001` for the Ethereum bindings, and
  `CLEANUP-BTC-ERROR-CODES-001` for the Bitcoin error codes. This ticket should
  not duplicate that work — either sequence after those tickets land, or fold
  in trivial single-item cases directly if they're outside those tickets'
  scope.
- **(b) Legitimately unused-for-now scaffolding.** Apply a narrow, item-level
  `#[allow(dead_code)]` with a one-line comment explaining why (e.g. "kept for
  upcoming X, tracked in TICKET-ID"). Never reintroduce a blanket file- or
  crate-level allow with no justification.

## Acceptance criteria

- [ ] No remaining blanket `#![allow(dead_code)]` without an explanatory
      comment at file or crate scope, anywhere in the workspace.
- [ ] `cargo clippy --workspace --all-features -- -D warnings` still passes.
- [ ] Any narrow, item-level `#[allow(dead_code)]` that remains has a one-line
      justification comment directly above it.
- [ ] Production code does not introduce `todo!`, `unimplemented!`, `unwrap`,
      `expect`, or silent fallbacks while triaging warnings.
- [ ] All `verify_commands` pass.

## Notes

Run this **after** `CLEANUP-LEGACY-CONFIG-001`, `CLEANUP-ETH-BINDINGS-001`,
`CLEANUP-BTC-ERROR-CODES-001`, and `RUNTIME-POSTGRES-HA-001` land — removing
those items first shrinks what this ticket has to triage, since several of the
warnings this ticket will surface are already accounted for by those tickets.
Sequencing this last avoids re-doing the same removal twice under two
different ticket IDs.
