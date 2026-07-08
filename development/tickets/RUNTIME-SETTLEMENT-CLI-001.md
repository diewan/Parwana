---
id: RUNTIME-SETTLEMENT-CLI-001
title: "Wire SettlementEvidence/SettlementStatus into an operator-facing CLI query"
theme: "operator settlement visibility"
crate: "csv-runtime"
priority: P2
security_critical: false
model_hint: sonnet
status: open
context_radius: 25
agent_md: "AGENTS.md"
target_file: "csv-runtime/src/transfer_coordinator.rs"
target_patterns:
  - "pub fn settlement_evidence("
  - "pub fn settlement_status("
  - "pub struct SettlementEvidence"
  - "pub enum SettlementStatus"
target_file_2: "csv-cli/src/commands/cross_chain/status.rs"
target_patterns_2:
  - "pub async fn cmd_status("
interface_files:
  - "csv-cli/src/commands/cross_chain/mod.rs"
  - "csv-docs/runbooks/OPERATOR_MINT_BTC_ETH.md"
  - "csv-sdk/src/transfers.rs"
reference_crate: "csv-cli"
reference_file: "csv-cli/src/commands/cross_chain/mod.rs"
reference_patterns:
  - "CrossChainAction::Status { transfer_id } => {"
  - "status::cmd_status(transfer_id, config, state).await"
verify_commands:
  - "CXXFLAGS=\"-include cstdint\" cargo check -p csv-runtime --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo check -p csv-sdk --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo check -p csv-cli --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo test -p csv-cli cross_chain:: --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo test -p csv-runtime --all-features"
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

`csv-runtime/src/transfer_coordinator.rs` exposes
`TransferCoordinator::settlement_evidence(&self, sanad_id: &csv_hash::SanadId)`
and `TransferCoordinator::settlement_status(&self, sanad_id: &csv_hash::SanadId)`,
built under TRM-OPER-001 to give operators a read path over recorded
`SettlementEvidence`/`SettlementStatus`. A workspace-wide grep for
`settlement_evidence(` and `settlement_status(` shows every call site is inside
`transfer_coordinator.rs` itself (internal helpers and its own test module) —
there are zero callers anywhere in `csv-sdk` or `csv-cli`.

The operator runbook at `csv-docs/runbooks/OPERATOR_MINT_BTC_ETH.md` already
references this path directly at the source level — e.g. "(`TransferCoordinator::settlement_evidence`). Check status:" — as if an operator
is expected to call it, but there is no CLI command that reaches it. The
existing `csv cross-chain status <transfer_id>` command
(`csv-cli/src/commands/cross_chain/status.rs::cmd_status`) only reads local
display-cache state (`UnifiedStateManager`), explicitly labeled "non-canonical"
in its own output, and does not touch the runtime's settlement event store at
all.

## Why it matters

This is backend plumbing that landed correctly per TRM-OPER-001 but was never
given a CLI or SDK-facing entry point, so it is a real feature gap rather than
abandoned code. Operators following the runbook today would need to read Rust
source and construct their own `TransferCoordinator` call to answer "did this
transfer's settlement release or refund, and what evidence backs it?" — there
is no `csv` command that does it for them.

## Task

Add a CLI command that calls through to `settlement_evidence()`/
`settlement_status()` — for example `csv cross-chain settlement-status
<transfer_id>` or `<sanad_id>`, following the existing `CrossChainAction`
variant + `cmd_*` function convention in `csv-cli/src/commands/cross_chain/`
(see `Status`/`cmd_status` and `Retry`/`cmd_retry` in
`csv-cli/src/commands/cross_chain/mod.rs` and `status.rs` for the pattern).
Wire it through `csv-sdk` if that layer needs a corresponding accessor (check
`csv-sdk/src/transfers.rs` for the existing `TransferReceipt`/status accessors
this should sit alongside). Update
`csv-docs/runbooks/OPERATOR_MINT_BTC_ETH.md` to reference the real command
instead of (or in addition to) the raw `TransferCoordinator` method call, if
the runbook's current wording implies a CLI path that doesn't exist.

## Acceptance criteria

- [ ] A CLI command exists that lets an operator query settlement
      evidence/status for a transfer without reading source code.
- [ ] The command clearly distinguishes "no settlement evidence recorded yet"
      from "settlement released" vs. "settlement refunded" (the three states
      `SettlementStatus` already models), rather than collapsing them.
- [ ] The command does not fabricate or infer settlement state from local
      display cache — it reads through to `settlement_evidence()`/
      `settlement_status()` on the runtime's event store, consistent with the
      "CLI state is a display/discovery cache, chain/runtime state is
      authoritative" rule this codebase follows elsewhere.
- [ ] Test covering the new command for a transfer with recorded settlement
      evidence, and a test covering a transfer with none.
- [ ] `csv-docs/runbooks/OPERATOR_MINT_BTC_ETH.md` is updated if it referenced
      a query path that did not previously exist in the CLI.
- [ ] All `verify_commands` pass.

## Notes

Do not add authority state to `csv-cli` to support this — `csv-cli` must
continue to hold no protocol authority state (leases/transfers) per this
repo's architecture rules; the new command should be a thin pass-through query
into `csv-runtime`, not a new local cache of settlement state.
