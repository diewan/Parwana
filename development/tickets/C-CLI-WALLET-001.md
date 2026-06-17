---
id: C-CLI-WALLET-001
title: "Track actual derivation index in CLI wallet UTXO display"
theme: C
crate: csv-cli
priority: P3
security_critical: false
model_hint: sonnet
status: open
context_radius: 20
agent_md: csv-cli/.agents/AGENT.md
target_file: csv-cli/src/commands/wallet/mod.rs
target_patterns:
  - "index: 0, // TODO: track actual index from derivation_path"
interface_files:
  - csv-store/src/state/wallet.rs
verify_commands:
  - "cargo check -p csv-cli"
  - "cargo test -p csv-cli"
---

## Problem

`csv-cli/src/commands/wallet/mod.rs` stores UTXOs with `index: 0` hardcoded, with a TODO comment: "track actual index from derivation_path". The derivation path format is `m/86'/1'/{}'/0/0` where the last component (`0`) is the address index, but this value is not extracted and stored.

## Why it matters

While this is a low-priority issue (the index is always 0 in the current derivation path format), it means:
- UTXO records don't track which derivation index they correspond to
- If the derivation path format changes, UTXO records won't reflect the correct index
- It's a technical debt item that should be resolved before production

## Task

Extract the address index from the derivation path and store it in the `UtxoRecord`. The derivation path format is `m/86'/1'/{}'/0/0` where:
- `86'` = purpose (BIP-86 for taproot)
- `1'` = coin type (testnet)
- `{}` = account (variable)
- `0` = change (external chain)
- `0` = address index (variable)

Parse the last component as the address index and store it.

## Acceptance criteria

- [ ] UTXO records store the actual address index from the derivation path
- [ ] The `index` field is no longer hardcoded to `0`
- [ ] The TODO comment is removed
- [ ] `cargo check -p csv-cli` passes
- [ ] `cargo test -p csv-cli` passes

## Notes

The derivation path is constructed as `format!("m/86'/1'/{}'/0/0", account)`. The last `0` is the address index. Parse this from the path string or track it as a separate variable before formatting.
