---
id: C-CLI-WALLET-002
title: "Implement wallet operations for chains that return 'not available'"
theme: C
crate: csv-cli
priority: P2
security_critical: false
model_hint: sonnet
status: open
context_radius: 25
agent_md: csv-cli/.agents/AGENT.md
target_file: csv-cli/src/commands/wallet/generate.rs
target_patterns:
  - "Wallet operations not available for"
interface_files:
  - csv-cli/src/commands/wallet/mod.rs
  - csv-wallet/src/wallet_traits.rs
verify_commands:
  - "cargo check -p csv-cli"
  - "cargo test -p csv-cli"
---

## Problem

`csv-cli/src/commands/wallet/generate.rs` has stubs that return "Wallet operations not available for {chain}" for multiple chains:
- Line 171: Fallback to csv-wallet if factory not available
- Line 240: Bitcoin wallet operations not available
- Line 284: Other chain wallet operations not available

## Why it matters

Users cannot generate wallets for these chains via CLI. The CLI is incomplete without wallet generation support.

## Task

Wire the CLI wallet generation commands to the csv-wallet crate. Check if `csv-wallet` already supports wallet generation for these chains and wire the CLI to use it.

If csv-wallet doesn't support a chain, return a typed error with a clear message indicating which chain is not supported.

## Acceptance criteria

- [ ] Wallet generation works for chains supported by csv-wallet
- [ ] Unsupported chains return a typed error (not a generic "not available")
- [ ] All "Wallet operations not available" errors are removed or replaced with typed errors
- [ ] `cargo check -p csv-cli` passes
- [ ] `cargo test -p csv-cli` passes

## Notes

Check which chains csv-wallet supports. The wallet_operations.rs stubs (fixed by A-ADAPTER-WALLETOPS-001) may affect this.
