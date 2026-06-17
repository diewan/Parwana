---
id: A-ADAPTER-WALLETOPS-001
title: "Replace wallet_operations.rs stubs with proper fail-closed errors across all adapters"
theme: A
crate: csv-adapters
priority: P2
security_critical: false
model_hint: sonnet
status: open
context_radius: 20
agent_md: csv-adapters/.agents/AGENT.md
target_file: csv-adapters/csv-aptos/src/wallet_operations.rs
target_patterns:
  - "// This would require RPC client - for now return placeholder"
  - "// This is a placeholder - real implementation would use Aptos SDK"
target_file_2: csv-adapters/csv-ethereum/src/wallet_operations.rs
target_patterns_2:
  - "// This would require RPC client - for now return placeholder"
  - "// This is a placeholder - real implementation would use EIP-2718 typed transactions"
target_file_3: csv-adapters/csv-solana/src/wallet_operations.rs
target_patterns_3:
  - "// This would require RPC client - for now return placeholder"
  - "// This is a placeholder - real implementation would use Solana SDK"
target_file_4: csv-adapters/csv-sui/src/wallet_operations.rs
target_patterns_4:
  - "// This would require RPC client - for now return placeholder"
  - "// This is a placeholder - real implementation would use Sui SDK"
target_file_5: csv-adapters/csv-bitcoin/src/wallet_operations.rs
target_patterns_5:
  - "// This would require RPC client - for now return placeholder"
  - "// This is a placeholder - real implementation would use PSBT signing"
interface_files:
  - csv-wallet/src/wallet_traits.rs
  - csv-wallet/src/error.rs
verify_commands:
  - "cargo check -p csv-aptos"
  - "cargo check -p csv-ethereum"
  - "cargo check -p csv-solana"
  - "cargo check -p csv-sui"
  - "cargo check -p csv-bitcoin"
  - "cargo test -p csv-aptos"
  - "cargo test -p csv-ethereum"
  - "cargo test -p csv-solana"
  - "cargo test -p csv-sui"
  - "cargo test -p csv-bitcoin"
---

## Problem

All 6 chain adapters have `wallet_operations.rs` files with identical stub patterns:
- `get_balance()` returns `"0"` with a "for now return placeholder" comment
- `sign_transaction()` returns `SigningFailed` with a "placeholder" comment
- `broadcast_transaction()` returns `SigningFailed` with a "placeholder" comment
- `get_transaction_status()` returns `{"status": "unknown"}` with a "placeholder" comment

Each adapter has 4 stub methods (16 total across 6 adapters) with identical structure but chain-specific comment text.

## Why it matters

These stubs silently return fake data (`"0"` balance, `"unknown"` status) which can mislead callers into thinking operations succeeded. The wallet traits contract expects real data or typed errors, not placeholder responses.

## Task

Replace all 4 stub methods in each adapter's `wallet_operations.rs` with proper fail-closed errors. Use `WalletError::RpcNotConfigured` or a similar typed error that clearly indicates the RPC backend is not available. Do NOT return fake data. The pattern is identical across all 6 adapters — fix them all in one session.

## Acceptance criteria

- [ ] All `get_balance()` methods return a typed error (e.g., `RpcNotConfigured`) instead of `"0"`
- [ ] All `sign_transaction()` methods return a typed error instead of a hardcoded `SigningFailed` message
- [ ] All `broadcast_transaction()` methods return a typed error instead of a hardcoded `SigningFailed` message
- [ ] All `get_transaction_status()` methods return a typed error instead of `{"status": "unknown"}`
- [ ] All "for now return placeholder" and "This is a placeholder" comments are removed
- [ ] `cargo check` passes for all 6 adapter crates
- [ ] `cargo test` passes for all 6 adapter crates

## Notes

The `derive_address()` method is already implemented and should NOT be touched. Only the 4 async methods need fixing. Each adapter's error message should mention the specific chain name (e.g., "Ethereum RPC not configured" vs "Solana RPC not configured").
