---
id: A-BTC-ADAPTER-001
title: "Replace bitcoin adapter_impl.rs placeholder returns with proper fail-closed errors"
theme: A
crate: csv-adapters/csv-bitcoin
priority: P1
security_critical: true
model_hint: opus
status: open
context_radius: 25
agent_md: csv-adapters/csv-bitcoin/.agents/AGENT.md
target_file: csv-adapters/csv-bitcoin/src/adapter_impl.rs
target_patterns:
  - "Ok(true) // Placeholder - actual implementation would use existing verification"
  - "Ok(Hash::new([0u8; 32])) // Placeholder - actual implementation would use existing mint"
  - "Ok(MintStatus::Pending) // Placeholder - actual implementation would check RPC"
  - "Ok(0) // Placeholder - actual implementation would call RPC"
  - "Ok(TransactionStatus::Pending) // Placeholder - actual implementation would check RPC"
  - "Ok(Hash::new([0u8; 32])) // Placeholder - actual implementation would broadcast"
interface_files:
  - csv-adapters/csv-bitcoin/src/ops.rs
  - csv-adapters/csv-bitcoin/src/rpc.rs
  - csv-adapter-core/src/lib.rs
verify_commands:
  - "cargo check -p csv-bitcoin"
  - "cargo test -p csv-bitcoin"
---

## Problem

`csv-adapters/csv-bitcoin/src/adapter_impl.rs` implements `ProofAdapter`, `MintAdapter`, and `ChainOps` traits but all methods return hardcoded placeholder values:
- `verify_proof_bundle` returns `Ok(true)` — always passes
- `mint_commitment` returns `Hash::new([0u8; 32])` — zero hash
- `get_mint_status` returns `MintStatus::Pending` — always pending
- `get_mint_receipt` returns a receipt with `block_number: 0, timestamp: 0, gas_used: 0`
- `get_chain_height` returns `0`
- `get_balance` returns `0`
- `get_transaction_status` returns `TransactionStatus::Pending`
- `broadcast_transaction` returns `Hash::new([0u8; 32])`

This is a security-critical issue: the adapter claims all operations succeed when they actually do nothing.

## Why it matters

This adapter is used by the runtime to interact with Bitcoin. Placeholder returns mean:
- Proof verification always passes (no actual verification)
- Mint operations appear to succeed with zero hashes
- Balance/height queries return zero
- Transaction broadcasts appear to succeed

This violates the AGENTS.md rule: "No placeholder verification may remain in production paths" and "No fabricated blockchain state."

## Task

Replace all 8 placeholder returns with proper fail-closed errors. Since the `BitcoinAdapter` holds an `Arc<dyn BitcoinRpc>`, the methods should delegate to the RPC interface. If the RPC is unavailable or returns an error, propagate it. Do NOT return hardcoded values.

If the RPC trait methods are not yet implemented, add them to the trait with proper error types and return `Err` from the adapter methods indicating the RPC is not configured.

## Acceptance criteria

- [ ] `verify_proof_bundle` delegates to existing proof verification logic (from `proofs.rs`) or returns a typed error
- [ ] `mint_commitment` delegates to existing mint logic or returns a typed error
- [ ] `get_mint_status` queries RPC or returns a typed error
- [ ] `get_mint_receipt` queries RPC or returns a typed error
- [ ] `get_chain_height` queries RPC or returns a typed error
- [ ] `get_balance` queries RPC or returns a typed error
- [ ] `get_transaction_status` queries RPC or returns a typed error
- [ ] `broadcast_transaction` queries RPC or returns a typed error
- [ ] No hardcoded `Ok(0)`, `Ok(true)`, `Ok(Hash::new([0u8; 32]))`, or `Ok(MintStatus::Pending)` remains
- [ ] `cargo check -p csv-bitcoin` passes
- [ ] `cargo test -p csv-bitcoin` passes

## Notes

The existing `csv-adapters/csv-bitcoin/src/ops.rs` has production-grade implementations. The `adapter_impl.rs` file appears to be a thin wrapper that should delegate to those. Check if `ops.rs` methods can be reused.
