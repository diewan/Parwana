---
id: X-CROSS-BOUNDARY-001
title: "Wire offchain 'not implemented' stubs to existing contract functions"
theme: X
crate: csv-adapters
priority: P1
security_critical: true
model_hint: opus
status: open
context_radius: 30
agent_md: csv-adapters/.agents/AGENT.md
target_file: csv-adapters/csv-ethereum/src/ops.rs
target_patterns:
  - "This is a simplified implementation - in production, call getSanadState on the contract"
  - "This is a simplified implementation"
target_file_2: csv-adapters/csv-ethereum/src/seal_protocol.rs
target_patterns_2:
  - "// For now, skip on-chain verification"
target_file_3: csv-adapters/csv-solana/src/ops.rs
target_patterns_3:
  - "This is a simplified implementation"
target_file_4: csv-adapters/csv-sui/src/ops.rs
target_patterns_4:
  - "Simplified since we don't have checkpoint from sign_and_execute"
target_file_5: csv-adapters/csv-bitcoin/src/ops.rs
target_patterns_5:
  - "This is a simplified implementation"
contract_files:
  - csv-contracts/ethereum/contracts/src/CSVSeal.sol
cross_boundary_check: true
interface_files:
  - csv-protocol/src/seal_protocol.rs
  - csv-adapters/csv-ethereum/src/verifier.rs
verify_commands:
  - "cargo check -p csv-ethereum"
  - "cargo check -p csv-solana"
  - "cargo check -p csv-sui"
  - "cargo check -p csv-bitcoin"
  - "cargo test -p csv-ethereum"
  - "cargo test -p csv-solana"
  - "cargo test -p csv-sui"
  - "cargo test -p csv-bitcoin"
---

## Problem

Multiple adapters have `ops.rs` files with simplified implementations that should call contract functions but instead return placeholder data:

**Ethereum** (`csv-ethereum/src/ops.rs`):
- `get_sanad_state()` returns hardcoded `state: 1, Created` instead of calling `contract.get_sanad_state()`
- `get_seal_state()` returns hardcoded data instead of calling `contract.get_seal_state()`

**Solana** (`csv-solana/src/ops.rs`):
- `get_sanad_state()` returns simplified data instead of querying the on-chain program

**Sui** (`csv-sui/src/ops.rs`):
- `get_sanad_state()` returns simplified data instead of calling Sui view functions

**Bitcoin** (`csv-bitcoin/src/ops.rs`):
- `get_sanad_state()` returns simplified data instead of querying the blockchain

**Ethereum seal_protocol** (`csv-ethereum/src/seal_protocol.rs`):
- Skips on-chain verification with "// For now, skip on-chain verification"

## Why it matters

These stubs make the CLI useless:
- `csv sanad show <id>` returns fake data instead of real on-chain state
- `csv seal verify <ref>` doesn't actually verify against the contract
- Users cannot trust any CLI output because it's not connected to the contract

The Ethereum contract `CSVSeal.sol` already has all the view functions needed:
- `get_sanad_state(bytes32)` — returns full SanadStateView
- `get_seal_state(bytes32)` — returns full SealStateView
- `is_seal_available(bytes32)` — returns bool
- `is_seal_consumed(bytes32)` — returns bool
- `can_refund(bytes32)` — returns bool

## Task

For each adapter, replace the simplified implementation with actual contract calls:

1. **Ethereum**: Call `CSVSealContract::get_sanad_state()` and `CSVSealContract::get_seal_state()` via the RPC provider. Parse the returned `SanadStateView` struct into the protocol's state type.

2. **Solana**: Query the Solana program's account data for sanad/seal state. Parse the on-chain account struct.

3. **Sui**: Call Sui view functions (e.g., `get_sanad_state`) via the Sui RPC. Parse the returned Move struct.

4. **Bitcoin**: Query the Bitcoin blockchain for relevant data (or return a typed error if Bitcoin doesn't have a smart contract layer).

5. **Ethereum seal_protocol**: Wire `verify_seal_registry` to call `contract.is_seal_consumed()` or `contract.is_seal_available()`.

## Acceptance criteria

- [ ] `get_sanad_state()` in each adapter calls the contract/view function and returns real on-chain state
- [ ] `get_seal_state()` in each adapter calls the contract/view function and returns real on-chain state
- [ ] `is_seal_available()` / `is_seal_consumed()` calls are wired to contract functions
- [ ] Ethereum seal protocol verification calls `contract.is_seal_consumed()` instead of skipping
- [ ] No hardcoded `state: 1, Created` or similar placeholder data remains
- [ ] All "simplified implementation" and "skip on-chain verification" comments are removed
- [ ] `cargo check` passes for all 4 adapter crates
- [ ] `cargo test` passes for all 4 adapter crates
- [ ] CLI command `csv sanad show <id>` returns real on-chain state (manual test)

## Notes

The Ethereum contract `CSVSeal.sol` is at `csv-contracts/ethereum/contracts/src/CSVSeal.sol`. It has comprehensive view functions. The Rust bindings are auto-generated from the ABI — check if they exist in `csv-contract-bindings/`. If not, generate them from the contract ABI.

For Solana/Sui, check if the SDK provides view function wrappers. If not, add them to the adapter's RPC client.
