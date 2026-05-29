# Chain Migration to Runtime Plan

## Overview

This document outlines the migration plan for moving chain-specific wallet and sanad operations from the CLI to the runtime/coordinator layer, following the architecture established during the Bitcoin migration.

## Background

The Bitcoin chain has been successfully migrated from direct CLI chain adapter usage to the runtime/coordinator architecture. This pattern should be replicated for other chains (Ethereum, Sui, Aptos, Celestia).

## Architecture Principles

1. **CLI**: No direct chain adapter dependencies. Uses csv-runtime/csv-coordinator for all chain operations.
2. **csv-runtime**: Re-exports coordinator operations. No direct chain adapter dependencies.
3. **csv-coordinator**: Can depend on chain adapters. Provides chain-specific wallet operations.
4. **Authority crates** (csv-cli, csv-runtime, csv-protocol): Must NOT depend on chain adapters.

## Migration Status

### Completed

- ✅ Bitcoin: Wallet operations (derive address, scan UTXOs with wallet integration) moved to csv-coordinator
- ✅ Bitcoin: UTXO validation moved to csv-coordinator
- ✅ Bitcoin: CLI uses csv-coordinator for all Bitcoin operations
- ✅ Ethereum: Wallet operations (derive address) moved to csv-coordinator
- ✅ Sui: Wallet operations (derive address) moved to csv-coordinator
- ✅ Aptos: Wallet operations (derive address) moved to csv-coordinator
- ✅ Solana: Wallet operations (derive address) moved to csv-coordinator
- ✅ Architecture compliance: No direct chain adapter dependencies in CLI/runtime
- ✅ CLI uses csv-coordinator for all chain wallet operations
- ✅ Private key derivation fixed: Using BIP-44 chain-specific keys instead of raw seed
- ✅ Sui signing key configuration: Ed25519 SigningKey properly configured
- ✅ Sui signer address configuration: Signer address derived and set on RPC client
- ✅ Aptos signing key configuration: Ed25519 SigningKey properly configured

### Pending

- ⏳ Celestia: Not yet implemented in codebase
- ⏳ Contract deployment: Seal contracts need to be deployed on testnets for sanad creation to work

## Migration Steps per Chain

For each chain (Ethereum, Sui, Aptos, Celestia):

### Step 1: Add Chain Wallet Module to csv-coordinator

**File**: `csv-coordinator/src/wallet.rs`

Add chain-specific wallet module with:

- `derive_funding_address(seed, network, account, index) -> Result<String>`
- `scan_utxos_with_wallet(seed, network, account, gap_limit, rpc_url) -> Result<(Wallet, Vec<WalletUtxo>)>`
- `validate_utxo_onchain(txid, vout, rpc_url) -> Result<(bool, bool, bool, Option<Value>)>` (if applicable)

**Dependencies to add to csv-coordinator/Cargo.toml**:

```toml
[dependencies]
csv-ethereum = { path = "../csv-adapters/csv-ethereum", optional = true }
csv-sui = { path = "../csv-adapters/csv-sui", optional = true }
csv-aptos = { path = "../csv-adapters/csv-aptos", optional = true }
csv-celestia = { path = "../csv-adapters/csv-celestia", optional = true }

[features]
ethereum = ["csv-ethereum"]
sui = ["csv-sui"]
aptos = ["csv-aptos"]
celestia = ["csv-celestia"]
```

### Step 2: Update csv-coordinator lib.rs

**File**: `csv-coordinator/src/lib.rs`

Add wallet module exports:

```rust
pub mod wallet;
```

### Step 3: Update csv-runtime to Re-export Coordinator

**File**: `csv-runtime/src/wallet.rs` (create if doesn't exist)

Re-export coordinator wallet operations:

```rust
pub use csv_coordinator::wallet;
```

**File**: `csv-runtime/src/lib.rs`

Add wallet module:

```rust
pub mod wallet;
```

### Step 4: Update CLI Commands

**Files to update**:

- `csv-cli/src/commands/wallet/mod.rs` (cmd_scan, cmd_fund_address)
- `csv-cli/src/commands/wallet/balance.rs` (cmd_balance)
- `csv-cli/src/commands/wallet/generate.rs` (generate_ethereum, generate_sui, generate_aptos)
- `csv-cli/src/commands/sanads.rs` (cmd_create validation logic)

**Changes**:

- Replace direct chain adapter imports with csv-coordinator calls
- Remove on-chain validation from CLI (let SDK/adapter handle it)
- Use csv-coordinator for address derivation and UTXO scanning

### Step 5: Update CLI Cargo.toml

**File**: `csv-cli/Cargo.toml`

Add coordinator features:

```toml
csv-coordinator = { path = "../csv-coordinator", features = ["bitcoin", "ethereum", "sui", "aptos", "celestia"] }
```

Remove direct chain adapter dependencies (if present):

```toml
# Remove these if they exist:
# csv-ethereum = { path = "../csv-adapters/csv-ethereum" }
# csv-sui = { path = "../csv-adapters/csv-sui" }
# csv-aptos = { path = "../csv-adapters/csv-aptos" }
# csv-celestia = { path = "../csv-adapters/csv-celestia" }
```

### Step 6: Update Architecture Test

**File**: `csv-architecture/tests/architecture_guard.rs`

Ensure csv-coordinator is allowed to depend on chain adapters (already done).

### Step 7: Build and Test

```bash
# Build
CXXFLAGS="-include cstdint" cargo build -p csv-coordinator
CXXFLAGS="-include cstdint" cargo build -p csv-runtime
CXXFLAGS="-include cstdint" cargo build -p csv-cli

# Run architecture tests
CXXFLAGS="-include cstdint" cargo test -p csv-architecture authority_crates_do_not_depend_on_chain_adapters
CXXFLAGS="-include cstdint" cargo test -p csv-cli test_no_reqwest_chain_operations
```

## Chain-Specific Considerations

### Ethereum

- Use csv-ethereum wallet for address derivation
- ERC-20 token support may need special handling
- Gas estimation and fee calculation should remain in SDK/adapter

### Sui

- Use csv-sui wallet for address derivation
- Sui Move objects may have different UTXO semantics
- Consider Sui-specific validation logic

### Aptos

- Use csv-aptos wallet for address derivation
- Aptos account model differs from Bitcoin UTXO model
- May need different scanning approach

### Celestia

- Use csv-celestia wallet for address derivation
- Celestia's data availability focus may require different validation

## Validation Checklist

For each chain migration:

- [ ] csv-coordinator has chain-specific wallet module
- [ ] csv-coordinator Cargo.toml has chain adapter dependency
- [ ] csv-coordinator lib.rs exports wallet module
- [ ] csv-runtime re-exports coordinator wallet module
- [ ] CLI commands use csv-coordinator instead of direct chain adapters
- [ ] CLI Cargo.toml has coordinator feature enabled
- [ ] CLI Cargo.toml has no direct chain adapter dependencies
- [ ] Architecture test passes
- [ ] Build succeeds
- [ ] CLI commands work correctly (manual testing)

## Rollback Plan

If issues arise during migration:

1. Revert CLI changes to use direct chain adapters
2. Disable coordinator feature in CLI Cargo.toml
3. Keep coordinator module for future migration
4. Document issues and root cause

## Estimated Effort

- Ethereum: 2-3 hours (similar complexity to Bitcoin)
- Sui: 2-3 hours (different account model, may need adjustments)
- Aptos: 2-3 hours (different account model, may need adjustments)
- Celestia: 2-3 hours (data availability focus, may need adjustments)

Total: ~8-12 hours for all chains

## References

- Bitcoin migration: See commits and changes in csv-coordinator/src/wallet.rs
- Architecture rules: See AGENTS.md and csv-architecture/tests/architecture_guard.rs
- CLI commands: See csv-cli/src/commands/wallet/ and csv-cli/src/commands/sanads.rs
