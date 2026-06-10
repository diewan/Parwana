# Config/Data-Oriented Chain Addition Plan

**Last validated:** 2025-06-09
**Status:** Partially implemented — chain registry exists, wallet factory and chain discovery are pending.

## Overview

Adding a new chain currently requires changes across multiple crates. This plan proposes making chain addition primarily config-driven, minimizing code changes.

## Current State

### What's Implemented

1. **Chain Registry** — `csv-protocol/src/chain_registry.rs` (324 lines)
   - `ChainConfig` struct with chain_id, chain_name, rpc_endpoints, block_explorer_urls, start_block, network_type, features, finality_guarantee, wallet, custom_settings
   - `ChainRegistry` with `load_from_dir()`, `register_chain()`, `get_chain()`, `chain_ids()`, `all_chains()`, `has_chain()`, `len()`, `is_empty()`
   - `ChainFeatures`, `FinalityGuarantee`, `WalletConfig`, `NetworkType` types

2. **Chain Config Files** — `chains/` directory exists with TOML configs:
   - `ethereum.toml`, `ethereum-sepolia.toml`, `aptos-testnet.toml`, `sui-testnet.toml`, `solana-devnet.toml`, `bitcoin-signet.toml`
   - Format uses flat top-level keys (`chain_id`, `chain_name`, etc.) and sections `[finality_guarantee]`, `[capabilities]`, `[custom_settings]`

3. **SanadStateReader Trait** — All 5 chain adapters implement the trait (`csv-protocol/src/backend.rs:548-557`)

4. **CanonicalSanadState** — Defined in `csv-store/src/state/domain.rs` for CLI/display use

### What's NOT Implemented

1. **WalletFactory** — No `WalletFactory` struct with HashMap-based registration exists
2. **WalletOperations trait** — No `wallet_traits.rs` with generic wallet operations
3. **ChainDiscovery** — `csv-runtime/src/chain_discovery.rs` does not exist (but `csv_protocol::chain_discovery::ChainDiscovery` is referenced in CLI — broken import)
4. **Generic CLI wallet commands** — Commands are chain-specific, using submodules in `csv-coordinator/src/wallet.rs`
5. **Dynamic feature loading** — Chain adapters loaded via conditional compilation, not config-driven

## Current Friction Points

When adding a new chain today, you must modify:

1. **csv-adapters/** — Create new adapter crate (csv-ckb)
2. **csv-coordinator/src/wallet.rs** — Add chain-specific wallet module
3. **csv-coordinator/Cargo.toml** — Add chain adapter dependency and feature
4. **csv-runtime/src/wallet.rs** — Re-export coordinator wallet module
5. **csv-cli/src/commands/wallet/** — Add chain-specific wallet commands
6. **csv-cli/Cargo.toml** — Add coordinator feature for the chain
7. **chains/** — Add new chain config file (already partially supported via chain_registry)
8. **csv-architecture/tests/architecture_guard.rs** — Update architecture tests

## Proposed Architecture (Remaining Work)

### Phase 1: Chain Registry and Config (DONE)

`csv-protocol/src/chain_registry.rs` exists with `ChainConfig`, `ChainRegistry`, `ChainFeatures`, `FinalityGuarantee`, `WalletConfig`, `NetworkType`.

### Phase 2: Generic Wallet Operations (PENDING)

**To implement:**

1. **`csv-wallet/src/wallet_traits.rs`** — Generic wallet operations trait:
   ```rust
   #[async_trait::async_trait]
   pub trait WalletOperations {
       async fn derive_address(&self, seed: &[u8], account: u32, index: u32) -> Result<String>;
       async fn scan_utxos(&self, seed: &[u8], account: u32, gap_limit: usize, rpc_url: &str) -> Result<Vec<Utxo>>;
       async fn validate_utxo(&self, txid: &str, vout: u32, rpc_url: &str) -> Result<UtxoStatus>;
   }
   ```

2. **`csv-coordinator/src/wallet_factory.rs`** — HashMap-based registration:
   ```rust
   pub struct WalletFactory {
       implementations: HashMap<String, Arc<dyn WalletOperations>>,
   }
   impl WalletFactory {
       pub fn new() -> Self { /* register all feature-gated implementations */ }
       pub fn get_wallet(&self, chain_id: &str) -> Option<Arc<dyn WalletOperations>>;
   }
   ```

3. **`csv-runtime/src/chain_discovery.rs`** — Load chain configs from `chains/` directory:
   ```rust
   pub struct ChainDiscovery {
       registry: ChainRegistry,
   }
   impl ChainDiscovery {
       pub fn discover_chains(config_dir: &str) -> Result<Vec<ChainConfig>>;
       pub fn load_chain_adapter(&self, chain_id: &str) -> Result<Box<dyn ChainAdapter>>;
   }
   ```

### Phase 3: Generic CLI Commands (PENDING)

Update CLI wallet commands to use `WalletFactory` instead of chain-specific submodules.

### Phase 4: Remove Broken Imports (PENDING)

Fix the broken import of `csv_protocol::chain_discovery::ChainDiscovery` in CLI. Either:
- Implement `chain_discovery.rs` in csv-protocol, OR
- Remove the reference from CLI

## Implementation Priority

1. **Fix broken import** — Remove or implement `chain_discovery` reference in CLI
2. **Implement WalletOperations trait** — Generic wallet interface
3. **Implement WalletFactory** — HashMap-based registration
4. **Implement ChainDiscovery** — Config-driven chain loading
5. **Refactor CLI wallet commands** — Use WalletFactory instead of chain-specific code
6. **Add CKB as test case** — Validate new chain addition with minimal code changes

## Benefits (When Complete)

1. **Reduced friction**: Adding a chain requires config file + adapter implementation instead of 8+ code changes
2. **Config-driven**: Most chain behavior defined in config files
3. **Extensible**: Easy to add new chains without touching core code
4. **Maintainable**: Chain-specific code isolated in adapters
5. **Testable**: Can test new chains without affecting existing ones

## Estimated Effort

- Fix broken import: 1-2 hours
- Implement WalletOperations trait: 4-6 hours
- Implement WalletFactory: 4-6 hours
- Implement ChainDiscovery: 4-6 hours
- Refactor CLI wallet commands: 6-8 hours
- Add test chain: 4-6 hours

**Total: 25-34 hours (3-4 days)**
