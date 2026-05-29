# Config/Data-Oriented Chain Addition Refactoring Plan

## Overview

Currently, adding a new chain (like CKB NERVOS CELL UTXO) to csv-protocol requires changes in approximately 12 places across the codebase. This creates high friction and makes ecosystem expansion difficult. This plan proposes a refactoring to make chain addition primarily config/data-oriented, minimizing code changes.

## Current Friction Points (12 Places)

When adding a new chain today, you must modify:

1. **csv-protocol**: Add chain-specific types and traits
2. **csv-adapters**: Create new adapter crate (csv-ckb)
3. **csv-coordinator/src/wallet.rs**: Add chain-specific wallet module
4. **csv-coordinator/Cargo.toml**: Add chain adapter dependency and feature
5. **csv-coordinator/src/lib.rs**: Export wallet module
6. **csv-runtime/src/wallet.rs**: Re-export coordinator wallet module
7. **csv-runtime/src/lib.rs**: Add wallet module
8. **csv-cli/src/commands/wallet/**: Add chain-specific wallet commands
9. **csv-cli/src/commands/sanads.rs**: Add chain-specific validation logic
10. **csv-cli/Cargo.toml**: Add coordinator feature for the chain
11. **chains/**: Add new chain config file (ckb.toml)
12. **csv-architecture/tests/architecture_guard.rs**: Update architecture tests

## Refactoring Goals

1. **Config-driven chain registration**: Chains should be registered via config files
2. **Dynamic feature loading**: Chain adapters should be loaded dynamically based on config
3. **Generic wallet operations**: Wallet operations should be generic, not chain-specific
4. **Minimal code changes**: Adding a chain should require only:
   - Chain config file
   - Adapter implementation
   - Optional: Chain-specific CLI overrides

## Proposed Architecture

### Phase 1: Chain Registry and Config

#### 1.1 Create Chain Registry

**New file**: `csv-protocol/src/chain_registry.rs`

```rust
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    pub chain_id: String,
    pub name: String,
    pub network_type: NetworkType,
    pub adapter_module: String,  // e.g., "csv_bitcoin"
    pub default_rpc_url: String,
    pub features: ChainFeatures,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkType {
    Utxo,
    Account,
    DataAvailability,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainFeatures {
    pub supports_seals: bool,
    pub supports_sanads: bool,
    pub supports_proofs: bool,
    pub utxo_model: bool,
    pub account_model: bool,
}

pub struct ChainRegistry {
    chains: HashMap<String, ChainConfig>,
}

impl ChainRegistry {
    pub fn load_from_config(config_path: &str) -> Result<Self>;
    pub fn get_chain(&self, chain_id: &str) -> Option<&ChainConfig>;
    pub fn register_chain(&mut self, config: ChainConfig);
}
```

#### 1.2 Chain Config Files

**Directory**: `chains/`

Each chain has a config file:

```toml
# chains/bitcoin.toml
[chain]
chain_id = "bitcoin"
name = "Bitcoin"
network_type = "Utxo"
adapter_module = "csv_bitcoin"
default_rpc_url = "https://blockstream.info/signet/api"

[features]
supports_seals = true
supports_sanads = true
supports_proofs = true
utxo_model = true
account_model = false

[wallet]
derivation_path_format = "m/86'/1'/{account}'/{index}'/{change}"
min_utxo_value = 10000
```

```toml
# chains/ckb.toml (new)
[chain]
chain_id = "ckb"
name = "Nervos CKB"
network_type = "Utxo"
adapter_module = "csv_ckb"
default_rpc_url = "https://testnet.ckb.dev"

[features]
supports_seals = true
supports_sanads = true
supports_proofs = true
utxo_model = true
account_model = false

[wallet]
derivation_path_format = "m/44'/309'/{account}'/{index}'/{change}"
min_utxo_value = 61  # CKB has different dust limit
```

### Phase 2: Generic Wallet Operations

#### 2.1 Abstract Wallet Traits

**New file**: `csv-coordinator/src/wallet_traits.rs`

```rust
use anyhow::Result;

#[async_trait::async_trait]
pub trait WalletOperations {
    async fn derive_address(&self, seed: &[u8], account: u32, index: u32) -> Result<String>;
    async fn scan_utxos(&self, seed: &[u8], account: u32, gap_limit: usize, rpc_url: &str) -> Result<Vec<Utxo>>;
    async fn validate_utxo(&self, txid: &str, vout: u32, rpc_url: &str) -> Result<UtxoStatus>;
}

pub struct Utxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub scriptpubkey: Option<String>,
}

pub struct UtxoStatus {
    pub exists: bool,
    pub confirmed: bool,
    pub unspent: bool,
}
```

#### 2.2 Chain-Specific Implementations

**File**: `csv-coordinator/src/wallet/mod.rs`

```rust
pub mod bitcoin;
pub mod ethereum;
pub mod sui;
pub mod aptos;
pub mod ckb;  // New

use std::sync::Arc;
use std::collections::HashMap;

pub struct WalletFactory {
    implementations: HashMap<String, Arc<dyn WalletOperations>>,
}

impl WalletFactory {
    pub fn new() -> Self {
        let mut implementations = HashMap::new();
        
        // Register implementations
        #[cfg(feature = "bitcoin")]
        implementations.insert("bitcoin".to_string(), Arc::new(bitcoin::BitcoinWallet::new()));
        
        #[cfg(feature = "ethereum")]
        implementations.insert("ethereum".to_string(), Arc::new(ethereum::EthereumWallet::new()));
        
        #[cfg(feature = "ckb")]
        implementations.insert("ckb".to_string(), Arc::new(ckb::CkbWallet::new()));
        
        Self { implementations }
    }
    
    pub fn get_wallet(&self, chain_id: &str) -> Option<Arc<dyn WalletOperations>> {
        self.implementations.get(chain_id).cloned()
    }
}
```

### Phase 3: Dynamic Feature Loading

#### 3.1 Feature Flag Management

**File**: `csv-coordinator/Cargo.toml`

```toml
[features]
default = []
bitcoin = ["dep:csv-bitcoin"]
ethereum = ["dep:csv-ethereum"]
sui = ["dep:csv-sui"]
aptos = ["dep:csv-aptos"]
ckb = ["dep:csv-ckb"]  # New
all = ["bitcoin", "ethereum", "sui", "aptos", "ckb"]
```

#### 3.2 Runtime Chain Discovery

**File**: `csv-runtime/src/chain_discovery.rs`

```rust
use csv_protocol::chain_registry::ChainRegistry;

pub struct ChainDiscovery {
    registry: ChainRegistry,
}

impl ChainDiscovery {
    pub fn discover_chains(config_dir: &str) -> Result<Vec<ChainConfig>> {
        // Load all .toml files from chains/ directory
        // Parse each as ChainConfig
        // Return list of available chains
    }
    
    pub fn load_chain_adapter(&self, chain_id: &str) -> Result<Box<dyn ChainAdapter>> {
        let config = self.registry.get_chain(chain_id)?;
        // Dynamically load adapter based on config.adapter_module
        // This requires dynamic loading or conditional compilation
    }
}
```

### Phase 4: Generic CLI Commands

#### 4.1 Chain-Agnostic Wallet Commands

**File**: `csv-cli/src/commands/wallet/mod.rs`

```rust
use csv_coordinator::wallet::WalletFactory;
use csv_protocol::chain_registry::ChainRegistry;

pub async fn cmd_scan(
    chain: &str,
    account: u32,
    index: u32,
    state: &mut UnifiedStateManager,
) -> Result<()> {
    // Load chain config
    let registry = ChainRegistry::load_from_config("chains/")?;
    let chain_config = registry.get_chain(chain)?;
    
    // Get wallet implementation
    let factory = WalletFactory::new();
    let wallet = factory.get_wallet(chain)
        .ok_or_else(|| anyhow::anyhow!("Chain {} not supported", chain))?;
    
    // Perform wallet operations
    let seed = state.storage.wallet.seed.as_ref()
        .ok_or_else(|| anyhow::anyhow!("No seed found"))?;
    
    let utxos = wallet.scan_utxos(seed, account, 20, &chain_config.default_rpc_url).await?;
    
    // Store UTXOs
    for utxo in utxos {
        state.storage.wallet.utxos.push(UtxoRecord {
            txid: utxo.txid,
            vout: utxo.vout,
            value: utxo.value,
            account,
            index,
        });
    }
    
    state.save()?;
    
    Ok(())
}
```

### Phase 5: Minimal Chain Addition

After refactoring, adding CKB would require:

- **Create adapter** (one-time):

```bash
csv-adapters/csv-ckb/
```

- **Add config file**:

```toml
# chains/ckb.toml
[chain]
chain_id = "ckb"
name = "Nervos CKB"
network_type = "Utxo"
adapter_module = "csv_ckb"
default_rpc_url = "https://testnet.ckb.dev"
...
```

- **Add feature flag** (one-time):

```toml
# csv-coordinator/Cargo.toml
ckb = ["dep:csv-ckb"]
```

- **Enable in CLI** (optional):

```toml
# csv-cli/Cargo.toml
csv-coordinator = { path = "../csv-coordinator", features = ["bitcoin", "ethereum", "ckb"] }
```

**No code changes required** in CLI, runtime, or coordinator for basic functionality!

## Implementation Steps

### Step 1: Create Chain Registry (csv-protocol)

- [ ] Create `csv-protocol/src/chain_registry.rs`
- [ ] Define ChainConfig, NetworkType, ChainFeatures
- [ ] Implement ChainRegistry with config loading
- [ ] Add to csv-protocol/Cargo.toml: `toml = "0.8"`
- [ ] Update csv-protocol/src/lib.rs

### Step 2: Create Generic Wallet Traits (csv-coordinator)

- [ ] Create `csv-coordinator/src/wallet_traits.rs`
- [ ] Define WalletOperations trait
- [ ] Define Utxo, UtxoStatus structs
- [ ] Create WalletFactory

### Step 3: Refactor Existing Wallet Implementations

- [ ] Refactor bitcoin wallet to implement WalletOperations
- [ ] Refactor ethereum wallet to implement WalletOperations
- [ ] Refactor sui wallet to implement WalletOperations
- [ ] Refactor aptos wallet to implement WalletOperations

### Step 4: Migrate Chain Configs

- [ ] Convert existing chains/*.toml to new format
- [ ] Add chain-specific config sections (wallet, features, etc.)
- [ ] Test config loading

### Step 5: Refactor CLI Commands

- [ ] Update wallet commands to use WalletFactory
- [ ] Update sanads commands to use generic validation
- [ ] Remove chain-specific code from CLI

### Step 6: Add CKB as Test Case

- [ ] Create csv-adapters/csv-ckb stub
- [ ] Add chains/ckb.toml config
- [ ] Implement minimal WalletOperations for CKB
- [ ] Test CKB wallet operations

### Step 7: Documentation

- [ ] Update README with new chain addition process
- [ ] Create chain addition guide
- [ ] Update AGENTS.md with new architecture

## Migration Strategy

### Backward Compatibility

- Keep existing chain-specific code during migration
- Gradually migrate chains to new system
- Deprecate old interfaces after migration complete

### Testing

- Test Bitcoin with new system first
- Test Ethereum, Sui, Aptos
- Test CKB as new chain
- Ensure all existing functionality works

### Rollback

- Keep old code behind feature flags
- Can revert if issues arise
- Document migration issues

## Benefits

1. **Reduced friction**: Adding a chain requires 3-4 changes instead of 12
2. **Config-driven**: Most chain behavior defined in config files
3. **Extensible**: Easy to add new chains without touching core code
4. **Maintainable**: Chain-specific code isolated in adapters
5. **Testable**: Can test new chains without affecting existing ones

## Risks and Mitigations

### Risk: Dynamic loading complexity

**Mitigation**: Use conditional compilation initially, consider dynamic loading later

### Risk: Config file errors

**Mitigation**: Add config validation, provide clear error messages

### Risk: Performance overhead

**Mitigation**: Cache chain configs, lazy load adapters

### Risk: Breaking existing chains

**Mitigation**: Thorough testing, gradual migration, feature flags

## Estimated Effort

- Phase 1 (Chain Registry): 4-6 hours
- Phase 2 (Generic Wallet Traits): 6-8 hours
- Phase 3 (Dynamic Feature Loading): 4-6 hours
- Phase 4 (Generic CLI Commands): 6-8 hours
- Phase 5 (Refactor Existing): 8-12 hours
- Phase 6 (CKB Test Case): 8-12 hours
- Phase 7 (Documentation): 4-6 hours

**Total**: 40-58 hours (1-2 weeks)

## Next Steps

1. Review and approve this plan
2. Start with Phase 1 (Chain Registry)
3. Test with Bitcoin first
4. Gradually migrate other chains
5. Add CKB as validation of new system
