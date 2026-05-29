# RFC-0011: Config-Driven Chain Addition

## Status

Proposed

## Motivation

Currently, adding a new chain (like CKB NERVOS CELL UTXO) to csv-protocol requires changes in approximately 12 places across the codebase:

1. csv-protocol: Add chain-specific types and traits
2. csv-adapters: Create new adapter crate (csv-ckb)
3. csv-coordinator/src/wallet.rs: Add chain-specific wallet module
4. csv-coordinator/Cargo.toml: Add chain adapter dependency and feature
5. csv-coordinator/src/lib.rs: Export wallet module
6. csv-runtime/src/wallet.rs: Re-export coordinator wallet module
7. csv-runtime/src/lib.rs: Add wallet module
8. csv-cli/src/commands/wallet/**: Add chain-specific wallet commands
9. csv-cli/src/commands/sanads.rs: Add chain-specific validation logic
10. csv-cli/Cargo.toml: Add coordinator feature for the chain
11. chains/**: Add new chain config file (ckb.toml)
12. csv-architecture/tests/architecture_guard.rs: Update architecture tests

This creates high friction and makes ecosystem expansion difficult. Adding CKB or any other chain requires touching core code in multiple places, increasing the risk of errors and making maintenance harder.

## Proposed Change

### Phase 1: Chain Registry and Config

Create a chain registry system where chains are defined via config files:

**New file**: `csv-protocol/src/chain_registry.rs`

```rust
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    pub chain_id: String,
    pub name: String,
    pub network_type: NetworkType,
    pub adapter_module: String,
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

**Chain config files** in `chains/`:

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
# chains/ckb.toml
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
min_utxo_value = 61
```

### Phase 2: Generic Wallet Operations

Create abstract wallet traits to eliminate chain-specific code in CLI/runtime:

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

**Wallet factory** in `csv-coordinator/src/wallet/mod.rs`:

```rust
use std::sync::Arc;
use std::collections::HashMap;

pub struct WalletFactory {
    implementations: HashMap<String, Arc<dyn WalletOperations>>,
}

impl WalletFactory {
    pub fn new() -> Self {
        let mut implementations = HashMap::new();
        
        #[cfg(feature = "bitcoin")]
        implementations.insert("bitcoin".to_string(), Arc::new(bitcoin::BitcoinWallet::new()));
        
        #[cfg(feature = "ckb")]
        implementations.insert("ckb".to_string(), Arc::new(ckb::CkbWallet::new()));
        
        Self { implementations }
    }
    
    pub fn get_wallet(&self, chain_id: &str) -> Option<Arc<dyn WalletOperations>> {
        self.implementations.get(chain_id).cloned()
    }
}
```

### Phase 3: Chain-Agnostic CLI Commands

Refactor CLI commands to use generic wallet operations:

```rust
use csv_coordinator::wallet::WalletFactory;
use csv_protocol::chain_registry::ChainRegistry;

pub async fn cmd_scan(
    chain: &str,
    account: u32,
    index: u32,
    state: &mut UnifiedStateManager,
) -> Result<()> {
    let registry = ChainRegistry::load_from_config("chains/")?;
    let chain_config = registry.get_chain(chain)?;
    
    let factory = WalletFactory::new();
    let wallet = factory.get_wallet(chain)
        .ok_or_else(|| anyhow::anyhow!("Chain {} not supported", chain))?;
    
    let seed = state.storage.wallet.seed.as_ref()
        .ok_or_else(|| anyhow::anyhow!("No seed found"))?;
    
    let utxos = wallet.scan_utxos(seed, account, 20, &chain_config.default_rpc_url).await?;
    
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

### Phase 4: Minimal Chain Addition

After refactoring, adding CKB requires only:

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

## Rationale

This approach provides:

1. **Reduced friction**: Adding a chain requires 3-4 changes instead of 12
2. **Config-driven**: Most chain behavior defined in config files
3. **Extensible**: Easy to add new chains without touching core code
4. **Maintainable**: Chain-specific code isolated in adapters
5. **Testable**: Can test new chains without affecting existing ones

The config-driven approach separates data (chain configuration) from logic (wallet operations), following the principle that data should be externalized while code remains generic.

## Impact

### Breaking Changes

- All existing chain wallet implementations must implement `WalletOperations` trait
- Chain configs must be migrated to new format
- CLI commands must be refactored to use generic operations

### Migration Path

1. Create chain registry and traits alongside existing code
2. Migrate Bitcoin to new system as proof of concept
3. Gradually migrate other chains
4. Deprecate old interfaces after migration complete
5. Keep old code behind feature flags for rollback

### Estimated Effort

- Phase 1 (Chain Registry): 4-6 hours
- Phase 2 (Generic Wallet Traits): 6-8 hours
- Phase 3 (Chain-Agnostic CLI): 6-8 hours
- Phase 4 (Migrate Existing Chains): 8-12 hours
- Phase 5 (CKB Test Case): 8-12 hours
- Phase 6 (Documentation): 4-6 hours

**Total**: 36-52 hours (1-2 weeks)

## Alternatives

### Alternative 1: Code Generation

Generate chain-specific code from templates.

**Rejected**: Still requires code generation step, adds complexity, doesn't solve the core problem of touching multiple files.

### Alternative 2: Dynamic Loading

Load chain adapters dynamically at runtime.

**Rejected**: Adds complexity, security concerns, harder to debug. Conditional compilation is simpler and safer.

### Alternative 3: Status Quo

Keep current approach of modifying 12 places per chain.

**Rejected**: High friction, error-prone, doesn't scale as ecosystem grows.

## Unresolved Questions

1. Should chain configs be validated at startup or lazily loaded?
2. How to handle chain-specific CLI command overrides?
3. Should wallet operations be async or sync?
4. How to handle chains with different account models (UTXO vs account)?
5. Should chain registry be global or per-component?
