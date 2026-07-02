//! Test chain discovery with all 6 chain TOML configs

use csv_runtime::adapter_registry::AdapterRegistryImpl;
use csv_runtime::chain_discovery::{ChainConfig, ChainDiscovery};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

/// Resolve the workspace-root `chains/` directory regardless of the test's
/// current working directory. `cargo test -p csv-runtime` runs with the CWD set
/// to the crate dir (which has no `chains/`), so a bare `Path::new("chains")`
/// would not resolve. The configs live at the workspace root, one level up from
/// this crate's manifest dir.
fn chains_dir() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest.parent().expect("crate has a parent dir");
    workspace_root.join("chains")
}

#[test]
fn test_load_all_chains_from_toml() {
    let adapter_registry = Arc::new(RwLock::new(AdapterRegistryImpl::new()));
    let discovery = ChainDiscovery::new(adapter_registry);

    let chains_dir = chains_dir();
    assert!(chains_dir.exists(), "chains directory should exist");

    let count = discovery
        .load_from_directory(&chains_dir)
        .expect("Should load chain configs from directory");

    println!("Loaded {} chain configurations", count);

    // Should load at least 6 chains (aptos-testnet, bitcoin-signet, ethereum-sepolia, ethereum, solana-devnet, sui-testnet)
    assert!(
        count >= 6,
        "Should load at least 6 chain configs, got {}",
        count
    );

    // Verify we can get configs for known chains
    let configs = discovery.all_configs().expect("Should get all configs");
    println!("Loaded configs for chains:");
    for config in &configs {
        println!("  - {} ({})", config.id, config.name);
    }

    // Check that specific chains are present
    let chain_ids: Vec<_> = configs.iter().map(|c| c.id.clone()).collect();
    assert!(
        chain_ids.contains(&"bitcoin-signet".to_string()),
        "Should have bitcoin-signet"
    );
    assert!(
        chain_ids.contains(&"ethereum-sepolia".to_string()),
        "Should have ethereum-sepolia"
    );
    assert!(
        chain_ids.contains(&"sui-testnet".to_string()),
        "Should have sui-testnet"
    );
    assert!(
        chain_ids.contains(&"aptos-testnet".to_string()),
        "Should have aptos-testnet"
    );
    assert!(
        chain_ids.contains(&"solana-devnet".to_string()),
        "Should have solana-devnet"
    );
}

#[test]
fn test_load_single_toml() {
    let adapter_registry = Arc::new(RwLock::new(AdapterRegistryImpl::new()));
    let discovery = ChainDiscovery::new(adapter_registry);

    let bitcoin_config_path = chains_dir().join("bitcoin-signet.toml");
    assert!(
        bitcoin_config_path.exists(),
        "bitcoin-signet.toml should exist"
    );

    let config = discovery
        .load_from_toml(&bitcoin_config_path)
        .expect("Should load bitcoin-signet.toml");

    assert_eq!(config.id, "bitcoin-signet");
    // `name` mirrors the toml's `chain_name` field verbatim.
    assert_eq!(config.name, "bitcoin-signet");
    assert_eq!(config.network, "signet");
    assert!(!config.rpc_urls.is_empty(), "Should have RPC URLs");
    assert!(config.enabled, "Should be enabled by default");

    println!("Loaded bitcoin-signet config: {:?}", config);
}
