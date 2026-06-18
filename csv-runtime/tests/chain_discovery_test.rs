//! Test chain discovery with all 6 chain TOML configs

use csv_runtime::chain_discovery::{ChainDiscovery, ChainConfig};
use csv_runtime::adapter_registry::AdapterRegistryImpl;
use std::sync::{Arc, RwLock};
use std::path::Path;

#[test]
fn test_load_all_chains_from_toml() {
    let adapter_registry = Arc::new(RwLock::new(AdapterRegistryImpl::new()));
    let discovery = ChainDiscovery::new(adapter_registry);

    let chains_dir = Path::new("chains");
    assert!(chains_dir.exists(), "chains directory should exist");

    let count = discovery.load_from_directory(chains_dir)
        .expect("Should load chain configs from directory");

    println!("Loaded {} chain configurations", count);

    // Should load at least 6 chains (aptos-testnet, bitcoin-signet, ethereum-sepolia, ethereum, solana-devnet, sui-testnet)
    assert!(count >= 6, "Should load at least 6 chain configs, got {}", count);

    // Verify we can get configs for known chains
    let configs = discovery.all_configs();
    println!("Loaded configs for chains:");
    for config in &configs {
        println!("  - {} ({})", config.id, config.name);
    }

    // Check that specific chains are present
    let chain_ids: Vec<_> = configs.iter().map(|c| c.id.clone()).collect();
    assert!(chain_ids.contains(&"bitcoin-signet".to_string()), "Should have bitcoin-signet");
    assert!(chain_ids.contains(&"ethereum-sepolia".to_string()), "Should have ethereum-sepolia");
    assert!(chain_ids.contains(&"sui-testnet".to_string()), "Should have sui-testnet");
    assert!(chain_ids.contains(&"aptos-testnet".to_string()), "Should have aptos-testnet");
    assert!(chain_ids.contains(&"solana-devnet".to_string()), "Should have solana-devnet");
}

#[test]
fn test_load_single_toml() {
    let adapter_registry = Arc::new(RwLock::new(AdapterRegistryImpl::new()));
    let discovery = ChainDiscovery::new(adapter_registry);

    let bitcoin_config_path = Path::new("chains/bitcoin-signet.toml");
    assert!(bitcoin_config_path.exists(), "bitcoin-signet.toml should exist");

    let config = discovery.load_from_toml(bitcoin_config_path)
        .expect("Should load bitcoin-signet.toml");

    assert_eq!(config.id, "bitcoin-signet");
    assert_eq!(config.name, "Bitcoin Signet");
    assert_eq!(config.network, "signet");
    assert!(!config.rpc_urls.is_empty(), "Should have RPC URLs");
    assert!(config.enabled, "Should be enabled by default");

    println!("Loaded bitcoin-signet config: {:?}", config);
}
