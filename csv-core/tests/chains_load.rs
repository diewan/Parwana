//! Testnet chain configuration loading (Phase 7 deployment framework).

use csv_core::chain_config::{ChainCapabilities, ChainConfig, ChainConfigLoader};
use std::collections::HashMap;
use std::path::Path;

fn testnet_config(chain_id: &str, capabilities: ChainCapabilities, rpc: &str, explorer: &str) -> ChainConfig {
    ChainConfig {
        chain_id: chain_id.to_string(),
        chain_name: chain_id.to_string(),
        default_network: "testnet".to_string(),
        rpc_endpoints: vec![rpc.to_string()],
        program_id: None,
        block_explorer_urls: vec![explorer.to_string()],
        start_block: 0,
        capabilities,
        custom_settings: HashMap::new(),
    }
}

#[test]
fn testnet_chain_config_toml_roundtrip() {
    let configs = [
        testnet_config(
            "bitcoin-signet",
            ChainCapabilities::bitcoin(),
            "https://mempool.space/signet/api",
            "https://mempool.space/signet",
        ),
        testnet_config(
            "ethereum-sepolia",
            ChainCapabilities::ethereum(),
            "https://rpc.sepolia.org",
            "https://sepolia.etherscan.io",
        ),
        testnet_config(
            "solana-devnet",
            ChainCapabilities::solana(),
            "https://api.devnet.solana.com",
            "https://explorer.solana.com/?cluster=devnet",
        ),
        testnet_config(
            "sui-testnet",
            ChainCapabilities::sui(),
            "https://fullnode.testnet.sui.io:443",
            "https://suiscan.xyz/testnet",
        ),
        testnet_config(
            "aptos-testnet",
            ChainCapabilities::aptos(),
            "https://fullnode.testnet.aptoslabs.com/v1",
            "https://explorer.aptoslabs.com/?network=testnet",
        ),
    ];

    for config in &configs {
        let toml_str = toml::to_string_pretty(config).expect("serialize chain config");
        let parsed: ChainConfig = toml::from_str(&toml_str).expect("deserialize chain config");
        assert_eq!(parsed.chain_id, config.chain_id);
        assert_eq!(parsed.capabilities.state_model, config.capabilities.state_model);
    }
}

#[test]
fn chains_directory_configs_load() {
    let chains_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../chains");
    if !chains_dir.exists() {
        panic!(
            "missing chains/ directory at {}; run `cargo test -p csv-core --test chains_load write_testnet_chain_configs -- --ignored`",
            chains_dir.display()
        );
    }

    let mut loader = ChainConfigLoader::new();
    loader
        .load_from_directory(chains_dir.to_str().unwrap())
        .expect("load chain configs");

    for chain_id in [
        "bitcoin-signet",
        "ethereum-sepolia",
        "solana-devnet",
        "sui-testnet",
        "aptos-testnet",
    ] {
        assert!(
            loader.get_config(chain_id).is_some(),
            "expected chain config for {chain_id}"
        );
    }
}

#[test]
#[ignore = "run manually to refresh chains/*.toml from canonical capabilities"]
fn write_testnet_chain_configs() {
    let chains_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../chains");
    std::fs::create_dir_all(&chains_dir).expect("create chains directory");

    let configs = [
        testnet_config(
            "bitcoin-signet",
            ChainCapabilities::bitcoin(),
            "https://mempool.space/signet/api",
            "https://mempool.space/signet",
        ),
        testnet_config(
            "ethereum-sepolia",
            ChainCapabilities::ethereum(),
            "https://rpc.sepolia.org",
            "https://sepolia.etherscan.io",
        ),
        testnet_config(
            "solana-devnet",
            ChainCapabilities::solana(),
            "https://api.devnet.solana.com",
            "https://explorer.solana.com/?cluster=devnet",
        ),
        testnet_config(
            "sui-testnet",
            ChainCapabilities::sui(),
            "https://fullnode.testnet.sui.io:443",
            "https://suiscan.xyz/testnet",
        ),
        testnet_config(
            "aptos-testnet",
            ChainCapabilities::aptos(),
            "https://fullnode.testnet.aptoslabs.com/v1",
            "https://explorer.aptoslabs.com/?network=testnet",
        ),
    ];

    for config in configs {
        let path = chains_dir.join(format!("{}.toml", config.chain_id));
        let toml_str = toml::to_string_pretty(&config).expect("serialize");
        std::fs::write(path, toml_str).expect("write chain config");
    }
}
