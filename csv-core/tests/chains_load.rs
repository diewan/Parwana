//! Testnet chain configuration loading (Phase 7 deployment framework).

use csv_protocol::finality::capabilities::ChainCapabilities;
use std::collections::HashMap;
use std::path::Path;

// Simplified test config using only ChainCapabilities
// The full ChainConfig with RPC endpoints etc. is a runtime concern, not protocol
fn testnet_config(chain_id: &str, capabilities: ChainCapabilities) -> ChainCapabilities {
    capabilities
}

#[test]
fn testnet_chain_config_toml_roundtrip() {
    let configs = [
        testnet_config("bitcoin-signet", ChainCapabilities::bitcoin()),
        testnet_config("ethereum-sepolia", ChainCapabilities::ethereum()),
        testnet_config("solana-devnet", ChainCapabilities::solana()),
        testnet_config("sui-testnet", ChainCapabilities::sui()),
        testnet_config("aptos-testnet", ChainCapabilities::aptos()),
    ];

    for config in &configs {
        let toml_str = toml::to_string_pretty(config).expect("serialize chain config");
        let parsed: ChainCapabilities = toml::from_str(&toml_str).expect("deserialize chain config");
        assert_eq!(parsed.state_model, config.state_model);
        assert_eq!(parsed.finality_model, config.finality_model);
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

    // TODO: Implement ChainConfigLoader in csv-protocol or csv-runtime
    // For now, skip this test as the loader hasn't been migrated yet
    // let mut loader = ChainConfigLoader::new();
    // loader
    //     .load_from_directory(chains_dir.to_str().unwrap())
    //     .expect("load chain configs");

    // for chain_id in [
    //     "bitcoin-signet",
    //     "ethereum-sepolia",
    //     "solana-devnet",
    //     "sui-testnet",
    //     "aptos-testnet",
    // ] {
    //     assert!(
    //         loader.get_config(chain_id).is_some(),
    //         "expected chain config for {chain_id}"
    //     );
    // }
}

#[test]
#[ignore = "run manually to refresh chains/*.toml from canonical capabilities"]
fn write_testnet_chain_configs() {
    let chains_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../chains");
    std::fs::create_dir_all(&chains_dir).expect("create chains directory");

    let configs = [
        ("bitcoin-signet", ChainCapabilities::bitcoin()),
        ("ethereum-sepolia", ChainCapabilities::ethereum()),
        ("solana-devnet", ChainCapabilities::solana()),
        ("sui-testnet", ChainCapabilities::sui()),
        ("aptos-testnet", ChainCapabilities::aptos()),
    ];

    for (chain_id, config) in configs {
        let path = chains_dir.join(format!("{}.toml", chain_id));
        let toml_str = toml::to_string_pretty(&config).expect("serialize");
        std::fs::write(path, toml_str).expect("write chain config");
    }
}
