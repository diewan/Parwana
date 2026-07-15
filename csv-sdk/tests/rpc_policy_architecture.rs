//! Regression checks for the single RPC configuration authority.

use std::fs;
use std::path::Path;

use csv_sdk::rpc_policy::ChainRpcPolicy;
use serde::Deserialize;

fn source(relative: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    fs::read_to_string(path).expect("SDK source fixture must be readable")
}

#[test]
fn sdk_rpc_resolution_does_not_read_process_environment() {
    for path in ["src/config.rs", "src/client.rs", "src/rpc_policy.rs"] {
        let content = source(path);
        assert!(
            !content.contains("std::env::var"),
            "{path} must receive endpoint policy explicitly"
        );
    }
}

#[test]
fn concrete_adapter_construction_has_no_endpoint_literals() {
    let content = source("src/client.rs");
    assert!(
        !content.contains("https://") && !content.contains("wss://"),
        "adapter construction must use Config::required_request_url"
    );
}

#[derive(Deserialize)]
struct ShippedChainFile {
    rpc_policy: ChainRpcPolicy,
}

fn protocol_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("csv-sdk lives directly below the protocol workspace root")
        .to_path_buf()
}

#[test]
fn every_shipped_chain_file_contains_a_valid_canonical_policy() {
    let root = protocol_root();
    let files = [
        "aptos-testnet.toml",
        "bitcoin-signet.toml",
        "ethereum-sepolia.toml",
        "ethereum.toml",
        "solana-devnet.toml",
        "sui-testnet.toml",
    ];

    for file in files {
        let path = root.join("chains").join(file);
        let contents = fs::read_to_string(&path).expect("shipped chain file must be readable");
        assert!(
            !contents.contains("rpc_endpoints") && !contents.contains("rpc_url"),
            "{file} must not retain a scalar RPC configuration field"
        );
        assert!(
            !contents.contains("${"),
            "{file} must not contain shell-expansion syntax"
        );

        let parsed: ShippedChainFile = toml::from_str(&contents)
            .unwrap_or_else(|error| panic!("{file} must deserialize: {error}"));
        parsed
            .rpc_policy
            .validate()
            .unwrap_or_else(|error| panic!("{file} policy must validate: {error}"));
    }
}

#[test]
fn shared_testnet_policy_fixture_deserializes_and_validates() {
    let fixture = protocol_root().join("development/fixtures/rpc-policy-testnet.toml");
    let contents = fs::read_to_string(&fixture).expect("shared RPC fixture must be readable");
    let policy: ChainRpcPolicy =
        toml::from_str(&contents).expect("shared RPC fixture must deserialize into ChainRpcPolicy");
    policy.validate().expect("shared RPC fixture must validate");
    assert_eq!(policy.chain, "ethereum");
    assert_eq!(policy.network, "sepolia");
}
