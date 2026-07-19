//! Architecture compliance tests to prevent direct adapter imports in SDK/Runtime
//!
//! These tests ensure that the SDK and Runtime crates do not directly import
//! chain adapter implementations, but instead use the factory pattern and
//! protocol traits.

#[test]
fn test_sdk_no_direct_bitcoin_adapter_imports() {
    // This test verifies that csv-sdk does not directly import csv-bitcoin
    // adapter types. It should use the factory pattern instead.

    // Check that the SDK source files don't contain direct adapter imports
    let sdk_source = include_str!("../src/client.rs");

    // Should not import csv_bitcoin::config::BitcoinConfig directly
    assert!(
        !sdk_source.contains("use csv_bitcoin::config::BitcoinConfig"),
        "SDK should not directly import BitcoinConfig - use factory instead"
    );

    // Should not import csv_bitcoin::ops::BitcoinBackend directly
    assert!(
        !sdk_source.contains("use csv_bitcoin::ops::BitcoinBackend"),
        "SDK should not directly import BitcoinBackend - use factory instead"
    );

    // Should use factory instead
    assert!(
        sdk_source.contains("csv_adapter_factory"),
        "SDK should use csv_adapter_factory for adapter creation"
    );
}

#[test]
fn test_sdk_no_direct_ethereum_adapter_imports() {
    let sdk_source = include_str!("../src/client.rs");

    // Should not import csv_ethereum::config::EthereumConfig directly
    assert!(
        !sdk_source.contains("use csv_ethereum::config::EthereumConfig"),
        "SDK should not directly import EthereumConfig - use factory instead"
    );

    // Should not import csv_ethereum::ops::EthereumBackend directly
    assert!(
        !sdk_source.contains("use csv_ethereum::ops::EthereumBackend"),
        "SDK should not directly import EthereumBackend - use factory instead"
    );
}

#[test]
fn test_sdk_no_direct_sui_adapter_imports() {
    let sdk_source = include_str!("../src/client.rs");

    // Should not import csv_sui::config::SuiConfig directly
    assert!(
        !sdk_source.contains("use csv_sui::config::SuiConfig"),
        "SDK should not directly import SuiConfig - use factory instead"
    );

    // Should not import csv_sui::ops::SuiBackend directly
    assert!(
        !sdk_source.contains("use csv_sui::ops::SuiBackend"),
        "SDK should not directly import SuiBackend - use factory instead"
    );
}

#[test]
fn test_sdk_no_direct_aptos_adapter_imports() {
    let sdk_source = include_str!("../src/client.rs");

    // Should not import csv_aptos::config::AptosConfig directly
    assert!(
        !sdk_source.contains("use csv_aptos::config::AptosConfig"),
        "SDK should not directly import AptosConfig - use factory instead"
    );

    // Should not import csv_aptos::ops::AptosBackend directly
    assert!(
        !sdk_source.contains("use csv_aptos::ops::AptosBackend"),
        "SDK should not directly import AptosBackend - use factory instead"
    );
}

#[test]
fn test_sdk_no_direct_solana_adapter_imports() {
    let sdk_source = include_str!("../src/client.rs");

    // Should not import csv_solana::config::SolanaConfig directly
    assert!(
        !sdk_source.contains("use csv_solana::config::SolanaConfig"),
        "SDK should not directly import SolanaConfig - use factory instead"
    );

    // Should not import csv_solana::ops::SolanaBackend directly
    assert!(
        !sdk_source.contains("use csv_solana::ops::SolanaBackend"),
        "SDK should not directly import SolanaBackend - use factory instead"
    );
}

#[test]
fn test_sdk_uses_adapter_build_result() {
    let sdk_source = include_str!("../src/client.rs");

    // Should use the factory AdapterResult alias for factory/legacy compatibility
    assert!(
        sdk_source.contains("AdapterResult as FactoryAdapterResult")
            && sdk_source.contains("pub type AdapterResult = FactoryAdapterResult"),
        "SDK should use the factory AdapterResult alias for factory/legacy compatibility"
    );
}

#[test]
fn test_sdk_registers_chain_adapter() {
    let sdk_source = include_str!("../src/client.rs");

    // Should register ChainAdapter in adapter_registry
    assert!(
        sdk_source.contains("register_adapter"),
        "SDK should register ChainAdapter in adapter_registry"
    );
}

#[test]
fn client_and_accountability_are_separate_product_neutral_capabilities() {
    let manifest = include_str!("../Cargo.toml");
    let library = include_str!("../src/lib.rs");

    for dependency in [
        "csv-runtime",
        "csv-storage",
        "csv-remote",
        "csv-chain-ports",
        "csv-observability",
        "csv-keys",
    ] {
        let declaration = manifest
            .lines()
            .find(|line| line.starts_with(dependency))
            .unwrap_or_else(|| panic!("missing {dependency} dependency declaration"));
        assert!(
            declaration.contains("optional = true"),
            "{dependency} must remain optional for accountability-only consumers"
        );
    }

    for module in [
        "builder",
        "client",
        "contract",
        "runtime",
        "transfers",
        "wallet",
    ] {
        assert!(
            library.contains(&format!("#[cfg(feature = \"client\")]\npub mod {module};")),
            "{module} must stay behind the primary Parwana client feature"
        );
    }

    assert!(
        library.contains("#[cfg(feature = \"accountability\")]\npub mod accountability;"),
        "the Accountability add-on must have its own compilation boundary"
    );
    assert!(
        !manifest.contains("legacy = [") && !manifest.contains("piteka = ["),
        "Parwana features must not deprecate its SDK or encode a consumer project"
    );
}
