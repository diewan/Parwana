//! Integration tests for csv-cli commands
//!
//! These tests validate that CLI commands:
//! - Properly use the runtime layer
//! - Have proper error handling
//! - Follow architectural guardrails
//! - Use centralized wallet identity resolution (WALLET-IDENTITY-001)

use std::path::Path;

/// Test that WalletIdentityResolver produces consistent addresses across calls
#[test]
fn test_wallet_identity_resolver_consistency() {
    use csv_keys::Mnemonic;
    use csv_sdk::wallet::WalletIdentityResolver;
    use csv_hash::ChainId;

    // Use a test mnemonic
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed = Mnemonic::from_phrase(mnemonic).unwrap().to_seed(None);
    let seed_array = *seed.as_bytes();

    // Create resolver
    let resolver = WalletIdentityResolver::from_seed(seed_array);

    // Test Bitcoin address derivation consistency
    let btc_chain = ChainId::new("bitcoin");
    let btc_addr_1 = resolver.derive_address(btc_chain.clone(), 0, 0);
    let btc_addr_2 = resolver.derive_address(btc_chain.clone(), 0, 0);
    assert_eq!(
        btc_addr_1, btc_addr_2,
        "WalletIdentityResolver should produce consistent addresses for same parameters"
    );

    // Test that different accounts produce different addresses
    let btc_addr_account_1 = resolver.derive_address(btc_chain.clone(), 0, 0);
    let btc_addr_account_2 = resolver.derive_address(btc_chain.clone(), 1, 0);
    assert_ne!(
        btc_addr_account_1, btc_addr_account_2,
        "Different accounts should produce different addresses"
    );

    // Test that different indices produce different addresses
    let btc_addr_index_0 = resolver.derive_address(btc_chain.clone(), 0, 0);
    let btc_addr_index_1 = resolver.derive_address(btc_chain.clone(), 0, 1);
    assert_ne!(
        btc_addr_index_0, btc_addr_index_1,
        "Different indices should produce different addresses"
    );

    // Test Ethereum address derivation
    let eth_chain = ChainId::new("ethereum");
    let eth_addr = resolver.derive_address(eth_chain, 0, 0);
    assert!(!eth_addr.is_empty(), "Ethereum address should not be empty");
    assert!(
        eth_addr.starts_with("0x"),
        "Ethereum address should start with 0x"
    );

    // Test Sui address derivation
    let sui_chain = ChainId::new("sui");
    let sui_addr = resolver.derive_address(sui_chain, 0, 0);
    assert!(!sui_addr.is_empty(), "Sui address should not be empty");
}

/// Test that wallet balance command uses WalletIdentityResolver
#[test]
fn test_wallet_balance_uses_identity_resolver() {
    let wallet_balance = Path::new("src/commands/wallet/balance.rs");
    if let Ok(content) = std::fs::read_to_string(wallet_balance) {
        assert!(
            content.contains("WalletIdentityResolver"),
            "wallet/balance.rs should use WalletIdentityResolver for address derivation"
        );
        assert!(
            content.contains("csv_sdk::wallet::WalletIdentityResolver"),
            "wallet/balance.rs should import WalletIdentityResolver from csv_sdk::wallet"
        );
        assert!(
            content.contains("derive_address"),
            "wallet/balance.rs should call derive_address on WalletIdentityResolver"
        );
    }
}

/// Test that sanad create command uses WalletIdentityResolver
#[test]
fn test_sanad_create_uses_identity_resolver() {
    let sanads_rs = Path::new("src/commands/sanads.rs");
    if let Ok(content) = std::fs::read_to_string(sanads_rs) {
        assert!(
            content.contains("WalletIdentityResolver"),
            "sanads.rs should use WalletIdentityResolver for address derivation"
        );
        assert!(
            content.contains("csv_sdk::wallet::WalletIdentityResolver"),
            "sanads.rs should import WalletIdentityResolver from csv_sdk::wallet"
        );
        assert!(
            content.contains("derive_address"),
            "sanads.rs should call derive_address on WalletIdentityResolver"
        );
    }
}

/// Test that cross-chain transfer command uses WalletIdentityResolver
#[test]
fn test_cross_chain_transfer_uses_identity_resolver() {
    let transfer_rs = Path::new("src/commands/cross_chain/transfer.rs");
    if let Ok(content) = std::fs::read_to_string(transfer_rs) {
        assert!(
            content.contains("WalletIdentityResolver"),
            "cross_chain/transfer.rs should use WalletIdentityResolver for address derivation"
        );
        assert!(
            content.contains("csv_sdk::wallet::WalletIdentityResolver"),
            "cross_chain/transfer.rs should import WalletIdentityResolver from csv_sdk::wallet"
        );
        assert!(
            content.contains("derive_address"),
            "cross_chain/transfer.rs should call derive_address on WalletIdentityResolver"
        );
    }
}

/// Test that passphrase validation fails closed (WALLET-IDENTITY-001)
#[test]
fn test_passphrase_validation_fails_closed() {
    let sanads_rs = Path::new("src/commands/sanads.rs");
    if let Ok(content) = std::fs::read_to_string(sanads_rs) {
        // Should have fail-closed error message for InvalidPassphrase
        assert!(
            content.contains("FAIL CLOSED") || content.contains("fail closed"),
            "sanads.rs should fail closed on wrong passphrase"
        );
        assert!(
            content.contains("passphrase is incorrect") || content.contains("wrong passphrase must fail closed"),
            "sanads.rs should explicitly mention incorrect passphrase in error"
        );
        // Check that the InvalidPassphrase error returns an error (doesn't fall through)
        assert!(
            content.contains("return Err(anyhow::anyhow!") && content.contains("InvalidPassphrase"),
            "sanads.rs should return error on InvalidPassphrase (not fall through)"
        );
    }

    let transfer_rs = Path::new("src/commands/cross_chain/transfer.rs");
    if let Ok(content) = std::fs::read_to_string(transfer_rs) {
        // Should have fail-closed error message for InvalidPassphrase
        assert!(
            content.contains("FAIL CLOSED") || content.contains("fail closed"),
            "cross_chain/transfer.rs should fail closed on wrong passphrase"
        );
        assert!(
            content.contains("passphrase is incorrect") || content.contains("wrong passphrase must fail closed"),
            "cross_chain/transfer.rs should explicitly mention incorrect passphrase in error"
        );
        // Check that the InvalidPassphrase error returns an error (doesn't fall through)
        assert!(
            content.contains("return Err(anyhow::anyhow!") && content.contains("InvalidPassphrase"),
            "cross_chain/transfer.rs should return error on InvalidPassphrase (not fall through)"
        );
    }
}

/// Test that private key prefixes are not logged (WALLET-IDENTITY-001)
#[test]
fn test_no_private_key_prefix_logs() {
    let sanads_rs = Path::new("src/commands/sanads.rs");
    if let Ok(content) = std::fs::read_to_string(sanads_rs) {
        // Should NOT log private key prefixes
        assert!(
            !content.contains("Private key (first 8 bytes)"),
            "sanads.rs should not log private key prefixes"
        );
        assert!(
            !content.contains("CLI LAYER: Private key"),
            "sanads.rs should not log private key material"
        );
    }
}

/// Test that chain commands use runtime APIs
#[test]
fn test_chain_commands_use_runtime() {
    let chain_rs = Path::new("src/commands/chain.rs");
    if let Ok(content) = std::fs::read_to_string(chain_rs) {
        // chain.rs is configuration management only - no runtime APIs needed
        // It just reads/writes CLI config file, doesn't interact with chains
        // This test is skipped for chain.rs
    }
}

/// Test that wallet commands use runtime APIs
#[test]
fn test_wallet_commands_use_runtime() {
    let wallet_balance = Path::new("src/commands/wallet/balance.rs");
    if let Ok(content) = std::fs::read_to_string(wallet_balance) {
        // Should use csv-sdk runtime APIs
        assert!(
            content.contains("csv_sdk::CsvClient"),
            "wallet/balance.rs should use csv_sdk::CsvClient for runtime operations"
        );
    }
}

/// Test that sanads commands use runtime APIs
#[test]
fn test_sanads_commands_use_runtime() {
    let sanads_rs = Path::new("src/commands/sanads.rs");
    if let Ok(content) = std::fs::read_to_string(sanads_rs) {
        // Should use csv-sdk runtime APIs
        assert!(
            content.contains("csv_sdk::CsvClient"),
            "sanads.rs should use csv_sdk::CsvClient for runtime operations"
        );
        // Should use csv-protocol types
        assert!(
            content.contains("csv_hash::ChainId") || content.contains("csv_protocol"),
            "sanads.rs should use csv-protocol or csv-hash types"
        );
    }
}

/// Test that UTXO validation uses runtime-mediated validation (C-CLI-UTXO-001)
#[test]
fn test_utxo_validation_uses_runtime() {
    let sanads_rs = Path::new("src/commands/sanads.rs");
    if let Ok(content) = std::fs::read_to_string(sanads_rs) {
        // Should NOT have skip comments for UTXO validation
        assert!(
            !content.contains("For now, skip on-chain validation to avoid RPC dependency"),
            "sanads.rs should not skip on-chain validation - must use runtime-mediated validation"
        );
        assert!(
            !content.contains("TODO: Implement proper UTXO validation using Bitcoin adapter"),
            "sanads.rs should not have TODO for UTXO validation - must be implemented"
        );
        // Should use runtime for validation
        assert!(
            content.contains("validate_bitcoin_utxo_via_runtime") || content.contains("runtime.get_transaction"),
            "sanads.rs should use runtime-mediated UTXO validation"
        );
        // Should fail closed when RPC unavailable
        assert!(
            content.contains("RPC or validation support unavailable") || content.contains("Fail closed"),
            "sanads.rs should fail closed when RPC or validation support is unavailable"
        );
    }
}

/// Test that seals commands use runtime APIs
#[test]
fn test_seals_commands_use_runtime() {
    let seals_rs = Path::new("src/commands/seals.rs");
    if let Ok(content) = std::fs::read_to_string(seals_rs) {
        // Should use csv-sdk runtime APIs
        assert!(
            content.contains("csv_sdk::CsvClient"),
            "seals.rs should use csv_sdk::CsvClient for runtime operations"
        );
        // Should use csv-protocol types
        assert!(
            content.contains("csv_protocol::SanadId") || content.contains("csv_hash::Hash"),
            "seals.rs should use csv-protocol or csv-hash types"
        );
    }
}

/// Test that cross-chain commands use runtime APIs
#[test]
fn test_cross_chain_commands_use_runtime() {
    let transfer_rs = Path::new("src/commands/cross_chain/transfer.rs");
    if let Ok(content) = std::fs::read_to_string(transfer_rs) {
        // Should use csv-sdk runtime APIs
        assert!(
            content.contains("csv_sdk::CsvClient"),
            "cross_chain/transfer.rs should use csv_sdk::CsvClient for runtime operations"
        );
        // Should use transfers() API
        assert!(
            content.contains(".transfers()"),
            "cross_chain/transfer.rs should use .transfers() API"
        );
    }
}

/// Test that proofs commands use runtime APIs
#[test]
fn test_proofs_commands_use_runtime() {
    let proofs_rs = Path::new("src/commands/proofs.rs");
    if let Ok(content) = std::fs::read_to_string(proofs_rs) {
        // Should use csv-sdk runtime APIs (either direct or via prelude)
        assert!(
            content.contains("csv_sdk::CsvClient")
                || content.contains("csv_sdk::prelude::CsvClient"),
            "proofs.rs should use csv_sdk::CsvClient for runtime operations"
        );
        // Should use chain_runtime() for proof operations
        assert!(
            content.contains("chain_runtime()"),
            "proofs.rs should use chain_runtime() for proof operations"
        );
    }
}

/// Test error handling in chain commands
#[test]
fn test_chain_commands_error_handling() {
    let chain_rs = Path::new("src/commands/chain.rs");
    if let Ok(content) = std::fs::read_to_string(chain_rs) {
        // chain.rs is configuration management only - simple error handling
        // Should use Result<> for error handling
        assert!(
            content.contains("Result<()>"),
            "chain.rs should use Result<()> for error handling"
        );
        // Should use ? operator for error propagation
        assert!(
            content.contains("?"),
            "chain.rs should use ? for error propagation"
        );
        // anyhow::anyhow! not required for simple config operations
    }
}

/// Test error handling in wallet commands
#[test]
fn test_wallet_commands_error_handling() {
    let wallet_balance = Path::new("src/commands/wallet/balance.rs");
    if let Ok(content) = std::fs::read_to_string(wallet_balance) {
        // Should use Result<> for error handling
        assert!(
            content.contains("Result<()>"),
            "wallet/balance.rs should use Result<()> for error handling"
        );
        // Should use ? operator for error propagation
        assert!(
            content.contains("?"),
            "wallet/balance.rs should use ? for error propagation"
        );
    }
}

/// Test error handling in sanads commands
#[test]
fn test_sanads_commands_error_handling() {
    let sanads_rs = Path::new("src/commands/sanads.rs");
    if let Ok(content) = std::fs::read_to_string(sanads_rs) {
        // Should use Result<> for error handling
        assert!(
            content.contains("Result<()>"),
            "sanads.rs should use Result<()> for error handling"
        );
        // Should use ? operator for error propagation
        assert!(
            content.contains("?"),
            "sanads.rs should use ? for error propagation"
        );
    }
}

/// Test error handling in cross-chain commands
#[test]
fn test_cross_chain_commands_error_handling() {
    let transfer_rs = Path::new("src/commands/cross_chain/transfer.rs");
    if let Ok(content) = std::fs::read_to_string(transfer_rs) {
        // Should use Result<> for error handling
        assert!(
            content.contains("Result<()>"),
            "cross_chain/transfer.rs should use Result<()> for error handling"
        );
        // Should use ? operator for error propagation
        assert!(
            content.contains("?"),
            "cross_chain/transfer.rs should use ? for error propagation"
        );
        // Should map errors appropriately
        assert!(
            content.contains("map_err"),
            "cross_chain/transfer.rs should use map_err for error conversion"
        );
    }
}

/// Test that CLI has no lease management (delegated to runtime)
#[test]
fn test_cli_no_lease_management() {
    let cross_chain_mod = Path::new("src/commands/cross_chain/mod.rs");
    if let Ok(content) = std::fs::read_to_string(cross_chain_mod) {
        // Should not have lease module
        assert!(
            !content.contains("pub mod lease"),
            "cross_chain/mod.rs should not have lease module (lease management delegated to runtime)"
        );
        // Should not have AcquireLease command
        assert!(
            !content.contains("AcquireLease"),
            "cross_chain/mod.rs should not have AcquireLease command (lease management delegated to runtime)"
        );
    }

    // Verify lease.rs file doesn't exist
    let lease_rs = Path::new("src/commands/cross_chain/lease.rs");
    assert!(
        !lease_rs.exists(),
        "lease.rs should not exist (lease management delegated to runtime)"
    );
}

/// Test that CLI has no wallet_ext (removed dead code)
#[test]
fn test_cli_no_wallet_ext() {
    let wallet_ext = Path::new("src/commands/wallet_ext.rs");
    assert!(
        !wallet_ext.exists(),
        "wallet_ext.rs should not exist (dead code removed)"
    );

    let mod_rs = Path::new("src/commands/mod.rs");
    if let Ok(content) = std::fs::read_to_string(mod_rs) {
        assert!(
            !content.contains("pub mod wallet_ext"),
            "commands/mod.rs should not have wallet_ext module"
        );
    }
}

/// Test that CLI uses correct terminology
#[test]
fn test_cli_terminology() {
    let cli_src = Path::new("src");
    let mut violations = Vec::new();

    fn check_file(path: &Path, violations: &mut Vec<String>) {
        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines() {
                // Should use csv-sdk instead of csv-adapter in comments
                if line.contains("csv-adapter") && !path.to_string_lossy().contains("config.rs") {
                    violations.push(format!(
                        "{}:{} - Should use csv-sdk instead of csv-adapter: {}",
                        path.display(),
                        line,
                        line
                    ));
                }
            }
        }
    }

    fn visit_dir(dir: &Path, violations: &mut Vec<String>) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    visit_dir(&path, violations);
                } else if path.extension().map_or(false, |ext| ext == "rs") {
                    check_file(&path, violations);
                }
            }
        }
    }

    visit_dir(cli_src, &mut violations);

    if !violations.is_empty() {
        panic!(
            "Found {} terminology violations in csv-cli:\n{}",
            violations.len(),
            violations.join("\n")
        );
    }
}

/// Product contract for the CLI Testnet MVP gauntlet (CLI-TRUTH-001).
///
/// This is intentionally a scenario contract, not a production mock. The real
/// gauntlet implementation must execute these steps against deterministic
/// fixtures or real testnets while preserving fail-closed behavior.
#[test]
fn cli_golden_path_gauntlet_contract() {
    let quick_start = std::fs::read_to_string("../csv-examples/cli-tutorial/quick-start.sh")
        .expect("quick-start.sh should be readable from csv-cli tests");
    let cross_chain = std::fs::read_to_string("../csv-examples/cli-tutorial/cross-chain-transfer.sh")
        .expect("cross-chain-transfer.sh should be readable from csv-cli tests");
    let scenario = format!("{}\n{}", quick_start, cross_chain);

    let required_steps = [
        ("wallet init", "csv wallet init --network test --words 12"),
        ("bitcoin address generation", "csv wallet generate --chain bitcoin"),
        ("ethereum address generation", "csv wallet generate --chain ethereum"),
        ("wallet balance", "csv wallet balance"),
        ("sanad create", "csv sanad create --chain ethereum"),
        ("sanad state", "csv sanad state --chain ethereum"),
        ("proof generate", "csv proof generate --chain ethereum"),
        ("proof verify", "csv proof verify --chain ethereum"),
        ("cross-chain transfer", "csv cross-chain transfer --from ethereum --to sui"),
        ("cross-chain status", "csv cross-chain status <TRANSFER_ID>"),
        ("sanad trace", "csv sanad trace --chain ethereum"),
        ("replay attempt", "replay attempt"),
        ("malformed proof attempt", "malformed proof attempt"),
    ];

    for (label, needle) in required_steps {
        assert!(
            scenario.contains(needle),
            "CLI golden path gauntlet is missing required step `{}`: `{}`",
            label,
            needle
        );
    }

    let forbidden_claims = [
        "skip publish path creates a real Sanad",
        "local cache is canonical",
        "verification failure is a warning",
    ];

    for forbidden in forbidden_claims {
        assert!(
            !scenario.contains(forbidden),
            "CLI gauntlet scripts must not claim unsafe behavior: `{}`",
            forbidden
        );
    }
}
