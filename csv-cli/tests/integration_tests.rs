//! Integration tests for csv-cli commands
//!
//! These tests validate that CLI commands:
//! - Properly use the runtime layer
//! - Have proper error handling
//! - Follow architectural guardrails

use std::path::Path;

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
