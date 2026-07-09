//! Architecture compliance tests for csv-cli
//!
//! These tests enforce the architectural guardrails:
//! - No direct csv_core imports in csv-cli
//! - No direct chain adapter imports in csv-cli
//! - No direct reqwest calls for chain operations
//! - Commands must use csv-sdk runtime APIs

use std::path::Path;

/// Test that csv-cli does not import csv_core directly
#[test]
fn test_no_csv_core_imports() {
    let cli_src = Path::new("src");
    let mut violations = Vec::new();

    fn check_file(path: &Path, violations: &mut Vec<String>) {
        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines() {
                if line.contains("use csv_core::") {
                    violations.push(format!(
                        "{}:{} - Direct csv_core import: {}",
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
            "Found {} direct csv_core imports in csv-cli:\n{}",
            violations.len(),
            violations.join("\n")
        );
    }
}

/// Test that csv-cli does not import chain adapters directly
#[test]
fn test_no_chain_adapter_imports() {
    let cli_src = Path::new("src");
    let mut violations = Vec::new();
    let forbidden_adapters = vec![
        "csv_bitcoin",
        "csv_ethereum",
        "csv_sui",
        "csv_aptos",
        "csv_solana",
        "csv_celestia",
    ];

    fn check_file(path: &Path, forbidden_adapters: &[&str], violations: &mut Vec<String>) {
        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines() {
                for adapter in forbidden_adapters {
                    if line.contains(&format!("use {}::", adapter)) {
                        violations.push(format!(
                            "{}:{} - Direct chain adapter import: {}",
                            path.display(),
                            line,
                            line
                        ));
                    }
                }
            }
        }
    }

    fn visit_dir(dir: &Path, forbidden_adapters: &[&str], violations: &mut Vec<String>) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    visit_dir(&path, forbidden_adapters, violations);
                } else if path.extension().map_or(false, |ext| ext == "rs") {
                    check_file(&path, forbidden_adapters, violations);
                }
            }
        }
    }

    visit_dir(cli_src, &forbidden_adapters, &mut violations);

    if !violations.is_empty() {
        panic!(
            "Found {} direct chain adapter imports in csv-cli:\n{}",
            violations.len(),
            violations.join("\n")
        );
    }
}

/// Test that csv-cli does not use reqwest for chain operations
#[test]
fn test_no_reqwest_chain_operations() {
    let cli_src = Path::new("src");
    let mut violations = Vec::new();

    fn check_file(path: &Path, violations: &mut Vec<String>) {
        if let Ok(content) = std::fs::read_to_string(path) {
            let lines: Vec<&str> = content.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                // Check for reqwest usage in command files
                // Skip test files (tests.rs) as they may use reqwest for testing
                if path.to_string_lossy().contains("commands")
                    && !path.to_string_lossy().contains("tests.rs")
                {
                    if line.contains("reqwest::") || line.contains("reqwest.") {
                        // Allow reqwest imports but warn about usage
                        if line.contains("get(")
                            || line.contains("post(")
                            || line.contains("blocking")
                        {
                            violations.push(format!(
                                "{}:{} - Direct reqwest call for chain operation: {}",
                                path.display(),
                                i + 1,
                                line
                            ));
                        }
                    }
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
            "Found {} direct reqwest calls for chain operations in csv-cli:\n{}",
            violations.len(),
            violations.join("\n")
        );
    }
}

/// Test that commands use csv-sdk runtime APIs
#[test]
fn test_commands_use_csv_sdk_runtime() {
    let commands_dir = Path::new("src/commands");
    let mut violations = Vec::new();

    if !commands_dir.exists() {
        return;
    }

    fn check_file(path: &Path, violations: &mut Vec<String>) {
        if let Ok(content) = std::fs::read_to_string(path) {
            let uses_csv_sdk = content.contains("csv_sdk::CsvClient")
                || content.contains("csv_sdk::prelude")
                || content.contains("csv_sdk::config");

            // Skip files that don't need runtime:
            // - inspect.rs: Protocol inspection utilities
            // - schema_cmd.rs: Schema validation (no chain operations)
            // - mod.rs: Module declarations
            // - wallet/import.rs: Import from csv-wallet (legacy)
            // - wallet/export.rs: Export to csv-wallet (legacy)
            // - wallet/types.rs: Type definitions
            // - wallet/private_key.rs: Key derivation (no chain operations)
            // - wallet/generate.rs: Key generation (no chain operations)
            // - contracts.rs: Contract metadata management (no chain operations)
            // - validate.rs: Validation utilities (uses csv-verifier)
            // - tests.rs: End-to-end testing utilities
            // - status.rs: Status checking (reads local state, no chain operations)
            // - content.rs: Content tree management (local operations)
            // - runtime.rs: Runtime diagnostics (reads local state)
            // - trust.rs: Trust package management (local operations)
            // - chain.rs: Chain configuration management (no chain operations)
            // - chain_management.rs: Chain configuration management (no chain operations)
            let filename = path.file_name().unwrap_or_default().to_string_lossy();
            let needs_runtime = !matches!(
                filename.as_ref(),
                "inspect.rs"
                    | "schema_cmd.rs"
                    | "mod.rs"
                    | "import.rs"
                    | "export.rs"
                    | "types.rs"
                    | "private_key.rs"
                    | "generate.rs"
                    | "contracts.rs"
                    | "validate.rs"
                    | "tests.rs"
                    | "status.rs"
                    | "content.rs"
                    | "sanad_manifest.rs"
                    | "runtime.rs"
                    | "trust.rs"
                    | "chain.rs"
                    | "chain_management.rs"
            );

            if needs_runtime && !uses_csv_sdk {
                violations.push(format!(
                    "{} - Command does not use csv-sdk runtime APIs",
                    path.display()
                ));
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

    visit_dir(commands_dir, &mut violations);

    if !violations.is_empty() {
        panic!(
            "Found {} commands not using csv-sdk runtime APIs:\n{}",
            violations.len(),
            violations.join("\n")
        );
    }
}

/// Test that csv-cli uses correct type imports (csv-protocol, csv-hash)
#[test]
fn test_uses_correct_type_imports() {
    let cli_src = Path::new("src");
    let mut violations = Vec::new();

    fn check_file(path: &Path, violations: &mut Vec<String>) {
        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines() {
                // Should use csv_protocol for protocol types
                if line.contains("csv_protocol::") {
                    // This is correct
                }
                // Should use csv_hash for hash types
                if line.contains("csv_hash::") {
                    // This is correct
                }
                // Should not use csv_core for types (except in config.rs which re-exports)
                if line.contains("csv_core::") && !path.to_string_lossy().contains("config.rs") {
                    violations.push(format!(
                        "{}:{} - Should use csv-protocol or csv-hash instead of csv-core: {}",
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
            "Found {} incorrect type imports in csv-cli:\n{}",
            violations.len(),
            violations.join("\n")
        );
    }
}
