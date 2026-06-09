//! Deployment Manifest Update Script
//!
//! Updates ~/.csv/config.toml and ~/.csv/deployment-ethereum.json after deployment.
//!
//! Usage:
//!   cargo run --bin update_manifest -- <seal_address> <deployment_tx> <block_number>

use std::env;
use std::fs;
use std::path::Path;
use sha3::{Digest, Keccak256};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().skip(1).collect();

    if args.len() < 3 {
        eprintln!("Usage: update_manifest <seal_address> <deployment_tx> <block_number>");
        std::process::exit(1);
    }

    let seal_address = &args[0];
    let deployment_tx = &args[1];
    let block_number = &args[2];

    // Compute bytecode hash from compiled artifact
    let bytecode_hash = compute_bytecode_hash()?;

    // Update ~/.csv/config.toml
    update_config_toml(seal_address)?;

    // Update ~/.csv/deployment-ethereum.json
    update_deployment_manifest(seal_address, deployment_tx, block_number, &bytecode_hash)?;

    println!("Deployment manifest updated successfully!");
    println!("  CSVSeal address: {}", seal_address);
    println!("  Deployment TX: {}", deployment_tx);
    println!("  Block number: {}", block_number);
    println!("  Bytecode hash: {}", bytecode_hash);

    Ok(())
}

fn compute_bytecode_hash() -> Result<String, Box<dyn std::error::Error>> {
    // Try multiple possible paths for the compiled ABI/bytecode
    let possible_paths = [
        "csv-contracts/ethereum/contracts/out/CSVSeal.sol/CSVSeal.json",
        "csv-contracts/ethereum/out/CSVSeal.sol/CSVSeal.json",
        "contracts/out/CSVSeal.sol/CSVSeal.json",
        "out/CSVSeal.sol/CSVSeal.json",
    ];

    for path_str in &possible_paths {
        let path = Path::new(path_str);
        if path.exists() {
            let content = fs::read_to_string(path)?;
            if let Some(bytecode) = extract_bytecode(&content) {
                let hash = Keccak256::digest(bytecode.as_bytes());
                return Ok(format!("0x{}", hex::encode(hash)));
            }
        }
    }

    // If no bytecode found, return placeholder
    eprintln!("Warning: Could not find bytecode file, using placeholder hash");
    Ok("0x0000000000000000000000000000000000000000000000000000000000000000".to_string())
}

fn extract_bytecode(content: &str) -> Option<String> {
    // Parse JSON to extract bytecode.object field
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(content) {
        if let Some(bytecode) = value.get("bytecode").and_then(|b| b.get("object")) {
            return bytecode.as_str().map(|s| s.to_string());
        }
    }
    None
}

fn update_config_toml(seal_address: &str) -> Result<(), Box<dyn std::error::Error>> {
    let config_path = Path::new(&format!("{}/.csv/config.toml", env::var("HOME").unwrap_or_else(|_| "/root".to_string())));

    if !config_path.exists() {
        eprintln!("Warning: {} not found, skipping config update", config_path.display());
        return Ok(());
    }

    let config_content = fs::read_to_string(config_path)?;
    let updated_content = config_content.replace(
        "contract_address = \"\"",
        &format!("contract_address = \"{}\"", seal_address)
    ).replace(
        r#"contract_address = "0x"#,
        &format!("contract_address = \"{}\"", seal_address)
    );

    // Create backup
    let backup_path = format!("{}.backup", config_path.display());
    fs::copy(config_path, &backup_path)?;

    fs::write(config_path, updated_content)?;
    println!("Updated {}", config_path.display());

    Ok(())
}

fn update_deployment_manifest(
    seal_address: &str,
    deployment_tx: &str,
    block_number: &str,
    bytecode_hash: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let home = env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    let deployment_path = Path::new(&format!("{}/.csv/deployment-ethereum.json", home));

    let manifest = format!(
        r#"{{
  "version": "1.0.0",
  "network": "sepolia",
  "chain_id": 11155111,
  "deployed_at": "{}",
  "contracts": {{
    "CSVSeal": {{
      "address": "{}",
      "deployment_tx": "{}",
      "block_number": {},
      "bytecode_hash": "{}",
      "verified": false,
      "constructor_args": {{
        "verifier": ""
      }}
    }}
  }},
  "abi_hash": "pending",
  "protocol_version": "1.0.0"
}}"#,
        chrono::Utc::now().to_rfc3339(),
        seal_address,
        deployment_tx,
        block_number,
        bytecode_hash,
    );

    // Create directory if it doesn't exist
    if let Some(parent) = deployment_path.parent() {
        fs::create_dir_all(parent)?;
    }

    fs::write(deployment_path, manifest)?;
    println!("Updated {}", deployment_path.display());

    // Also copy to repo deployments folder
    let repo_path = Path::new("deployments/ethereum/deployment.json");
    if let Some(parent) = repo_path.parent() {
        fs::create_dir_all(parent).ok();
    }
    fs::copy(deployment_path, repo_path)?;
    println!("Copied to {}", repo_path.display());

    Ok(())
}
