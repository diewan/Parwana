//! Deployment Manifest Update Script
//!
//! This script updates the deployment-manifest.json with actual deployment
//! information after deploying the CSVSeal contract to Sepolia.
//!
//! Usage:
//!   cargo run --bin update_manifest -- <seal_address> <deployment_tx> <block_number>
//!
//! Example:
//!   cargo run --bin update_manifest -- 0x1234... 0xabcd... 1234567

use std::env;
use std::fs;
use std::path::Path;
use sha3::{Digest, Keccak256};
use hex;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().skip(1).collect();

    if args.len() < 3 {
        eprintln!("Usage: update_manifest <seal_address> <deployment_tx> <block_number>");
        eprintln!("Example: update_manifest 0x1234... 0xabcd... 1234567");
        std::process::exit(1);
    }

    let seal_address = &args[0];
    let deployment_tx = &args[1];
    let block_number = &args[2];

    // Read the deployment manifest
    let manifest_path = Path::new("deployments/deployment-manifest.json");
    let manifest_content = fs::read_to_string(manifest_path)?;
    let mut manifest: serde_json::Value = serde_json::from_str(&manifest_content)?;

    // Update Ethereum contracts section
    if let Some(ethereum) = manifest["deployments"]["ethereum"].as_object_mut() {
        if let Some(contracts) = ethereum["contracts"].as_array_mut() {
            // Update CSVSeal contract
            if let Some(seal_contract) = contracts.get_mut(0) {
                if let Some(seal_obj) = seal_contract.as_object_mut() {
                    seal_obj.insert("address".to_string(), serde_json::json!(seal_address));
                    seal_obj.insert("deployment_tx".to_string(), serde_json::json!(deployment_tx));
                    seal_obj.insert("block_number".to_string(), serde_json::json!(block_number));
                    // Compute actual bytecode hash from deployed contract
                    let bytecode_path = Path::new("deployments/artifacts/CSVSeal.bin");
                    if bytecode_path.exists() {
                        let bytecode = fs::read(bytecode_path)?;
                        let hash = sha3::Keccak256::digest(&bytecode);
                        seal_obj.insert("bytecode_hash".to_string(), serde_json::json!(format!("0x{}", hex::encode(hash))));
                    } else {
                        return Err(Box::from(format!("Bytecode file not found: {:?}", bytecode_path)));
                    }
                    seal_obj.insert("verified".to_string(), serde_json::json!(false));
                    
                    // Update constructor args
                    if let Some(constructor_args) = seal_obj["constructor_args"].as_object_mut() {
                        let verifier_address = env::var("VERIFIER_ADDRESS").unwrap_or_else(|_| "".to_string());
                        constructor_args.insert("verifier".to_string(), serde_json::json!(verifier_address));
                    }
                }
            }

            // Update deployment block and timestamp
            ethereum.insert("deployment_block".to_string(), serde_json::json!(block_number));
            ethereum.insert("deployment_timestamp".to_string(), serde_json::json!(chrono::Utc::now().to_rfc3339()));
        }
    }

    // Write the updated manifest
    fs::write(manifest_path, serde_json::to_string_pretty(&manifest)?)?;

    println!("Deployment manifest updated successfully!");
    println!("CSVSeal address: {}", seal_address);
    println!("Deployment TX: {}", deployment_tx);
    println!("Block number: {}", block_number);

    // Also update chains/ethereum.toml
    update_chains_config(seal_address)?;

    Ok(())
}

fn update_chains_config(seal_address: &str) -> Result<(), Box<dyn std::error::Error>> {
    let config_path = Path::new("chains/ethereum.toml");
    let config_content = fs::read_to_string(config_path)?;
    
    let updated_content = config_content
        .replace("contract_address = \"\"", &format!("contract_address = \"{}\"", seal_address));
    
    fs::write(config_path, updated_content)?;
    
    println!("chains/ethereum.toml updated successfully!");
    
    Ok(())
}
