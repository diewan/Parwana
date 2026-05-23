//! Deployment Manifest Update Script
//!
//! This script updates the deployment-manifest.json with actual deployment
//! information after deploying contracts to Sepolia.
//!
//! Usage:
//!   cargo run --bin update_manifest -- <lock_address> <mint_address> <deployment_tx> <block_number>
//!
//! Example:
//!   cargo run --bin update_manifest -- 0x1234... 0x5678... 0xabcd... 1234567

use std::env;
use std::fs;
use std::path::Path;
use sha3::{Digest, Keccak256};
use hex;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().skip(1).collect();

    if args.len() < 4 {
        eprintln!("Usage: update_manifest <lock_address> <mint_address> <deployment_tx> <block_number>");
        eprintln!("Example: update_manifest 0x1234... 0x5678... 0xabcd... 1234567");
        std::process::exit(1);
    }

    let lock_address = &args[0];
    let mint_address = &args[1];
    let deployment_tx = &args[2];
    let block_number = &args[3];

    // Read the deployment manifest
    let manifest_path = Path::new("deployments/deployment-manifest.json");
    let manifest_content = fs::read_to_string(manifest_path)?;
    let mut manifest: serde_json::Value = serde_json::from_str(&manifest_content)?;

    // Update Ethereum contracts section
    if let Some(ethereum) = manifest["deployments"]["ethereum"].as_object_mut() {
        if let Some(contracts) = ethereum["contracts"].as_array_mut() {
            // Update CSVLock contract
            if let Some(lock_contract) = contracts.get_mut(0) {
                if let Some(lock_obj) = lock_contract.as_object_mut() {
                    lock_obj.insert("address".to_string(), serde_json::json!(lock_address));
                    lock_obj.insert("deployment_tx".to_string(), serde_json::json!(deployment_tx));
                    lock_obj.insert("block_number".to_string(), serde_json::json!(block_number));
                    // Compute actual bytecode hash from deployed contract
                    let bytecode_path = Path::new("deployments/artifacts/CSVLock.bin");
                    if bytecode_path.exists() {
                        let bytecode = fs::read(bytecode_path)?;
                        let hash = sha3::Keccak256::digest(&bytecode);
                        lock_obj.insert("bytecode_hash".to_string(), serde_json::json!(format!("0x{}", hex::encode(hash))));
                    } else {
                        return Err(Box::from(format!("Bytecode file not found: {:?}", bytecode_path)));
                    }
                    lock_obj.insert("verified".to_string(), serde_json::json!(false));
                    
                    // Update constructor args
                    if let Some(constructor_args) = lock_obj["constructor_args"].as_object_mut() {
                        constructor_args.insert("mintContract".to_string(), serde_json::json!(mint_address));
                    }
                }
            }

            // Update CSVMint contract
            if let Some(mint_contract) = contracts.get_mut(1) {
                if let Some(mint_obj) = mint_contract.as_object_mut() {
                    mint_obj.insert("address".to_string(), serde_json::json!(mint_address));
                    mint_obj.insert("deployment_tx".to_string(), serde_json::json!(deployment_tx));
                    mint_obj.insert("block_number".to_string(), serde_json::json!(block_number));
                    // Compute actual bytecode hash from deployed contract
                    let bytecode_path = Path::new("deployments/artifacts/CSVMint.bin");
                    if bytecode_path.exists() {
                        let bytecode = fs::read(bytecode_path)?;
                        let hash = sha3::Keccak256::digest(&bytecode);
                        mint_obj.insert("bytecode_hash".to_string(), serde_json::json!(format!("0x{}", hex::encode(hash))));
                    } else {
                        return Err(Box::from(format!("Bytecode file not found: {:?}", bytecode_path)));
                    }
                    mint_obj.insert("verified".to_string(), serde_json::json!(false));
                    
                    // Update constructor args
                    if let Some(constructor_args) = mint_obj["constructor_args"].as_object_mut() {
                        constructor_args.insert("lockContract".to_string(), serde_json::json!(lock_address));
                        // Verifier address must be set from deployment config
                    let verifier_address = env::var("VERIFIER_ADDRESS")
                        .map_err(|_| Box::from("VERIFIER_ADDRESS environment variable not set. Please set it to the deployed ZK verifier contract address."))?;
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
    println!("CSVLock address: {}", lock_address);
    println!("CSVMint address: {}", mint_address);
    println!("Deployment TX: {}", deployment_tx);
    println!("Block number: {}", block_number);

    // Also update chains/ethereum.toml
    update_chains_config(lock_address, mint_address)?;

    Ok(())
}

fn update_chains_config(lock_address: &str, mint_address: &str) -> Result<(), Box<dyn std::error::Error>> {
    let config_path = Path::new("chains/ethereum.toml");
    let config_content = fs::read_to_string(config_path)?;
    
    let updated_content = config_content
        .replace("lock_contract_address = \"\"", &format!("lock_contract_address = \"{}\"", lock_address))
        .replace("mint_contract_address = \"\"", &format!("mint_contract_address = \"{}\"", mint_address));
    
    fs::write(config_path, updated_content)?;
    
    println!("chains/ethereum.toml updated successfully!");
    
    Ok(())
}
