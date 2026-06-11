//! Deployment manifest reader
//! 
//! This module provides functions to read contract addresses from the deployment manifest,
//! which serves as the single source of truth for all deployed contract addresses.

use serde::Deserialize;
use std::path::Path;
use std::fs;

/// Deployment manifest structure
#[derive(Debug, Deserialize)]
pub struct DeploymentManifest {
    pub deployments: Deployments,
}

#[derive(Debug, Deserialize)]
pub struct Deployments {
    pub ethereum: Option<EthereumDeployment>,
    pub solana: Option<BasicDeployment>,
    pub sui: Option<BasicDeployment>,
    pub aptos: Option<AptosDeployment>,
}

#[derive(Debug, Deserialize)]
pub struct EthereumDeployment {
    pub network: String,
    pub contracts: Vec<EthereumContract>,
}

#[derive(Debug, Deserialize)]
pub struct EthereumContract {
    pub name: String,
    pub address: String,
    pub deployment_tx: String,
}

#[derive(Debug, Deserialize)]
pub struct BasicDeployment {
    pub network: String,
    #[serde(rename = "package_id")]
    pub package_id: Option<String>,
    #[serde(rename = "program_id")]
    pub program_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AptosDeployment {
    pub network: String,
    #[serde(rename = "module_address")]
    pub module_address: String,
    #[serde(rename = "deployment_tx")]
    pub deployment_tx: Option<String>,
}

/// Load the deployment manifest from the default location
pub fn load_deployment_manifest() -> Result<DeploymentManifest, Box<dyn std::error::Error>> {
    // Try to find the deployment manifest in the workspace root
    let manifest_path = if Path::new("deployments/deployment-manifest.json").exists() {
        Path::new("deployments/deployment-manifest.json")
    } else if Path::new("../deployments/deployment-manifest.json").exists() {
        Path::new("../deployments/deployment-manifest.json")
    } else if Path::new("../../deployments/deployment-manifest.json").exists() {
        Path::new("../../deployments/deployment-manifest.json")
    } else {
        Path::new("deployments/deployment-manifest.json")
    };
    load_deployment_manifest_from_path(manifest_path)
}

/// Load the deployment manifest from a specific path
pub fn load_deployment_manifest_from_path(path: &Path) -> Result<DeploymentManifest, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;
    let manifest: DeploymentManifest = serde_json::from_str(&content)?;
    Ok(manifest)
}

/// Get the Aptos module address from the deployment manifest
pub fn get_aptos_module_address() -> Result<String, Box<dyn std::error::Error>> {
    let manifest = load_deployment_manifest()?;
    let aptos = manifest.deployments.aptos
        .ok_or_else(|| Box::<dyn std::error::Error>::from("Aptos deployment not found in manifest"))?;
    Ok(aptos.module_address)
}

/// Get the Aptos contract address (same as module address)
pub fn get_aptos_contract_address() -> Result<String, Box<dyn std::error::Error>> {
    get_aptos_module_address()
}

/// Get the Ethereum contract address from the deployment manifest
pub fn get_ethereum_contract_address() -> Result<String, Box<dyn std::error::Error>> {
    let manifest = load_deployment_manifest()?;
    let ethereum = manifest.deployments.ethereum
        .ok_or_else(|| Box::<dyn std::error::Error>::from("Ethereum deployment not found in manifest"))?;
    let contract = ethereum.contracts
        .iter()
        .find(|c| c.name == "CSVSeal")
        .ok_or_else(|| Box::<dyn std::error::Error>::from("CSVSeal contract not found in Ethereum deployment"))?;
    Ok(contract.address.clone())
}

/// Get the Solana program ID from the deployment manifest
pub fn get_solana_program_id() -> Result<String, Box<dyn std::error::Error>> {
    let manifest = load_deployment_manifest()?;
    let solana = manifest.deployments.solana
        .ok_or_else(|| Box::<dyn std::error::Error>::from("Solana deployment not found in manifest"))?;
    solana.program_id
        .or_else(|| solana.package_id.clone())
        .ok_or_else(|| Box::<dyn std::error::Error>::from("Solana program_id not found in manifest"))
}

/// Get the Sui package ID from the deployment manifest
pub fn get_sui_package_id() -> Result<String, Box<dyn std::error::Error>> {
    let manifest = load_deployment_manifest()?;
    let sui = manifest.deployments.sui
        .ok_or_else(|| Box::<dyn std::error::Error>::from("Sui deployment not found in manifest"))?;
    sui.package_id
        .ok_or_else(|| Box::<dyn std::error::Error>::from("Sui package_id not found in manifest"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_deployment_manifest() {
        let manifest = load_deployment_manifest();
        assert!(manifest.is_ok());
    }

    #[test]
    fn test_get_aptos_module_address() {
        let address = get_aptos_module_address();
        assert!(address.is_ok());
        let addr = address.unwrap();
        // Accept both with and without 0x prefix
        let addr_normalized = if addr.starts_with("0x") {
            addr.clone()
        } else {
            format!("0x{}", addr)
        };
        assert!(addr_normalized.starts_with("0x"));
        assert_eq!(addr_normalized.len(), 66); // 0x + 64 hex chars
    }
}
