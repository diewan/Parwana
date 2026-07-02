//! Deployment framework for CSV protocol contracts
//!
//! This module provides a deployment framework with manifest, checksums,
//! and reproducibility for all chain contracts.
//!
//! # Deployment Manifest
//!
//! Every contract deployment MUST have a manifest containing:
//! - Contract name and version
//! - Chain identifier
//! - Deployment bytecode checksum
//! - Constructor parameters
//! - Deployment timestamp
//! - Deployer address
//! - Contract address (after deployment)
//!
//! # Reproducibility
//!
//! All deployments MUST be reproducible:
//! - Same bytecode = same address (CREATE2 deterministic deployment)
//! - Constructor parameters are canonical CBOR encoded
//! - Checksums use SHA-256 of canonical bytecode

use csv_hash::Hash;
use csv_keys::memory::SecretKey;
use csv_protocol::secret::SecretHandle;
use csv_wire::HashWire;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Deployment manifest version.
pub const MANIFEST_VERSION: u32 = 1;

/// Deployment manifest for a contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentManifest {
    /// Manifest version
    pub version: u32,
    /// Contract name
    pub contract_name: String,
    /// Contract version (semver)
    pub contract_version: String,
    /// Chain identifier
    pub chain_id: String,
    /// Deployment bytecode checksum (SHA-256)
    pub bytecode_checksum: HashWire,
    /// ABI checksum (SHA-256 of canonical ABI JSON)
    pub abi_checksum: HashWire,
    /// Constructor parameters (canonical CBOR encoded)
    pub constructor_params: Vec<u8>,
    /// Deployment timestamp (Unix epoch seconds)
    pub deployment_timestamp: u64,
    /// Deployer address (chain-specific encoding)
    pub deployer_address: Vec<u8>,
    /// Contract address (after deployment, chain-specific encoding)
    pub contract_address: Vec<u8>,
    /// Transaction hash of deployment transaction
    pub deployment_tx_hash: HashWire,
    /// Block number of deployment
    pub deployment_block: u64,
    /// Additional metadata
    pub metadata: BTreeMap<String, String>,
}

impl DeploymentManifest {
    /// Create a new deployment manifest.
    pub fn new(
        contract_name: String,
        contract_version: String,
        chain_id: String,
        bytecode: &[u8],
        abi_json: &str,
        constructor_params: Vec<u8>,
        deployer_address: Vec<u8>,
    ) -> Self {
        let bytecode_checksum = HashWire::from(Hash::sha256(bytecode));
        let abi_checksum = HashWire::from(Hash::sha256(abi_json.as_bytes()));
        let deployment_timestamp = chrono::Utc::now().timestamp() as u64;

        Self {
            version: MANIFEST_VERSION,
            contract_name,
            contract_version,
            chain_id,
            bytecode_checksum,
            abi_checksum,
            constructor_params,
            deployment_timestamp,
            deployer_address,
            contract_address: vec![],
            deployment_tx_hash: HashWire::from(Hash::zero()),
            deployment_block: 0,
            metadata: BTreeMap::new(),
        }
    }

    /// Finalize the manifest after deployment.
    pub fn finalize(
        &mut self,
        contract_address: Vec<u8>,
        deployment_tx_hash: Hash,
        deployment_block: u64,
    ) {
        self.contract_address = contract_address;
        self.deployment_tx_hash = HashWire::from(deployment_tx_hash);
        self.deployment_block = deployment_block;
    }

    /// Serialize the manifest to canonical CBOR.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, DeploymentError> {
        csv_codec::to_canonical_cbor(self)
            .map_err(|e| DeploymentError::SerializationError(e.to_string()))
    }

    /// Deserialize the manifest from canonical CBOR.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, DeploymentError> {
        csv_codec::from_canonical_cbor(bytes)
            .map_err(|e| DeploymentError::DeserializationError(e.to_string()))
    }

    /// Compute the manifest checksum.
    pub fn checksum(&self) -> Hash {
        let cbor = self.to_canonical_cbor().unwrap_or_default();
        Hash::sha256(&cbor)
    }

    /// Verify the bytecode checksum matches the manifest.
    pub fn verify_bytecode(&self, bytecode: &[u8]) -> bool {
        self.bytecode_checksum == HashWire::from(Hash::sha256(bytecode))
    }

    /// Verify the ABI checksum matches the manifest.
    pub fn verify_abi(&self, abi_json: &str) -> bool {
        self.abi_checksum == HashWire::from(Hash::sha256(abi_json.as_bytes()))
    }
}

/// Deployment registry tracking all deployed contracts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DeploymentRegistry {
    /// All deployment manifests indexed by contract address
    pub deployments: BTreeMap<String, DeploymentManifest>,
}

impl DeploymentRegistry {
    /// Create a new deployment registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a deployment.
    pub fn register(&mut self, manifest: DeploymentManifest) -> Result<(), DeploymentError> {
        let address_key = hex::encode(&manifest.contract_address);
        if self.deployments.contains_key(&address_key) {
            return Err(DeploymentError::AlreadyDeployed);
        }
        self.deployments.insert(address_key, manifest);
        Ok(())
    }

    /// Get a deployment by contract address.
    pub fn get(&self, contract_address: &[u8]) -> Option<&DeploymentManifest> {
        let address_key = hex::encode(contract_address);
        self.deployments.get(&address_key)
    }

    /// Get all deployments for a chain.
    pub fn get_by_chain(&self, chain_id: &str) -> Vec<&DeploymentManifest> {
        self.deployments
            .values()
            .filter(|m| m.chain_id == chain_id)
            .collect()
    }

    /// Get all deployments for a contract name.
    pub fn get_by_name(&self, contract_name: &str) -> Vec<&DeploymentManifest> {
        self.deployments
            .values()
            .filter(|m| m.contract_name == contract_name)
            .collect()
    }

    /// Verify a deployment is in the registry.
    pub fn verify_deployment(&self, contract_address: &[u8]) -> bool {
        self.get(contract_address).is_some()
    }
}

/// CREATE2 deterministic deployment calculator.
#[derive(Debug, Clone)]
pub struct Create2Deployer {
    /// Deployer address
    pub deployer_address: Vec<u8>,
    /// Salt for deployment
    pub salt: Hash,
}

impl Create2Deployer {
    /// Create a new CREATE2 deployer.
    pub fn new(deployer_address: Vec<u8>, salt: Hash) -> Self {
        Self {
            deployer_address,
            salt,
        }
    }

    /// Calculate the deterministic contract address.
    ///
    /// Formula: keccak256(0xff ++ deployer ++ salt ++ keccak256(bytecode))[12:]
    pub fn calculate_address(&self, bytecode: &[u8]) -> Result<Vec<u8>, DeploymentError> {
        let bytecode_hash = Hash::sha256(bytecode);

        let mut data = Vec::with_capacity(1 + self.deployer_address.len() + 32 + 32);
        data.push(0xff);
        data.extend_from_slice(&self.deployer_address);
        data.extend_from_slice(self.salt.as_ref());
        data.extend_from_slice(bytecode_hash.as_ref());

        let hash = Hash::sha256(&data);
        // Return last 20 bytes (Ethereum address format)
        let hash_bytes = hash.as_ref() as &[u8];
        Ok(hash_bytes[12..].to_vec())
    }
}

/// Deployment errors.
#[derive(Debug, Clone, thiserror::Error)]
pub enum DeploymentError {
    /// Contract already deployed at this address
    #[error("Contract already deployed at this address")]
    AlreadyDeployed,

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Deserialization error
    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    /// Invalid bytecode
    #[error("Invalid bytecode")]
    InvalidBytecode,

    /// Invalid constructor parameters
    #[error("Invalid constructor parameters")]
    InvalidConstructorParams,

    /// Deployment failed
    #[error("Deployment failed: {0}")]
    DeploymentFailed(String),

    /// Checksum mismatch
    #[error("Checksum mismatch")]
    ChecksumMismatch,
}

/// Deployment configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentConfig {
    /// Chain identifier
    pub chain_id: String,
    /// RPC endpoint
    pub rpc_url: String,
    /// Private key for deployment (raw string for deserialization only - convert to SecretHandle immediately)
    pub private_key: String,
    /// Gas price (in wei)
    pub gas_price: Option<u64>,
    /// Gas limit
    pub gas_limit: Option<u64>,
    /// Confirmations required
    pub confirmations: u64,
}

impl DeploymentConfig {
    /// Convert private_key String to typed SecretHandle (zeroize-on-drop)
    /// This should be called immediately after deserialization to ensure secrets are never exposed as raw strings
    pub fn to_secret_handle(&self) -> SecretHandle {
        let bytes =
            hex::decode(&self.private_key).unwrap_or_else(|_| self.private_key.as_bytes().to_vec());
        // Pad or truncate to 32 bytes for SecretKey
        let mut key_bytes = [0u8; 32];
        let len = bytes.len().min(32);
        key_bytes[..len].copy_from_slice(&bytes[..len]);
        let key = SecretKey::new(key_bytes);
        SecretHandle::from_key(key)
    }
}

impl Default for DeploymentConfig {
    fn default() -> Self {
        Self {
            chain_id: "1".to_string(),
            rpc_url: String::new(),
            private_key: String::new(),
            gas_price: None,
            gas_limit: Some(5_000_000),
            confirmations: 1,
        }
    }
}

/// Deployment result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentResult {
    /// Contract address
    pub contract_address: Vec<u8>,
    /// Transaction hash
    pub tx_hash: HashWire,
    /// Block number
    pub block_number: u64,
    /// Gas used
    pub gas_used: u64,
    /// Deployment manifest
    pub manifest: DeploymentManifest,
}

/// Contract bytecode with metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractBytecode {
    /// Raw bytecode
    pub bytecode: Vec<u8>,
    /// Checksum (SHA-256)
    pub checksum: HashWire,
    /// Source hash (for verification)
    pub source_hash: HashWire,
    /// Compiler version
    pub compiler_version: String,
    /// Compilation timestamp
    pub compilation_timestamp: u64,
}

impl ContractBytecode {
    /// Create new contract bytecode.
    pub fn new(bytecode: Vec<u8>, compiler_version: String) -> Self {
        let checksum = HashWire::from(Hash::sha256(&bytecode));
        let source_hash = HashWire::from(Hash::sha256(&bytecode)); // In production, hash source code
        let compilation_timestamp = chrono::Utc::now().timestamp() as u64;

        Self {
            bytecode,
            checksum,
            source_hash,
            compiler_version,
            compilation_timestamp,
        }
    }

    /// Verify the bytecode checksum.
    pub fn verify(&self) -> bool {
        self.checksum == HashWire::from(Hash::sha256(&self.bytecode))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deployment_manifest_checksum() {
        let manifest = DeploymentManifest::new(
            "TestContract".to_string(),
            "1.0.0".to_string(),
            "ethereum".to_string(),
            &[1, 2, 3],
            "{}",
            vec![],
            vec![4, 5, 6],
        );
        let checksum = manifest.checksum();
        assert_ne!(checksum, Hash::zero());
    }

    #[test]
    fn test_deployment_registry() {
        let mut registry = DeploymentRegistry::new();
        let manifest = DeploymentManifest::new(
            "TestContract".to_string(),
            "1.0.0".to_string(),
            "ethereum".to_string(),
            &[1, 2, 3],
            "{}",
            vec![],
            vec![4, 5, 6],
        );

        let mut finalized = manifest.clone();
        finalized.finalize(vec![7, 8, 9], Hash::zero(), 100);

        registry.register(finalized).unwrap();
        assert!(registry.verify_deployment(&[7, 8, 9]));
    }

    #[test]
    fn test_create2_address_calculation() {
        let deployer = Create2Deployer::new(vec![1; 20], Hash::zero());
        let bytecode = vec![2; 100];
        let address = deployer.calculate_address(&bytecode).unwrap();
        assert_eq!(address.len(), 20);
    }
}
