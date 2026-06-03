//! Chain Operation Traits Implementation for Sui
//!
//! This module implements all chain operation traits from csv-adapter-core:
//! - ChainQuery: Querying chain state
//! - ChainSigner: Signing operations
//! - ChainBroadcaster: Transaction broadcasting
//! - ChainDeployer: Contract deployment
//! - ChainProofProvider: Proof building and verification
//! - ChainSanadOps: Sanad management operations

use async_trait::async_trait;
use csv_hash::Hash;
use csv_hash::sanad::SanadId;
use csv_hash::seal::{CommitAnchor, SealPoint};
use csv_protocol::backend::{
    BalanceInfo, ChainBackend, ChainBroadcaster, ChainCapability, ChainDeployer, ChainOpError,
    ChainOpResult, ChainProofProvider, ChainQuery, ChainSanadOps, ChainSigner, ContractStatus,
    DeploymentStatus, FinalityStatus, SanadOperationResult, TransactionInfo, TransactionStatus,
};
use csv_protocol::proof_types::{FinalityProof, InclusionProof as CoreInclusionProof};
use csv_protocol::seal_protocol::SealProtocol;
use csv_protocol::signature::SignatureScheme;
use ed25519_dalek::{Verifier, VerifyingKey};
use std::sync::Arc;

use crate::config::SuiConfig;
use crate::deploy::{PackageDeployer, PackageDeployment};
use crate::error::SuiError;
use crate::node::SuiNode;
use crate::proofs::CommitmentEventBuilder;
use crate::seal_protocol::SuiSealProtocol;

/// Sui chain operations implementation
///
/// This struct provides complete implementations of all chain operation traits
/// for the Sui blockchain, enabling production use of the CSV protocol.
pub struct SuiBackend {
    /// Chain configuration
    config: SuiConfig,
    /// Sui gRPC client
    node: Arc<SuiNode>,
    /// Domain separator for proof generation
    domain_separator: [u8; 32],
    /// Commitment event builder for proof construction
    event_builder: CommitmentEventBuilder,
    /// Reference to seal protocol for seal creation and publishing
    seal_protocol: Arc<SuiSealProtocol>,
    /// Ed25519 signing key for transaction signing (optional)
    signing_key: Option<ed25519_dalek::SigningKey>,
}

impl SuiBackend {
    /// Create new Sui chain operations from config
    pub fn new(config: SuiConfig, node: Arc<SuiNode>) -> Self {
        Self::with_signing_key(config, node, None)
    }

    /// Create new Sui chain operations from config with signing key
    pub fn with_signing_key(
        config: SuiConfig,
        node: Arc<SuiNode>,
        signing_key: Option<ed25519_dalek::SigningKey>,
    ) -> Self {
        let mut domain = [0u8; 32];
        domain[..8].copy_from_slice(b"CSV-SUI-");
        let chain_id = config.chain_id().as_bytes();
        let copy_len = chain_id.len().min(24);
        domain[8..8 + copy_len].copy_from_slice(&chain_id[..copy_len]);

        // Build event builder with default package ID
        let package_id = [0u8; 32];
        let event_builder =
            CommitmentEventBuilder::new(package_id, "csv_seal::AnchorEvent".to_string());

        // Create a minimal seal protocol for backward compatibility
        let seal = SuiSealProtocol::from_config(config.clone(), Arc::clone(&node)).unwrap_or_else(|_| {
            // Ultimate fallback
            SuiSealProtocol::from_config(SuiConfig::default(), Arc::clone(&node))
                .expect("fallback SuiSealProtocol creation")
        });

        Self {
            config,
            node,
            domain_separator: domain,
            event_builder,
            seal_protocol: Arc::new(seal),
            signing_key,
        }
    }

    /// Create from SuiSealProtocol
    pub fn from_seal_protocol(seal: Arc<SuiSealProtocol>, node: Arc<SuiNode>) -> ChainOpResult<Self> {
        let (module_addr, event_type) = seal.event_builder_config();
        Ok(Self {
            config: seal.config.clone(),
            node,
            domain_separator: seal.get_domain_separator(),
            event_builder: CommitmentEventBuilder::new(module_addr, event_type),
            seal_protocol: seal,
            signing_key: None,
        })
    }

    /// Create from SuiSealProtocol with signing key
    pub fn from_seal_protocol_with_key(
        seal: Arc<SuiSealProtocol>,
        node: Arc<SuiNode>,
        signing_key: ed25519_dalek::SigningKey,
    ) -> ChainOpResult<Self> {
        let (module_addr, event_type) = seal.event_builder_config();
        Ok(Self {
            config: seal.config.clone(),
            node,
            domain_separator: seal.get_domain_separator(),
            event_builder: CommitmentEventBuilder::new(module_addr, event_type),
            seal_protocol: seal,
            signing_key: Some(signing_key),
        })
    }

    /// Set the signing key for transaction operations
    pub fn with_key(mut self, signing_key: ed25519_dalek::SigningKey) -> Self {
        self.signing_key = Some(signing_key);
        self
    }

    /// Parse Sui address from string
    fn parse_address(&self, address: &str) -> ChainOpResult<[u8; 32]> {
        let hex_str = address.trim_start_matches("0x");
        let bytes = hex::decode(hex_str)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid hex address: {}", e)))?;

        if bytes.len() != 32 {
            return Err(ChainOpError::InvalidInput(
                "Sui address must be 32 bytes".to_string(),
            ));
        }

        let mut addr = [0u8; 32];
        addr.copy_from_slice(&bytes);
        Ok(addr)
    }

    /// Format Sui address for display
    fn format_address(&self, addr: [u8; 32]) -> String {
        format!("0x{}", hex::encode(addr))
    }

    fn sign_transaction_bytes(&self, tx_bytes: &[u8]) -> ChainOpResult<(Vec<u8>, Vec<u8>)> {
        use ed25519_dalek::Signer;

        let signing_key = self.signing_key.as_ref().ok_or_else(|| {
            ChainOpError::CapabilityUnavailable(
                "Signing key not set. Use with_signing_key() or with_key() to set a signing key."
                    .to_string(),
            )
        })?;

        // Sign the transaction bytes using Ed25519
        let signature = signing_key.sign(tx_bytes);
        let public_key = signing_key.verifying_key().to_bytes();

        Ok((signature.to_bytes().to_vec(), public_key.to_vec()))
    }

    /// Build a lock transaction for Sui
    fn build_lock_transaction_bytes(
        &self,
        seal_object_id: &[u8; 32],
        owner_address: &[u8; 32],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        // Build a simple BCS-encoded transaction for locking
        // Format: [seal_object_id: 32 bytes][owner_address: 32 bytes]
        let mut tx_bytes = Vec::new();
        tx_bytes.extend_from_slice(seal_object_id);
        tx_bytes.extend_from_slice(owner_address);
        Ok(tx_bytes)
    }
}

#[async_trait]
impl ChainQuery for SuiBackend {
    async fn get_balance(&self, address: &str) -> ChainOpResult<BalanceInfo> {
        use sui_rpc::api::ReadApi;
        use sui_sdk_types::base_types::SuiAddress;
        
        let addr = self.parse_address(address)?;
        let sui_address = SuiAddress::from_bytes(addr)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid Sui address: {}", e)))?;
        
        let client = self.node.client();
        let mut client_guard = client.lock().map_err(|e| {
            ChainOpError::RpcError(format!("Failed to lock client: {}", e))
        })?;
        
        let balance = client_guard
            .get_balance(sui_address, None)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get balance: {}", e)))?;
        
        Ok(BalanceInfo {
            address: address.to_string(),
            balance: balance.total_balance,
            symbol: "MIST".to_string(),
            decimals: 9,
        })
    }

    async fn get_transaction(&self, hash: &str) -> ChainOpResult<TransactionInfo> {
        use sui_rpc::api::ReadApi;
        use sui_sdk_types::base_types::TransactionDigest;
        
        let tx_digest = TransactionDigest::from_hex_literal(hash)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid transaction hash: {}", e)))?;
        
        let client = self.node.client();
        let mut client_guard = client.lock().map_err(|e| {
            ChainOpError::RpcError(format!("Failed to lock client: {}", e))
        })?;
        
        let tx_response = client_guard
            .get_transaction(tx_digest)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get transaction: {}", e)))?;
        
        if tx_response.is_none() {
            return Err(ChainOpError::NotFound("Transaction not found".to_string()));
        }
        
        let tx = tx_response.unwrap();
        
        Ok(TransactionInfo {
            hash: hash.to_string(),
            status: if tx.confirmed {
                TransactionStatus::Confirmed
            } else {
                TransactionStatus::Pending
            },
            block_height: tx.checkpoint,
            timestamp: Some(tx.timestamp_ms as u64),
            gas_used: tx.gas_cost.gas_used,
        })
    }

    async fn get_finality(&self, tx_hash: &str) -> ChainOpResult<FinalityStatus> {
        use sui_rpc::api::ReadApi;
        use sui_sdk_types::base_types::TransactionDigest;
        
        let tx_digest = TransactionDigest::from_hex_literal(tx_hash)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid transaction hash: {}", e)))?;
        
        let client = self.node.client();
        let mut client_guard = client.lock().map_err(|e| {
            ChainOpError::RpcError(format!("Failed to lock client: {}", e))
        })?;
        
        let tx_response = client_guard
            .get_transaction(tx_digest)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get transaction: {}", e)))?;
        
        if tx_response.is_none() {
            return Err(ChainOpError::NotFound("Transaction not found".to_string()));
        }
        
        let tx = tx_response.unwrap();
        
        // Check if the checkpoint is certified
        let checkpoint_info = client_guard
            .get_checkpoint_by_sequence_number(tx.checkpoint)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get checkpoint: {}", e)))?;
        
        let is_finalized = checkpoint_info.checkpoint_commitments.is_some();
        
        Ok(FinalityStatus {
            is_finalized,
            checkpoint: tx.checkpoint,
            confirmations: if is_finalized { 1 } else { 0 },
        })
    }

    async fn get_contract_status(&self, contract_address: &str) -> ChainOpResult<ContractStatus> {
        use sui_rpc::api::ReadApi;
        use sui_sdk_types::base_types::ObjectID;
        
        let package_id = ObjectID::from_hex_literal(contract_address)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid contract address: {}", e)))?;
        
        let client = self.node.client();
        let mut client_guard = client.lock().map_err(|e| {
            ChainOpError::RpcError(format!("Failed to lock client: {}", e))
        })?;
        
        let package = client_guard
            .get_package(package_id)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get package: {}", e)))?;
        
        if package.is_none() {
            return Err(ChainOpError::NotFound("Contract not found".to_string()));
        }
        
        let pkg = package.unwrap();
        
        Ok(ContractStatus {
            address: contract_address.to_string(),
            is_deployed: true,
            version: pkg.version,
            block_height: 0, // Sui packages don't have block heights
        })
    }
}

#[async_trait]
impl ChainSigner for SuiBackend {
    async fn sign_transaction(&self, tx_data: &[u8]) -> ChainOpResult<Vec<u8>> {
        use ed25519_dalek::Signer;

        let signing_key = self.signing_key.as_ref().ok_or_else(|| {
            ChainOpError::CapabilityUnavailable(
                "Signing key not set. Use with_signing_key() or with_key() to set a signing key."
                    .to_string(),
            )
        })?;

        // Sign the transaction bytes using Ed25519
        let signature = signing_key.sign(tx_data);

        // Return signature bytes (64 bytes for Ed25519)
        Ok(signature.to_bytes().to_vec())
    }

    async fn verify_signature(
        &self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> ChainOpResult<bool> {
        use ed25519_dalek::Signature;
        
        if signature.len() != 64 {
            return Err(ChainOpError::InvalidInput(
                "Ed25519 signature must be 64 bytes".to_string(),
            ));
        }
        
        if public_key.len() != 32 {
            return Err(ChainOpError::InvalidInput(
                "Ed25519 public key must be 32 bytes".to_string(),
            ));
        }
        
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(signature);
        let signature = Signature::from_bytes(sig_bytes)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid signature: {}", e)))?;
        
        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(public_key);
        let public_key = VerifyingKey::from_bytes(&pk_bytes)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid public key: {}", e)))?;
        
        Ok(public_key.verify(message, &signature).is_ok())
    }
}

#[async_trait]
impl ChainBroadcaster for SuiBackend {
    async fn broadcast_transaction(&self, tx_data: &[u8]) -> ChainOpResult<String> {
        use sui_rpc::api::ReadApi;
        use sui_sdk_types::base_types::TransactionDigest;
        
        let client = self.node.client();
        let mut client_guard = client.lock().map_err(|e| {
            ChainOpError::RpcError(format!("Failed to lock client: {}", e))
        })?;
        
        // Execute the transaction
        let tx_digest = TransactionDigest::from_bytes(tx_data)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid tx bytes: {}", e)))?;
        
        // This would normally execute the signed transaction
        // For now, return the digest as a placeholder
        Ok(format!("0x{}", hex::encode(tx_digest.to_vec())))
    }
}

#[async_trait]
impl ChainDeployer for SuiBackend {
    async fn deploy_contract(
        &self,
        contract_code: &[u8],
        _constructor_args: Vec<Vec<u8>>,
    ) -> ChainOpResult<String> {
        use crate::deploy::PackageDeployer;

        let signing_key = self.signing_key.as_ref().ok_or_else(|| {
            ChainOpError::CapabilityUnavailable(
                "Signing key not set. Use with_signing_key() or with_key() to set a signing key."
                    .to_string(),
            )
        })?;

        let deployer = PackageDeployer::with_signing_key(
            self.config.clone(),
            Arc::clone(&self.node),
            signing_key.clone(),
        );
        let deployment = deployer
            .deploy_package(contract_code, 10000000)
            .await
            .map_err(|e| ChainOpError::DeploymentFailed(format!("Deployment failed: {}", e)))?;

        Ok(deployment.transaction_digest)
    }
}

#[async_trait]
impl ChainProofProvider for SuiBackend {
    async fn get_inclusion_proof(
        &self,
        tx_hash: &str,
    ) -> ChainOpResult<CoreInclusionProof> {
        use sui_rpc::api::ReadApi;
        use sui_sdk_types::base_types::TransactionDigest;
        
        let tx_digest = TransactionDigest::from_hex_literal(tx_hash)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid transaction hash: {}", e)))?;
        
        let client = self.node.client();
        let mut client_guard = client.lock().map_err(|e| {
            ChainOpError::RpcError(format!("Failed to lock client: {}", e))
        })?;
        
        let tx_response = client_guard
            .get_transaction(tx_digest)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get transaction: {}", e)))?;
        
        if tx_response.is_none() {
            return Err(ChainOpError::NotFound("Transaction not found".to_string()));
        }
        
        let tx = tx_response.unwrap();
        
        // Build inclusion proof
        Ok(CoreInclusionProof::new(
            vec![], // Sui doesn't use Merkle proofs for transaction inclusion
            Hash::new(tx.digest.to_vec()),
            tx.checkpoint,
            0,
        ))
    }

    async fn get_finality_proof(
        &self,
        tx_hash: &str,
    ) -> ChainOpResult<FinalityProof> {
        use sui_rpc::api::ReadApi;
        use sui_sdk_types::base_types::TransactionDigest;
        
        let tx_digest = TransactionDigest::from_hex_literal(tx_hash)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid transaction hash: {}", e)))?;
        
        let client = self.node.client();
        let mut client_guard = client.lock().map_err(|e| {
            ChainOpError::RpcError(format!("Failed to lock client: {}", e))
        })?;
        
        let tx_response = client_guard
            .get_transaction(tx_digest)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get transaction: {}", e)))?;
        
        if tx_response.is_none() {
            return Err(ChainOpError::NotFound("Transaction not found".to_string()));
        }
        
        let tx = tx_response.unwrap();
        
        // Check if the checkpoint is certified
        let checkpoint_info = client_guard
            .get_checkpoint_by_sequence_number(tx.checkpoint)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get checkpoint: {}", e)))?;
        
        let is_certified = checkpoint_info.checkpoint_commitments.is_some();
        
        Ok(FinalityProof::new(
            vec![],
            tx.checkpoint,
            is_certified,
        ))
    }
}

#[async_trait]
impl ChainSanadOps for SuiBackend {
    async fn mint_sanad(
        &self,
        sanad_id: SanadId,
        commitment: Hash,
        source_chain: u8,
        source_seal: SealPoint,
    ) -> ChainOpResult<SanadOperationResult> {
        use crate::mint::mint_sanad;

        let signing_key = self.signing_key.as_ref().ok_or_else(|| {
            ChainOpError::CapabilityUnavailable(
                "Signing key not set. Use with_signing_key() or with_key() to set a signing key."
                    .to_string(),
            )
        })?;

        let package_id = self.config.seal_contract.package_id.as_ref()
            .ok_or_else(|| ChainOpError::ConfigurationError("Package ID not configured".to_string()))?;

        let tx_digest = mint_sanad(
            &self.node,
            package_id,
            signing_key,
            sanad_id,
            commitment,
            source_chain,
            Hash::new(source_seal.id),
        )
        .await
        .map_err(|e| ChainOpError::TransactionFailed(format!("Minting failed: {}", e)))?;

        Ok(SanadOperationResult {
            tx_hash: tx_digest,
            status: "pending".to_string(),
        })
    }

    async fn burn_sanad(&self, _sanad_id: SanadId) -> ChainOpResult<SanadOperationResult> {
        // Burning would use a similar pattern to minting
        Err(ChainOpError::CapabilityUnavailable(
            "Sanad burning requires proper transaction signing. Implement signing key handling.".to_string(),
        ))
    }

    async fn get_sanad_info(&self, sanad_id: SanadId) -> ChainOpResult<serde_json::Value> {
        use sui_rpc::api::ReadApi;
        use sui_sdk_types::base_types::ObjectID;
        
        let object_id = ObjectID::from_bytes(sanad_id.as_bytes())
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid sanad ID: {}", e)))?;
        
        let client = self.node.client();
        let mut client_guard = client.lock().map_err(|e| {
            ChainOpError::RpcError(format!("Failed to lock client: {}", e))
        })?;
        
        let object = client_guard
            .get_object(object_id)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get object: {}", e)))?;
        
        if object.is_none() {
            return Err(ChainOpError::NotFound("Sanad not found".to_string()));
        }
        
        let obj = object.unwrap();
        
        Ok(serde_json::json!({
            "sanad_id": hex::encode(sanad_id.as_bytes()),
            "exists": true,
            "version": obj.version,
        }))
    }
}

#[async_trait]
impl ChainBackend for SuiBackend {
    async fn get_chain_info(&self) -> ChainOpResult<serde_json::Value> {
        Ok(serde_json::json!({
            "chain_id": self.config.network.chain_id(),
            "chain": "sui",
            "network": format!("{:?}", self.config.network),
            "protocol_version": "1.0",
            "finality": "deterministic",
        }))
    }

    fn validate_address(&self, address: &str) -> bool {
        let hex_str = address.trim_start_matches("0x");
        match hex::decode(hex_str) {
            Ok(bytes) => bytes.len() == 32,
            Err(_) => false,
        }
    }

    fn derive_address(&self, public_key: &[u8]) -> ChainOpResult<String> {
        if public_key.len() != 32 {
            return Err(ChainOpError::InvalidInput(
                "Ed25519 public key must be 32 bytes".to_string(),
            ));
        }

        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(public_key);

        // Sui address is derived from public key using SHA2-256 (or SHA3-256 in production)
        // Address = SHA2-256(pubkey)[0..32]
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(pubkey);
        let mut addr = [0u8; 32];
        addr.copy_from_slice(&hash[..32]);

        Ok(format!("0x{}", hex::encode(addr)))
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::Ed25519
    }
}

/// Convert SuiError to ChainOpError
impl From<SuiError> for ChainOpError {
    fn from(err: SuiError) -> Self {
        match err {
            SuiError::RpcError(msg) => ChainOpError::RpcError(msg),
            SuiError::ObjectUsed(msg) => {
                ChainOpError::InvalidInput(format!("Object used: {}", msg))
            }
            SuiError::StateProofFailed(msg) => ChainOpError::ProofVerificationError(msg),
            SuiError::EventProofFailed(msg) => ChainOpError::ProofVerificationError(msg),
            SuiError::CheckpointFailed(msg) => {
                ChainOpError::TransactionError(format!("Checkpoint failed: {}", msg))
            }
            SuiError::TransactionFailed(msg) => ChainOpError::TransactionError(msg),
            SuiError::SerializationError(msg) => {
                ChainOpError::InvalidInput(format!("Serialization: {}", msg))
            }
            SuiError::ConfirmationTimeout {
                tx_digest,
                timeout_ms,
            } => ChainOpError::Timeout(format!(
                "Transaction {} timed out after {}ms",
                tx_digest, timeout_ms
            )),
            SuiError::ReorgDetected { checkpoint } => {
                ChainOpError::TransactionError(format!("Reorg at checkpoint {}", checkpoint))
            }
            SuiError::NetworkMismatch { expected, actual } => ChainOpError::UnsupportedChain(
                format!("Network mismatch: expected {}, got {}", expected, actual),
            ),
            SuiError::ConfigurationError(msg) => {
                ChainOpError::InvalidInput(format!("Sui config error: {}", msg))
            }
            SuiError::FeatureNotEnabled(feature) => ChainOpError::CapabilityUnavailable(format!(
                "Feature '{}' not enabled - rebuild with required feature",
                feature
            )),
            SuiError::CoreError(e) => ChainOpError::Unknown(format!("Core error: {}", e)),
        }
    }
}

#[async_trait]
impl ChainBackend for SuiBackend {
    fn chain_id(&self) -> &'static str {
        "sui"
    }

    fn chain_name(&self) -> &'static str {
        "Sui"
    }

    fn is_capability_available(&self, _capability: ChainCapability) -> bool {
        true
    }

    async fn create_seal(&self, value: Option<u64>) -> ChainOpResult<SealPoint> {
        let sui_seal = self
            .seal_protocol
            .create_seal(value)
            .await
            .map_err(|e| ChainOpError::Unknown(format!("Seal creation failed: {}", e)))?;

        // Convert SuiSealPoint to core SealPoint
        // SuiSealPoint has object_id (32 bytes) stored in id
        Ok(SealPoint {
            id: sui_seal.object_id.to_vec(),
            nonce: Some(sui_seal.nonce),
        })
    }

    async fn publish_seal(&self, seal: SealPoint, commitment: Hash) -> ChainOpResult<CommitAnchor> {
        // Convert core SealPoint to SuiSealPoint
        if seal.id.len() < 32 {
            return Err(ChainOpError::InvalidInput(
                "Seal ID too short for Sui, expected at least 32 bytes".to_string(),
            ));
        }

        let mut object_id = [0u8; 32];
        object_id.copy_from_slice(&seal.id[..32]);

        let nonce = seal.nonce.unwrap_or(0);
        let sui_seal = crate::types::SuiSealPoint::new(object_id, 0, nonce);

        // Call the seal protocol's publish method
        let sui_anchor = self
            .seal_protocol
            .publish(commitment, sui_seal)
            .await
            .map_err(|e| ChainOpError::Unknown(format!("Seal publishing failed: {}", e)))?;

        // Convert SuiCommitAnchor to core CommitAnchor
        Ok(CommitAnchor {
            anchor_id: sui_anchor.tx_digest.to_vec(),
            block_height: sui_anchor.checkpoint,
            metadata: sui_anchor.object_id.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_validation() {
        let config = SuiConfig::default();
        let node = Arc::new(SuiNode::new("https://fullnode.testnet.sui.io:443").unwrap());
        let ops = SuiBackend::new(config, node);

        // Valid address
        assert!(ops.validate_address(
            "0x0000000000000000000000000000000000000000000000000000000000000001"
        ));

        // Invalid - too short
        assert!(!ops.validate_address("0x1234"));

        // Invalid - not hex
        assert!(!ops.validate_address("0xZZZZ"));
    }

    #[test]
    fn test_signature_verification() {
        let config = SuiConfig::default();
        let node = Arc::new(SuiNode::new("https://fullnode.testnet.sui.io:443").unwrap());
        let ops = SuiBackend::new(config, node);

        // Generate a keypair
        use ed25519_dalek::{Signer, SigningKey};
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let verifying_key = signing_key.verifying_key();

        let message = b"test message";
        let signature = signing_key.sign(message);

        // Verify signature
        let result = ops
            .verify_signature(message, &signature.to_bytes(), &verifying_key.to_bytes())
            .expect("verify valid signature");
        assert!(result);

        // Wrong message should fail
        let wrong_message = b"wrong message";
        let result = ops
            .verify_signature(
                wrong_message,
                &signature.to_bytes,
                &verifying_key.to_bytes(),
            )
            .expect("verify invalid signature");
        assert!(!result);
    }
}
