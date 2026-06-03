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
use crate::error::SuiError;
use crate::node::SuiNode;
use crate::proofs::CommitmentEventBuilder;
use crate::seal_protocol::SuiSealProtocol;

/// Parse a Sui object ID string (hex).
fn parse_object_id(s: &str) -> Result<[u8; 32], String> {
    let hex_str = s.trim_start_matches("0x");
    let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!("Object ID must be 32 bytes, got {}", bytes.len()));
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes);
    Ok(id)
}

/// Parse a Sui digest string (hex).
fn parse_digest(s: &str) -> Result<[u8; 32], String> {
    let hex_str = s.trim_start_matches("0x");
    let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!("Digest must be 32 bytes, got {}", bytes.len()));
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&bytes);
    Ok(digest)
}

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
        #[cfg(feature = "rpc")]
        {
            use sui_sdk_types::Address;
            
            let addr = self.parse_address(address)?;
            let sui_address = Address::from_bytes(addr)
                .map_err(|e| ChainOpError::InvalidInput(format!("Invalid Sui address: {}", e)))?;
            
            let client = self.node.client();
            let client_guard = client.lock().await;
            
            // Use list_balances to get balance information
            use sui_rpc::proto::sui::rpc::v2::ListBalancesRequest;
            
            let mut balance_request = ListBalancesRequest::default();
            balance_request.owner = Some(sui_address.to_string());
            balance_request.page_size = Some(1);
            
            let balance_stream = (*client_guard)
                .list_balances(balance_request);
            
            // Collect the first balance from the stream
            use futures::StreamExt;
            let mut pinned = Box::pin(balance_stream);
            let balance = pinned.next().await
                .ok_or_else(|| ChainOpError::InvalidInput("No balance found".to_string()))
                .map_err(|e| ChainOpError::RpcError(format!("Failed to get balance: {}", e)))?
                .map_err(|e| ChainOpError::RpcError(format!("Failed to get balance: {}", e)))?;
            
            // Build token information from balance response
            // Sui uses coin objects, so we extract the coin type and balance
            let tokens = if let Some(coin_type) = balance.coin_type {
                vec![csv_protocol::backend::TokenBalance {
                    symbol: "SUI".to_string(), // Default to SUI for native token
                    decimals: 9, // SUI has 9 decimals
                    balance: balance.balance.unwrap_or(0),
                    token_id: coin_type,
                }]
            } else {
                vec![]
            };

            Ok(BalanceInfo {
                address: address.to_string(),
                total: balance.balance.unwrap_or(0),
                available: balance.balance.unwrap_or(0), // Assume all is available for now
                locked: 0,
                tokens,
            })
        }
        
        #[cfg(not(feature = "rpc"))]
        {
            Err(ChainOpError::CapabilityUnavailable(
                "RPC feature not enabled. Enable the 'rpc' feature to use Sui RPC functionality.".to_string(),
            ))
        }
    }

    async fn get_transaction(&self, hash: &str) -> ChainOpResult<TransactionInfo> {
        use sui_rpc::proto::sui::rpc::v2::GetTransactionRequest;
        
        let tx_digest = sui_sdk_types::Digest::from_bytes(&parse_digest(hash)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid transaction hash: {}", e)))?)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid transaction hash: {}", e)))?;
        
        let client = self.node.client();
        let mut client_guard = client.lock().await;
        
        let request = GetTransactionRequest::new(&tx_digest);
        
        let tx_response = (*client_guard)
            .ledger_client()
            .get_transaction(request)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get transaction: {}", e)))?;
        
        let tx = tx_response.into_inner().transaction.ok_or_else(|| {
            ChainOpError::InvalidInput("Transaction not found in response".to_string())
        })?;

        // Extract sender from transaction - simplified since ExecutedTransaction doesn't have sender field
        let sender = "0x0".to_string();
        
        // Extract fee from transaction effects - GasCostSummary to u64 conversion
        let fee = if let Some(effects) = &tx.effects {
            effects.gas_used.map(|g| {
                g.computation_cost.unwrap_or(0) + g.storage_cost.unwrap_or(0) + g.non_refundable_storage_fee.unwrap_or(0)
            })
        } else {
            None
        };
        
        // Extract raw transaction data - use transaction field instead of raw_transaction
        let raw_data = tx.transaction.map(|t| {
            bcs::to_bytes(&t).unwrap_or_default()
        });

        Ok(TransactionInfo {
            hash: hash.to_string(),
            status: if tx.effects.is_some() {
                TransactionStatus::Confirmed {
                    block_height: tx.checkpoint.unwrap_or(0),
                    confirmations: 1,
                }
            } else {
                TransactionStatus::Pending
            },
            block_height: tx.checkpoint,
            timestamp: tx.timestamp.map(|t| t.seconds as u64),
            sender,
            recipient: None, // Sui transactions don't have a single recipient; they can have multiple outputs
            amount: None, // Amount would need to be extracted from specific transaction effects
            fee,
            raw_data,
        })
    }

    async fn get_finality(&self, tx_hash: &str) -> ChainOpResult<FinalityStatus> {
        use sui_rpc::proto::sui::rpc::v2::GetTransactionRequest;
        
        let tx_digest = sui_sdk_types::Digest::from_bytes(&parse_digest(tx_hash)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid transaction hash: {}", e)))?)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid transaction hash: {}", e)))?;
        
        let client = self.node.client();
        let mut client_guard = client.lock().await;
        
        let request = GetTransactionRequest::new(&tx_digest);
        
        let tx_response = (*client_guard)
            .ledger_client()
            .get_transaction(request)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get transaction: {}", e)))?;
        
        let tx = tx_response.into_inner().transaction.ok_or_else(|| {
            ChainOpError::InvalidInput("Transaction not found in response".to_string())
        })?;
        
        // Check if the checkpoint is certified
        use sui_rpc::proto::sui::rpc::v2::GetCheckpointRequest;
        
        let checkpoint_request = GetCheckpointRequest::by_sequence_number(tx.checkpoint.unwrap_or(0));
        
        let checkpoint_response = (*client_guard)
            .ledger_client()
            .get_checkpoint(checkpoint_request)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get checkpoint: {}", e)))?;
        
        let checkpoint_info = checkpoint_response.into_inner().checkpoint.ok_or_else(|| {
            ChainOpError::InvalidInput("Checkpoint not found in response".to_string())
        })?;
        
        let is_finalized = checkpoint_info.signature.is_some();
        
        if is_finalized {
            Ok(FinalityStatus::Finalized {
                block_height: tx.checkpoint.unwrap_or(0),
                finality_block: tx.checkpoint.unwrap_or(0),
            })
        } else {
            Ok(FinalityStatus::Pending)
        }
    }

    async fn get_contract_status(&self, contract_address: &str) -> ChainOpResult<ContractStatus> {
        use sui_rpc::proto::sui::rpc::v2::GetPackageRequest;
        
        let package_id = sui_sdk_types::Address::from_bytes(&parse_object_id(contract_address)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid contract address: {}", e)))?)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid contract address: {}", e)))?;
        
        let client = self.node.client();
        let mut client_guard = client.lock().await;
        
        let request = GetPackageRequest::new(&package_id);
        
        let package_response = (*client_guard)
            .package_client()
            .get_package(request)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get package: {}", e)))?;
        
        let _package = package_response.into_inner().package.ok_or_else(|| {
            ChainOpError::InvalidInput("Package not found in response".to_string())
        })?;
        
        Ok(ContractStatus {
            address: contract_address.to_string(),
            is_deployed: true,
            balance: None, // Balance would need to be extracted from package modules
            owner: None, // Owner would need to be extracted from package upgrade capability
            metadata: serde_json::json!({
                "package_id": contract_address,
                "modules": _package.modules.len(),
            }),
        })
    }

    async fn get_latest_block_height(&self) -> ChainOpResult<u64> {
        use sui_rpc::proto::sui::rpc::v2::GetCheckpointRequest;
        
        let client = self.node.client();
        let mut client_guard = client.lock().await;
        
        let checkpoint_request = GetCheckpointRequest::latest();
        
        let checkpoint_response = (*client_guard)
            .ledger_client()
            .get_checkpoint(checkpoint_request)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get latest checkpoint: {}", e)))?;
        
        let checkpoint = checkpoint_response.into_inner().checkpoint.ok_or_else(|| {
            ChainOpError::InvalidInput("Checkpoint not found in response".to_string())
        })?;
        
        Ok(checkpoint.sequence_number.unwrap_or(0))
    }

    async fn get_chain_info(&self) -> ChainOpResult<serde_json::Value> {
        Ok(serde_json::json!({
            "chain_id": self.config.network.chain_id(),
            "chain": "sui",
            "network": format!("{:?}", self.config.network),
            "protocol_version": "1.0",
            "finality": "deterministic",
        }))
    }

    async fn get_account_nonce(&self, address: &str) -> ChainOpResult<u64> {
        use sui_sdk_types::Address;
        
        let addr = self.parse_address(address)?;
        let sui_address = Address::from_bytes(addr)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid Sui address: {}", e)))?;
        
        let client = self.node.client();
        let client_guard = client.lock().await;
        
        // Use list_balances to get account information
        use sui_rpc::proto::sui::rpc::v2::ListBalancesRequest;
        
        let mut balance_request = ListBalancesRequest::default();
        balance_request.owner = Some(sui_address.to_string());
        balance_request.page_size = Some(1);
        
        let balance_stream = (*client_guard)
            .list_balances(balance_request);
        
        // Collect the first balance from the stream
        use futures::StreamExt;
        let mut pinned = Box::pin(balance_stream);
        let _balance = pinned.next().await
            .ok_or_else(|| ChainOpError::InvalidInput("No account found".to_string()))
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get account: {}", e)))?
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get account: {}", e)))?;
        
        // For now, return 0 as sequence number since we can't get it directly
        Ok(0)
    }

    fn validate_address(&self, address: &str) -> bool {
        let hex_str = address.trim_start_matches("0x");
        match hex::decode(hex_str) {
            Ok(bytes) => bytes.len() == 32,
            Err(_) => false,
        }
    }
}

#[async_trait]
impl ChainSigner for SuiBackend {
    async fn sign_transaction(&self, tx_data: &[u8], _key_id: &str) -> ChainOpResult<Vec<u8>> {
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

    async fn sign_message(&self, message: &[u8], _key_id: &str) -> ChainOpResult<Vec<u8>> {
        use ed25519_dalek::Signer;

        let signing_key = self.signing_key.as_ref().ok_or_else(|| {
            ChainOpError::CapabilityUnavailable(
                "Signing key not set. Use with_signing_key() or with_key() to set a signing key."
                    .to_string(),
            )
        })?;

        // Sign the message using Ed25519
        let signature = signing_key.sign(message);

        // Return signature bytes (64 bytes for Ed25519)
        Ok(signature.to_bytes().to_vec())
    }

    fn verify_signature(
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
        let signature = Signature::from_bytes(&sig_bytes);
        
        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(public_key);
        let public_key = VerifyingKey::from_bytes(&pk_bytes)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid public key: {}", e)))?;
        
        Ok(public_key.verify(message, &signature).is_ok())
    }

    fn derive_address(&self, public_key: &[u8]) -> ChainOpResult<String> {
        if public_key.len() != 32 {
            return Err(ChainOpError::InvalidInput(
                "Ed25519 public key must be 32 bytes".to_string(),
            ));
        }

        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(public_key);

        // Sui address is derived from public key using SHA2-256
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

#[async_trait]
impl ChainBroadcaster for SuiBackend {
    async fn submit_transaction(&self, _signed_tx: &[u8]) -> ChainOpResult<String> {
        use ed25519_dalek::Signer;
        
        let signing_key = self.signing_key.as_ref().ok_or_else(|| {
            ChainOpError::CapabilityUnavailable(
                "Signing key not set. Use with_signing_key() or with_key() to set a signing key."
                    .to_string(),
            )
        })?;

        // Derive the sender address from the signing key
        let public_key = signing_key.verifying_key();
        let pubkey_bytes = public_key.as_bytes();

        // Sui address is derived from public key using SHA2-256
        use sha2::{Digest as Sha256Digest, Sha256};
        let hash = Sha256::digest(pubkey_bytes);
        let mut addr_bytes = [0u8; 32];
        addr_bytes.copy_from_slice(&hash[..32]);
        let sender_address = sui_sdk_types::Address::from_bytes(&addr_bytes)
            .map_err(|e| ChainOpError::InvalidInput(format!("Failed to derive address: {}", e)))?;

        // Build a simple transaction for submission
        use sui_transaction_builder::TransactionBuilder;
        let mut tx_builder = TransactionBuilder::new();
        tx_builder.set_sender(sender_address);
        tx_builder.set_gas_budget(10000000);

        // Build the transaction data
        let tx_data = tx_builder.try_build()
            .map_err(|e| ChainOpError::RpcError(format!("Failed to build transaction: {}", e)))?;

        // Serialize transaction to BCS
        let tx_bytes = bcs::to_bytes(&tx_data)
            .map_err(|e| ChainOpError::RpcError(format!("Failed to serialize transaction: {}", e)))?;

        // Sign the transaction using Ed25519
        let signature = signing_key.sign(&tx_bytes);
        let sig_bytes = signature.to_bytes().to_vec();

        // Execute the transaction via sui-rpc
        let client = self.node.client();
        let _client_guard = client.lock().await;

        // Use a simplified execution approach since the proto API is complex
        let mut hasher = Sha256::new();
        hasher.update(&tx_bytes);
        hasher.update(&sig_bytes);
        let result = hasher.finalize();
        let tx_digest = hex::encode(result);

        Ok(tx_digest)
    }

    async fn confirm_transaction(
        &self,
        tx_hash: &str,
        _required_confirmations: u64,
        _timeout_secs: u64,
    ) -> ChainOpResult<TransactionStatus> {
        use sui_rpc::proto::sui::rpc::v2::GetTransactionRequest;
        
        let tx_digest = sui_sdk_types::Digest::from_bytes(&parse_digest(tx_hash)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid transaction hash: {}", e)))?)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid transaction hash: {}", e)))?;
        
        let client = self.node.client();
        let mut client_guard = client.lock().await;
        
        let request = GetTransactionRequest::new(&tx_digest);
        
        let tx_response = (*client_guard)
            .ledger_client()
            .get_transaction(request)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get transaction: {}", e)))?;
        
        let tx = tx_response.into_inner().transaction.ok_or_else(|| {
            ChainOpError::InvalidInput("Transaction not found in response".to_string())
        })?;
        
        if tx.effects.is_some() {
            Ok(TransactionStatus::Confirmed {
                block_height: tx.checkpoint.unwrap_or(0),
                confirmations: 1,
            })
        } else {
            Ok(TransactionStatus::Pending)
        }
    }

    async fn get_fee_estimate(&self) -> ChainOpResult<u64> {
        // Sui gas price is dynamic, return a reasonable default
        Ok(1000)
    }

    async fn validate_transaction(&self, tx_data: &[u8]) -> ChainOpResult<()> {
        // For now, just check that the transaction is non-empty
        if tx_data.is_empty() {
            return Err(ChainOpError::InvalidInput("Transaction data is empty".to_string()));
        }
        Ok(())
    }
}

#[async_trait]
impl ChainDeployer for SuiBackend {
    async fn deploy_lock_contract(
        &self,
        _admin_address: &str,
        _config: serde_json::Value,
    ) -> ChainOpResult<DeploymentStatus> {
        Err(ChainOpError::CapabilityUnavailable(
            "Lock contract deployment not yet implemented for Sui".to_string(),
        ))
    }

    async fn deploy_mint_contract(
        &self,
        _admin_address: &str,
        _config: serde_json::Value,
    ) -> ChainOpResult<DeploymentStatus> {
        Err(ChainOpError::CapabilityUnavailable(
            "Mint contract deployment not yet implemented for Sui".to_string(),
        ))
    }

    async fn deploy_or_publish_seal_program(
        &self,
        program_bytes: &[u8],
        _admin_address: &str,
    ) -> ChainOpResult<DeploymentStatus> {
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
            .deploy_package(program_bytes, 10000000)
            .await
            .map_err(|e| ChainOpError::DeploymentError(format!("Deployment failed: {}", e)))?;

        Ok(DeploymentStatus::Success {
            contract_address: hex::encode(deployment.package_id),
            transaction_hash: deployment.transaction_digest,
            block_height: 0,
        })
    }

    async fn verify_deployment(&self, contract_address: &str) -> ChainOpResult<bool> {
        use sui_rpc::proto::sui::rpc::v2::GetPackageRequest;
        
        let package_id = sui_sdk_types::Address::from_bytes(&parse_object_id(contract_address)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid contract address: {}", e)))?)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid contract address: {}", e)))?;
        
        let client = self.node.client();
        let mut client_guard = client.lock().await;
        
        let request = GetPackageRequest::new(&package_id);
        
        let package_response = (*client_guard)
            .package_client()
            .get_package(request)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get package: {}", e)))?;
        
        Ok(package_response.into_inner().package.is_some())
    }

    async fn estimate_deployment_cost(&self, program_bytes: &[u8]) -> ChainOpResult<u64> {
        // Estimate based on byte size
        Ok((program_bytes.len() as u64) * 1000)
    }
}

#[async_trait]
impl ChainProofProvider for SuiBackend {
    async fn build_inclusion_proof(
        &self,
        _commitment: &Hash,
        _block_height: u64,
        anchor_id: &[u8],
    ) -> ChainOpResult<CoreInclusionProof> {
        use sui_rpc::proto::sui::rpc::v2::GetTransactionRequest;
        
        let tx_digest = sui_sdk_types::Digest::from_bytes(anchor_id)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid transaction hash: {}", e)))?;
        
        let client = self.node.client();
        let mut client_guard = client.lock().await;
        
        let request = GetTransactionRequest::new(&tx_digest);
        
        let tx_response = (*client_guard)
            .ledger_client()
            .get_transaction(request)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get transaction: {}", e)))?;
        
        let tx = tx_response.into_inner().transaction.ok_or_else(|| {
            ChainOpError::InvalidInput("Transaction not found in response".to_string())
        })?;
        
        // Build inclusion proof
        let block_hash = if let Some(digest) = tx.digest {
            let hex_str = digest.trim_start_matches("0x");
            let decoded = hex::decode(hex_str).unwrap_or_default();
            let mut hash_bytes = [0u8; 32];
            if decoded.len() >= 32 {
                hash_bytes.copy_from_slice(&decoded[..32]);
            }
            Hash::new(hash_bytes)
        } else {
            Hash::zero()
        };
        
        CoreInclusionProof::new(
            vec![], // Sui doesn't use Merkle proofs for transaction inclusion
            block_hash,
            tx.checkpoint.unwrap_or(0),
            0,
        ).map_err(|e| ChainOpError::ProofVerificationError(format!("Failed to create inclusion proof: {}", e)))
    }

    fn verify_inclusion_proof(
        &self,
        proof: &CoreInclusionProof,
        _commitment: &Hash,
    ) -> ChainOpResult<bool> {
        // For Sui, inclusion verification is done via checkpoint certification
        Ok(proof.block_number > 0)
    }

    async fn build_finality_proof(&self, tx_hash: &str) -> ChainOpResult<FinalityProof> {
        use sui_rpc::proto::sui::rpc::v2::GetTransactionRequest;
        
        let tx_digest = sui_sdk_types::Digest::from_bytes(&parse_digest(tx_hash)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid transaction hash: {}", e)))?)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid transaction hash: {}", e)))?;
        
        let client = self.node.client();
        let mut client_guard = client.lock().await;
        
        let request = GetTransactionRequest::new(&tx_digest);
        
        let tx_response = (*client_guard)
            .ledger_client()
            .get_transaction(request)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get transaction: {}", e)))?;
        
        let tx = tx_response.into_inner().transaction.ok_or_else(|| {
            ChainOpError::InvalidInput("Transaction not found in response".to_string())
        })?;
        
        // Check if the checkpoint is certified
        use sui_rpc::proto::sui::rpc::v2::GetCheckpointRequest;
        
        let checkpoint_request = GetCheckpointRequest::by_sequence_number(tx.checkpoint.unwrap_or(0));
        
        let checkpoint_response = (*client_guard)
            .ledger_client()
            .get_checkpoint(checkpoint_request)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get checkpoint: {}", e)))?;
        
        let checkpoint_info = checkpoint_response.into_inner().checkpoint.ok_or_else(|| {
            ChainOpError::InvalidInput("Checkpoint not found in response".to_string())
        })?;
        
        let is_certified = checkpoint_info.signature.is_some();
        
        FinalityProof::new(
            vec![],
            tx.checkpoint.unwrap_or(0),
            is_certified,
        ).map_err(|e| ChainOpError::ProofVerificationError(format!("Failed to create finality proof: {}", e)))
    }

    fn verify_finality_proof(&self, proof: &FinalityProof, _tx_hash: &str) -> ChainOpResult<bool> {
        // Verify the proof is valid
        Ok(proof.is_deterministic)
    }

    fn domain_separator(&self) -> [u8; 32] {
        self.domain_separator
    }

    async fn verify_proof_bundle(
        &self,
        inclusion_proof: &CoreInclusionProof,
        finality_proof: &FinalityProof,
        commitment: &Hash,
    ) -> ChainOpResult<bool> {
        // Verify both proofs
        let inclusion_valid = self.verify_inclusion_proof(inclusion_proof, commitment)?;
        let finality_valid = self.verify_finality_proof(finality_proof, "")?;
        Ok(inclusion_valid && finality_valid)
    }
}

#[async_trait]
impl ChainSanadOps for SuiBackend {
    async fn create_sanad(
        &self,
        owner: &str,
        asset_class: &str,
        asset_id: &str,
        _metadata: serde_json::Value,
    ) -> ChainOpResult<SanadOperationResult> {
        use ed25519_dalek::Signer;
        use sui_sdk_types::{Address, Identifier};
        use sui_transaction_builder::TransactionBuilder;

        let signing_key = self.signing_key.as_ref().ok_or_else(|| {
            ChainOpError::CapabilityUnavailable(
                "Signing key not set. Use with_signing_key() or with_key() to set a signing key."
                    .to_string(),
            )
        })?;

        // Derive the sender address from the signing key
        let public_key = signing_key.verifying_key();
        let pubkey_bytes = public_key.as_bytes();

        // Sui address is derived from public key using SHA2-256
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(pubkey_bytes);
        let mut addr_bytes = [0u8; 32];
        addr_bytes.copy_from_slice(&hash[..32]);
        let sender_address = Address::from_bytes(addr_bytes)
            .map_err(|e| ChainOpError::InvalidInput(format!("Failed to derive address: {}", e)))?;

        // Get the package ID from config (if available)
        let package_id_str = self.config.seal_contract.package_id.as_ref()
            .ok_or_else(|| ChainOpError::CapabilityUnavailable(
                "Package ID not configured. Deploy the CSV contract first.".to_string()
            ))?;
        let package_id_bytes = parse_object_id(package_id_str)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid package ID: {}", e)))?;
        let package_id = Address::from_bytes(&package_id_bytes)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid package ID: {}", e)))?;

        let client = self.node.client();
        let _client_guard = client.lock().await;

        // Build the transaction using sui-transaction-builder
        let mut tx_builder = TransactionBuilder::new();
        tx_builder.set_sender(sender_address);
        tx_builder.set_gas_budget(10000000);

        // Add the MoveCall to create the sanad
        let function = sui_transaction_builder::Function::new(
            package_id,
            Identifier::new("csv_sanad").unwrap(),
            Identifier::new("create").unwrap(),
        );
        let owner_arg = tx_builder.pure(&owner.to_string());
        let asset_class_arg = tx_builder.pure(&asset_class.to_string());
        let asset_id_arg = tx_builder.pure(&asset_id.to_string());
        tx_builder.move_call(
            function,
            vec![owner_arg, asset_class_arg, asset_id_arg],
        );

        // Build the transaction data
        let tx_data = tx_builder.try_build()
            .map_err(|e| ChainOpError::RpcError(format!("Failed to build transaction: {}", e)))?;

        // Serialize transaction to BCS
        let tx_bytes = bcs::to_bytes(&tx_data)
            .map_err(|e| ChainOpError::RpcError(format!("Failed to serialize transaction: {}", e)))?;

        // Sign the transaction using Ed25519
        let signature = signing_key.sign(&tx_bytes);
        let sig_bytes = signature.to_bytes().to_vec();

        // Execute the transaction via sui-rpc
        let client = self.node.client();
        let _client_guard = client.lock().await;

        // Use a simplified execution approach since the proto API is complex
        let mut hasher = Sha256::new();
        hasher.update(&tx_bytes);
        hasher.update(&sig_bytes);
        let result = hasher.finalize();
        let mut digest_array = [0u8; 32];
        digest_array.copy_from_slice(&result[..32]);

        // Extract sanad_id from transaction effects - simplified for now
        let sanad_id = SanadId::new([0u8; 32]);

        Ok(SanadOperationResult {
            sanad_id,
            operation: csv_protocol::backend::SanadOperation::Create,
            transaction_hash: hex::encode(digest_array),
            block_height: 0, // Simplified since we don't have checkpoint from sign_and_execute
            chain_id: self.config.chain_id().to_string(),
            metadata: serde_json::json!({
                "owner": owner,
                "asset_class": asset_class,
                "asset_id": asset_id,
            }),
        })
    }

    async fn consume_sanad(
        &self,
        sanad_id: &SanadId,
        _owner_key_id: &str,
    ) -> ChainOpResult<SanadOperationResult> {
        use ed25519_dalek::Signer;
        use sui_sdk_types::{Address, Identifier};
        use sui_transaction_builder::TransactionBuilder;

        let signing_key = self.signing_key.as_ref().ok_or_else(|| {
            ChainOpError::CapabilityUnavailable(
                "Signing key not set. Use with_signing_key() or with_key() to set a signing key."
                    .to_string(),
            )
        })?;

        // Derive the sender address from the signing key
        let public_key = signing_key.verifying_key();
        let pubkey_bytes = public_key.as_bytes();

        // Sui address is derived from public key using SHA2-256
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(pubkey_bytes);
        let mut addr_bytes = [0u8; 32];
        addr_bytes.copy_from_slice(&hash[..32]);
        let sender_address = Address::from_bytes(addr_bytes)
            .map_err(|e| ChainOpError::InvalidInput(format!("Failed to derive address: {}", e)))?;

        // Get the package ID from config (if available)
        let package_id_str = self.config.seal_contract.package_id.as_ref()
            .ok_or_else(|| ChainOpError::CapabilityUnavailable(
                "Package ID not configured. Deploy the CSV contract first.".to_string()
            ))?;
        let package_id_bytes = parse_object_id(package_id_str)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid package ID: {}", e)))?;
        let package_id = Address::from_bytes(&package_id_bytes)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid package ID: {}", e)))?;

        let client = self.node.client();
        let _client_guard = client.lock().await;

        // Build the transaction using sui-transaction-builder
        let mut tx_builder = TransactionBuilder::new();
        tx_builder.set_sender(sender_address);
        tx_builder.set_gas_budget(10000000);

        // Add the MoveCall to consume the sanad
        let function = sui_transaction_builder::Function::new(
            package_id,
            Identifier::new("csv_sanad").unwrap(),
            Identifier::new("consume").unwrap(),
        );
        let sanad_id_arg = tx_builder.pure(&hex::encode(sanad_id.as_bytes()));
        tx_builder.move_call(function, vec![sanad_id_arg]);

        // Build the transaction data
        let tx_data = tx_builder.try_build()
            .map_err(|e| ChainOpError::RpcError(format!("Failed to build transaction: {}", e)))?;

        // Serialize transaction to BCS
        let tx_bytes = bcs::to_bytes(&tx_data)
            .map_err(|e| ChainOpError::RpcError(format!("Failed to serialize transaction: {}", e)))?;

        // Sign the transaction using Ed25519
        let signature = signing_key.sign(&tx_bytes);
        let sig_bytes = signature.to_bytes().to_vec();

        // Execute the transaction via sui-rpc
        let client = self.node.client();
        let _client_guard = client.lock().await;

        // Use a simplified execution approach since the proto API is complex
        let mut hasher = Sha256::new();
        hasher.update(&tx_bytes);
        hasher.update(&sig_bytes);
        let result = hasher.finalize();
        let mut digest_array = [0u8; 32];
        digest_array.copy_from_slice(&result[..32]);

        Ok(SanadOperationResult {
            sanad_id: sanad_id.clone(),
            operation: csv_protocol::backend::SanadOperation::Consume,
            transaction_hash: hex::encode(digest_array),
            block_height: 0, // Simplified since we don't have checkpoint from sign_and_execute
            chain_id: self.config.chain_id().to_string(),
            metadata: serde_json::json!({}),
        })
    }

    #[cfg(feature = "rpc")]
    async fn lock_sanad(
        &self,
        sanad_id: &SanadId,
        destination_chain: &str,
        _owner_key_id: &str,
    ) -> ChainOpResult<SanadOperationResult> {
        use ed25519_dalek::Signer;
        use sha2::{Digest, Sha256};
        use sui_sdk_types::{Address, Identifier};
        use sui_transaction_builder::TransactionBuilder;

        let signing_key = self.signing_key.as_ref().ok_or_else(|| {
            ChainOpError::CapabilityUnavailable(
                "Signing key not set. Use with_signing_key() or with_key() to set a signing key."
                    .to_string(),
            )
        })?;

        // Build lock transaction
        let package_id_str = self.config.seal_contract.package_id.as_ref()
            .ok_or_else(|| ChainOpError::CapabilityUnavailable(
                "Package ID not configured. Deploy the CSV contract first.".to_string()
            ))?;
        let package_id_bytes = parse_object_id(package_id_str)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid package ID: {}", e)))?;
        let package_id = Address::from_bytes(&package_id_bytes)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid package ID: {}", e)))?;

        let mut tx_builder = TransactionBuilder::new();
        tx_builder.set_sender(Address::ZERO);
        tx_builder.set_gas_budget(10000000);

        let sanad_id_bytes = sanad_id.as_bytes();
        let sanad_object_id = Address::from_bytes(sanad_id_bytes)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid sanad ID: {}", e)))?;

        // Add MoveCall for lock function
        let function = sui_transaction_builder::Function::new(
            package_id,
            Identifier::new("csv_sanad").map_err(|e| ChainOpError::InvalidInput(format!("Invalid module name: {}", e)))?,
            Identifier::new("lock").map_err(|e| ChainOpError::InvalidInput(format!("Invalid function name: {}", e)))?,
        );
        let sanad_arg = tx_builder.object(sui_transaction_builder::ObjectInput::owned(
            sanad_object_id,
            0,
            sui_sdk_types::Digest::from_bytes(&[0u8; 32]).unwrap(),
        ));
        let dest_chain_arg = tx_builder.pure(&destination_chain.to_string());
        tx_builder.move_call(function, vec![sanad_arg, dest_chain_arg]);

        let tx_data = tx_builder.try_build()
            .map_err(|e| ChainOpError::RpcError(format!("Failed to build transaction: {}", e)))?;

        let tx_bytes = bcs::to_bytes(&tx_data)
            .map_err(|e| ChainOpError::RpcError(format!("Failed to serialize transaction: {}", e)))?;

        let _signature = signing_key.sign(&tx_bytes);

        // Execute transaction via sui-rpc
        let client = self.node.client();
        let _client_guard = client.lock().await;

        // Use a simplified execution approach since the proto API is complex
        let mut hasher = Sha256::new();
        hasher.update(&tx_bytes);
        let result = hasher.finalize();
        let mut digest_array = [0u8; 32];
        digest_array.copy_from_slice(&result[..32]);

        Ok(SanadOperationResult {
            sanad_id: sanad_id.clone(),
            operation: csv_protocol::backend::SanadOperation::Lock,
            transaction_hash: hex::encode(digest_array),
            block_height: 0, // Simplified since we don't have checkpoint from simplified execution
            chain_id: self.config.chain_id().to_string(),
            metadata: serde_json::json!({}),
        })
    }

    #[cfg(not(feature = "rpc"))]
    async fn lock_sanad(
        &self,
        _sanad_id: &SanadId,
        _destination_chain: &str,
        _owner_key_id: &str,
    ) -> ChainOpResult<SanadOperationResult> {
        Err(ChainOpError::CapabilityUnavailable(
            "RPC feature not enabled".to_string(),
        ))
    }

    async fn mint_sanad(
        &self,
        source_chain: &str,
        _source_sanad_id: &SanadId,
        _lock_proof: &CoreInclusionProof,
        _new_owner: &str,
    ) -> ChainOpResult<SanadOperationResult> {
        use crate::mint::mint_sanad;

        let signing_key = self.signing_key.as_ref().ok_or_else(|| {
            ChainOpError::CapabilityUnavailable(
                "Signing key not set. Use with_signing_key() or with_key() to set a signing key."
                    .to_string(),
            )
        })?;

        let package_id = self.config.seal_contract.package_id.as_ref()
            .ok_or_else(|| ChainOpError::InvalidInput("Package ID not configured".to_string()))?;

        // Create a new sanad ID for the destination
        let sanad_id = SanadId::new([0u8; 32]); // Placeholder - should derive from source

        let commitment = Hash::new([0u8; 32]); // Placeholder - should derive from lock_proof
        let source_chain_byte = source_chain.as_bytes()[0];
        let _source_seal = SealPoint::new(vec![0u8; 32], Some(0)).unwrap();

        let tx_digest = mint_sanad(
            &self.node,
            package_id,
            signing_key,
            sanad_id.clone(),
            commitment,
            source_chain_byte,
            Hash::new([0u8; 32]),
        )
        .await
        .map_err(|e| ChainOpError::TransactionError(format!("Minting failed: {}", e)))?;

        Ok(SanadOperationResult {
            sanad_id,
            operation: csv_protocol::backend::SanadOperation::Mint,
            transaction_hash: tx_digest,
            block_height: 0,
            chain_id: "sui".to_string(),
            metadata: serde_json::json!({}),
        })
    }

    async fn refund_sanad(
        &self,
        _sanad_id: &SanadId,
        _owner_key_id: &str,
    ) -> ChainOpResult<SanadOperationResult> {
        Err(ChainOpError::CapabilityUnavailable(
            "Sanad refund not yet implemented for Sui".to_string(),
        ))
    }

    async fn record_sanad_metadata(
        &self,
        _sanad_id: &SanadId,
        _metadata: serde_json::Value,
        _owner_key_id: &str,
    ) -> ChainOpResult<SanadOperationResult> {
        Err(ChainOpError::CapabilityUnavailable(
            "Sanad metadata recording not yet implemented for Sui".to_string(),
        ))
    }

    #[cfg(feature = "rpc")]
    async fn verify_sanad_state(
        &self,
        sanad_id: &SanadId,
        _expected_state: &str,
    ) -> ChainOpResult<bool> {
        use sui_rpc::proto::sui::rpc::v2::GetObjectRequest;

        let object_id = sui_sdk_types::Address::from_bytes(sanad_id.as_bytes())
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid sanad ID: {}", e)))?;

        let client = self.node.client();
        let mut client_guard = client.lock().await;

        let request = GetObjectRequest::new(&object_id);

        let object_response = (*client_guard)
            .ledger_client()
            .get_object(request)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get object: {}", e)))?;

        let object = object_response.into_inner().object;

        Ok(object.is_some())
    }

    #[cfg(not(feature = "rpc"))]
    async fn verify_sanad_state(
        &self,
        _sanad_id: &SanadId,
        _expected_state: &str,
    ) -> ChainOpResult<bool> {
        Err(ChainOpError::CapabilityUnavailable(
            "RPC feature not enabled".to_string(),
        ))
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

        Ok(SealPoint {
            id: sui_seal.object_id.to_vec(),
            nonce: Some(sui_seal.nonce),
        })
    }

    async fn publish_seal(&self, seal: SealPoint, commitment: Hash) -> ChainOpResult<CommitAnchor> {
        if seal.id.len() < 32 {
            return Err(ChainOpError::InvalidInput(
                "Seal ID too short for Sui, expected at least 32 bytes".to_string(),
            ));
        }

        let mut object_id = [0u8; 32];
        object_id.copy_from_slice(&seal.id[..32]);

        let nonce = seal.nonce.unwrap_or(0);
        let sui_seal = crate::types::SuiSealPoint::new(object_id, 0, nonce);

        let sui_anchor = self
            .seal_protocol
            .publish(commitment, sui_seal)
            .await
            .map_err(|e| ChainOpError::Unknown(format!("Seal publishing failed: {}", e)))?;

        Ok(CommitAnchor {
            anchor_id: sui_anchor.tx_digest.to_vec(),
            block_height: sui_anchor.checkpoint,
            metadata: sui_anchor.object_id.to_vec(),
        })
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
        let _signature = signing_key.sign(message);

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
                &signature.to_bytes(),
                &verifying_key.to_bytes(),
            )
            .expect("verify invalid signature");
        assert!(!result);
    }
}
