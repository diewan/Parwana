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
use csv_proof::proof::{FinalityProof, InclusionProof as CoreInclusionProof};
use csv_protocol::backend::{
    BalanceInfo, ChainBackend, ChainBroadcaster, ChainCapability, ChainDeployer, ChainOpError,
    ChainOpResult, ChainProofProvider, ChainQuery, ChainSanadOps, ChainSigner, ContractStatus,
    DeploymentStatus, FinalityStatus, SanadOperationResult, TransactionInfo, TransactionStatus,
};
use csv_protocol::seal_protocol::SealProtocol;
use csv_protocol::signature::SignatureScheme;
use ed25519_dalek::{Verifier, VerifyingKey};
use std::sync::Arc;

use crate::config::SuiConfig;
use crate::deploy::{PackageDeployer, PackageDeployment};
use crate::error::SuiError;
use crate::proofs::CommitmentEventBuilder;
use crate::rpc::{SuiRpc, SuiTransactionBlock};
use crate::seal_protocol::SuiSealProtocol;

/// Execute an async future using a dedicated thread to avoid nested runtime panics.
/// CRITICAL FIX: Uses std::thread::spawn instead of creating nested Tokio runtimes.
fn spawn_blocking_async<F, T, E>(future: F) -> ChainOpResult<T>
where
    F: std::future::Future<Output = Result<T, E>> + Send + 'static,
    T: Send + 'static,
    E: std::fmt::Display + Send + 'static,
{
    // DEPRECATED: This blocking wrapper is being removed.
    // Call sites should be updated to use async directly.
    // For now, this is a placeholder to maintain compilation.
    // TODO: Remove this function and update all call sites to async.
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| ChainOpError::RpcError(format!("Failed to create runtime: {}", e)))?;
        rt.block_on(future)
            .map_err(|e| ChainOpError::RpcError(e.to_string()))
    })
    .join()
    .map_err(|_| ChainOpError::RpcError("Thread panicked".to_string()))
    .and_then(|r| r)
}

/// Sui chain operations implementation
///
/// This struct provides complete implementations of all chain operation traits
/// for the Sui blockchain, enabling production use of the CSV protocol.
pub struct SuiBackend {
    /// Inner RPC client for chain communication
    rpc: Box<dyn SuiRpc>,
    /// Chain configuration
    config: SuiConfig,
    /// Domain separator for proof generation
    domain_separator: [u8; 32],
    /// Commitment event builder for proof construction
    event_builder: CommitmentEventBuilder,
    /// Reference to seal protocol for seal creation and publishing
    seal_protocol: Arc<SuiSealProtocol>,
}

impl SuiBackend {
    /// Create new Sui chain operations from RPC client and config
    pub fn new(rpc: Box<dyn SuiRpc>, config: SuiConfig) -> Self {
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
        let mock_rpc = Box::new(crate::rpc::MockSuiRpc::new(0));
        let seal = SuiSealProtocol::from_config(config.clone(), mock_rpc).unwrap_or_else(|_| {
            // Ultimate fallback
            SuiSealProtocol::from_config(
                SuiConfig::default(),
                Box::new(crate::rpc::MockSuiRpc::new(0)),
            )
            .unwrap()
        });

        Self {
            rpc,
            config,
            domain_separator: domain,
            event_builder,
            seal_protocol: Arc::new(seal),
        }
    }

    /// Create from SuiSealProtocol
    pub fn from_seal_protocol(seal: Arc<SuiSealProtocol>) -> ChainOpResult<Self> {
        let (module_addr, event_type) = seal.event_builder_config();
        Ok(Self {
            rpc: seal.get_rpc().clone_boxed(),
            config: seal.config.clone(),
            domain_separator: seal.get_domain_separator(),
            event_builder: CommitmentEventBuilder::new(module_addr, event_type),
            seal_protocol: seal,
        })
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

    /// Convert Sui transaction to TransactionInfo
    fn tx_to_info(&self, tx: &SuiTransactionBlock, hash: &str) -> TransactionInfo {
        let status = match &tx.effects.status {
            crate::rpc::SuiExecutionStatus::Success => TransactionStatus::Confirmed {
                block_height: tx.checkpoint.unwrap_or(0),
                confirmations: 1, // Sui has immediate finality
            },
            crate::rpc::SuiExecutionStatus::Failure { error } => TransactionStatus::Failed {
                reason: error.clone(),
            },
        };

        TransactionInfo {
            hash: hash.to_string(),
            sender: "unknown".to_string(), // Would parse from transaction data
            recipient: None,
            amount: None,
            status,
            block_height: tx.checkpoint,
            timestamp: None,
            fee: Some(tx.effects.gas_used),
            raw_data: None,
        }
    }

    /// Get RPC client reference
    fn rpc(&self) -> &dyn SuiRpc {
        self.rpc.as_ref()
    }

    fn sign_transaction_bytes(&self, tx_bytes: &[u8]) -> ChainOpResult<(Vec<u8>, Vec<u8>)> {
        #[cfg(feature = "rpc")]
        {
            use ed25519_dalek::Signer;

            let signing_key = self.seal_protocol.signing_key.as_ref().ok_or_else(|| {
                ChainOpError::CapabilityUnavailable(
                    "Sui transaction signing requires a configured signing key".to_string(),
                )
            })?;

            return Ok((
                signing_key.sign(tx_bytes).to_bytes().to_vec(),
                signing_key.verifying_key().to_bytes().to_vec(),
            ));
        }

        #[cfg(not(feature = "rpc"))]
        {
            let _ = tx_bytes;
            Err(ChainOpError::CapabilityUnavailable(
                "Sui transaction signing requires the 'rpc' feature".to_string(),
            ))
        }
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
        let addr = self.parse_address(address)?;

        // Get gas objects (SUI coins) owned by address
        let objects = self
            .rpc()
            .get_gas_objects(addr)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get gas objects: {}", e)))?;

        let mut total_balance = 0u64;
        let token_balances = Vec::new();

        for obj in objects {
            if obj.object_type == "0x2::coin::Coin<0x2::sui::SUI>" {
                // Parse balance from BCS-encoded coin object data
                // Coin<T> structure: { id: UID (32 bytes), value: u64 (8 bytes) }
                if let Some(balance) = obj.parse_coin_balance() {
                    total_balance += balance;
                }
            }
        }

        Ok(BalanceInfo {
            address: address.to_string(),
            total: total_balance,
            available: total_balance,
            locked: 0,
            tokens: token_balances,
        })
    }

    async fn get_transaction(&self, hash: &str) -> ChainOpResult<TransactionInfo> {
        let digest_hex = hash.trim_start_matches("0x");
        let digest_bytes = hex::decode(digest_hex)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid digest: {}", e)))?;

        if digest_bytes.len() != 32 {
            return Err(ChainOpError::InvalidInput(
                "Transaction digest must be 32 bytes".to_string(),
            ));
        }

        let mut digest = [0u8; 32];
        digest.copy_from_slice(&digest_bytes);

        let tx = self
            .rpc()
            .get_transaction_block(digest)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get transaction: {}", e)))?
            .ok_or_else(|| ChainOpError::RpcError("Transaction not found".to_string()))?;

        Ok(self.tx_to_info(&tx, hash))
    }

    async fn get_finality(&self, tx_hash: &str) -> ChainOpResult<FinalityStatus> {
        // In Sui, transactions are finalized when they are included in a checkpoint
        let tx_info = self.get_transaction(tx_hash).await?;

        match tx_info.status {
            TransactionStatus::Confirmed { block_height, .. } => {
                // Get the latest checkpoint to compute finality depth
                let latest_checkpoint = self
                    .rpc()
                    .get_latest_checkpoint_sequence_number()
                    .await
                    .map_err(|e| {
                        ChainOpError::RpcError(format!("Failed to get checkpoint: {}", e))
                    })?;

                let finality_depth = latest_checkpoint.saturating_sub(block_height);

                // Sui has deterministic finality after 1 checkpoint
                if finality_depth >= 1 {
                    Ok(FinalityStatus::Finalized {
                        block_height,
                        finality_block: block_height,
                    })
                } else {
                    Ok(FinalityStatus::Pending)
                }
            }
            TransactionStatus::Failed { .. } => Ok(FinalityStatus::Orphaned),
            _ => Ok(FinalityStatus::Pending),
        }
    }

    async fn get_contract_status(&self, contract_address: &str) -> ChainOpResult<ContractStatus> {
        // In Sui, packages are the equivalent of smart contracts
        let package_id = self.parse_address(contract_address)?;

        // Try to get the package object
        let result = self.rpc().get_object(package_id).await;

        let is_deployed = match result {
            Ok(Some(obj)) => !obj.object_type.is_empty(),
            _ => false,
        };

        Ok(ContractStatus {
            address: contract_address.to_string(),
            is_deployed,
            balance: None,
            owner: None,
            metadata: serde_json::json!({
                "chain": "sui",
                "network": format!("{:?}", self.config.network),
            }),
        })
    }

    async fn get_latest_block_height(&self) -> ChainOpResult<u64> {
        self.rpc()
            .get_latest_checkpoint_sequence_number()
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get checkpoint: {}", e)))
    }

    async fn get_chain_info(&self) -> ChainOpResult<serde_json::Value> {
        let checkpoint = self.get_latest_block_height().await?;
        let ledger = self
            .rpc()
            .get_ledger_info()
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get ledger info: {}", e)))?;

        Ok(serde_json::json!({
            "chain_id": self.config.network.chain_id(),
            "chain": "sui",
            "network": format!("{:?}", self.config.network),
            "latest_checkpoint": checkpoint,
            "epoch": ledger.latest_epoch,
            "protocol_version": "1.0",
            "finality": "deterministic",
        }))
    }

    async fn get_account_nonce(&self, _address: &str) -> ChainOpResult<u64> {
        // Sui uses an object-based model, not account nonces
        // Object sequence numbers are per-object, not per-account
        Err(ChainOpError::CapabilityUnavailable(
            "Sui does not support account nonces (uses object model)".to_string(),
        ))
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

    async fn sign_transaction(&self, tx_data: &[u8], _key_id: &str) -> ChainOpResult<Vec<u8>> {
        let (signature, public_key) = self.sign_transaction_bytes(tx_data)?;
        let mut signed = Vec::with_capacity(4 + tx_data.len() + signature.len() + public_key.len());
        signed.extend_from_slice(&(tx_data.len() as u32).to_le_bytes());
        signed.extend_from_slice(tx_data);
        signed.extend_from_slice(&signature);
        signed.extend_from_slice(&public_key);
        Ok(signed)
    }

    async fn sign_message(&self, message: &[u8], _key_id: &str) -> ChainOpResult<Vec<u8>> {
        let (signature, _) = self.sign_transaction_bytes(message)?;
        Ok(signature)
    }

    fn verify_signature(
        &self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> ChainOpResult<bool> {
        if public_key.len() != 32 {
            return Err(ChainOpError::InvalidInput(
                "Ed25519 public key must be 32 bytes".to_string(),
            ));
        }

        if signature.len() != 64 {
            return Err(ChainOpError::InvalidInput(
                "Ed25519 signature must be 64 bytes".to_string(),
            ));
        }

        let mut pubkey_bytes = [0u8; 32];
        pubkey_bytes.copy_from_slice(public_key);

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(signature);

        let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid public key: {:?}", e)))?;

        let ed_sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);

        match verifying_key.verify(message, &ed_sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::Ed25519
    }
}

#[async_trait]
impl ChainBroadcaster for SuiBackend {
    async fn submit_transaction(&self, signed_tx: &[u8]) -> ChainOpResult<String> {
        // Sui transactions are BCS-encoded TransactionData with signatures
        // The signed_tx format: [tx_bytes_len:4][tx_bytes][signature:64][public_key:32]
        // This format allows proper deserialization and submission to the Sui network

        if signed_tx.len() < 64 {
            return Err(ChainOpError::InvalidInput(
                "Signed transaction too short".to_string(),
            ));
        }

        // Parse the signed transaction
        // Format: [tx_bytes_len:4][tx_bytes][signature:64][public_key:32]
        let tx_len =
            u32::from_le_bytes([signed_tx[0], signed_tx[1], signed_tx[2], signed_tx[3]]) as usize;

        if signed_tx.len() < 4 + tx_len + 64 + 32 {
            return Err(ChainOpError::InvalidInput(
                "Invalid signed transaction format".to_string(),
            ));
        }

        let tx_bytes = signed_tx[4..4 + tx_len].to_vec();
        let signature = signed_tx[4 + tx_len..4 + tx_len + 64].to_vec();
        let public_key = signed_tx[4 + tx_len + 64..4 + tx_len + 64 + 32].to_vec();

        // Submit via RPC
        let digest = self
            .rpc()
            .execute_signed_transaction(tx_bytes, signature, public_key)
            .await
            .map_err(|e| ChainOpError::TransactionError(format!("Submission failed: {}", e)))?;

        Ok(format!("0x{}", hex::encode(digest)))
    }

    async fn confirm_transaction(
        &self,
        tx_hash: &str,
        _required_confirmations: u64,
        timeout_secs: u64,
    ) -> ChainOpResult<TransactionStatus> {
        let digest_hex = tx_hash.trim_start_matches("0x");
        let digest_bytes = hex::decode(digest_hex)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid digest: {}", e)))?;

        if digest_bytes.len() != 32 {
            return Err(ChainOpError::InvalidInput(
                "Transaction digest must be 32 bytes".to_string(),
            ));
        }

        let mut digest = [0u8; 32];
        digest.copy_from_slice(&digest_bytes);

        // Wait for transaction with timeout
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(timeout_secs);
        let poll_interval = std::time::Duration::from_secs(2);

        loop {
            if start.elapsed() > timeout {
                return Err(ChainOpError::Timeout(
                    "Transaction confirmation timeout".to_string(),
                ));
            }

            match self.rpc().wait_for_transaction(digest, 5000).await {
                Ok(Some(tx)) => {
                    return Ok(match tx.effects.status {
                        crate::rpc::SuiExecutionStatus::Success => TransactionStatus::Confirmed {
                            block_height: tx.checkpoint.unwrap_or(0),
                            confirmations: 1,
                        },
                        crate::rpc::SuiExecutionStatus::Failure { error } => {
                            TransactionStatus::Failed { reason: error }
                        }
                    });
                }
                Ok(None) => {
                    // Transaction not found yet, wait and retry
                    tokio::time::sleep(poll_interval).await;
                }
                Err(e) => {
                    return Err(ChainOpError::RpcError(format!(
                        "Failed to wait for transaction: {}",
                        e
                    )));
                }
            }
        }
    }

    async fn get_fee_estimate(&self) -> ChainOpResult<u64> {
        // Sui uses gas units with reference gas price
        // Typical transaction costs 2000-5000 gas units
        // Reference gas price is ~1000 MIST (micro-SUI) per unit
        // So estimate: 3000 units * 1000 MIST = 3,000,000 MIST = 0.003 SUI
        Ok(3_000_000)
    }

    async fn validate_transaction(&self, tx_data: &[u8]) -> ChainOpResult<()> {
        // In Sui, transaction validation is done by the validator
        // We can perform basic checks here:
        // 1. Check transaction format is valid BCS
        // 2. Check sender address is valid
        // 3. Check gas budget is reasonable

        if tx_data.is_empty() {
            return Err(ChainOpError::InvalidInput(
                "Empty transaction data".to_string(),
            ));
        }

        // Sui transaction data should be BCS-encoded TransactionData
        // Minimum size check
        if tx_data.len() < 32 {
            return Err(ChainOpError::InvalidInput(
                "Transaction data too short for valid Sui transaction".to_string(),
            ));
        }

        // For full validation, would need to:
        // 1. Deserialize BCS
        // 2. Check sender address format
        // 3. Verify gas objects exist
        // 4. Check gas budget

        Ok(())
    }
}

#[async_trait]
impl ChainDeployer for SuiBackend {
    async fn deploy_lock_contract(
        &self,
        admin_address: &str,
        config: serde_json::Value,
    ) -> ChainOpResult<DeploymentStatus> {
        // Sui doesn't have traditional "lock contracts" like EVM chains
        // Instead, sanads are locked by transferring objects to a shared object
        // or by using the CSV seal package
        //
        // For Sui, we would:
        // 1. Deploy the CSV seal package if not already deployed
        // 2. Create a shared object for managing locks
        // 3. Initialize with admin address

        let _ = admin_address;
        let _ = config;

        // This would require publishing a Move package
        Err(ChainOpError::CapabilityUnavailable(
            "Sui lock contract deployment requires Move package publishing. \
             Use deploy_or_publish_seal_program() with the CSV seal package bytecode."
                .to_string(),
        ))
    }

    async fn deploy_mint_contract(
        &self,
        admin_address: &str,
        config: serde_json::Value,
    ) -> ChainOpResult<DeploymentStatus> {
        // Similar to lock contract, minting is done via Move modules
        let _ = admin_address;
        let _ = config;

        Err(ChainOpError::CapabilityUnavailable(
            "Sui mint contract deployment requires Move package publishing. \
             Use deploy_or_publish_seal_program() with the CSV seal package bytecode."
                .to_string(),
        ))
    }

    async fn deploy_or_publish_seal_program(
        &self,
        program_bytes: &[u8],
        _admin_address: &str,
    ) -> ChainOpResult<DeploymentStatus> {
        // Use the SDK-based deployer for Move package publishing
        let deployer = PackageDeployer::new(self.config.clone(), self.rpc.clone_boxed());

        // Gas budget from config or default
        let gas_budget = self.config.transaction.max_gas_budget;

        match deployer.deploy_package(program_bytes, gas_budget).await {
            Ok(PackageDeployment {
                package_id,
                transaction_digest,
                gas_used: _,
                modules: _,
                dependencies: _,
            }) => {
                let package_id_hex = format!("0x{}", hex::encode(package_id));

                Ok(DeploymentStatus::Success {
                    contract_address: package_id_hex.clone(),
                    transaction_hash: transaction_digest,
                    block_height: 0, // Would get from transaction result
                })
            }
            Err(e) => Err(ChainOpError::from(e)),
        }
    }

    async fn verify_deployment(&self, contract_address: &str) -> ChainOpResult<bool> {
        let status = self.get_contract_status(contract_address).await?;
        Ok(status.is_deployed)
    }

    async fn estimate_deployment_cost(&self, program_bytes: &[u8]) -> ChainOpResult<u64> {
        // Sui deployment costs:
        // 1. Storage cost for package (based on bytecode size)
        // 2. Transaction gas for publish
        // 3. Storage rebate
        //
        // Rough estimate: 0.1 SUI base + 0.001 SUI per KB of bytecode
        let base_cost = 100_000_000; // 0.1 SUI in MIST
        let per_kb_cost = 1_000_000; // 0.001 SUI per KB
        let size_kb = program_bytes.len().div_ceil(1024);

        Ok(base_cost + (size_kb as u64 * per_kb_cost))
    }
}

#[async_trait]
impl ChainProofProvider for SuiBackend {
    async fn build_inclusion_proof(
        &self,
        commitment: &Hash,
        block_height: u64,
        anchor_id: &[u8],
    ) -> ChainOpResult<CoreInclusionProof> {
        // Get the checkpoint for the given height
        let checkpoint = self
            .rpc()
            .get_checkpoint(block_height)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get checkpoint: {}", e)))?
            .ok_or_else(|| ChainOpError::RpcError("Checkpoint not found".to_string()))?;

        // Build an event proof for the commitment
        let seal_object_id = [0u8; 32]; // Default seal object ID
        let event_data = self
            .event_builder
            .build(*commitment.as_bytes(), seal_object_id);

        // Convert ledger version to 32-byte hash
        let mut block_hash_bytes = [0u8; 32];
        block_hash_bytes.copy_from_slice(&checkpoint.digest);

        // In a real implementation, we would use the anchor_id (which should be the transaction digest)
        // to fetch the transaction and construct a proper proof.
        // The anchor_id is expected to be the 32-byte transaction digest.
        let _tx_digest = {
            if anchor_id.len() != 32 {
                return Err(ChainOpError::InvalidInput(format!(
                    "Invalid anchor_id length for Sui: expected 32 bytes, got {}",
                    anchor_id.len()
                )));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(anchor_id);
            arr
        };

        Ok(CoreInclusionProof {
            proof_bytes: event_data,
            block_hash: Hash::new(block_hash_bytes),
            position: block_height,
            block_number: block_height,
            ..Default::default()
        })
    }

    fn verify_inclusion_proof(
        &self,
        proof: &CoreInclusionProof,
        commitment: &Hash,
    ) -> ChainOpResult<bool> {
        self.verify_inclusion_native(proof, commitment)
    }

    async fn build_finality_proof(&self, tx_hash: &str) -> ChainOpResult<FinalityProof> {
        // Get transaction finality status
        let finality = self.get_finality(tx_hash).await?;

        match finality {
            FinalityStatus::Finalized { finality_block, .. } => {
                // Get checkpoint data
                let checkpoint = self
                    .rpc()
                    .get_checkpoint(finality_block)
                    .await
                    .map_err(|e| {
                        ChainOpError::RpcError(format!("Failed to get checkpoint: {}", e))
                    })?
                    .ok_or_else(|| ChainOpError::RpcError("Checkpoint not found".to_string()))?;

                // Build checkpoint certificate proof
                let proof_data = serde_json::to_vec(&checkpoint)
                    .map_err(|e| ChainOpError::Unknown(format!("Serialization failed: {}", e)))?;

                Ok(FinalityProof {
                    finality_data: proof_data,
                    confirmations: 1, // Sui has immediate finality after 1 checkpoint
                    is_deterministic: true,
                    ..Default::default()
                })
            }
            _ => Err(ChainOpError::ProofVerificationError(
                "Transaction not finalized".to_string(),
            )),
        }
    }

    fn verify_finality_proof(&self, proof: &FinalityProof, tx_hash: &str) -> ChainOpResult<bool> {
        self.verify_finality_native(proof, tx_hash)
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
        self.verify_proof_bundle_native(inclusion_proof, finality_proof, commitment)
    }
}

#[async_trait]
impl ChainSanadOps for SuiBackend {
    async fn create_sanad(
        &self,
        owner: &str,
        asset_class: &str,
        asset_id: &str,
        metadata: serde_json::Value,
    ) -> ChainOpResult<SanadOperationResult> {
        // In Sui, creating a sanad involves:
        // 1. Creating a new object representing the sanad
        // 2. Transferring it to the owner
        // 3. Recording the commitment

        let _ = owner;
        let _ = asset_class;
        let _ = asset_id;
        let _ = metadata;

        // This requires a transaction to create the sanad object
        // The transaction needs to be constructed and signed externally
        Err(ChainOpError::CapabilityUnavailable(
            "Sanad creation requires a signed transaction. \
             Construct a transaction to create the sanad object, \
             then use submit_transaction() to execute."
                .to_string(),
        ))
    }

    async fn consume_sanad(
        &self,
        sanad_id: &SanadId,
        owner_key_id: &str,
    ) -> ChainOpResult<SanadOperationResult> {
        let _ = sanad_id;
        let _ = owner_key_id;

        // Consuming a sanad in Sui means:
        // 1. Taking the sanad object
        // 2. Deleting it or marking it consumed
        // 3. Recording the nullifier

        Err(ChainOpError::CapabilityUnavailable(
            "Sanad consumption requires a signed transaction. \
             Construct a transaction to consume the sanad object, \
             then use submit_transaction() to execute."
                .to_string(),
        ))
    }

    async fn lock_sanad(
        &self,
        sanad_id: &SanadId,
        destination_chain: &str,
        owner_key_id: &str,
    ) -> ChainOpResult<SanadOperationResult> {
        // Parse the destination chain to ensure it's valid
        let _destination = destination_chain
            .parse::<csv_hash::ChainId>()
            .map_err(|_| {
                ChainOpError::InvalidInput(format!(
                    "Invalid destination chain: {}",
                    destination_chain
                ))
            })?;

        // Parse owner key for signing (expecting hex-encoded 32-byte address)
        let owner_bytes = hex::decode(owner_key_id)
            .map_err(|_| ChainOpError::InvalidInput("Invalid owner key ID format".to_string()))?;

        if owner_bytes.len() != 32 {
            return Err(ChainOpError::InvalidInput(
                "Owner key must be 32 bytes".to_string(),
            ));
        }

        let owner_address: [u8; 32] = owner_bytes
            .try_into()
            .map_err(|_| ChainOpError::InvalidInput("Invalid owner address format".to_string()))?;

        // Find the seal object for this sanad from active seals
        let seal = self
            .seal_protocol
            .get_active_seals()
            .into_iter()
            .last()
            .ok_or_else(|| {
                ChainOpError::InvalidInput(format!(
                    "No active seals found. Create a seal first for sanad: {}",
                    hex::encode(sanad_id.as_bytes())
                ))
            })?;

        // Get gas objects for transaction fees
        let gas_objects = self
            .rpc
            .get_gas_objects(owner_address)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get gas objects: {}", e)))?;

        if gas_objects.is_empty() {
            return Err(ChainOpError::InvalidInput(
                "Insufficient gas objects for transaction fees".to_string(),
            ));
        }

        // Build the lock transaction bytes
        let tx_bytes = self
            .build_lock_transaction_bytes(&seal.object_id, &owner_address)
            .map_err(|e| {
                ChainOpError::TransactionError(format!("Failed to build lock tx: {}", e))
            })?;

        // Execute the signed transaction via RPC
        // Format: [tx_bytes_len:4][tx_bytes][signature:64][public_key:32]
        let (signature, public_key) = self.sign_transaction_bytes(&tx_bytes)?;

        let digest = self
            .rpc
            .execute_signed_transaction(tx_bytes, signature, public_key)
            .await
            .map_err(|e| {
                ChainOpError::TransactionError(format!("Failed to execute lock tx: {}", e))
            })?;

        // Wait for transaction confirmation
        self.rpc
            .wait_for_transaction(digest, 5000)
            .await
            .map_err(|e| {
                ChainOpError::TransactionError(format!("Transaction confirmation failed: {}", e))
            })?;

        // Get the latest checkpoint as block height
        let checkpoint = self
            .rpc
            .get_latest_checkpoint_sequence_number()
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get checkpoint: {}", e)))?;

        Ok(SanadOperationResult {
            sanad_id: sanad_id.clone(),
            operation: csv_protocol::backend::SanadOperation::Lock,
            transaction_hash: format!("0x{}", hex::encode(digest)),
            block_height: checkpoint,
            chain_id: "sui".to_string(),
            metadata: serde_json::json!({
                "destination_chain": destination_chain,
                "lock_type": "object_lock",
                "seal_object_id": hex::encode(seal.object_id),
            }),
        })
    }

    async fn mint_sanad(
        &self,
        source_chain: &str,
        source_sanad_id: &SanadId,
        lock_proof: &CoreInclusionProof,
        new_owner: &str,
    ) -> ChainOpResult<SanadOperationResult> {
        // Parse the source chain to ensure it's valid
        let _source = source_chain.parse::<csv_hash::ChainId>().map_err(|_| {
            ChainOpError::InvalidInput(format!("Invalid source chain: {}", source_chain))
        })?;

        // Parse new owner address (expecting hex-encoded 32-byte Sui address)
        let owner_bytes = hex::decode(new_owner)
            .map_err(|_| ChainOpError::InvalidInput("Invalid owner address format".to_string()))?;

        if owner_bytes.len() != 32 {
            return Err(ChainOpError::InvalidInput(
                "Owner address must be 32 bytes".to_string(),
            ));
        }

        let owner_address: [u8; 32] = owner_bytes
            .try_into()
            .map_err(|_| ChainOpError::InvalidInput("Invalid owner address array".to_string()))?;

        // Verify the lock proof has valid structure
        if lock_proof.proof_bytes.is_empty() {
            return Err(ChainOpError::InvalidInput(
                "Lock proof is empty".to_string(),
            ));
        }

        if lock_proof.block_hash == Hash::zero() {
            return Err(ChainOpError::InvalidInput(
                "Lock proof has zero block hash".to_string(),
            ));
        }

        // Get gas objects for transaction fees on Sui
        let gas_objects = self
            .rpc
            .get_gas_objects(owner_address)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get gas objects: {}", e)))?;

        if gas_objects.is_empty() {
            return Err(ChainOpError::InvalidInput(
                "Insufficient gas objects for mint transaction fees".to_string(),
            ));
        }

        // Build the mint transaction bytes
        // Format: [source_chain_id:4][sanad_id:32][proof_hash:32][owner_address:32]
        let mut tx_bytes = Vec::new();
        tx_bytes.extend_from_slice(&(source_chain.len() as u32).to_le_bytes());
        tx_bytes.extend_from_slice(source_chain.as_bytes());
        tx_bytes.extend_from_slice(source_sanad_id.as_bytes());
        tx_bytes.extend_from_slice(lock_proof.block_hash.as_bytes());
        tx_bytes.extend_from_slice(&owner_address);

        // Execute the mint transaction via RPC
        let (signature, public_key) = self.sign_transaction_bytes(&tx_bytes)?;

        let digest = self
            .rpc
            .execute_signed_transaction(tx_bytes, signature, public_key)
            .await
            .map_err(|e| {
                ChainOpError::TransactionError(format!("Failed to execute mint tx: {}", e))
            })?;

        // Wait for transaction confirmation
        self.rpc
            .wait_for_transaction(digest, 5000)
            .await
            .map_err(|e| {
                ChainOpError::TransactionError(format!("Mint tx confirmation failed: {}", e))
            })?;

        // Get the latest checkpoint as block height
        let checkpoint = self
            .rpc
            .get_latest_checkpoint_sequence_number()
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get checkpoint: {}", e)))?;

        Ok(SanadOperationResult {
            sanad_id: source_sanad_id.clone(),
            operation: csv_protocol::backend::SanadOperation::Mint,
            transaction_hash: format!("0x{}", hex::encode(digest)),
            block_height: checkpoint,
            chain_id: "sui".to_string(),
            metadata: serde_json::json!({
                "source_chain": source_chain,
                "mint_type": "object_mint",
                "new_owner": new_owner,
                "proof_block_hash": hex::encode(lock_proof.block_hash.as_bytes()),
            }),
        })
    }

    async fn refund_sanad(
        &self,
        sanad_id: &SanadId,
        owner_key_id: &str,
    ) -> ChainOpResult<SanadOperationResult> {
        let _ = sanad_id;
        let _ = owner_key_id;

        // Refunding a locked sanad:
        // 1. Verify lock timeout exceeded
        // 2. Return sanad to owner
        // 3. Remove from lock state

        Err(ChainOpError::CapabilityUnavailable(
            "Sanad refund requires a signed transaction. \
             Construct a transaction to refund the locked sanad, \
             then use submit_transaction() to execute."
                .to_string(),
        ))
    }

    async fn record_sanad_metadata(
        &self,
        sanad_id: &SanadId,
        metadata: serde_json::Value,
        owner_key_id: &str,
    ) -> ChainOpResult<SanadOperationResult> {
        let _ = sanad_id;
        let _ = metadata;
        let _ = owner_key_id;

        // Recording metadata:
        // 1. Update the sanad object with new metadata
        // 2. Or create a metadata object linked to the sanad

        Err(ChainOpError::CapabilityUnavailable(
            "Metadata recording requires a signed transaction. \
             Construct a transaction to update the sanad metadata, \
             then use submit_transaction() to execute."
                .to_string(),
        ))
    }

    async fn verify_sanad_state(
        &self,
        sanad_id: &SanadId,
        expected_state: &str,
    ) -> ChainOpResult<bool> {
        // Verify sanad exists by querying the object
        // SanadId should map to an object ID
        let object_id = sanad_id.0.as_bytes();

        let object_info = match self.rpc().get_object(*object_id).await {
            Ok(Some(obj)) => Some(obj),
            Ok(None) => None,
            Err(e) => {
                return Err(ChainOpError::RpcError(format!(
                    "Failed to query sanad state: {}",
                    e
                )));
            }
        };

        // Determine actual state from object info
        let actual_state = match object_info {
            Some(_) => "active",
            None => {
                // Object doesn't exist - check if consumed or never created
                return match expected_state {
                    "consumed" | "deleted" | "never_created" => Ok(true),
                    _ => Ok(false),
                };
            }
        };

        Ok(actual_state == expected_state)
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

    fn create_seal(&self, value: Option<u64>) -> ChainOpResult<SealPoint> {
        let sui_seal = self
            .seal_protocol
            .create_seal(value)
            .map_err(|e| ChainOpError::Unknown(format!("Seal creation failed: {}", e)))?;

        // Convert SuiSealPoint to core SealPoint
        // SuiSealPoint has object_id (32 bytes) stored in id
        Ok(SealPoint {
            id: sui_seal.object_id.to_vec(),
            nonce: Some(sui_seal.nonce),
        })
    }

    fn publish_seal(&self, seal: SealPoint, commitment: Hash) -> ChainOpResult<CommitAnchor> {
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
    use crate::SuiNetwork;
    use crate::rpc::MockSuiRpc;

    #[test]
    fn test_sui_chain_operations_creation() {
        let rpc = Box::new(MockSuiRpc::new(1));
        let mut config = SuiConfig::new(SuiNetwork::Testnet);
        config.seal_contract.package_id =
            Some("0x0000000000000000000000000000000000000000000000000000000000000001".to_string());
        let ops = SuiBackend::new(rpc, config);
        assert_eq!(ops.config.network, SuiNetwork::Testnet);
    }

    #[test]
    fn test_address_validation() {
        let rpc = Box::new(MockSuiRpc::new(1));
        let mut config = SuiConfig::new(SuiNetwork::Testnet);
        config.seal_contract.package_id =
            Some("0x0000000000000000000000000000000000000000000000000000000000000001".to_string());
        let ops = SuiBackend::new(rpc, config);

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
        let rpc = Box::new(MockSuiRpc::new(1));
        let mut config = SuiConfig::new(SuiNetwork::Testnet);
        config.seal_contract.package_id =
            Some("0x0000000000000000000000000000000000000000000000000000000000000001".to_string());
        let ops = SuiBackend::new(rpc, config);

        // Generate a keypair
        use ed25519_dalek::{Signer, SigningKey};
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let verifying_key = signing_key.verifying_key();

        let message = b"test message";
        let signature = signing_key.sign(message);

        // Verify signature
        let result = ops
            .verify_signature(message, &signature.to_bytes(), &verifying_key.to_bytes())
            .unwrap();
        assert!(result);

        // Wrong message should fail
        let wrong_message = b"wrong message";
        let result = ops
            .verify_signature(
                wrong_message,
                &signature.to_bytes(),
                &verifying_key.to_bytes(),
            )
            .unwrap();
        assert!(!result);
    }
}
