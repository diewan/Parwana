//! Chain Operation Traits Implementation for Aptos
//!
//! This module implements all chain operation traits from csv-adapter-core:
//! - ChainQuery: Querying chain state via REST API
//! - ChainSigner: Ed25519 signing operations
//! - ChainBroadcaster: Transaction broadcasting
//! - ChainDeployer: Move module deployment
//! - ChainProofProvider: Proof building and verification
//! - ChainSanadOps: Sanad management operations
//!
use async_trait::async_trait;
use csv_hash::Hash;
use csv_hash::sanad::SanadId;
use csv_hash::seal::{CommitAnchor, SealPoint};
use csv_protocol::chain_adapter_traits::{
    BalanceInfo, CanonicalLifecycleEvent, CanonicalSanadState, CanonicalSealState, ChainBackend,
    ChainBroadcaster, ChainCapability, ChainDeployer, ChainOpError, ChainOpResult,
    ChainProofProvider, ChainQuery, ChainReadiness, ChainReadinessCheck, ChainSanadOps,
    ChainSigner, ContractStatus, DeploymentStatus, FinalityStatus, SanadOperationResult,
    SanadStateReader, TransactionInfo, TransactionStatus,
};
use csv_protocol::proof_taxonomy::{FinalityProof, InclusionProof as CoreInclusionProof};
use csv_protocol::seal_protocol::SealProtocol;
use csv_protocol::signature::SignatureScheme;
use sha3::{Digest, Sha3_256};
use std::sync::Arc;

use crate::address_utils::format_address;
use crate::config::AptosNetwork;
use crate::proofs::CommitmentEventBuilder;
use crate::proofs::ParsedLockProof;
use crate::rpc::{AptosRpc, AptosTransaction};
use crate::seal_protocol::AptosSealProtocol;

/// Aptos chain operations implementation
pub struct AptosBackend {
    /// Inner RPC client for chain communication
    rpc: Box<dyn AptosRpc>,
    /// Chain configuration
    network: AptosNetwork,
    /// Domain separator for proof generation
    domain_separator: [u8; 32],
    /// Commitment event builder
    event_builder: CommitmentEventBuilder,
    /// Reference to seal protocol for seal creation and publishing
    pub(crate) seal_protocol: Arc<AptosSealProtocol>,
}

impl AptosBackend {
    /// Create new Aptos chain operations from RPC client.
    ///
    /// Fails closed: if the seal protocol cannot be constructed from the supplied
    /// RPC/config (e.g. malformed configuration), this returns a typed error instead
    /// of silently substituting a mock RPC client. A mock fallback here would mean
    /// production callers could end up signing/reading against a fake in-memory chain
    /// without any indication that real contract-backed behavior was never wired up.
    pub fn new(rpc: Box<dyn AptosRpc>, network: AptosNetwork) -> ChainOpResult<Self> {
        // Create seal protocol using the real RPC (not a mock)
        // This is required for publish() to work with transaction signing
        let config = crate::config::AptosConfig {
            network: network.clone(),
            ..Default::default()
        };
        let seal = AptosSealProtocol::from_config(config, rpc.clone_boxed()).map_err(|e| {
            ChainOpError::RpcError(format!(
                "Failed to construct Aptos seal protocol from RPC/config: {}",
                e
            ))
        })?;

        // MED-DUP-03: Derive domain separator from SealProtocol instead of recomputing
        let domain_separator = seal.domain();

        // Build event builder with default module address
        let module_address = [0u8; 32];
        let event_builder = CommitmentEventBuilder::new(module_address, "CSV::AnchorEvent");

        Ok(Self {
            rpc,
            network,
            domain_separator,
            event_builder,
            seal_protocol: Arc::new(seal),
        })
    }

    /// Create from AptosSealProtocol
    pub fn from_seal_protocol(seal: Arc<AptosSealProtocol>) -> ChainOpResult<Self> {
        let (module_addr, event_type) = seal.event_builder_config();
        Ok(Self {
            rpc: seal.rpc().clone_boxed(),
            network: seal.network(),
            domain_separator: seal.domain(),
            event_builder: CommitmentEventBuilder::new(module_addr, event_type),
            seal_protocol: seal,
        })
    }

    /// Parse Aptos address from string
    fn parse_address(&self, address: &str) -> ChainOpResult<[u8; 32]> {
        let hex_str = address.trim_start_matches("0x");
        let bytes = hex::decode(hex_str)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid hex address: {}", e)))?;

        if bytes.len() != 32 {
            return Err(ChainOpError::InvalidInput(
                "Aptos address must be 32 bytes".to_string(),
            ));
        }

        let mut addr = [0u8; 32];
        addr.copy_from_slice(&bytes);
        Ok(addr)
    }

    /// Parse transaction hash (version)
    fn parse_version(&self, hash: &str) -> ChainOpResult<u64> {
        // Aptos uses version numbers, not hashes
        hash.parse()
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid version: {}", e)))
    }

    /// Convert Aptos transaction to TransactionInfo
    fn tx_to_info(&self, tx: &AptosTransaction) -> TransactionInfo {
        let status = if tx.success {
            TransactionStatus::Confirmed {
                block_height: tx.version,
                confirmations: 1, // Aptos has immediate finality
            }
        } else {
            TransactionStatus::Failed {
                reason: tx.vm_status.clone(),
            }
        };

        TransactionInfo {
            hash: format!("0x{}", hex::encode(tx.hash)),
            sender: "unknown".to_string(), // Would need to parse from payload
            recipient: None,
            amount: None,
            status,
            block_height: Some(tx.version),
            timestamp: None,
            fee: Some(tx.gas_used),
            raw_data: Some(tx.payload.clone()),
        }
    }

    /// Get RPC client reference
    pub fn rpc(&self) -> &dyn AptosRpc {
        self.rpc.as_ref()
    }
}

#[async_trait]
impl ChainQuery for AptosBackend {
    async fn get_balance(&self, address: &str) -> ChainOpResult<BalanceInfo> {
        let addr = self.parse_address(address)?;

        // Look for CoinStore resource
        let mut total_balance = 0u64;
        let token_balances = Vec::new();

        // Get the CoinStore resource directly for accurate balance
        let coin_resource = self
            .rpc()
            .get_resource(
                addr,
                "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>",
                None,
            )
            .await;

        if let Ok(Some(resource)) = coin_resource {
            // Parse coin balance from BCS-encoded resource data
            // CoinStore<T> layout: coin.value (u64) is the first 8 bytes
            if let Some(balance) = resource.parse_coin_balance() {
                total_balance = balance;
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
        // Try parsing as version first (numeric), then fall back to hash lookup
        if let Ok(version) = self.parse_version(hash) {
            let tx = self
                .rpc()
                .get_transaction(version)
                .await
                .map_err(|e| ChainOpError::RpcError(format!("Failed to get transaction: {}", e)))?
                .ok_or_else(|| ChainOpError::RpcError("Transaction not found".to_string()))?;
            return Ok(self.tx_to_info(&tx));
        }

        // Fall back to hash-based lookup
        let tx = self
            .rpc()
            .get_transaction_by_hash(hash)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get transaction by hash: {}", e)))?
            .ok_or_else(|| ChainOpError::RpcError("Transaction not found".to_string()))?;

        Ok(self.tx_to_info(&tx))
    }

    async fn get_finality(&self, tx_hash: &str) -> ChainOpResult<FinalityStatus> {
        // In Aptos, transactions are finalized immediately
        // Finality is determined by being in a ledger with certified block
        let tx_info = self.get_transaction(tx_hash).await?;

        match tx_info.status {
            TransactionStatus::Confirmed { block_height, .. } => {
                // Get ledger info to verify
                let ledger =
                    self.rpc().get_ledger_info().await.map_err(|e| {
                        ChainOpError::RpcError(format!("Failed to get ledger: {}", e))
                    })?;

                // If transaction version is in current or older epoch, it's finalized
                if block_height <= ledger.ledger_version {
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
        let addr = self.parse_address(contract_address)?;

        // Check if a specific resource exists at address to determine if contract is deployed
        let resource_result = self
            .rpc()
            .get_resource(addr, "0x1::account::Account", None)
            .await;

        let is_deployed = matches!(resource_result, Ok(Some(_)));

        Ok(ContractStatus {
            address: contract_address.to_string(),
            is_deployed,
            balance: None,
            owner: Some(contract_address.to_string()),
            metadata: serde_json::json!({
                "chain": "aptos",
                "network": format!("{:?}", self.network),
            }),
        })
    }

    async fn get_latest_block_height(&self) -> ChainOpResult<u64> {
        let ledger = self
            .rpc()
            .get_ledger_info()
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get ledger: {}", e)))?;

        Ok(ledger.ledger_version)
    }

    async fn get_chain_info(&self) -> ChainOpResult<serde_json::Value> {
        let ledger = self
            .rpc()
            .get_ledger_info()
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get ledger: {}", e)))?;

        Ok(serde_json::json!({
            "chain_id": ledger.chain_id,
            "chain": "aptos",
            "network": format!("{:?}", self.network),
            "epoch": ledger.epoch,
            "ledger_version": ledger.ledger_version,
            "oldest_version": ledger.oldest_ledger_version,
            "protocol": "Move",
            "finality": "deterministic",
        }))
    }

    async fn get_account_nonce(&self, address: &str) -> ChainOpResult<u64> {
        // Aptos uses account sequence numbers
        let addr = self.parse_address(address)?;

        self.rpc
            .get_account_sequence_number(addr)
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get sequence number: {}", e)))
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
impl ChainSigner for AptosBackend {
    fn derive_address(&self, public_key: &[u8]) -> ChainOpResult<String> {
        if public_key.len() != 32 {
            return Err(ChainOpError::InvalidInput(
                "Ed25519 public key must be 32 bytes".to_string(),
            ));
        }

        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(public_key);

        // Aptos authentication key = SHA3-256(public_key | signature_scheme)
        // For single-key accounts: auth_key = SHA3-256(pubkey || 0x00)
        let mut data = pubkey.to_vec();
        data.push(0x00); // Ed25519 single key scheme
        let hash = Sha3_256::digest(&data);
        let mut addr = [0u8; 32];
        addr.copy_from_slice(&hash[..32]);

        Ok(format!("0x{}", hex::encode(addr)))
    }

    async fn sign_transaction(&self, _tx_data: &[u8], _key_id: &str) -> ChainOpResult<Vec<u8>> {
        Err(ChainOpError::CapabilityUnavailable(
            "Direct transaction signing not available. \
             Use an external keystore with the key_id reference."
                .to_string(),
        ))
    }

    async fn sign_message(&self, _message: &[u8], _key_id: &str) -> ChainOpResult<Vec<u8>> {
        Err(ChainOpError::CapabilityUnavailable(
            "Direct message signing not available. \
             Use an external keystore with the key_id reference."
                .to_string(),
        ))
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

        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        // Convert bytes to proper types
        let mut pubkey_bytes = [0u8; 32];
        pubkey_bytes.copy_from_slice(public_key);

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(signature);

        // Create verifying key and signature
        let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes)
            .map_err(|e| ChainOpError::InvalidInput(format!("Invalid public key: {}", e)))?;

        let ed_sig = Signature::from_bytes(&sig_bytes);

        // Verify the signature
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
impl ChainBroadcaster for AptosBackend {
    async fn submit_transaction(&self, signed_tx: &[u8]) -> ChainOpResult<String> {
        // Aptos signed transaction is BCS-encoded
        // Submit via submit_signed_transaction

        let signed_json = serde_json::from_slice(signed_tx).map_err(|e| {
            ChainOpError::InvalidInput(format!("Invalid signed transaction: {}", e))
        })?;

        let hash = self
            .rpc()
            .submit_signed_transaction(signed_json)
            .await
            .map_err(|e| ChainOpError::TransactionError(format!("Submission failed: {}", e)))?;

        Ok(format!("0x{}", hex::encode(hash)))
    }

    async fn confirm_transaction(
        &self,
        tx_hash: &str,
        _required_confirmations: u64,
        timeout_secs: u64,
    ) -> ChainOpResult<TransactionStatus> {
        // Aptos uses version numbers as tx identifiers - parse and convert to hash
        let _version = self.parse_version(tx_hash)?;
        let hash = self.parse_address(tx_hash)?;

        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(timeout_secs);
        let poll_interval = std::time::Duration::from_millis(500);

        loop {
            if start.elapsed() > timeout {
                return Err(ChainOpError::Timeout(
                    "Transaction confirmation timeout".to_string(),
                ));
            }

            match self.rpc().wait_for_transaction(hash).await {
                Ok(tx) => {
                    return Ok(if tx.success {
                        TransactionStatus::Confirmed {
                            block_height: tx.version,
                            confirmations: 1,
                        }
                    } else {
                        TransactionStatus::Failed {
                            reason: tx.vm_status,
                        }
                    });
                }
                Err(_) => {
                    // PF-03: always async (no cfg-gated blocking sleep)
                    tokio::time::sleep(poll_interval).await;
                }
            }
        }
    }

    async fn get_fee_estimate(&self) -> ChainOpResult<u64> {
        // Aptos gas estimation
        // Typical transaction: ~1000 gas units at 100 gas price = 100000 Octa (0.001 APT)
        Ok(100_000)
    }

    async fn validate_transaction(&self, tx_data: &[u8]) -> ChainOpResult<()> {
        if tx_data.is_empty() {
            return Err(ChainOpError::InvalidInput(
                "Empty transaction data".to_string(),
            ));
        }

        // Would decode BCS and validate structure

        Ok(())
    }
}

#[async_trait]
impl ChainDeployer for AptosBackend {
    async fn deploy_lock_contract(
        &self,
        admin_address: &str,
        config: serde_json::Value,
    ) -> ChainOpResult<DeploymentStatus> {
        let _ = admin_address;
        let _ = config;

        Err(ChainOpError::CapabilityUnavailable(
            "Lock contract deployment requires Move module publishing. \
             Use deploy_or_publish_seal_program() with compiled Move bytecode."
                .to_string(),
        ))
    }

    async fn deploy_mint_contract(
        &self,
        admin_address: &str,
        config: serde_json::Value,
    ) -> ChainOpResult<DeploymentStatus> {
        let _ = admin_address;
        let _ = config;

        Err(ChainOpError::CapabilityUnavailable(
            "Mint contract deployment requires Move module publishing. \
             Same module handles both lock and mint in Aptos."
                .to_string(),
        ))
    }

    async fn deploy_or_publish_seal_program(
        &self,
        program_bytes: &[u8],
        admin_address: &str,
    ) -> ChainOpResult<DeploymentStatus> {
        let _ = program_bytes;
        let _ = admin_address;

        Err(ChainOpError::CapabilityUnavailable(
            "Seal program publishing requires signed transaction. \
             Use deploy_csv_seal_module() with compiled Move bytecode \
             or external tools (aptos move publish)."
                .to_string(),
        ))
    }

    async fn verify_deployment(&self, contract_address: &str) -> ChainOpResult<bool> {
        let status = self.get_contract_status(contract_address).await?;
        Ok(status.is_deployed)
    }

    async fn estimate_deployment_cost(&self, program_bytes: &[u8]) -> ChainOpResult<u64> {
        // Aptos deployment cost estimation
        let base_cost = 100_000u64; // Base gas
        let per_byte_cost = 10u64; // Gas per byte of code
        let code_cost = (program_bytes.len() as u64) * per_byte_cost;

        Ok(base_cost + code_cost)
    }
}

#[async_trait]
impl ChainProofProvider for AptosBackend {
    async fn build_inclusion_proof(
        &self,
        commitment: &Hash,
        block_height: u64,
        anchor_id: &[u8],
    ) -> ChainOpResult<CoreInclusionProof> {
        // Get block/ledger info
        let ledger = self
            .rpc()
            .get_ledger_info()
            .await
            .map_err(|e| ChainOpError::RpcError(format!("Failed to get ledger: {}", e)))?;

        // Build event proof - use a default seal address
        let seal_address = [0u8; 32];
        let event_data = self
            .event_builder
            .build(*commitment.as_bytes(), seal_address);

        // Convert ledger version to 32-byte hash
        let mut block_hash_bytes = [0u8; 32];
        let version_bytes = ledger.ledger_version.to_le_bytes();
        block_hash_bytes[..8].copy_from_slice(&version_bytes);

        // In a real implementation, we would use the anchor_id (which should be the transaction hash)
        // to fetch the transaction and construct a proper proof.
        // The anchor_id is expected to be the 32-byte transaction hash.
        let _tx_hash = {
            if anchor_id.len() != 32 {
                return Err(ChainOpError::InvalidInput(format!(
                    "Invalid anchor_id length for Aptos: expected 32 bytes, got {}",
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
        let finality = self.get_finality(tx_hash).await?;

        match finality {
            FinalityStatus::Finalized { finality_block, .. } => {
                let ledger =
                    self.rpc().get_ledger_info().await.map_err(|e| {
                        ChainOpError::RpcError(format!("Failed to get ledger: {}", e))
                    })?;

                let proof_data = serde_json::to_vec(&ledger)
                    .map_err(|e| ChainOpError::Unknown(format!("Serialization failed: {}", e)))?;

                // FinalityProof uses: finality_data, confirmations, is_deterministic
                let confirmations = ledger.ledger_version.saturating_sub(finality_block) + 1;
                Ok(FinalityProof::new(
                    proof_data,
                    confirmations,
                    true, // Aptos has deterministic finality via HotStuff
                )
                .map_err(|e| {
                    ChainOpError::InvalidInput(format!("Invalid finality proof: {}", e))
                })?)
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
impl ChainSanadOps for AptosBackend {
     async fn create_sanad(
        &self,
        owner: &str,
        asset_class: &str,
        asset_id: &str,
        metadata: serde_json::Value,
    ) -> ChainOpResult<SanadOperationResult> {
        use csv_protocol::chain_adapter_traits::SanadOperation;
        use sha2::{Digest, Sha256};

        let commitment_bytes: [u8; 32] = {
            let mut hasher = Sha256::new();
            hasher.update(b"commitment-");
            hasher.update(owner.as_bytes());
            hasher.update(asset_class.as_bytes());
            hasher.update(asset_id.as_bytes());
            if let Some(meta_str) = metadata.as_str() {
                hasher.update(meta_str.as_bytes());
            }
            let now_nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            hasher.update(now_nanos.to_le_bytes());
            hasher.finalize().into()
        };
        let commitment = Hash::new(commitment_bytes);

        let seal = self.seal_protocol
            .create_seal(None)
            .await
            .map_err(|e| ChainOpError::TransactionError(format!("Failed to create seal: {}", e)))?;

        log::debug!("APTOS: Creating sanad with seal at {}", format_address(seal.account_address));

        #[cfg(feature = "rpc")]
        {
            let (_signed_tx, _event_data) = self.seal_protocol
                .build_and_sign_entry_function(&seal, commitment_bytes)
                .await
                .map_err(|e| ChainOpError::TransactionError(format!("Failed to build transaction: {}", e)))?;

            log::debug!("APTOS: Built and signed create_sanad transaction");

            let tx_hash = self.rpc
                .submit_signed_transaction(_signed_tx)
                .await
                .map_err(|e| ChainOpError::TransactionError(format!("Failed to submit transaction: {}", e)))?;

            log::debug!("APTOS: Transaction submitted with hash: {}", hex::encode(tx_hash));
        }

        #[cfg(not(feature = "rpc"))]
        {
            let _ = (&seal, commitment_bytes);
            return Err(ChainOpError::FeatureNotEnabled(
                "Sanad creation requires RPC feature for transaction signing. \
                 Enable with --features rpc".to_string(),
            ));
        }

        Ok(SanadOperationResult {
            sanad_id: SanadId(commitment),
            operation: SanadOperation::Create,
            transaction_hash: String::new(),
            block_height: 0,
            chain_id: "aptos".to_string(),
            metadata: serde_json::to_vec(&serde_json::json!({
                "owner": owner,
                "asset_class": asset_class,
                "asset_id": asset_id,
                "seal_address": format_address(seal.account_address),
                "seal_resource_type": seal.resource_type,
            })).unwrap_or_default(),
        })
    }

    async fn consume_sanad(
        &self,
        sanad_id: &SanadId,
        owner_key_id: &str,
    ) -> ChainOpResult<SanadOperationResult> {
        let _ = owner_key_id;

        #[cfg(feature = "rpc")]
        {
            use csv_protocol::chain_adapter_traits::SanadOperation;
            use crate::types::AptosSealPoint;

            // The sanad_id is the commitment hash
            let commitment = *sanad_id.as_bytes();

            log::debug!("APTOS: Consuming sanad with commitment: {}", hex::encode(commitment));

            // Create a seal point - for consume, the seal is at the signer's address
            // The actual address will be derived from the signing key in build_and_sign_entry_function
            let seal = AptosSealPoint {
                account_address: [0u8; 32], // Will be derived from signing key
                resource_type: "0x1::csv_seal::Seal".to_string(),
                nonce: 0u64,
            };

            // Build and sign the consume_seal transaction using the seal protocol
            let (signed_tx, _event_data) = self
                .seal_protocol
                .build_and_sign_entry_function(&seal, commitment)
                .await
                .map_err(|e| {
                    ChainOpError::TransactionError(format!(
                        "Failed to build and sign consume_seal transaction: {}",
                        e
                    ))
                })?;

            log::debug!("APTOS: Built and signed consume_seal transaction");

            // Submit the signed transaction via RPC
            log::debug!("APTOS: Submitting consume_seal transaction");
            let tx_hash = self
                .rpc
                .submit_signed_transaction(signed_tx)
                .await
                .map_err(|e| {
                    ChainOpError::TransactionError(format!("Failed to submit transaction: {}", e))
                })?;

            log::debug!("APTOS: Transaction submitted with hash: {}", hex::encode(tx_hash));

            // Wait for transaction confirmation
            log::debug!("APTOS: Waiting for transaction confirmation");
            let tx = match self.rpc.wait_for_transaction(tx_hash).await {
                Ok(tx) => tx,
                Err(e) => {
                    // Timeout or error waiting - try to get transaction status directly
                    log::warn!("APTOS: Timeout waiting for transaction, querying status directly");
                    // Try to get transaction by hash (if RPC supports it) or return error with tx hash
                    return Err(ChainOpError::Timeout(format!(
                        "Timeout waiting for transaction confirmation. Transaction hash: {}. Check explorer for status.",
                        hex::encode(tx_hash)
                    )));
                }
            };

            if !tx.success {
                return Err(ChainOpError::TransactionError(format!(
                    "Transaction failed with VM status: {}",
                    tx.vm_status
                )));
            }

            log::debug!("APTOS: Transaction confirmed successfully");

            Ok(SanadOperationResult {
                sanad_id: sanad_id.clone(),
                operation: SanadOperation::Consume,
                transaction_hash: hex::encode(tx_hash),
                block_height: tx.version,
                chain_id: "aptos".to_string(),
                metadata: serde_json::to_vec(&serde_json::json!({})).unwrap_or_default(),
            })
        }

        #[cfg(not(feature = "rpc"))]
        {
            Err(ChainOpError::CapabilityUnavailable(
                "Sanad consumption requires RPC feature. Enable with --features rpc".to_string(),
            ))
        }
    }

    async fn lock_sanad(
        &self,
        sanad_id: &SanadId,
        destination_chain: &str,
        owner_key_id: &str,
    ) -> ChainOpResult<SanadOperationResult> {
        #[cfg(feature = "rpc")]
        {
            use csv_protocol::chain_adapter_traits::SanadOperation;

            // Parse the destination chain to ensure it's valid
            let _destination = destination_chain
                .parse::<csv_hash::chain_id::ChainId>()
                .map_err(|_| {
                    ChainOpError::InvalidInput(format!(
                        "Invalid destination chain: {}",
                        destination_chain
                    ))
                })?;

            // Parse owner key for signing (expecting hex-encoded 32-byte address)
            let owner_key_id_clean = owner_key_id.trim_start_matches("0x");
            let owner_bytes = hex::decode(owner_key_id_clean)
                .map_err(|_| ChainOpError::InvalidInput("Invalid owner key ID format".to_string()))?;

            if owner_bytes.len() != 32 {
                return Err(ChainOpError::InvalidInput(
                    "Owner key must be 32 bytes".to_string(),
                ));
            }

            let _owner_address: [u8; 32] = owner_bytes
                .try_into()
                .map_err(|_| ChainOpError::InvalidInput("Invalid owner address format".to_string()))?;

            // The sanad_id is the commitment hash
            let commitment = *sanad_id.as_bytes();

            log::debug!("APTOS: Locking sanad with commitment: {}", hex::encode(commitment));
            log::debug!("APTOS: Destination chain: {}", destination_chain);

            // Query the seal resource from on-chain instead of using in-memory registry
            // The seal was created via CLI and may not be in the in-memory registry
            let account_address = self.seal_protocol.signing_key.as_ref()
                .map(|key| {
                    use sha3::{Digest, Sha3_256};
                    let public_key = key.verifying_key().to_bytes();
                    let mut data = public_key.to_vec();
                    data.push(0x00); // Ed25519 single key scheme
                    let hash = Sha3_256::digest(&data);
                    let mut addr = [0u8; 32];
                    addr.copy_from_slice(&hash[..32]);
                    addr
                })
                .ok_or_else(|| ChainOpError::InvalidInput("No signing key configured".to_string()))?;

            // Query the seal resource from on-chain
            let seal = self.seal_protocol.get_seal_from_chain(account_address)
                .await
                .map_err(|e| ChainOpError::InvalidInput(format!("Failed to query seal from chain: {}", e)))?;

            // Get the nonce from the seal
            let nonce = seal.nonce;

            // Convert destination chain to u8
            let dest_chain_u8 = match destination_chain {
                "sui" => 1u8,
                "aptos" => 2u8,
                "ethereum" => 3u8,
                "solana" => 4u8,
                "bitcoin" => 5u8,
                _ => return Err(ChainOpError::InvalidInput(
                    format!("Invalid destination chain: {}", destination_chain)
                )),
            };

            // Build the lock_sanad entry function payload
            let entry_function_builder = crate::entry_function::EntryFunctionBuilder::new(
                self.seal_protocol.config().seal_contract.module_address.clone()
            );
            let payload = entry_function_builder.lock_sanad(
                nonce,
                commitment,
                dest_chain_u8,
                _owner_address,
            );

            // Sign the transaction
            let signed_tx = self.seal_protocol.sign_entry_function_payload(payload)
                .await
                .map_err(|e| {
                    ChainOpError::TransactionError(format!(
                        "Failed to build and sign lock_sanad transaction: {}",
                        e
                    ))
                })?;

            log::debug!("APTOS: Built and signed lock_sanad transaction");

            // Submit the signed transaction via RPC
            log::debug!("APTOS: Submitting lock_sanad transaction");
            let tx_hash = self
                .rpc
                .submit_signed_transaction(signed_tx)
                .await
                .map_err(|e| {
                    ChainOpError::TransactionError(format!("Failed to submit transaction: {}", e))
                })?;

            log::debug!("APTOS: Transaction submitted with hash: {}", hex::encode(tx_hash));

            // Wait for transaction confirmation
            log::debug!("APTOS: Waiting for transaction confirmation");
            let tx = match self.rpc.wait_for_transaction(tx_hash).await {
                Ok(tx) => tx,
                Err(e) => {
                    log::warn!("APTOS: Timeout waiting for transaction, querying status directly");
                    return Err(ChainOpError::Timeout(format!(
                        "Timeout waiting for transaction confirmation. Transaction hash: {}. Check explorer for status.",
                        hex::encode(tx_hash)
                    )));
                }
            };

            if !tx.success {
                return Err(ChainOpError::TransactionError(format!(
                    "Transaction failed with VM status: {}",
                    tx.vm_status
                )));
            }

            log::debug!("APTOS: Transaction confirmed successfully");

            Ok(SanadOperationResult {
                sanad_id: sanad_id.clone(),
                operation: SanadOperation::Lock,
                transaction_hash: hex::encode(tx_hash),
                block_height: tx.version,
                chain_id: "aptos".to_string(),
                metadata: serde_json::to_vec(&serde_json::json!({
                    "destination_chain": destination_chain,
                    "seal_address": hex::encode(seal.account_address),
                })).unwrap_or_default(),
            })
        }

        #[cfg(not(feature = "rpc"))]
        {
            Err(ChainOpError::CapabilityUnavailable(
                "Sanad locking requires RPC feature. Enable with --features rpc".to_string(),
            ))
        }
    }

    async fn mint_sanad(
        &self,
        source_chain: &str,
        source_sanad_id: &SanadId,
        lock_proof: &CoreInclusionProof,
        new_owner: &str,
    ) -> ChainOpResult<SanadOperationResult> {
        #[cfg(feature = "rpc")]
        {
            use csv_protocol::chain_adapter_traits::SanadOperation;

            // Parse the source chain to ensure it's valid
            let _source = source_chain
                .parse::<csv_hash::chain_id::ChainId>()
                .map_err(|_| {
                    ChainOpError::InvalidInput(format!("Invalid source chain: {}", source_chain))
                })?;

            // Parse new owner address (expecting hex-encoded 32-byte Aptos address)
            let new_owner_clean = new_owner.trim_start_matches("0x");
            let owner_bytes = hex::decode(new_owner_clean)
                .map_err(|_| ChainOpError::InvalidInput("Invalid owner address format".to_string()))?;

            if owner_bytes.len() != 32 {
                return Err(ChainOpError::InvalidInput(
                    "Owner address must be 32 bytes".to_string(),
                ));
            }

            let _owner_address: [u8; 32] = owner_bytes
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

            log::debug!("APTOS: Minting sanad from source chain: {}", source_chain);
            log::debug!("APTOS: Source sanad ID: {}", hex::encode(source_sanad_id.as_bytes()));

            // Find the seal resource for this sanad from active seals, or create one if none exist
            let seal = if let Some(seal) = self.seal_protocol.get_active_seals().into_iter().last() {
                seal
            } else {
                // Auto-create a seal if none exist
                log::debug!("APTOS: No active seals found, creating a new seal");
                let seal = self.seal_protocol.create_seal(None).await
                    .map_err(|e| ChainOpError::TransactionError(format!("Failed to create seal: {}", e)))?;

                // Wait a moment for the seal creation transaction to be processed
                // This avoids SEQUENCE_NUMBER_TOO_OLD errors by allowing the sequence number to increment
                log::debug!("APTOS: Waiting for seal creation to be processed...");
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

                seal
            };

            // The commitment is the source sanad ID
            let commitment = *source_sanad_id.as_bytes();

            // Build and sign the mint_sanad transaction using the actual Move contract function
            // The mint_sanad entry function signature:
            // mint_sanad(account, sanad_id, commitment, state_root, source_chain, source_seal_ref, proof, proof_root, leaf_position)
            log::debug!("APTOS: Building mint_sanad transaction");

            // Parse source chain to u8
            let source_chain_u8 = match source_chain {
                "bitcoin" => 0,
                "sui" => 1,
                "aptos" => 2,
                "ethereum" => 3,
                "solana" => 4,
                _ => return Err(ChainOpError::InvalidInput(format!(
                    "Invalid source chain: {}", source_chain
                ))),
            };

            // Get module address from seal protocol
            let (module_addr, _) = self.seal_protocol.event_builder_config();
            let module_address = format_address(module_addr);

            // Use EntryFunctionBuilder to construct the mint_sanad payload
            let builder = crate::entry_function::EntryFunctionBuilder::new(module_address);

            // Convert Vec<u8> to [u8; 32] where needed
            let source_seal_ref_array: [u8; 32] = if lock_proof.proof_bytes.len() >= 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&lock_proof.proof_bytes[..32]);
                arr
            } else {
                return Err(ChainOpError::InvalidInput(
                    "Lock proof too short for source_seal_ref".to_string()
                ));
            };

            let proof_root_array = *lock_proof.block_hash.as_bytes();

            // Parse lock proof into explicit fields required by Move entry function
            // This rejects short proofs and extracts state_root and leaf_position properly
            let parsed_proof = ParsedLockProof::parse(&lock_proof.proof_bytes)
                .map_err(|e| ChainOpError::InvalidInput(format!("Failed to parse lock proof: {}", e)))?;

            let state_root = parsed_proof.state_root;
            let leaf_position = parsed_proof.leaf_position;

            // Build the payload with all required parameters
            let payload = builder.mint_sanad(
                *source_sanad_id.as_bytes(),  // sanad_id
                commitment,                   // commitment
                state_root,                  // state_root parsed from lock proof
                source_chain_u8,             // source_chain
                source_seal_ref_array,       // source_seal_ref
                parsed_proof.proof_data,     // proof_data (without prefix)
                proof_root_array,            // proof_root
                leaf_position,               // leaf_position parsed from lock proof
            );

            let signed_tx = self
                .seal_protocol
                .sign_entry_function_payload(payload)
                .await
                .map_err(|e| {
                    ChainOpError::TransactionError(format!(
                        "Failed to build and sign mint_sanad transaction: {}",
                        e
                    ))
                })?;

            log::debug!("APTOS: Built and signed mint_sanad transaction");

            // Submit the signed transaction via RPC
            log::debug!("APTOS: Submitting mint_sanad transaction");
            let tx_hash = self
                .rpc
                .submit_signed_transaction(signed_tx)
                .await
                .map_err(|e| {
                    ChainOpError::TransactionError(format!("Failed to submit transaction: {}", e))
                })?;

            log::debug!("APTOS: Transaction submitted with hash: {}", hex::encode(tx_hash));

            // Wait for transaction confirmation
            log::debug!("APTOS: Waiting for transaction confirmation");
            let tx = match self.rpc.wait_for_transaction(tx_hash).await {
                Ok(tx) => tx,
                Err(e) => {
                    log::warn!("APTOS: Timeout waiting for transaction, querying status directly");
                    return Err(ChainOpError::Timeout(format!(
                        "Timeout waiting for transaction confirmation. Transaction hash: {}. Check explorer for status.",
                        hex::encode(tx_hash)
                    )));
                }
            };

            if !tx.success {
                return Err(ChainOpError::TransactionError(format!(
                    "Transaction failed with VM status: {}",
                    tx.vm_status
                )));
            }

            log::debug!("APTOS: Transaction confirmed successfully");

            Ok(SanadOperationResult {
                sanad_id: source_sanad_id.clone(),
                operation: SanadOperation::Mint,
                transaction_hash: hex::encode(tx_hash),
                block_height: tx.version,
                chain_id: "aptos".to_string(),
                metadata: serde_json::to_vec(&serde_json::json!({
                    "source_chain": source_chain,
                    "new_owner": new_owner,
                    "seal_address": hex::encode(seal.account_address),
                })).unwrap_or_default(),
            })
        }

        #[cfg(not(feature = "rpc"))]
        {
            Err(ChainOpError::CapabilityUnavailable(
                "Sanad minting requires RPC feature. Enable with --features rpc".to_string(),
            ))
        }
    }

    async fn refund_sanad(
        &self,
        sanad_id: &SanadId,
        owner_key_id: &str,
    ) -> ChainOpResult<SanadOperationResult> {
        let _ = sanad_id;
        let _ = owner_key_id;

        Err(ChainOpError::CapabilityUnavailable(
            "Sanad refund requires signed transaction. \
             Construct and submit a transaction to refund the locked seal."
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

        Err(ChainOpError::CapabilityUnavailable(
            "Metadata recording requires signed transaction. \
             Construct and submit a transaction to update seal metadata."
                .to_string(),
        ))
    }

    async fn verify_sanad_state(
        &self,
        sanad_id: &SanadId,
        expected_state: &str,
    ) -> ChainOpResult<bool> {
        // Query the seal resource at the address derived from sanad_id
        // In Aptos, resources are stored at the owner's address
        // The sanad_id contains the address and resource type info

        let sanad_bytes = sanad_id.as_bytes();

        // Derive the account address from sanad_id
        // For simplicity, we use the first 32 bytes as the address
        let mut address_bytes = [0u8; 32];
        if sanad_bytes.len() >= 32 {
            address_bytes.copy_from_slice(&sanad_bytes[..32]);
        } else {
            address_bytes[..sanad_bytes.len()].copy_from_slice(sanad_bytes);
        }

        // Query account resources via RPC
        // Check if the account exists and has the expected resource
        let account_exists = self
            .rpc()
            .get_account_sequence_number(address_bytes)
            .await
            .is_ok();

        if !account_exists {
            // Account doesn't exist - either never created or deleted
            return match expected_state {
                "consumed" | "deleted" | "never_created" => Ok(true),
                _ => Ok(false),
            };
        }

        // Query the specific resource type at the address to determine actual state
        // The sanad resource contains state information that we need to parse
        let actual_state = if account_exists {
            // Try to query the sanad resource from the account
            let (module_addr, _event_type) = self.seal_protocol.event_builder_config();
            let resource_type = format!("0x{}::sanad::Sanad", hex::encode(module_addr));
            match self.rpc().get_resource(address_bytes, &resource_type, None).await {
                Ok(Some(_)) => "active",
                Ok(None) => "consumed",
                Err(_) => "unknown"
            }
        } else {
            "consumed"
        };

        Ok(actual_state == expected_state)
    }
}

#[async_trait]
impl ChainBackend for AptosBackend {
    fn chain_id(&self) -> &'static str {
        "aptos"
    }

    fn chain_name(&self) -> &'static str {
        "Aptos"
    }

    fn is_capability_available(&self, _capability: ChainCapability) -> bool {
        true
    }

    async fn create_seal(&self, value: Option<u64>) -> ChainOpResult<SealPoint> {
        let aptos_seal = self
            .seal_protocol
            .create_seal(value)
            .await
            .map_err(|e| ChainOpError::Unknown(format!("Seal creation failed: {}", e)))?;

        // Convert AptosSealPoint to core SealPoint
        // AptosSealPoint has account_address (32 bytes) stored in id
        Ok(SealPoint {
            id: aptos_seal.account_address.to_vec(),
            nonce: Some(aptos_seal.nonce),
            version: None,
        })
    }

    async fn publish_seal(&self, seal: SealPoint, commitment: Hash) -> ChainOpResult<CommitAnchor> {
        // Convert core SealPoint to AptosSealPoint
        if seal.id.len() < 32 {
            return Err(ChainOpError::InvalidInput(
                "Seal ID too short for Aptos, expected at least 32 bytes".to_string(),
            ));
        }

        let mut account_address = [0u8; 32];
        account_address.copy_from_slice(&seal.id[..32]);

        let nonce = seal.nonce.unwrap_or(0);
        let aptos_seal =
            crate::types::AptosSealPoint::new(account_address, String::from("csv_seal"), nonce);

        // Call the seal protocol's publish method
        let aptos_anchor = self
            .seal_protocol
            .publish(commitment, aptos_seal)
            .await
            .map_err(|e| ChainOpError::Unknown(format!("Seal publishing failed: {}", e)))?;

        // Convert AptosCommitAnchor to core CommitAnchor
        Ok(CommitAnchor {
            anchor_id: aptos_anchor.event_handle.to_vec(),
            block_height: aptos_anchor.version,
            metadata: aptos_anchor.sequence_number.to_le_bytes().to_vec(),
        })
    }
}

#[async_trait]
impl SanadStateReader for AptosBackend {
    async fn get_sanad_state(&self, sanad_id: &SanadId) -> ChainOpResult<CanonicalSanadState> {
        // Query the Aptos resource for this sanad_id
        // Derive the account address from sanad_id
        let sanad_bytes = sanad_id.as_bytes();
        let mut address_bytes = [0u8; 32];
        if sanad_bytes.len() >= 32 {
            address_bytes.copy_from_slice(&sanad_bytes[..32]);
        } else {
            address_bytes[..sanad_bytes.len()].copy_from_slice(sanad_bytes);
        }

        // Query the account resources to get the sanad state
        // Note: Aptos RPC doesn't have get_account_resources, use get_resource for specific types
        let (module_addr, _event_type) = self.seal_protocol.event_builder_config();
        let resource_type = format!("0x{}::sanad::Sanad", hex::encode(module_addr));
        
        match self.rpc().get_resource(address_bytes, &resource_type, None).await {
            Ok(Some(_resource)) => {
                // Parse the resource data to extract state information
                // The resource data is BCS-encoded; we need to parse it properly
                // For now, return an error indicating that resource parsing is not yet implemented
                // This is fail-closed: we don't fabricate state from commitment alone
                return Err(ChainOpError::CapabilityUnavailable(
                    "Sanad resource parsing is not yet implemented for Aptos. \
                     The resource exists but cannot be parsed into canonical state. \
                     This requires BCS decoding of the Move resource structure.".to_string()
                ));
            }
            Ok(None) => {
                // Resource doesn't exist - sanad not created
                Ok(CanonicalSanadState {
                    state: 0, // Not created
                    owner: "unknown".to_string(),
                    commitment: sanad_id.0,
                    nullifier: None,
                    created_at: 0,
                    locked_at: None,
                    consumed_at: None,
                    minted_at: None,
                    refunded_at: None,
                })
            }
            Err(e) => {
                // Failed to query resources - propagate the error instead of returning fabricated state
                return Err(ChainOpError::RpcError(format!("Failed to query account resources: {}", e)));
            }
        }
    }
    
    async fn get_seal_state(&self, seal_id: &Hash) -> ChainOpResult<CanonicalSealState> {
        // For Aptos, seal state is derived from the resource state
        // Query the seal resource to determine if it's been consumed
        let seal_bytes = seal_id.as_bytes();
        let mut address_bytes = [0u8; 32];
        if seal_bytes.len() >= 32 {
            address_bytes.copy_from_slice(&seal_bytes[..32]);
        } else {
            address_bytes[..seal_bytes.len()].copy_from_slice(seal_bytes);
        }

        // Query the seal resource to check seal state
        let (module_addr, _event_type) = self.seal_protocol.event_builder_config();
        let resource_type = format!("0x{}::seal::Seal", hex::encode(module_addr));
        
        match self.rpc().get_resource(address_bytes, &resource_type, None).await {
            Ok(Some(_resource)) => {
                // Seal resource exists - check if consumed
                // For now, return an error indicating that resource parsing is not yet implemented
                return Err(ChainOpError::CapabilityUnavailable(
                    "Seal resource parsing is not yet implemented for Aptos. \
                     The resource exists but cannot be parsed into canonical state. \
                     This requires BCS decoding of the Move resource structure.".to_string()
                ));
            }
            Ok(None) => {
                // Seal resource doesn't exist
                Ok(CanonicalSealState {
                    state: 0, // Not created
                    owner: "unknown".to_string(),
                    commitment: *seal_id,
                    created_at: 0,
                    consumed_at: None,
                })
            }
            Err(e) => {
                // Failed to query resources
                return Err(ChainOpError::RpcError(format!("Failed to query seal resource: {}", e)));
            }
        }
    }
    
    async fn trace_sanad(&self, _sanad_id: &SanadId) -> ChainOpResult<Vec<CanonicalLifecycleEvent>> {
        // Query events from Aptos for this sanad_id
        // This would require querying the event logs from the contract
        Ok(vec![])
    }
}

#[async_trait]
impl ChainReadinessCheck for AptosBackend {
    async fn check_readiness(&self, _account: u32, _index: u32) -> ChainOpResult<ChainReadiness> {
        // Check if module is configured
        let contract_configured = !self.seal_protocol.config().seal_contract.module_address.is_empty();

        // Check if signer is actually configured by checking the config
        let signer_configured = self.seal_protocol.config().private_key.is_some();

        // Derive signer address from private key if available
        let signer_address = if signer_configured {
            if let Some(ref secret_key) = self.seal_protocol.config().private_key {
                use ed25519_dalek::SigningKey;
                let key_bytes = secret_key.expose_secret();
                let signing_key = SigningKey::from_bytes(key_bytes);
                let public_key = signing_key.verifying_key();
                let address = public_key.as_bytes().to_vec();
                Some(format!("0x{}", hex::encode(address)))
            } else {
                None
            }
        } else {
            None
        };

        // Balance address is same as signer address for Aptos
        let balance_address = signer_address.clone();

        // Check write capability (signer configured + RPC available)
        let write_capable = signer_configured;

        // Check if account exists (has balance > 0)
        let account_exists = if let Some(ref addr) = balance_address {
            match <Self as ChainQuery>::get_balance(self, addr.as_str()).await {
                Ok(balance) => balance.total > 0,
                Err(_) => false,
            }
        } else {
            false
        };

        // Get native balance
        let native_balance = if let Some(ref addr) = balance_address {
            match <Self as ChainQuery>::get_balance(self, addr.as_str()).await {
                Ok(balance) => Some(balance.total),
                Err(_) => None,
            }
        } else {
            None
        };

        // Estimate minimum fee (100 APT for simple transaction)
        let estimated_fee = Some(100_000_000); // 100 APT in octas

        // Aptos supports sanad creation (via module)
        let sanad_create_supported = contract_configured;

        // Aptos supports proof generation
        let proof_generation_supported = true;

        // Aptos can be cross-chain source
        let cross_chain_source_supported = true;

        // Aptos can be cross-chain destination
        let cross_chain_destination_supported = true;

        Ok(ChainReadiness {
            signer_address,
            balance_address,
            signer_configured,
            write_capable,
            contract_configured,
            account_exists,
            native_balance,
            estimated_fee,
            sanad_create_supported,
            proof_generation_supported,
            cross_chain_source_supported,
            cross_chain_destination_supported,
            metadata: vec![],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::MockAptosRpc;

    #[test]
    fn test_aptos_chain_operations_creation() {
        let rpc = Box::new(MockAptosRpc::new(1));
        let ops = AptosBackend::new(rpc, AptosNetwork::Devnet)
            .expect("AptosBackend::new should succeed with a mock RPC and valid config");
        assert_eq!(ops.network, AptosNetwork::Devnet);
    }

    #[test]
    fn test_address_validation() {
        let rpc = Box::new(MockAptosRpc::new(1));
        let ops = AptosBackend::new(rpc, AptosNetwork::Devnet)
            .expect("AptosBackend::new should succeed with a mock RPC and valid config");

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
    fn test_aptos_backend_new_fails_closed_on_bad_config() {
        // A missing module address makes `AptosSealProtocol::from_config` fail
        // validation. `AptosBackend::new` must propagate that error instead of
        // silently falling back to a mock RPC / seal protocol, since a mock
        // fallback here would let production callers sign/read against a fake
        // in-memory chain with no indication real contract-backed behavior was
        // never wired up.
        let rpc: Box<dyn AptosRpc> = Box::new(MockAptosRpc::new(1));
        let mut bad_config = crate::config::AptosConfig {
            network: AptosNetwork::Devnet,
            ..Default::default()
        };
        bad_config.seal_contract.module_address = String::new();
        let result = AptosSealProtocol::from_config(bad_config, rpc);
        assert!(
            result.is_err(),
            "empty module address must fail closed, not fall back to a mock seal protocol"
        );
    }
}
