//! Runtime adapter wrapper for Sui chain adapter
//!
//! This module implements the ChainAdapter trait from csv-adapter-core,
//! bridging the Sui-specific implementation with the generic
//! runtime orchestration layer.

use csv_adapter_core::{
    AdapterError, ChainAdapter, LockResult, MintResult, SealRegistryStatus,
    CrossChainTransfer,
};
use csv_protocol::finality::capabilities::{
    ChainCapabilities, StateModel, FinalityModel, ProofModel, 
    ReplayProtectionModel, ReorgRisk, ChainRole
};
use csv_protocol::signature::SignatureScheme;
use csv_protocol::proof_taxonomy::ProofBundle;
use csv_protocol::chain_adapter_traits::ChainBackend;
use std::sync::Arc;

use crate::ops::SuiBackend;

/// Runtime adapter wrapper for Sui
pub struct SuiRuntimeAdapter {
    /// Chain identifier
    chain_id: String,
    /// Chain capabilities
    capabilities: ChainCapabilities,
    /// Signature scheme
    signature_scheme: SignatureScheme,
    /// The underlying ChainBackend implementation
    backend: Arc<SuiBackend>,
}

impl SuiRuntimeAdapter {
    /// Create a new Sui runtime adapter
    pub fn new(backend: Arc<SuiBackend>) -> Self {
        let chain_id = backend.chain_id().to_string();
        let capabilities = ChainCapabilities {
            state_model: StateModel::Object,
            finality_model: FinalityModel::BftInstant,
            finality_depth: 15,
            deterministic_finality: true,
            proof_model: ProofModel::CheckpointMerkle,
            replay_protection: ReplayProtectionModel::ObjectDeleted,
            native_single_use_semantics: true,
            reorg_risk: ReorgRisk::Low,
            max_safe_reorg_depth: 0,
            supports_light_client_proofs: true,
            supports_state_proofs: false,
            supports_transaction_inclusion_proofs: true,
            supports_offline_verification: false,
            supports_zk_proofs: false,
            chain_role: ChainRole::Settlement,
        };
        let signature_scheme = SignatureScheme::Ed25519;

        Self {
            chain_id,
            capabilities,
            signature_scheme,
            backend,
        }
    }
}

#[async_trait::async_trait]
impl ChainAdapter for SuiRuntimeAdapter {
    fn chain_id(&self) -> &str {
        &self.chain_id
    }

    fn capabilities(&self) -> ChainCapabilities {
        self.capabilities.clone()
    }

    fn signature_scheme(&self) -> SignatureScheme {
        self.signature_scheme
    }

    async fn lock_sanad(
        &self,
        transfer: &CrossChainTransfer,
    ) -> Result<LockResult, AdapterError> {
        // Use the backend's lock_sanad method which properly constructs and signs the transaction
        use csv_protocol::chain_adapter_traits::ChainSanadOps;

        let sanad_id = csv_hash::sanad::SanadId::new(*transfer.sanad_id.as_bytes());
        let destination_chain = &transfer.destination_chain;

        let result = self.backend
            .lock_sanad(&sanad_id, destination_chain, "0x0000000000000000000000000000000000000000000000000000000000000000")
            .await
            .map_err(|e| AdapterError::Generic(format!("Failed to lock sanad: {}", e)))?;

        // Extract tx_hash and block_height from the result
        let tx_hash = result.transaction_hash;
        let block_height = result.block_height;

        Ok(LockResult {
            tx_hash,
            block_height,
        })
    }

    async fn mint_sanad(
        &self,
        transfer: &CrossChainTransfer,
        proof_bundle: &[u8],
    ) -> Result<MintResult, AdapterError> {
        // Use the backend's mint_sanad method which properly constructs and signs the transaction
        use csv_protocol::chain_adapter_traits::ChainSanadOps;

        let sanad_id = csv_hash::sanad::SanadId::new(*transfer.sanad_id.as_bytes());
        let source_chain = &transfer.source_chain;

        // Parse proof bundle to extract needed fields
        let proof_bundle: csv_protocol::proof_taxonomy::ProofBundle = csv_hash::canonical::from_canonical_cbor(proof_bundle)
            .map_err(|e| AdapterError::Generic(format!("Failed to decode proof bundle: {}", e)))?;

        // Extract commitment from anchor_ref (anchor_id is Vec<u8>, need to convert to [u8; 32])
        let mut commitment_bytes = [0u8; 32];
        let len = proof_bundle.anchor_ref.anchor_id.len().min(32);
        commitment_bytes[..len].copy_from_slice(&proof_bundle.anchor_ref.anchor_id[..len]);
        let _commitment = csv_hash::Hash::new(commitment_bytes);

        // Use the inclusion_proof directly
        let inclusion_proof = &proof_bundle.inclusion_proof;

        let result = self.backend
            .mint_sanad(source_chain, &sanad_id, inclusion_proof, "0x0000000000000000000000000000000000000000000000000000000000000000")
            .await
            .map_err(|e| AdapterError::Generic(format!("Failed to mint sanad: {}", e)))?;

        // Extract tx_hash and block_height from the result (these are not Option types)
        let tx_hash = result.transaction_hash;
        let block_height = result.block_height;

        Ok(MintResult {
            tx_hash,
            block_height,
        })
    }

    async fn build_inclusion_proof(
        &self,
        transfer: &CrossChainTransfer,
        lock_result: &LockResult,
    ) -> Result<ProofBundle, AdapterError> {
        // Decode lock tx hash
        let lock_tx_hash = hex::decode(&lock_result.tx_hash)
            .map_err(|e| AdapterError::Generic(format!("Invalid lock tx hash: {}", e)))?;
        let lock_tx_hash = csv_hash::Hash::try_from(lock_tx_hash.as_slice())
            .map_err(|_| AdapterError::Generic("Invalid lock tx hash length".to_string()))?;

        // Build inclusion proof using the backend
        use csv_protocol::chain_adapter_traits::ChainProofProvider;

        let inclusion_proof = self.backend
            .build_inclusion_proof(&transfer.sanad_id, lock_result.block_height, lock_tx_hash.as_bytes())
            .await
            .map_err(|e| AdapterError::Generic(format!("Failed to build inclusion proof: {}", e)))?;

        // Convert to ProofBundle - need to construct it properly
        // For now, return a minimal ProofBundle with the inclusion proof
        use csv_protocol::proof_taxonomy::{FinalityProof};
        use csv_hash::seal::{CommitAnchor, SealPoint};

        let seal_point = SealPoint::new(vec![0u8; 32], Some(0), None)
            .map_err(|e| AdapterError::Generic(format!("Failed to create seal point: {}", e)))?;
        let commit_anchor = CommitAnchor::new(
            lock_tx_hash.as_bytes().to_vec(),
            lock_result.block_height,
            vec![],
        ).map_err(|e| AdapterError::Generic(format!("Failed to create commit anchor: {}", e)))?;

        // Create a canonical ProofLeafV1 for this transfer
        use csv_protocol::proof_taxonomy::ProofLeafV1;
        let proof_leaf = ProofLeafV1::new(
            transfer.source_chain.clone(),
            transfer.destination_chain.clone(),
            transfer.sanad_id,
            lock_tx_hash, // Use the lock transaction hash as commitment
        );
        let leaf_hash = proof_leaf.hash()
            .map_err(|e| AdapterError::Generic(format!("Failed to compute proof leaf hash: {}", e)))?;

        // Create a minimal DAG with one node using the canonical proof leaf hash
        let root_commitment = csv_hash::Hash::new([9u8; 32]);
        let node = csv_hash::dag::DAGNode::new(
            leaf_hash,
            vec![],
            vec![],
            vec![],
            vec![],
        );
        
        Ok(ProofBundle {
            version: 1,
            transition_dag: csv_hash::dag::DAGSegment::new(vec![node], root_commitment),
            signatures: vec![],
            signature_scheme: csv_protocol::signature::SignatureScheme::Ed25519,
            seal_ref: seal_point,
            anchor_ref: commit_anchor,
            inclusion_proof: inclusion_proof,
            finality_proof: FinalityProof::default(),
        })
    }

    async fn validate_source_proof(
        &self,
        _transfer: &CrossChainTransfer,
        _proof_bundle: &ProofBundle,
    ) -> Result<(), AdapterError> {
        // Validate source chain proof
        // This is a simplified stub implementation
        // TODO: Implement actual Sui proof validation logic
        Err(AdapterError::Generic("Sui proof validation not implemented yet".to_string()))
    }

    async fn check_seal_registry(&self, _seal_id: &[u8]) -> Result<SealRegistryStatus, AdapterError> {
        // Verify seal registry status on Sui
        // This is a simplified stub implementation
        // TODO: Implement actual Sui seal registry verification
        Err(AdapterError::Generic("Sui seal registry verification not implemented yet".to_string()))
    }

    async fn get_balance(&self, _address: &str) -> Result<String, AdapterError> {
        // Get balance for an address on Sui
        // This is a simplified stub implementation
        // TODO: Implement actual Sui balance query logic
        Err(AdapterError::Generic("Sui balance query not implemented yet".to_string()))
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
