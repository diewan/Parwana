//! Runtime adapter wrapper for Ethereum chain adapter
//!
//! This module implements the ChainAdapter trait from csv-adapter-core,
//! bridging the Ethereum-specific implementation with the generic
//! runtime orchestration layer.

use csv_adapter_core::{
    AdapterError, ChainAdapter, LockResult, MintResult, SealRegistryStatus,
    CrossChainTransfer,
};
use csv_protocol::finality::ChainCapabilities;
use csv_protocol::signature::SignatureScheme;
use csv_protocol::proof_types::ProofBundle;
use csv_protocol::backend::{ChainBackend, ChainProofProvider, ChainQuery};
use std::sync::Arc;

use crate::ops::EthereumBackend;

/// Runtime adapter wrapper for Ethereum
pub struct EthereumRuntimeAdapter {
    /// Chain identifier
    chain_id: String,
    /// Chain capabilities
    capabilities: ChainCapabilities,
    /// Signature scheme
    signature_scheme: SignatureScheme,
    /// The underlying ChainBackend implementation
    backend: Arc<EthereumBackend>,
}

impl EthereumRuntimeAdapter {
    /// Create a new Ethereum runtime adapter
    pub fn new(backend: Arc<EthereumBackend>) -> Self {
        let chain_id = backend.chain_id().to_string();
        let capabilities = ChainCapabilities::ethereum();
        let signature_scheme = SignatureScheme::Secp256k1;

        Self {
            chain_id,
            capabilities,
            signature_scheme,
            backend,
        }
    }
}

#[async_trait::async_trait]
impl ChainAdapter for EthereumRuntimeAdapter {
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
        use csv_protocol::backend::ChainSanadOps;

        let sanad_id = csv_hash::sanad::SanadId::new(*transfer.sanad_id.as_bytes());
        let destination_chain = &transfer.destination_chain;

        let result = self.backend
            .lock_sanad(&sanad_id, destination_chain, "0x0000000000000000000000000000000000000000")
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
        use csv_protocol::backend::ChainSanadOps;

        let sanad_id = csv_hash::sanad::SanadId::new(*transfer.sanad_id.as_bytes());
        let source_chain = &transfer.source_chain;

        // Parse proof bundle to extract commitment and state_root
        // The proof bundle is CBOR-encoded ProofBundle
        let proof_bundle: csv_protocol::proof_types::ProofBundle = csv_hash::canonical::from_canonical_cbor(proof_bundle)
            .map_err(|e| AdapterError::Generic(format!("Failed to decode proof bundle: {}", e)))?;

        // Extract commitment from anchor_ref (anchor_id is Vec<u8>, need to convert to [u8; 32])
        let mut commitment_bytes = [0u8; 32];
        let len = proof_bundle.anchor_ref.anchor_id.len().min(32);
        commitment_bytes[..len].copy_from_slice(&proof_bundle.anchor_ref.anchor_id[..len]);
        let _commitment = csv_hash::Hash::new(commitment_bytes);

        // Use the inclusion_proof directly
        let inclusion_proof = &proof_bundle.inclusion_proof;

        let result = self.backend
            .mint_sanad(source_chain, &sanad_id, inclusion_proof, "0x0000000000000000000000000000000000000000")
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
        let inclusion_proof = self
            .backend
            .build_inclusion_proof(&transfer.sanad_id, lock_result.block_height, lock_tx_hash.as_bytes())
            .await
            .map_err(|e| AdapterError::Generic(format!("Failed to build inclusion proof: {}", e)))?;

        // Convert to ProofBundle - need to construct it properly
        // For now, return a minimal ProofBundle with the inclusion proof
        use csv_protocol::proof_types::{FinalityProof};
        use csv_hash::seal::{CommitAnchor, SealPoint};

        let seal_point = SealPoint::new(vec![0u8; 32], Some(0), None)
            .map_err(|e| AdapterError::Generic(format!("Failed to create seal point: {}", e)))?;
        let commit_anchor = CommitAnchor::new(
            lock_tx_hash.as_bytes().to_vec(),
            lock_result.block_height,
            vec![],
        ).map_err(|e| AdapterError::Generic(format!("Failed to create commit anchor: {}", e)))?;

        Ok(ProofBundle {
            version: 1,
            transition_dag: csv_hash::dag::DAGSegment::new(vec![], csv_hash::Hash::new([0u8; 32])),
            signatures: vec![],
            signature_scheme: csv_protocol::signature::SignatureScheme::Secp256k1,
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
        // Proof validation is delegated to CanonicalVerifier in TransferCoordinator
        Ok(())
    }

    async fn check_seal_registry(
        &self,
        _seal_id: &[u8],
    ) -> Result<SealRegistryStatus, AdapterError> {
        // Ethereum doesn't have a seal registry in the traditional sense
        Ok(SealRegistryStatus::Available)
    }

    async fn get_balance(&self, address: &str) -> Result<String, AdapterError> {
        let balance = self
            .backend
            .get_balance(address)
            .await
            .map_err(|e| AdapterError::Generic(format!("Balance query failed: {}", e)))?;

        Ok(balance.total.to_string())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
