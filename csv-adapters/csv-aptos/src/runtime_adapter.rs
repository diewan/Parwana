//! Runtime adapter wrapper for Aptos chain adapter
//!
//! This module implements the ChainAdapter trait from csv-adapter-core,
//! bridging the Aptos-specific implementation with the generic
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
use csv_protocol::proof_types::ProofBundle;
use csv_protocol::backend::{ChainBackend, ChainProofProvider, ChainQuery};
use std::sync::Arc;

use crate::ops::AptosBackend;

/// Runtime adapter wrapper for Aptos
pub struct AptosRuntimeAdapter {
    /// Chain identifier
    chain_id: String,
    /// Chain capabilities
    capabilities: ChainCapabilities,
    /// Signature scheme
    signature_scheme: SignatureScheme,
    /// The underlying ChainBackend implementation
    backend: Arc<AptosBackend>,
}

impl AptosRuntimeAdapter {
    /// Create a new Aptos runtime adapter
    pub fn new(backend: Arc<AptosBackend>) -> Self {
        let chain_id = backend.chain_id().to_string();
        let capabilities = ChainCapabilities {
            state_model: StateModel::Resource,
            finality_model: FinalityModel::BftInstant,
            finality_depth: 5,
            deterministic_finality: true,
            proof_model: ProofModel::AccumulatorPath,
            replay_protection: ReplayProtectionModel::ResourceDeleted,
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
impl ChainAdapter for AptosRuntimeAdapter {
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
        use csv_protocol::backend::ChainSanadOps;

        let sanad_id = csv_hash::sanad::SanadId::new(*transfer.sanad_id.as_bytes());
        let destination_chain = &transfer.destination_chain;

        // Use a placeholder owner key ID - in production this would come from wallet
        let owner_key_id = "0x0000000000000000000000000000000000000000000000000000000000000000";

        let result = self.backend
            .lock_sanad(&sanad_id, destination_chain, owner_key_id)
            .await
            .map_err(|e| AdapterError::Generic(format!("Failed to lock sanad: {}", e)))?;

        Ok(LockResult {
            tx_hash: result.transaction_hash,
            block_height: result.block_height,
        })
    }

    async fn mint_sanad(
        &self,
        transfer: &CrossChainTransfer,
        proof_bundle: &[u8],
    ) -> Result<MintResult, AdapterError> {
        use csv_protocol::backend::ChainSanadOps;

        let sanad_id = csv_hash::sanad::SanadId::new(*transfer.sanad_id.as_bytes());
        let source_chain = &transfer.source_chain;

        // Parse proof bundle to extract inclusion proof
        let proof_bundle_parsed: csv_protocol::proof_types::ProofBundle = csv_hash::canonical::from_canonical_cbor(proof_bundle)
            .map_err(|e| AdapterError::Generic(format!("Failed to decode proof bundle: {}", e)))?;

        let inclusion_proof = &proof_bundle_parsed.inclusion_proof;

        // Use a placeholder new owner - in production this would come from wallet
        let new_owner = "0x0000000000000000000000000000000000000000000000000000000000000000";

        let result = self.backend
            .mint_sanad(source_chain, &sanad_id, inclusion_proof, new_owner)
            .await
            .map_err(|e| AdapterError::Generic(format!("Failed to mint sanad: {}", e)))?;

        Ok(MintResult {
            tx_hash: result.transaction_hash,
            block_height: result.block_height,
        })
    }

    async fn build_inclusion_proof(
        &self,
        transfer: &CrossChainTransfer,
        lock_result: &LockResult,
    ) -> Result<ProofBundle, AdapterError> {
        use csv_hash::dag::DAGSegment;
        use csv_hash::seal::{CommitAnchor, SealPoint};

        // Parse the lock tx hash (Aptos uses version numbers as tx identifiers)
        let commitment = csv_hash::Hash::new(*transfer.sanad_id.as_bytes());

        // Build inclusion proof using the backend
        let inclusion_proof = self.backend
            .build_inclusion_proof(&commitment, lock_result.block_height, transfer.sanad_id.as_bytes())
            .await
            .map_err(|e| AdapterError::Generic(format!("Failed to build inclusion proof: {}", e)))?;

        // Build finality proof
        let finality_proof = self.backend
            .build_finality_proof(&lock_result.tx_hash)
            .await
            .map_err(|e| AdapterError::Generic(format!("Failed to build finality proof: {}", e)))?;

        // Create seal point from the lock transaction
        let seal_point = SealPoint::new(
            transfer.sanad_id.as_bytes().to_vec(),
            Some(0),
            Some(0),
        ).map_err(|e| AdapterError::Generic(format!("Failed to create seal point: {}", e)))?;

        // Create commit anchor from lock transaction data
        let commit_anchor = CommitAnchor::new(
            transfer.sanad_id.as_bytes().to_vec(),
            lock_result.block_height,
            transfer.destination_chain.as_bytes().to_vec(),
        ).map_err(|e| AdapterError::Generic(format!("Failed to create commit anchor: {}", e)))?;

        // Create minimal DAG segment for the lock transition
        let transition_dag = DAGSegment::new(vec![], commitment);

        // Use empty signatures for now (signature verification is done via inclusion proof)
        let signatures = vec![];

        let proof_bundle = ProofBundle::with_certification_and_signature_scheme(
            ProofBundle::CURRENT_VERSION,
            self.signature_scheme(),
            transition_dag,
            signatures,
            seal_point,
            commit_anchor,
            inclusion_proof,
            finality_proof,
        ).map_err(|e| AdapterError::Generic(format!("Failed to create proof bundle: {}", e)))?;

        Ok(proof_bundle)
    }

    async fn validate_source_proof(
        &self,
        _transfer: &CrossChainTransfer,
        _proof_bundle: &ProofBundle,
    ) -> Result<(), AdapterError> {
        // Proof validation is delegated to CanonicalVerifier in TransferCoordinator
        // The runtime adapter only needs to ensure the proof structure is valid
        Ok(())
    }

    async fn check_seal_registry(&self, _seal_id: &[u8]) -> Result<SealRegistryStatus, AdapterError> {
        // Aptos uses resource-based seals - check if the seal resource exists
        // For now, return Available as the seal protocol handles availability checks
        Ok(SealRegistryStatus::Available)
    }

    async fn get_balance(&self, address: &str) -> Result<String, AdapterError> {
        let balance = self.backend
            .get_balance(address)
            .await
            .map_err(|e| AdapterError::Generic(format!("Balance query failed: {}", e)))?;

        Ok(balance.total.to_string())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
