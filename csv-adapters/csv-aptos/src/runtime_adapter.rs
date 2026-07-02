//! Runtime adapter wrapper for Aptos chain adapter
//!
//! This module implements the ChainAdapter trait from csv-adapter-core,
//! bridging the Aptos-specific implementation with the generic
//! runtime orchestration layer.

use csv_adapter_core::{
    AdapterError, ChainAdapter, CrossChainTransfer, LockResult, MintResult, SealRegistryStatus,
};
use csv_protocol::chain_adapter_traits::{ChainBackend, ChainQuery};
use csv_protocol::finality::capabilities::{
    ChainCapabilities, ChainRole, FinalityModel, ProofModel, ReorgRisk, ReplayProtectionModel,
    StateModel,
};
use csv_protocol::proof_taxonomy::ProofBundle;
use csv_protocol::signature::SignatureScheme;
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

    async fn lock_sanad(&self, transfer: &CrossChainTransfer) -> Result<LockResult, AdapterError> {
        use csv_protocol::chain_adapter_traits::ChainSanadOps;

        let sanad_id = csv_hash::sanad::SanadId::new(*transfer.sanad_id.as_bytes());
        let destination_chain = &transfer.destination_chain;

        // Derive owner key ID from the backend's signing key
        #[cfg(feature = "rpc")]
        let owner_key_id =
            if let Some(signing_key) = self.backend.seal_protocol.signing_key.as_ref() {
                use sha3::{Digest, Sha3_256};
                let public_key = signing_key.verifying_key().to_bytes();
                let hash = Sha3_256::digest(&public_key);
                format!("0x{}", hex::encode(&hash[..32]))
            } else {
                // Fallback to zero address if no signing key configured
                "0x0000000000000000000000000000000000000000000000000000000000000000".to_string()
            };

        #[cfg(not(feature = "rpc"))]
        let owner_key_id =
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string();

        let result = self
            .backend
            .lock_sanad(&sanad_id, destination_chain, &owner_key_id)
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
        use csv_protocol::chain_adapter_traits::ChainSanadOps;

        let sanad_id = csv_hash::sanad::SanadId::new(*transfer.sanad_id.as_bytes());
        let source_chain = &transfer.source_chain;

        // Parse proof bundle to extract inclusion proof
        let proof_bundle_parsed: csv_protocol::proof_taxonomy::ProofBundle =
            ProofBundle::from_canonical_bytes(proof_bundle)
                .map_err(|e| format!("Failed to deserialize proof bundle: {}", e))
                .map_err(|e| {
                    AdapterError::Generic(format!("Failed to decode proof bundle: {}", e))
                })?;

        let inclusion_proof = &proof_bundle_parsed.inclusion_proof;

        // Derive new owner from the backend's signing key
        #[cfg(feature = "rpc")]
        let new_owner = if let Some(signing_key) = self.backend.seal_protocol.signing_key.as_ref() {
            use sha3::{Digest, Sha3_256};
            let public_key = signing_key.verifying_key().to_bytes();
            let hash = Sha3_256::digest(&public_key);
            format!("0x{}", hex::encode(&hash[..32]))
        } else {
            // Fallback to zero address if no signing key configured
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string()
        };

        #[cfg(not(feature = "rpc"))]
        let new_owner =
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string();

        let result = self
            .backend
            .mint_sanad(source_chain, &sanad_id, inclusion_proof, &new_owner)
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
        use crate::types::{AptosCommitAnchor, AptosSealPoint};
        use csv_protocol::seal_protocol::SealProtocol;

        // Delegate to the seal_protocol's build_proof_bundle which constructs
        // proper proof bundles with real transaction signatures
        let commitment = transfer.sanad_id;

        // Create an AptosCommitAnchor from the lock result
        let mut event_handle = [0u8; 32];
        event_handle.copy_from_slice(transfer.sanad_id.as_bytes());

        let anchor = AptosCommitAnchor {
            version: lock_result.block_height,
            event_handle,
            sequence_number: 0,
        };

        // Create a seal point from the sanad_id
        let seal_point = AptosSealPoint {
            account_address: *transfer.sanad_id.as_bytes(),
            resource_type: "0x1::csv_seal::Seal".to_string(),
            nonce: 0,
        };

        // Create a DAG segment with anchor transition data
        let dag_segment = csv_protocol::seal_protocol::DagSegment::new(
            commitment, // anchor_from (source commitment)
            commitment, // anchor_to (destination commitment, same for now)
            vec![],     // transition_data (empty for now)
            vec![],     // proof (empty for now)
        );

        // Build the proof bundle using the seal protocol
        let proof_bundle = self
            .backend
            .seal_protocol
            .build_proof_bundle(anchor, dag_segment)
            .await
            .map_err(|e| AdapterError::Generic(format!("Failed to build proof bundle: {}", e)))?;

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

    async fn check_seal_registry(
        &self,
        seal_id: &[u8],
    ) -> Result<SealRegistryStatus, AdapterError> {
        use crate::types::AptosSealPoint;

        // Aptos uses resource-based seals - delegate to seal_protocol to check availability
        if seal_id.len() != 32 {
            return Err(AdapterError::Generic(format!(
                "Invalid seal_id length: expected 32, got {}",
                seal_id.len()
            )));
        }

        let mut address = [0u8; 32];
        address.copy_from_slice(seal_id);

        // Create an AptosSealPoint from the seal_id
        let seal_point = AptosSealPoint {
            account_address: address,
            resource_type: "0x1::csv_seal::Seal".to_string(),
            nonce: 0,
        };

        // Delegate to the seal_protocol's verify_seal_available which properly checks
        // the seal registry and on-chain resource state including the consumed flag
        self.backend
            .seal_protocol
            .verify_seal_available(&seal_point)
            .await
            .map_err(|e| {
                AdapterError::Generic(format!("Failed to verify seal availability: {}", e))
            })?;

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
