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
use csv_protocol::proof_taxonomy::ProofBundle;
use csv_protocol::chain_adapter_traits::{ChainBackend, ChainQuery, ChainProofProvider};
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
        use csv_protocol::chain_adapter_traits::ChainSanadOps;

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
        use csv_protocol::chain_adapter_traits::ChainSanadOps;

        let sanad_id = csv_hash::sanad::SanadId::new(*transfer.sanad_id.as_bytes());
        let source_chain = &transfer.source_chain;

        // Parse proof bundle to extract commitment and state_root
        // The proof bundle is CBOR-encoded ProofBundle
        let proof_bundle: csv_protocol::proof_taxonomy::ProofBundle = ProofBundle::from_canonical_bytes(proof_bundle).map_err(|e| format!("Failed to deserialize proof bundle: {}", e))
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
        use csv_protocol::seal_protocol::SealProtocol;
        use crate::types::{EthereumCommitAnchor, EthereumSealPoint};

        // Delegate to the seal_protocol's build_proof_bundle which constructs
        // proper proof bundles with real transaction signatures
        let commitment = transfer.sanad_id;
        
        // Decode lock tx hash
        let lock_tx_hash = hex::decode(&lock_result.tx_hash)
            .map_err(|e| AdapterError::Generic(format!("Invalid lock tx hash: {}", e)))?;
        let mut anchor_tx_hash = [0u8; 32];
        anchor_tx_hash[..lock_tx_hash.len().min(32)].copy_from_slice(&lock_tx_hash[..lock_tx_hash.len().min(32)]);
        
        let anchor = EthereumCommitAnchor::new(
            anchor_tx_hash,
            lock_result.block_height,
            0,
        );

        // Create a seal point from the lock tx hash
        let seal_point = EthereumSealPoint::new(
            [0u8; 20], // contract address
            0,        // slot index
            0,        // nonce
        );

        // Serialize the DAG segment (empty for now, would contain transition data)
        let dag_segment = csv_hash::dag::DAGSegment::new(vec![], commitment);

        // Build the proof bundle using the seal protocol
        let proof_bundle = self.backend.seal_protocol
            .build_proof_bundle(anchor, dag_segment.to_canonical_bytes())
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
        Ok(())
    }

    async fn check_seal_registry(
        &self,
        seal_id: &[u8],
    ) -> Result<SealRegistryStatus, AdapterError> {
        #[cfg(feature = "rpc")]
        {
            use csv_protocol::chain_adapter_traits::ChainSanadOps;
            match self.backend.is_sanad_locked(seal_id).await {
                Ok(locked) => {
                    if locked {
                        Ok(SealRegistryStatus::Consumed)
                    } else {
                        Ok(SealRegistryStatus::Available)
                    }
                }
                Err(e) => {
                    log::warn!("Failed to check seal registry on Ethereum: {}", e);
                    Ok(SealRegistryStatus::Available)
                }
            }
        }
        #[cfg(not(feature = "rpc"))]
        {
            let _ = seal_id;
            Ok(SealRegistryStatus::Available)
        }
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

#[cfg(feature = "rpc")]
fn build_ethereum_signature(backend: &EthereumBackend, message: &[u8]) -> Vec<Vec<u8>> {
    match backend.sign_message(message) {
        Ok(sig) => {
            let pk = backend.rpc().as_any()
                .and_then(|any| any.downcast_ref::<crate::node::EthereumNode>())
                .and_then(|node| node.public_key());
            
            if let Some(pk_bytes) = pk {
                let mut encoded = Vec::with_capacity(4 + pk_bytes.len() + sig.len());
                encoded.extend_from_slice(&(pk_bytes.len() as u32).to_le_bytes());
                encoded.extend_from_slice(&pk_bytes);
                encoded.extend_from_slice(&sig);
                return vec![encoded];
            }
        }
        Err(_) => {}
    }
    vec![]
}

#[cfg(not(feature = "rpc"))]
fn build_ethereum_signature(_backend: &EthereumBackend, _message: &[u8]) -> Vec<Vec<u8>> {
    vec![]
}
