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
use csv_protocol::backend::{ChainBackend, ChainSanadOps, ChainProofProvider, ChainQuery};
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
        // Convert CrossChainTransfer to protocol types
        let sanad_id = csv_protocol::sanad::SanadId::new(*transfer.sanad_id.as_bytes());
        let destination_chain = transfer.destination_chain.as_str();
        let owner_key_id = ""; // TODO: Get from transfer

        let lock_result = self
            .backend
            .lock_sanad(&sanad_id, destination_chain, owner_key_id)
            .await
            .map_err(|e| AdapterError::Generic(format!("Lock failed: {}", e)))?;

        Ok(LockResult {
            tx_hash: hex::encode(lock_result.transaction_hash.as_bytes()),
            block_height: lock_result.block_height,
        })
    }

    async fn mint_sanad(
        &self,
        transfer: &CrossChainTransfer,
        proof_bundle: &[u8],
    ) -> Result<MintResult, AdapterError> {
        // Convert CrossChainTransfer to protocol types
        let source_chain = transfer.source_chain.as_str();
        let sanad_id = csv_protocol::sanad::SanadId::new(*transfer.sanad_id.as_bytes());
        let new_owner = ""; // TODO: Get from transfer

        // Decode proof bundle
        let proof = csv_codec::from_canonical_cbor::<csv_protocol::proof_types::InclusionProof>(proof_bundle)
            .map_err(|e| AdapterError::Generic(format!("Failed to decode proof bundle: {}", e)))?;

        let mint_result = self
            .backend
            .mint_sanad(source_chain, &sanad_id, &proof, new_owner)
            .await
            .map_err(|e| AdapterError::Generic(format!("Mint failed: {}", e)))?;

        Ok(MintResult {
            tx_hash: hex::encode(mint_result.transaction_hash.as_bytes()),
            block_height: mint_result.block_height,
        })
    }

    async fn build_inclusion_proof(
        &self,
        _transfer: &CrossChainTransfer,
        lock_result: &LockResult,
    ) -> Result<ProofBundle, AdapterError> {
        // Decode lock tx hash
        let lock_tx_hash = hex::decode(&lock_result.tx_hash)
            .map_err(|e| AdapterError::Generic(format!("Invalid lock tx hash: {}", e)))?;
        let lock_tx_hash = csv_hash::Hash::try_from(lock_tx_hash.as_slice())
            .map_err(|_| AdapterError::Generic("Invalid lock tx hash length".to_string()))?;

        // Build inclusion proof
        let _inclusion_proof = self
            .backend
            .build_inclusion_proof(&lock_tx_hash, lock_result.block_height, &[])
            .await
            .map_err(|e| AdapterError::Generic(format!("Failed to build inclusion proof: {}", e)))?;

        // Convert to ProofBundle
        // TODO: This is a simplified conversion - need proper ProofBundle construction
        Err(AdapterError::Generic(
            "ProofBundle construction not yet implemented for Ethereum".to_string()
        ))
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
}
