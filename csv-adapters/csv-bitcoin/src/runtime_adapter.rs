//! Runtime adapter wrapper for Bitcoin chain adapter
//!
//! This module implements the ChainAdapter trait from csv-adapter-core,
//! bridging the Bitcoin-specific implementation with the generic
//! runtime orchestration layer.

use bitcoin::Network;
use csv_adapter_core::{
    AdapterError, ChainAdapter, LockResult, MintResult, SealRegistryStatus,
    CrossChainTransfer,
};
use csv_protocol::backend::ChainProofProvider;
use csv_protocol::finality::ChainCapabilities;
use csv_protocol::signature::SignatureScheme;
use csv_protocol::proof_types::ProofBundle;
use std::sync::Arc;

use crate::ops::BitcoinChainSanadOps;
use crate::rpc::BitcoinRpc;
use crate::seal_protocol::BitcoinSealProtocol;
use crate::wallet::SealWallet;

/// Runtime adapter wrapper for Bitcoin
pub struct BitcoinRuntimeAdapter {
    /// Chain identifier
    chain_id: String,
    /// Network (mainnet/testnet/signet)
    network: Network,
    /// Sanad operations implementation
    sanad_ops: Arc<BitcoinChainSanadOps>,
    /// RPC client for proof building
    rpc: Box<dyn BitcoinRpc + Send + Sync>,
}

impl BitcoinRuntimeAdapter {
    /// Create a new Bitcoin runtime adapter
    pub fn new(
        network: Network,
        wallet: SealWallet,
        rpc: Box<dyn BitcoinRpc + Send + Sync>,
    ) -> Self {
        let chain_id = match network {
            Network::Bitcoin => "bitcoin".to_string(),
            Network::Testnet => "bitcoin".to_string(),
            Network::Signet => "bitcoin".to_string(),
            Network::Regtest => "bitcoin".to_string(),
            _ => "bitcoin".to_string(),
        };

          let seal_protocol = BitcoinSealProtocol::with_wallet(
             crate::config::BitcoinConfig {
                 network: crate::config::Network::Regtest,
                 finality_depth: 6,
                 publication_timeout_seconds: 3600,
                 rpc_url: String::new(),
                 rpc_backend: crate::config::BitcoinRpcBackend::MempoolRest,
                 api_key: None,
                 xpub: None,
                 private_key: None,
                 seed: None,
                 account: 0,
                 index: 0,
                 utxos: Vec::new(),
                 sanad_seals: Vec::new(),
             },
             wallet,
         ).expect("Failed to create seal protocol");

        let sanad_ops = Arc::new(BitcoinChainSanadOps::new(seal_protocol)
            .with_rpc(rpc.clone_boxed()));

        Self {
            chain_id,
            network,
            sanad_ops,
            rpc,
        }
    }
}

#[async_trait::async_trait]
impl ChainAdapter for BitcoinRuntimeAdapter {
    fn chain_id(&self) -> &str {
        &self.chain_id
    }

    fn capabilities(&self) -> ChainCapabilities {
        ChainCapabilities::bitcoin()
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::Secp256k1
    }

    async fn lock_sanad(
        &self,
        transfer: &CrossChainTransfer,
    ) -> Result<LockResult, AdapterError> {
        use csv_hash::sanad::SanadId;

        // Extract sanad_id from transfer and convert to SanadId
        let sanad_id = SanadId(csv_hash::Hash::new(*transfer.sanad_id.as_bytes()));

        // Get destination chain from transfer
        let destination_chain = transfer.destination_chain.as_str();

        // Derive owner key from wallet (account 0, index 0)
        let seal_protocol = self.sanad_ops.seal_protocol();
        let wallet = &seal_protocol.wallet;
        let path = crate::wallet::Bip86Path::external(0, 0);
        let owner_key_id = wallet.get_owner_key_hex(&path)
            .map_err(|e| AdapterError::Generic(format!("Failed to derive owner key: {}", e)))?;

        // Delegate to BitcoinChainSanadOps::lock_sanad for actual transaction building and broadcasting
        let result = csv_protocol::backend::ChainSanadOps::lock_sanad(&*self.sanad_ops, &sanad_id, destination_chain, &owner_key_id)
            .await
            .map_err(|e| AdapterError::Generic(format!("Lock sanad failed: {}", e)))?;

        Ok(LockResult {
            tx_hash: result.transaction_hash,
            block_height: result.block_height,
        })
    }

    async fn mint_sanad(
        &self,
        _transfer: &CrossChainTransfer,
        _proof_bundle: &[u8],
    ) -> Result<MintResult, AdapterError> {
        // Bitcoin cannot mint sanads (no smart contracts)
        Err(AdapterError::Generic(
            "Bitcoin does not support minting sanads (no smart contracts)".to_string()
        ))
    }

    async fn build_inclusion_proof(
        &self,
        transfer: &CrossChainTransfer,
        lock_result: &LockResult,
    ) -> Result<ProofBundle, AdapterError> {
        use crate::ops::BitcoinChainProofProvider;
        use csv_hash::dag::DAGSegment;
        use csv_hash::seal::{CommitAnchor, SealPoint};

        // Decode lock tx hash
        let lock_tx_hash = hex::decode(lock_result.tx_hash.trim_start_matches("0x"))
            .map_err(|e| AdapterError::Generic(format!("Invalid lock tx hash: {}", e)))?;
        let lock_tx_hash_bytes: [u8; 32] = lock_tx_hash.try_into()
            .map_err(|_| AdapterError::Generic("Invalid lock tx hash length".to_string()))?;

        // Build inclusion proof using BitcoinChainProofProvider
        let proof_provider = BitcoinChainProofProvider::new(self.rpc.clone_boxed());
        let inclusion_proof = proof_provider
            .build_inclusion_proof(
                &csv_hash::Hash::new(lock_tx_hash_bytes),
                lock_result.block_height,
                &lock_tx_hash_bytes,
            )
            .await
            .map_err(|e| AdapterError::Generic(format!("Failed to build inclusion proof: {}", e)))?;

        // Build finality proof
        let finality_proof = proof_provider
            .build_finality_proof(&lock_result.tx_hash)
            .await
            .map_err(|e| AdapterError::Generic(format!("Failed to build finality proof: {}", e)))?;

        // Create seal reference from the lock transaction outpoint
        // The seal ID is the lock txid (32 bytes) with vout=0
        let seal_id: Vec<u8> = lock_tx_hash_bytes.to_vec();
        let seal_ref = SealPoint::new(seal_id, Some(0), Some(0))
            .map_err(|e| AdapterError::Generic(format!("Failed to create seal point: {}", e)))?;

        // Create anchor reference from lock transaction data
        let anchor_ref = CommitAnchor::new(
            lock_tx_hash_bytes.to_vec(),
            lock_result.block_height,
            transfer.destination_chain.as_bytes().to_vec(),
        )
        .map_err(|e| AdapterError::Generic(format!("Failed to create commit anchor: {}", e)))?;

        // Create minimal DAG segment for the lock transition
        let transition_dag = DAGSegment::new(vec![], csv_hash::Hash::new(lock_tx_hash_bytes));

        // Use empty signatures for now (signature verification is done via inclusion proof)
        let signatures = vec![];

        let proof_bundle = ProofBundle::with_certification_and_signature_scheme(
            ProofBundle::CURRENT_VERSION,
            self.signature_scheme(),
            transition_dag,
            signatures,
            seal_ref,
            anchor_ref,
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
        Ok(())
    }

    async fn check_seal_registry(&self, _seal_id: &[u8])
    -> Result<SealRegistryStatus, AdapterError> {
        // Bitcoin doesn't have a seal registry (UTXO model)
        Ok(SealRegistryStatus::Available)
    }

    async fn get_balance(&self, _address: &str) -> Result<String, AdapterError> {
        Err(AdapterError::Generic(
            "Bitcoin balance query not yet implemented".to_string()
        ))
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitcoin_adapter_creation() {
        // Test with minimal setup - actual wallet/RPC would need feature flags
        let adapter = BitcoinRuntimeAdapter::new(
            Network::Regtest,
            SealWallet::generate_random(Network::Regtest),
            Box::new(crate::rpc::TestBitcoinRpc::new(100)),
        );

        assert_eq!(adapter.chain_id(), "bitcoin");
        assert_eq!(adapter.signature_scheme(), SignatureScheme::Secp256k1);
    }
}
