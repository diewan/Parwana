//! Runtime adapter wrapper for Bitcoin chain adapter
//!
//! This module implements the ChainAdapter trait from csv-adapter-core,
//! bridging the Bitcoin-specific implementation with the generic
//! runtime orchestration layer.

use bitcoin::Network;
use bitcoin_hashes::Hash;
use csv_adapter_core::{
    AdapterError, ChainAdapter, LockResult, MintResult, SealRegistryStatus,
    CrossChainTransfer,
};
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
            },
            wallet,
        ).expect("Failed to create seal protocol");

        let sanad_ops = Arc::new(BitcoinChainSanadOps::new(seal_protocol)
            .with_rpc(rpc));

        Self {
            chain_id,
            network,
            sanad_ops,
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
        // For Bitcoin, locking means creating a lock transaction
        // that spends the commitment UTXO to an OP_RETURN output with the destination hash
        
        // Parse the lock_tx_hash from transfer to get the commitment UTXO
        let txid_bytes = transfer.lock_tx_hash.clone();
        if txid_bytes.len() != 32 {
            return Err(AdapterError::Generic(format!(
                "Invalid lock_tx_hash: expected 32 bytes, got {}",
                txid_bytes.len()
            )));
        }

        // Build the lock transaction using BitcoinChainSanadOps
        let mut txid_array = [0u8; 32];
        txid_array.copy_from_slice(&txid_bytes);
        
        let outpoint = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_raw_hash(bitcoin_hashes::sha256d::Hash::from_byte_array(txid_array)),
            vout: transfer.lock_output_index,
        };

        // Create destination hash from sanad_id (for cross-chain proof)
        let dest_hash = bitcoin_hashes::sha256d::Hash::from_slice(
            &transfer.sanad_id.as_bytes()[..32]
        ).map_err(|_| AdapterError::Generic("Failed to create destination hash".to_string()))?;

        // Build lock transaction
        let lock_tx = self.sanad_ops.build_lock_transaction(
            outpoint,
            &dest_hash,
            &[], // owner_key not needed for Bitcoin
        ).map_err(|e| AdapterError::Generic(format!("Failed to build lock tx: {}", e)))?;

        // Sign and broadcast
        let txid = self.sanad_ops.sign_and_broadcast_lock(lock_tx, &[])
            .await
            .map_err(|e| AdapterError::Generic(format!("Failed to broadcast lock tx: {}", e)))?;

        // TODO: Get actual block height from RPC - for now use placeholder
        let block_height = 0;

        Ok(LockResult {
            tx_hash: txid,
            block_height,
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
        _transfer: &CrossChainTransfer,
        _lock_result: &LockResult,
    ) -> Result<ProofBundle, AdapterError> {
        // ProofBundle construction requires complex DAG segment and inclusion proof
        Err(AdapterError::Generic(
            "ProofBundle construction not yet implemented for Bitcoin".to_string()
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
            Box::new(crate::rpc::MockRpc::new()),
        );
        
        assert_eq!(adapter.chain_id(), "bitcoin");
        assert_eq!(adapter.signature_scheme(), SignatureScheme::Secp256k1);
    }
}
