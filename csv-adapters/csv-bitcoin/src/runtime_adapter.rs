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
use csv_protocol::chain_adapter_traits::ChainProofProvider;
use csv_protocol::finality::ChainCapabilities;
use csv_protocol::signature::SignatureScheme;
use csv_protocol::proof_taxonomy::ProofBundle;
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
    /// Seal protocol for proof bundle construction
    seal_protocol: Arc<BitcoinSealProtocol>,
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

        let seal_protocol = Arc::new(seal_protocol);
        let sanad_ops = Arc::new(BitcoinChainSanadOps::from_arc(Arc::clone(&seal_protocol))
            .with_rpc(rpc.clone_boxed()));

        Self {
            chain_id,
            network,
            sanad_ops,
            rpc,
            seal_protocol,
        }
    }

    /// Create a BitcoinRuntimeAdapter from an already-configured BitcoinSealProtocol.
    /// Use this in the factory so that the ChainAdapter shares the same seal wallet
    /// (and its registered sanad_seals) as the ChainBackend.
    pub fn from_seal_protocol(
        network: Network,
        seal: Arc<BitcoinSealProtocol>,
        rpc: Box<dyn BitcoinRpc + Send + Sync>,
    ) -> Self {
        let chain_id = match network {
            Network::Bitcoin => "bitcoin".to_string(),
            Network::Testnet => "bitcoin".to_string(),
            Network::Signet => "bitcoin".to_string(),
            Network::Regtest => "bitcoin".to_string(),
            _ => "bitcoin".to_string(),
        }
        .to_string();

        // Wrap the shared seal protocol in a ChainSanadOps instance.
        // BitcoinChainSanadOps::from_arc reuses the Arc without cloning the wallet data.
        let sanad_ops = Arc::new(BitcoinChainSanadOps::from_arc(Arc::clone(&seal)));

        Self {
            chain_id,
            network,
            sanad_ops,
            rpc,
            seal_protocol: seal,
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
        let result = csv_protocol::chain_adapter_traits::ChainSanadOps::lock_sanad(&*self.sanad_ops, &sanad_id, destination_chain, &owner_key_id)
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
        use csv_protocol::seal_protocol::SealProtocol;
        use crate::types::{BitcoinCommitAnchor, BitcoinSealPoint};

        // Delegate to the seal_protocol's build_proof_bundle which constructs
        // proper proof bundles with real transaction signatures
        let commitment = transfer.sanad_id;
        
        // Decode lock tx hash
        let lock_tx_hash = hex::decode(lock_result.tx_hash.trim_start_matches("0x"))
            .map_err(|e| AdapterError::Generic(format!("Invalid lock tx hash: {}", e)))?;
        let mut anchor_tx_hash = [0u8; 32];
        anchor_tx_hash[..lock_tx_hash.len().min(32)].copy_from_slice(&lock_tx_hash[..lock_tx_hash.len().min(32)]);
        
        let anchor = BitcoinCommitAnchor::new(
            anchor_tx_hash,
            0,
            lock_result.block_height,
        );

        // Create a seal point from the sanad_id
        let seal_point = BitcoinSealPoint::new(
            *transfer.sanad_id.as_bytes(),
            0,
            None,
        );

        // Serialize the DAG segment (empty for now, would contain transition data)
        let dag_segment = csv_hash::dag::DAGSegment::new(vec![], commitment);

        // Build the proof bundle using the seal protocol
        let proof_bundle = self.seal_protocol
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
