//! Implementation of csv-adapter-core traits for Bitcoin adapter

use async_trait::async_trait;
use csv_adapter_core::{
    AdapterResult, ChainOps, MintAdapter, MintReceipt, MintStatus, ProofAdapter, TransactionStatus,
};
use csv_hash::Hash;
use csv_protocol::proof_taxonomy::ProofBundle;
use std::sync::Arc;

use crate::{BitcoinRpc, BitcoinChainProofProvider};

/// Bitcoin adapter implementing adapter-core traits
pub struct BitcoinAdapter {
    rpc: Arc<dyn BitcoinRpc>,
}

impl BitcoinAdapter {
    /// Create a new Bitcoin adapter
    pub fn new(rpc: Arc<dyn BitcoinRpc>) -> Self {
        Self { rpc }
    }
}

#[async_trait]
impl ProofAdapter for BitcoinAdapter {
    async fn verify_proof_bundle(&self, bundle: &ProofBundle) -> AdapterResult<bool> {
        // Delegate to BitcoinChainProofProvider for production-grade verification
        let provider = BitcoinChainProofProvider::new(self.rpc.clone_boxed());
        
        // Extract inclusion and finality proofs from the bundle
        let inclusion_proof = &bundle.inclusion_proof;
        let finality_proof = &bundle.finality_proof;
        
        // Use anchor_id as the commitment hash for verification
        let anchor_id = &bundle.anchor_ref.anchor_id;
        if anchor_id.len() != 32 {
            return Err(csv_adapter_core::AdapterError::SerializationError(
                format!("anchor_id must be 32 bytes, got {}", anchor_id.len())
            ));
        }
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(anchor_id);
        let commitment_hash = Hash::new(hash_bytes);
        
        provider
            .verify_proof_bundle_native(inclusion_proof, finality_proof, &commitment_hash)
            .map_err(|e| csv_adapter_core::AdapterError::ProofVerificationFailed(format!(
                "Proof verification failed: {}",
                e
            )))
    }

    fn proof_type(&self) -> String {
        "bitcoin-spv".to_string()
    }
}

#[async_trait]
impl MintAdapter for BitcoinAdapter {
    async fn mint_commitment(
        &self,
        commitment: &csv_hash::commitment::Commitment,
    ) -> AdapterResult<Hash> {
        // Bitcoin uses UTXO model - minting means creating an OP_RETURN transaction
        // Serialize the commitment to canonical bytes for the OP_RETURN output
        let commitment_bytes = commitment.to_canonical_bytes();

        // Use a default fee rate of 1 sat/vbyte
        let fee_rate = 1;

        // Create and broadcast the OP_RETURN transaction via RPC
        let txid = self
            .rpc
            .create_op_return_transaction(commitment_bytes, fee_rate)
            .await
            .map_err(|e| csv_adapter_core::AdapterError::RpcError(format!(
                "Failed to create OP_RETURN transaction: {}",
                e
            )))?;

        Ok(Hash::from(txid))
    }

    async fn get_mint_status(&self, tx_hash: &Hash) -> AdapterResult<MintStatus> {
        // Check transaction status via RPC
        let confirmations = self
            .rpc
            .get_tx_confirmations(*tx_hash.as_bytes())
            .await
            .map_err(|e| csv_adapter_core::AdapterError::RpcError(format!(
                "Failed to get transaction confirmations from Bitcoin RPC: {}",
                e
            )))?;

        if confirmations == 0 {
            Ok(MintStatus::Pending)
        } else {
            Ok(MintStatus::Confirmed)
        }
    }

    async fn get_mint_receipt(&self, tx_hash: &Hash) -> AdapterResult<MintReceipt> {
        // Get transaction receipt via RPC
        let confirmations = self
            .rpc
            .get_tx_confirmations(*tx_hash.as_bytes())
            .await
            .map_err(|e| csv_adapter_core::AdapterError::RpcError(format!(
                "Failed to get transaction confirmations from Bitcoin RPC: {}",
                e
            )))?;

        // Get current block height to estimate block number
        let current_height = self
            .rpc
            .get_block_count()
            .await
            .map_err(|e| csv_adapter_core::AdapterError::RpcError(format!(
                "Failed to get block count from Bitcoin RPC: {}",
                e
            )))?;

        // Get block hash for the transaction's block
        let block_height = if confirmations > 0 {
            current_height.saturating_sub(confirmations)
        } else {
            current_height
        };

        let block_hash = self
            .rpc
            .get_block_hash(block_height)
            .await
            .map_err(|e| csv_adapter_core::AdapterError::RpcError(format!(
                "Failed to get block hash from Bitcoin RPC: {}",
                e
            )))?;

        // Get block header for timestamp
        let block_header = self
            .rpc
            .get_block_header(block_hash)
            .await
            .map_err(|e| csv_adapter_core::AdapterError::RpcError(format!(
                "Failed to get block header from Bitcoin RPC: {}",
                e
            )))?;

        Ok(MintReceipt {
            tx_hash: *tx_hash,
            block_number: block_height,
            timestamp: block_header.timestamp as u64,
            gas_used: 0, // Bitcoin doesn't use gas
        })
    }
}

#[async_trait]
impl ChainOps for BitcoinAdapter {
    async fn get_chain_height(&self) -> AdapterResult<u64> {
        self.rpc
            .get_block_count()
            .await
            .map_err(|e| csv_adapter_core::AdapterError::RpcError(format!(
                "Failed to get block count from Bitcoin RPC: {}",
                e
            )))
    }

    async fn get_balance(&self, address: &str) -> AdapterResult<u64> {
        let utxos = self
            .rpc
            .get_utxos_for_address(address.to_string())
            .await
            .map_err(|e| csv_adapter_core::AdapterError::RpcError(format!(
                "Failed to query UTXOs from Bitcoin RPC: {}",
                e
            )))?;

        let total_balance: u64 = utxos.iter().map(|utxo| utxo.amount_sat).sum();
        Ok(total_balance)
    }

    async fn get_transaction_status(&self, tx_hash: &Hash) -> AdapterResult<TransactionStatus> {
        let confirmations = self
            .rpc
            .get_tx_confirmations(*tx_hash.as_bytes())
            .await
            .map_err(|e| csv_adapter_core::AdapterError::RpcError(format!(
                "Failed to get transaction confirmations from Bitcoin RPC: {}",
                e
            )))?;

        if confirmations == 0 {
            Ok(TransactionStatus::Pending)
        } else {
            Ok(TransactionStatus::Confirmed)
        }
    }

    async fn broadcast_transaction(&self, tx_bytes: &[u8]) -> AdapterResult<Hash> {
        let txid = self
            .rpc
            .send_raw_transaction(tx_bytes.to_vec())
            .await
            .map_err(|e| csv_adapter_core::AdapterError::RpcError(format!(
                "Failed to broadcast transaction via Bitcoin RPC: {}",
                e
            )))?;

        Ok(Hash::from(txid))
    }
}
