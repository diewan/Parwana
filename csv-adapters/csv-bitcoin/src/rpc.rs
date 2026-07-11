//! Bitcoin RPC trait and test helpers
//!
//! ## Design Decision
//!
//! The `BitcoinRpc` trait defines the interface for real RPC implementations.
//! Test helpers are provided under `#[cfg(test)]` and **explicitly refuse**
//! to broadcast transactions, returning errors instead of fabricated txids.

use async_trait::async_trait;
#[cfg(test)]
use std::collections::HashSet;

/// UTXO information for a specific output
#[derive(Debug, Clone)]
pub struct UtxoInfo {
    /// Transaction ID
    pub txid: [u8; 32],
    /// Output index
    pub vout: u32,
    /// Amount in satoshis
    pub amount_sat: u64,
    /// Confirmations
    pub confirmations: u64,
}

/// Full UTXO details including value and scriptPubKey
#[derive(Debug, Clone)]
pub struct UtxoDetails {
    /// Transaction ID
    pub txid: [u8; 32],
    /// Output index
    pub vout: u32,
    /// Amount in satoshis
    pub value: u64,
    /// ScriptPubKey (hex)
    pub script_pubkey: String,
}

/// Block header information
#[derive(Debug, Clone)]
pub struct BlockHeader {
    /// Block hash
    pub block_hash: [u8; 32],
    /// Block height
    pub height: u64,
    /// Block timestamp (Unix timestamp)
    pub timestamp: u32,
    /// Block version
    pub version: i32,
}

/// Trait-based RPC interface for real implementations
#[async_trait]
pub trait BitcoinRpc: Send + Sync {
    async fn get_block_count(&self) -> Result<u64, Box<dyn std::error::Error + Send + Sync>>;
    async fn get_block_hash(
        &self,
        height: u64,
    ) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>>;
    async fn is_utxo_unspent(
        &self,
        txid: [u8; 32],
        vout: u32,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>;
    async fn send_raw_transaction(
        &self,
        tx_bytes: Vec<u8>,
    ) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>>;
    async fn get_tx_confirmations(
        &self,
        txid: [u8; 32],
    ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>>;

    /// Return the height of the block that confirms `txid`, or `None` if the
    /// transaction is not yet confirmed. `txid` is internal byte order.
    ///
    /// The default derives the height from the confirmation count and the current
    /// tip (`tip - confirmations + 1`). Backends with a direct transaction-status
    /// endpoint should override this for a race-free single lookup (a block
    /// arriving between the two RPC calls would otherwise skew the derived height).
    async fn get_tx_block_height(
        &self,
        txid: [u8; 32],
    ) -> Result<Option<u64>, Box<dyn std::error::Error + Send + Sync>> {
        let confirmations = self.get_tx_confirmations(txid).await?;
        if confirmations == 0 {
            return Ok(None);
        }
        let tip = self.get_block_count().await?;
        Ok(Some(tip.saturating_sub(confirmations) + 1))
    }

    /// Get UTXOs for a specific address
    /// Returns list of (txid, vout, amount_sat, confirmations)
    async fn get_utxos_for_address(
        &self,
        address: String,
    ) -> Result<Vec<UtxoInfo>, Box<dyn std::error::Error + Send + Sync>>;

    /// Build a transaction inclusion proof from real block transaction data.
    async fn get_inclusion_proof(
        &self,
        txid: [u8; 32],
        block_hash: [u8; 32],
    ) -> Result<crate::types::BitcoinInclusionProof, Box<dyn std::error::Error + Send + Sync>> {
        let _ = (txid, block_hash);
        Err("Bitcoin RPC implementation does not support merkle proof extraction".into())
    }

    /// Estimate fee rate in sat/vbyte from the backing node or fee API.
    async fn estimate_fee_rate(&self) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        Err("Bitcoin RPC implementation does not support fee estimation".into())
    }

    /// Get the scriptPubKey for a specific UTXO output
    async fn get_utxo_scriptpubkey(
        &self,
        txid: [u8; 32],
        vout: u32,
    ) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
        let _ = (txid, vout);
        Err("Bitcoin RPC implementation does not support scriptPubKey fetching".into())
    }

    /// Get full UTXO details (value and scriptPubKey) for a specific output
    async fn get_utxo_details(
        &self,
        txid: [u8; 32],
        vout: u32,
    ) -> Result<Option<UtxoDetails>, Box<dyn std::error::Error + Send + Sync>> {
        let _ = (txid, vout);
        Err("Bitcoin RPC implementation does not support UTXO details fetching".into())
    }

    /// Get block header including timestamp
    async fn get_block_header(
        &self,
        block_hash: [u8; 32],
    ) -> Result<BlockHeader, Box<dyn std::error::Error + Send + Sync>> {
        let _ = block_hash;
        Err("Bitcoin RPC implementation does not support block header fetching".into())
    }

    /// Get raw 80-byte block header data for SPV verification
    async fn get_raw_block_header(
        &self,
        block_hash: [u8; 32],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let _ = block_hash;
        Err("Bitcoin RPC implementation does not support raw block header fetching".into())
    }

    /// Create and broadcast an OP_RETURN transaction with the given data
    /// This is used for minting/committing data to the Bitcoin blockchain
    async fn create_op_return_transaction(
        &self,
        data: Vec<u8>,
        _fee_rate: u64, // sat/vbyte
    ) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
        let _ = data;
        Err("Bitcoin RPC implementation does not support OP_RETURN transaction creation".into())
    }

    /// Clone the RPC client into a new boxed trait object.
    /// Required for the runtime pattern to share RPC across operations.
    fn clone_boxed(&self) -> Box<dyn BitcoinRpc + Send + Sync>;
}

/// Test-only RPC client for unit testing
///
/// This implementation **explicitly refuses** to broadcast transactions.
/// Use this only for testing seal registry logic, not transaction broadcasting.
#[cfg(test)]
pub struct TestBitcoinRpc {
    block_count: u64,
    /// Confirmation count reported for every txid by `get_tx_confirmations`
    /// (0 = unconfirmed). Defaults to 0 to preserve existing test behavior.
    confirmations: u64,
    pub unspent_utxos: HashSet<(Vec<u8>, u32)>,
}

#[cfg(test)]
impl TestBitcoinRpc {
    pub fn new(block_count: u64) -> Self {
        Self {
            block_count,
            confirmations: 0,
            unspent_utxos: HashSet::new(),
        }
    }

    /// Report `confirmations` for every txid (drives `get_tx_block_height`).
    pub fn with_confirmations(mut self, confirmations: u64) -> Self {
        self.confirmations = confirmations;
        self
    }

    pub fn mark_utxo_unspent(&mut self, txid: Vec<u8>, vout: u32) {
        self.unspent_utxos.insert((txid, vout));
    }

    pub fn mark_utxo_spent(&mut self, txid: Vec<u8>, vout: u32) {
        self.unspent_utxos.remove(&(txid, vout));
    }
}

#[cfg(test)]
#[async_trait]
impl BitcoinRpc for TestBitcoinRpc {
    async fn get_block_count(&self) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.block_count)
    }

    async fn get_block_hash(
        &self,
        height: u64,
    ) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
        let mut hash = [0u8; 32];
        hash[..8].copy_from_slice(&height.to_le_bytes());
        Ok(hash)
    }

    async fn is_utxo_unspent(
        &self,
        txid: [u8; 32],
        vout: u32,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.unspent_utxos.contains(&(txid.to_vec(), vout)))
    }

    async fn send_raw_transaction(
        &self,
        _tx_bytes: Vec<u8>,
    ) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
        // Explicit refusal — test RPCs must not fabricate txids
        Err("TestBitcoinRpc cannot broadcast transactions — use real RPC for that".into())
    }

    async fn get_tx_confirmations(
        &self,
        _txid: [u8; 32],
    ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.confirmations)
    }

    async fn get_utxos_for_address(
        &self,
        _address: String,
    ) -> Result<Vec<UtxoInfo>, Box<dyn std::error::Error + Send + Sync>> {
        // For testing, return UTXOs from the stored set
        let utxos: Vec<UtxoInfo> = self
            .unspent_utxos
            .iter()
            .map(|(txid, vout)| UtxoInfo {
                txid: {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&txid[..32.min(txid.len())]);
                    arr
                },
                vout: *vout,
                amount_sat: 100000, // Default test amount
                confirmations: 6,
            })
            .collect();
        Ok(utxos)
    }

    async fn get_utxo_scriptpubkey(
        &self,
        _txid: [u8; 32],
        _vout: u32,
    ) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
        // For testing, return a dummy scriptPubKey
        Ok(Some(
            "5120ec0eaaefbcc12b0b0f13ae06f3c4190b047c469fa4ffa60df3a0319fd28f02fe".to_string(),
        ))
    }

    async fn get_block_header(
        &self,
        block_hash: [u8; 32],
    ) -> Result<BlockHeader, Box<dyn std::error::Error + Send + Sync>> {
        // For testing, return a dummy block header
        Ok(BlockHeader {
            block_hash,
            height: 100,
            timestamp: 1234567890,
            version: 1,
        })
    }

    async fn get_raw_block_header(
        &self,
        block_hash: [u8; 32],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        // For testing, return a dummy 80-byte block header
        // Format: version (4) + prev_blockhash (32) + merkle_root (32) + timestamp (4) + bits (4) + nonce (4)
        let mut header = vec![0u8; 80];
        header[0..4].copy_from_slice(&1u32.to_le_bytes()); // version
        header[4..36].copy_from_slice(&block_hash); // prev_blockhash (use block_hash as placeholder)
        header[36..68].copy_from_slice(&[0u8; 32]); // merkle_root (placeholder)
        header[68..72].copy_from_slice(&1234567890u32.to_le_bytes()); // timestamp
        header[72..76].copy_from_slice(&0x207fffffu32.to_le_bytes()); // bits
        header[76..80].copy_from_slice(&0u32.to_le_bytes()); // nonce
        Ok(header)
    }

    async fn create_op_return_transaction(
        &self,
        _data: Vec<u8>,
        _fee_rate: u64,
    ) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
        // Test RPC refuses to broadcast transactions
        Err("TestBitcoinRpc cannot broadcast transactions — use real RPC for that".into())
    }

    fn clone_boxed(&self) -> Box<dyn BitcoinRpc + Send + Sync> {
        Box::new(TestBitcoinRpc {
            block_count: self.block_count,
            confirmations: self.confirmations,
            unspent_utxos: self.unspent_utxos.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_bitcoin_rpc_block_count() {
        let rpc = TestBitcoinRpc::new(100);
        assert_eq!(rpc.get_block_count().await.unwrap(), 100);
    }

    #[tokio::test]
    async fn test_bitcoin_rpc_utxo_lifecycle() {
        let mut rpc = TestBitcoinRpc::new(100);
        let _txid = [1u8, 2, 3].to_vec().into_boxed_slice();
        let txid_bytes: [u8; 32] = {
            let mut arr = [0u8; 32];
            arr[..3].copy_from_slice(&[1, 2, 3]);
            arr
        };
        assert!(!rpc.is_utxo_unspent(txid_bytes, 0).await.unwrap());
        rpc.mark_utxo_unspent(txid_bytes.to_vec(), 0);
        assert!(rpc.is_utxo_unspent(txid_bytes, 0).await.unwrap());
        rpc.mark_utxo_spent(txid_bytes.to_vec(), 0);
        assert!(!rpc.is_utxo_unspent(txid_bytes, 0).await.unwrap());
    }

    #[tokio::test]
    async fn test_bitcoin_rpc_refuses_broadcast() {
        let rpc = TestBitcoinRpc::new(100);
        let result = rpc.send_raw_transaction(vec![0x01, 0x02]).await;
        assert!(result.is_err(), "Test RPC must refuse to broadcast");
    }
}
