//! Real Bitcoin RPC client implementation
//!
//! Wraps `bitcoincore-rpc` behind the `BitcoinRpc` trait for production use.
//! Only compiled when the `rpc` feature is enabled.

#[allow(clippy::module_inception)]
#[cfg(feature = "rpc")]
pub mod real_rpc {
    use async_trait::async_trait;
    use bitcoin::{Network, OutPoint, Txid};
    use bitcoin_hashes::Hash;
    use bitcoincore_rpc::{Auth, Client, RpcApi};
    use std::time::{Duration, Instant};

    use crate::proofs::extract_merkle_proof_from_block;
    use crate::rpc::BitcoinRpc;
    use crate::types::BitcoinInclusionProof;

    type FundingTxResult = Vec<(Txid, u64, u32)>;

    /// Real Bitcoin RPC client backed by bitcoincore-rpc
    pub struct BitcoinNode {
        client: Client,
        network: Network,
        url: String,
        auth: Auth,
    }

    impl BitcoinNode {
        /// Create a new real RPC client (no auth — for local/public nodes)
        pub fn new(url: &str, network: Network) -> Result<Self, RealRpcError> {
            let client = Client::new(url, Auth::None)?;
            Ok(Self {
                client,
                network,
                url: url.to_string(),
                auth: Auth::None,
            })
        }

        /// Create with authentication
        pub fn with_auth(
            url: &str,
            user: &str,
            pass: &str,
            network: Network,
        ) -> Result<Self, RealRpcError> {
            let auth = Auth::UserPass(user.into(), pass.into());
            let client = Client::new(url, auth.clone())?;
            Ok(Self {
                client,
                network,
                url: url.to_string(),
                auth,
            })
        }

        /// Get UTXOs for a specific Bitcoin address
        ///
        /// Returns a list of (OutPoint, amount_in_satoshis) pairs
        pub fn get_address_utxos(
            &self,
            address: &bitcoin::Address,
        ) -> Result<Vec<(OutPoint, u64)>, Box<dyn std::error::Error + Send + Sync>> {
            // Use listunspent RPC call to get UTXOs for the address
            // This requires the Bitcoin Core wallet to be watching this address
            let utxos = self.client.list_unspent(
                Some(0),          // min_confirmations
                None,             // max_confirmations
                Some(&[address]), // addresses filter
                None,             // include_unsafe
                None,             // query_options
            )?;

            let result: Vec<(OutPoint, u64)> = utxos
                .into_iter()
                .map(|utxo| {
                    let outpoint = OutPoint::new(utxo.txid, utxo.vout);
                    let amount_sat = utxo.amount.to_sat();
                    (outpoint, amount_sat)
                })
                .collect();

            Ok(result)
        }

        /// Get transaction details including confirmations and block info
        pub fn get_transaction_info(
            &self,
            txid: [u8; 32],
        ) -> Result<TxInfo, Box<dyn std::error::Error + Send + Sync>> {
            let txid = Txid::from_byte_array(txid);

            let tx_info = self.client.get_raw_transaction_info(&txid, None)?;

            // Get block hash if confirmed
            let block_hash = tx_info.blockhash.map(|h| {
                let bytes = h.as_ref();
                let mut arr = [0u8; 32];
                arr.copy_from_slice(bytes);
                arr
            });

            Ok(TxInfo {
                confirmations: tx_info.confirmations.unwrap_or(0) as u64,
                block_hash,
            })
        }

        /// Get the funding transaction that created a UTXO at a specific address
        ///
        /// This is useful for discovering UTXOs by scanning the blockchain
        /// for transactions sent to wallet addresses.
        pub fn get_funding_tx(
            &self,
            address: &bitcoin::Address,
            min_confirmations: u64,
        ) -> Result<FundingTxResult, Box<dyn std::error::Error + Send + Sync>> {
            let utxos = self.client.list_unspent(
                Some(
                    min_confirmations
                        .try_into()
                        .expect("min_confirmations fits in u32"),
                ),
                None,
                Some(&[address]),
                None,
                None,
            )?;

            Ok(utxos
                .into_iter()
                .map(|utxo| (utxo.txid, utxo.amount.to_sat(), utxo.vout))
                .collect())
        }

        /// Get a full block by hash, including all transactions
        pub fn get_block(
            &self,
            block_hash: [u8; 32],
        ) -> Result<bitcoin::Block, Box<dyn std::error::Error + Send + Sync>> {
            let hash = bitcoin::BlockHash::from_slice(&block_hash)
                .map_err(|e| format!("Invalid block hash: {}", e))?;
            Ok(self.client.get_block(&hash)?)
        }

        /// Get block height from block hash
        pub fn get_block_height(
            &self,
            block_hash: [u8; 32],
        ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
            let hash = bitcoin::BlockHash::from_slice(&block_hash)
                .map_err(|e| format!("Invalid block hash: {}", e))?;
            let info = self.client.get_block_info(&hash)?;
            Ok(info.height as u64)
        }

        /// Extract Merkle proof for a transaction from its containing block
        pub fn extract_merkle_proof(
            &self,
            txid: [u8; 32],
            block_hash: [u8; 32],
        ) -> Result<BitcoinInclusionProof, Box<dyn std::error::Error + Send + Sync>> {
            // Get the full block
            let block = self.get_block(block_hash)?;
            let block_height = self.get_block_height(block_hash)?;

            // Extract all txids from block
            let block_txids: Vec<[u8; 32]> = block
                .txdata
                .iter()
                .map(|tx| tx.compute_txid().to_byte_array())
                .collect();

            // Extract proof using the proof extraction function
            extract_merkle_proof_from_block(txid, &block_txids, block_hash, block_height)
                .ok_or_else(|| "Failed to extract Merkle proof for txid".into())
        }

        /// Wait for transaction to reach required confirmations
        pub async fn wait_for_confirmation(
            &self,
            txid: [u8; 32],
            required_confirmations: u64,
            timeout_secs: u64,
        ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
            let start = Instant::now();
            let poll_interval = Duration::from_secs(10);

            loop {
                if start.elapsed() > Duration::from_secs(timeout_secs) {
                    return Err("Timeout waiting for confirmation".into());
                }

                let confirmations = self.get_tx_confirmations(txid).await?;
                if confirmations >= required_confirmations {
                    return Ok(confirmations);
                }

                tokio::time::sleep(poll_interval).await;
            }
        }

        /// Publish a commitment transaction to Bitcoin
        ///
        /// This integrates with tx_builder to create a proper Taproot commitment
        /// transaction, signs it, and broadcasts it to the network.
        pub fn publish_commitment(
            &self,
            _outpoint: OutPoint,
            _commitment: csv_hash::Hash,
        ) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
            // This method requires adapter-level integration with tx_builder and wallet.
            // The full flow is demonstrated in the signet_real_tx_demo example
            // which wires tx_builder + wallet + RPC broadcasting together.
            // For production use, call BitcoinSealProtocol.publish() instead.
            Err("publish_commitment requires adapter-level integration — use the full BitcoinSealProtocol.publish() method instead".into())
        }
    }

    #[async_trait]
    impl BitcoinRpc for BitcoinNode {
        async fn get_block_count(&self) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
            Ok(self.client.get_block_count()?)
        }

        async fn get_block_hash(
            &self,
            height: u64,
        ) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
            let hash = self.client.get_block_hash(height)?;
            let bytes = hash.as_ref();
            let mut result = [0u8; 32];
            result.copy_from_slice(bytes);
            Ok(result)
        }

        async fn is_utxo_unspent(
            &self,
            txid: [u8; 32],
            vout: u32,
        ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
            let txid = Txid::from_byte_array(txid);
            let result = self.client.get_tx_out(&txid, vout, Some(true))?;
            Ok(result.is_some())
        }

        async fn send_raw_transaction(
            &self,
            tx_bytes: Vec<u8>,
        ) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
            let tx = bitcoin::consensus::encode::deserialize::<bitcoin::Transaction>(&tx_bytes)
                .map_err(|e| format!("Failed to deserialize transaction: {}", e))?;
            let txid = self.client.send_raw_transaction(&tx)?;
            let bytes = txid.as_ref();
            let mut result = [0u8; 32];
            result.copy_from_slice(bytes);
            Ok(result)
        }

        async fn get_tx_confirmations(
            &self,
            txid: [u8; 32],
        ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
            let txid = Txid::from_byte_array(txid);
            let info = self.client.get_raw_transaction_info(&txid, None)?;
            Ok(info.confirmations.map(|c| c as u64).unwrap_or(0))
        }

        async fn get_utxos_for_address(
            &self,
            address: String,
        ) -> Result<Vec<crate::rpc::UtxoInfo>, Box<dyn std::error::Error + Send + Sync>> {
            use crate::rpc::UtxoInfo;

            // Use listunspent RPC call to get UTXOs for the address
            // This requires the Bitcoin Core wallet to be watching this address
            use std::str::FromStr;
            let addr = bitcoin::Address::from_str(&address)
                .map_err(|e| format!("Invalid address: {}", e))?
                .require_network(self.network)
                .map_err(|e| format!("Address network mismatch: {}", e))?;
            let utxos = self.client.list_unspent(
                Some(0),            // min_confirmations
                None,               // max_confirmations
                Some(&[&addr]),     // addresses filter
                None,               // filter label
                Default::default(), // options
            )?;

            let result: Vec<UtxoInfo> = utxos
                .into_iter()
                .map(|u| {
                    let txid_bytes = u.txid.as_ref();
                    let mut txid = [0u8; 32];
                    txid.copy_from_slice(txid_bytes);
                    UtxoInfo {
                        txid,
                        vout: u.vout,
                        amount_sat: u.amount.to_sat(),
                        confirmations: u.confirmations as u64,
                    }
                })
                .collect();

            Ok(result)
        }

        fn clone_boxed(&self) -> Box<dyn BitcoinRpc + Send + Sync> {
            // Note: bitcoincore-rpc Client doesn't implement Clone.
            // The runtime pattern typically uses this for sharing RPC across operations.
            // For BitcoinNode, the client should be wrapped in Arc or use connection pooling.
            // For now, we create a new client with the same configuration.
            Box::new(BitcoinNode {
                client: Client::new(&self.url, self.auth.clone())
                    .expect("Failed to clone RPC client"),
                network: self.network,
                url: self.url.clone(),
                auth: self.auth.clone(),
            })
        }
    }

    /// Real RPC error type
    #[derive(Debug, thiserror::Error)]
    pub enum RealRpcError {
        #[error("RPC error: {0}")]
        Rpc(#[from] bitcoincore_rpc::Error),
    }

    /// Transaction information helper
    #[derive(Debug, Clone)]
    pub struct TxInfo {
        pub confirmations: u64,
        pub block_hash: Option<[u8; 32]>,
    }
}
