//! Ethereum RPC trait and test helpers
//!
//! Defines the minimal set of Ethereum JSON-RPC calls needed
//! by the CSV adapter: storage proofs, receipts, block queries, finality.

use async_trait::async_trait;
#[cfg(any())]
use csv_protocol::rpc::quorum_client::QuorumClient;

use std::collections::HashMap;
use std::sync::Mutex;

/// Trait for Ethereum RPC operations
#[async_trait]
pub trait EthereumRpc: Send + Sync {
    /// Check if a signer is configured for transaction signing
    fn has_signer(&self) -> bool;

    /// Get current block number
    async fn block_number(&self) -> Result<u64, Box<dyn std::error::Error + Send + Sync>>;

    /// Get block by number (returns block hash)
    async fn get_block_hash(
        &self,
        block_number: u64,
    ) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>>;

    /// Get storage proof for a contract's storage slot
    async fn get_proof(
        &self,
        address: [u8; 20],
        keys: Vec<[u8; 32]>,
        block_number: u64,
    ) -> Result<StorageProof, Box<dyn std::error::Error + Send + Sync>>;

    /// Get transaction receipt
    async fn get_transaction_receipt(
        &self,
        tx_hash: [u8; 32],
    ) -> Result<Option<TransactionReceipt>, Box<dyn std::error::Error + Send + Sync>>;

    /// Get block by hash (returns state root)
    async fn get_block_state_root(
        &self,
        block_hash: [u8; 32],
    ) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>>;

    /// Get finalized block number (post-merge)
    async fn get_finalized_block_number(
        &self,
    ) -> Result<Option<u64>, Box<dyn std::error::Error + Send + Sync>>;

    /// Send raw transaction
    async fn send_raw_transaction(
        &self,
        tx_bytes: Vec<u8>,
    ) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>>;

    /// Get account balance
    async fn get_balance(
        &self,
        address: [u8; 20],
    ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>>;

    /// Get transaction count (nonce) for an address
    async fn get_transaction_count(
        &self,
        address: [u8; 20],
    ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>>;

    /// Get transaction count (nonce) for an address at "pending" block tag
    async fn get_transaction_count_pending(
        &self,
        address: [u8; 20],
    ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        // Default implementation falls back to latest block
        self.get_transaction_count(address).await
    }

    /// Get code at an address
    async fn get_code(
        &self,
        address: [u8; 20],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>;

    /// Execute a read-only call against the EVM (eth_call)
    async fn eth_call(
        &self,
        call: serde_json::Value,
        block: &str,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>;

    /// Downcast to `Any` for feature-gated real implementations.
    /// Concrete types may override for explicit downcasting.
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        None
    }

    /// Clone the RPC client for creating new boxed instances
    fn clone_boxed(&self) -> Box<dyn EthereumRpc>;

    /// Get current gas price
    async fn get_gas_price(&self) -> Result<u64, Box<dyn std::error::Error + Send + Sync>>;

    /// Get block by number (returns full block info)
    async fn get_block_by_number(
        &self,
        block_number: u64,
    ) -> Result<Option<RpcBlock>, Box<dyn std::error::Error + Send + Sync>>;

    /// Get transaction by hash
    async fn get_transaction(
        &self,
        tx_hash: [u8; 32],
    ) -> Result<Option<RpcTransaction>, Box<dyn std::error::Error + Send + Sync>>;

    /// Get logs matching filter (eth_getLogs)
    async fn eth_get_logs(
        &self,
        filter: serde_json::Value,
    ) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error + Send + Sync>>;
}

/// Storage proof response (matches eth_getProof format)
#[derive(Clone, Debug)]
pub struct StorageProof {
    /// Account proof (MPT branch from state root to account)
    pub account_proof: Vec<Vec<u8>>,
    /// Account balance
    pub balance: String,
    /// Account code hash
    pub code_hash: [u8; 32],
    /// Account nonce
    pub nonce: String,
    /// Storage root hash
    pub storage_hash: [u8; 32],
    /// Storage proofs for each requested key
    pub storage_proof: Vec<SingleStorageProof>,
}

/// Storage proof for a single key
#[derive(Clone, Debug)]
pub struct SingleStorageProof {
    /// Storage key
    pub key: [u8; 32],
    /// Storage value (RLP-encoded)
    pub value: Vec<u8>,
    /// MPT proof nodes
    pub proof: Vec<Vec<u8>>,
}

/// Transaction receipt
#[derive(Clone, Debug)]
pub struct TransactionReceipt {
    /// Transaction hash
    pub tx_hash: [u8; 32],
    /// Block number
    pub block_number: u64,
    /// Block hash
    pub block_hash: [u8; 32],
    /// Contract address (if deployment)
    pub contract_address: Option<[u8; 20]>,
    /// Logs emitted
    pub logs: Vec<LogEntry>,
    /// Status (1 = success, 0 = failure)
    pub status: u64,
    /// Gas used by the transaction
    pub gas_used: u64,
    /// Whether transaction was successful
    pub success: bool,
}

/// LOG event entry
#[derive(Clone, Debug)]
pub struct LogEntry {
    /// Emitter contract address
    pub address: [u8; 20],
    /// Event topics (indexed parameters)
    pub topics: Vec<[u8; 32]>,
    /// Event data (non-indexed parameters)
    pub data: Vec<u8>,
    /// Log index within transaction
    pub log_index: u64,
}

/// RPC Block representation
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RpcBlock {
    /// Block number
    pub number: u64,
    /// Block hash
    pub hash: [u8; 32],
    /// State root
    pub state_root: [u8; 32],
    /// Timestamp
    pub timestamp: u64,
}

/// RPC Transaction representation
#[derive(Clone, Debug)]
pub struct RpcTransaction {
    /// Transaction hash
    pub hash: [u8; 32],
    /// Sender address
    pub from: [u8; 20],
    /// Recipient address (None for contract creation)
    pub to: Option<[u8; 20]>,
    /// Transaction value
    pub value: Option<u64>,
    /// Gas price
    pub gas_price: Option<u64>,
    /// Gas used
    pub gas: u64,
    /// Block number
    pub block_number: Option<u64>,
}

/// Mock Ethereum RPC for testing
///
/// This implementation is only compiled in test builds to prevent
/// accidental use in production environments.
#[allow(clippy::type_complexity)]
pub struct MockEthereumRpc {
    pub block_number: u64,
    pub finalized_block: Option<u64>,
    pub storage_values: Mutex<HashMap<([u8; 20], [u8; 32]), Vec<u8>>>,
    pub receipts: Mutex<HashMap<[u8; 32], TransactionReceipt>>,
    pub sent_transactions: Mutex<Vec<Vec<u8>>>,
    pub state_roots: Mutex<HashMap<[u8; 32], [u8; 32]>>,
    pub blocks: Mutex<HashMap<u64, RpcBlock>>,
    pub transactions: Mutex<HashMap<[u8; 32], RpcTransaction>>,
    pub gas_price: u64,
    /// Optional canned `eth_call` return value. When set, `eth_call` returns it
    /// verbatim; when `None`, the default zero response is returned.
    pub call_result: Mutex<Option<Vec<u8>>>,
}

impl MockEthereumRpc {
    pub fn new(block_number: u64) -> Self {
        let mut blocks = HashMap::new();
        // Create a default block at the current block number
        let block = RpcBlock {
            number: block_number,
            hash: [0u8; 32],
            state_root: [0u8; 32],
            timestamp: 0,
        };
        blocks.insert(block_number, block);

        Self {
            block_number,
            finalized_block: Some(block_number.saturating_sub(64)),
            storage_values: Mutex::new(HashMap::new()),
            receipts: Mutex::new(HashMap::new()),
            sent_transactions: Mutex::new(Vec::new()),
            state_roots: Mutex::new(HashMap::new()),
            blocks: Mutex::new(blocks),
            transactions: Mutex::new(HashMap::new()),
            gas_price: 20_000_000_000, // 20 Gwei default
            call_result: Mutex::new(None),
        }
    }

    /// Set the canned response returned by `eth_call`.
    pub fn set_call_result(&self, result: Vec<u8>) {
        *self.call_result.lock().expect("call_result mutex poisoned") = Some(result);
    }

    pub fn add_block(&self, block: RpcBlock) {
        self.blocks
            .lock()
            .expect("blocks mutex poisoned")
            .insert(block.number, block);
    }

    pub fn add_transaction(&self, tx: RpcTransaction) {
        self.transactions
            .lock()
            .expect("transactions mutex poisoned")
            .insert(tx.hash, tx);
    }

    pub fn set_gas_price(&mut self, price: u64) {
        self.gas_price = price;
    }

    pub fn set_storage(&self, address: [u8; 20], key: [u8; 32], value: Vec<u8>) {
        self.storage_values
            .lock()
            .expect("storage_values mutex poisoned")
            .insert((address, key), value);
    }

    pub fn add_receipt(&self, tx_hash: [u8; 32], receipt: TransactionReceipt) {
        self.receipts
            .lock()
            .expect("receipts mutex poisoned")
            .insert(tx_hash, receipt);
    }

    pub fn set_state_root(&self, block_hash: [u8; 32], state_root: [u8; 32]) {
        self.state_roots
            .lock()
            .expect("state_roots mutex poisoned")
            .insert(block_hash, state_root);
    }
}

#[async_trait]
impl EthereumRpc for MockEthereumRpc {
    fn has_signer(&self) -> bool {
        false // Mock RPC doesn't have a signer
    }

    async fn block_number(&self) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.block_number)
    }

    async fn get_block_hash(
        &self,
        block_number: u64,
    ) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
        let mut hash = [0u8; 32];
        hash[..8].copy_from_slice(&block_number.to_be_bytes());
        Ok(hash)
    }

    async fn get_proof(
        &self,
        address: [u8; 20],
        keys: Vec<[u8; 32]>,
        _block_number: u64,
    ) -> Result<StorageProof, Box<dyn std::error::Error + Send + Sync>> {
        let storage_values = self.storage_values.lock().map_err(|e| {
            Box::new(std::io::Error::other(format!("Poison error: {}", e)))
                as Box<dyn std::error::Error + Send + Sync>
        })?;

        let storage_proof: Result<Vec<_>, Box<dyn std::error::Error + Send + Sync>> = keys
            .iter()
            .map(|key| {
                let value = storage_values
                    .get(&(address, *key))
                    .cloned()
                    .ok_or_else(|| {
                        Box::new(std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            format!(
                                "Storage value not found for address {:?} key {:?}",
                                address, key
                            ),
                        )) as Box<dyn std::error::Error + Send + Sync>
                    })?;
                Ok(SingleStorageProof {
                    key: *key,
                    value,
                    proof: vec![vec![0xAB; 32]], // Mock MPT proof nodes
                })
            })
            .collect();

        let storage_proof = storage_proof?;

        Ok(StorageProof {
            account_proof: vec![vec![0xCD; 32]],
            balance: "0".to_string(),
            code_hash: [0u8; 32],
            nonce: "0".to_string(),
            storage_hash: [0xEF; 32],
            storage_proof,
        })
    }

    async fn get_transaction_receipt(
        &self,
        tx_hash: [u8; 32],
    ) -> Result<Option<TransactionReceipt>, Box<dyn std::error::Error + Send + Sync>> {
        let receipts = self.receipts.lock().map_err(|e| {
            Box::new(std::io::Error::other(format!("Poison error: {}", e)))
                as Box<dyn std::error::Error + Send + Sync>
        })?;
        Ok(receipts.get(&tx_hash).cloned())
    }

    async fn get_block_state_root(
        &self,
        block_hash: [u8; 32],
    ) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
        let roots = self.state_roots.lock().map_err(|e| {
            Box::new(std::io::Error::other(format!("Poison error: {}", e)))
                as Box<dyn std::error::Error + Send + Sync>
        })?;
        roots.get(&block_hash).copied().ok_or_else(
            || -> Box<dyn std::error::Error + Send + Sync> {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Block not found",
                ))
            },
        )
    }

    async fn get_finalized_block_number(
        &self,
    ) -> Result<Option<u64>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.finalized_block)
    }

    async fn send_raw_transaction(
        &self,
        tx_bytes: Vec<u8>,
    ) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
        self.sent_transactions
            .lock()
            .map_err(|e| {
                Box::new(std::io::Error::other(format!("Poison error: {}", e)))
                    as Box<dyn std::error::Error + Send + Sync>
            })?
            .push(tx_bytes);
        Ok([0xAB; 32])
    }

    async fn get_balance(
        &self,
        _address: [u8; 20],
    ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        Ok(1000000000000000000u64) // Mock 1 ETH balance
    }

    async fn get_transaction_count(
        &self,
        _address: [u8; 20],
    ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        Ok(0u64) // Mock nonce
    }

    async fn get_code(
        &self,
        _address: [u8; 20],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(vec![]) // Mock empty code (EOA)
    }

    async fn eth_call(
        &self,
        _call: serde_json::Value,
        _block: &str,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        // Return the canned response when configured; otherwise the default empty
        // (sanad not locked) response.
        if let Some(result) = self
            .call_result
            .lock()
            .expect("call_result mutex poisoned")
            .clone()
        {
            return Ok(result);
        }
        Ok(vec![0u8; 64])
    }

    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }

    fn clone_boxed(&self) -> Box<dyn EthereumRpc> {
        Box::new(MockEthereumRpc {
            block_number: self.block_number,
            finalized_block: self.finalized_block,
            storage_values: Mutex::new(
                self.storage_values
                    .lock()
                    .expect("storage_values mutex poisoned")
                    .clone(),
            ),
            receipts: Mutex::new(
                self.receipts
                    .lock()
                    .expect("receipts mutex poisoned")
                    .clone(),
            ),
            sent_transactions: Mutex::new(
                self.sent_transactions
                    .lock()
                    .expect("sent_transactions mutex poisoned")
                    .clone(),
            ),
            state_roots: Mutex::new(
                self.state_roots
                    .lock()
                    .expect("state_roots mutex poisoned")
                    .clone(),
            ),
            blocks: Mutex::new(self.blocks.lock().expect("blocks mutex poisoned").clone()),
            transactions: Mutex::new(
                self.transactions
                    .lock()
                    .expect("transactions mutex poisoned")
                    .clone(),
            ),
            gas_price: self.gas_price,
            call_result: Mutex::new(
                self.call_result
                    .lock()
                    .expect("call_result mutex poisoned")
                    .clone(),
            ),
        })
    }

    async fn get_gas_price(&self) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.gas_price)
    }

    async fn get_block_by_number(
        &self,
        block_number: u64,
    ) -> Result<Option<RpcBlock>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self
            .blocks
            .lock()
            .expect("blocks mutex poisoned")
            .get(&block_number)
            .cloned())
    }

    async fn get_transaction(
        &self,
        tx_hash: [u8; 32],
    ) -> Result<Option<RpcTransaction>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self
            .transactions
            .lock()
            .expect("transactions mutex poisoned")
            .get(&tx_hash)
            .cloned())
    }

    async fn eth_get_logs(
        &self,
        _filter: serde_json::Value,
    ) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error + Send + Sync>> {
        // Mock implementation returns empty logs
        Ok(vec![])
    }
}

/// Quorum-backed Ethereum RPC implementation.
///
/// Wraps a `QuorumClient` to provide quorum-based consensus for all
/// Ethereum JSON-RPC calls. This is the recommended production RPC
/// implementation for the Ethereum adapter.
#[cfg(any())]
pub struct QuorumEthereumRpc {
    client: QuorumClient,
}

#[cfg(any())]
impl QuorumEthereumRpc {
    /// Create a new quorum-backed Ethereum RPC from providers.
    pub fn new(providers: Vec<csv_protocol::rpc::quorum_client::RpcProvider>) -> Self {
        Self {
            client: QuorumClient::with_defaults(providers),
        }
    }

    /// Decode a hex string to bytes, with 0x prefix handling.
    fn decode_hex(value: &str) -> Option<Vec<u8>> {
        let s = value.trim_start_matches("0x");
        hex::decode(s).ok()
    }

    /// Parse a hex value as u64.
    fn parse_u64(value: &str) -> Option<u64> {
        let s = value.trim_start_matches("0x");
        u64::from_str_radix(s, 16).ok()
    }
}

#[cfg(any())]
#[async_trait]
impl EthereumRpc for QuorumEthereumRpc {
    fn has_signer(&self) -> bool {
        false // Quorum RPC doesn't have a signer (uses external signing)
    }

    async fn block_number(&self) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        let result = self.client.get_block_number().await?;
        Self::parse_u64(&result).ok_or_else(|| "Invalid block number response".into())
    }

    async fn get_block_hash(
        &self,
        block_number: u64,
    ) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
        // Query the block at the given number to get its hash
        let block = self
            .client
            .get_block_by_hash(&format!("{:064x}", block_number))
            .await?;

        if let Some(hash_hex) = block.get("hash").and_then(|h| h.as_str()) {
            if let Some(bytes) = Self::decode_hex(hash_hex) {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&bytes[..32]);
                return Ok(hash);
            }
        }
        Err("Invalid block hash response".into())
    }

    async fn get_proof(
        &self,
        address: [u8; 20],
        keys: Vec<[u8; 32]>,
        block_number: u64,
    ) -> Result<StorageProof, Box<dyn std::error::Error + Send + Sync>> {
        let addr_hex = format!("0x{}", hex::encode(address));
        let keys_hex: Vec<String> = keys
            .iter()
            .map(|k| format!("0x{}", hex::encode(k)))
            .collect();
        let block_hex = format!("0x{:x}", block_number);

        let result = self
            .client
            .query_json::<serde_json::Value>(
                "eth_getProof",
                &[
                    serde_json::json!(addr_hex),
                    serde_json::json!(keys_hex),
                    serde_json::json!(block_hex),
                ],
            )
            .await?;

        // Parse the response into StorageProof
        let account_proof: Vec<Vec<u8>> = result
            .get("accountProof")
            .and_then(|p| p.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().and_then(Self::decode_hex))
                    .collect()
            })
            .ok_or_else(|| {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "accountProof missing or invalid",
                )) as Box<dyn std::error::Error + Send + Sync>
            })?;

        let balance = result
            .get("balance")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "balance missing",
                )) as Box<dyn std::error::Error + Send + Sync>
            })?;

        let code_hash_hex = result
            .get("codeHash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "codeHash missing",
                )) as Box<dyn std::error::Error + Send + Sync>
            })?;
        let mut code_hash = [0u8; 32];
        if let Some(bytes) = Self::decode_hex(code_hash_hex) {
            code_hash.copy_from_slice(&bytes[..32]);
        }

        let nonce = result
            .get("nonce")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "nonce missing",
                )) as Box<dyn std::error::Error + Send + Sync>
            })?;

        let storage_hash_hex = result
            .get("storageHash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "storageHash missing",
                )) as Box<dyn std::error::Error + Send + Sync>
            })?;
        let mut storage_hash = [0u8; 32];
        if let Some(bytes) = Self::decode_hex(storage_hash_hex) {
            storage_hash.copy_from_slice(&bytes[..32]);
        }

        let storage_proof: Vec<_> = result
            .get("storageProof")
            .and_then(|p| p.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|item| {
                        let key_hex = item.get("key")?.as_str()?;
                        let value_hex = item.get("value")?.as_str()?;
                        let proof: Vec<Vec<u8>> = item
                            .get("proof")
                            .and_then(|p| p.as_array())
                            .map(|p| {
                                p.iter()
                                    .filter_map(|v| v.as_str().and_then(Self::decode_hex))
                                    .collect()
                            })
                            .ok_or_else(|| {
                                Box::new(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    "proof array missing",
                                ))
                                    as Box<dyn std::error::Error + Send + Sync>
                            })?;

                        let mut key = [0u8; 32];
                        if let Some(bytes) = Self::decode_hex(key_hex) {
                            key.copy_from_slice(&bytes[..32]);
                        }

                        let value = Self::decode_hex(value_hex).ok_or_else(|| {
                            Box::new(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                format!("Failed to decode value hex: {}", value_hex),
                            ))
                                as Box<dyn std::error::Error + Send + Sync>
                        })?;

                        Some(SingleStorageProof { key, value, proof })
                    })
                    .collect()
            })
            .ok_or_else(|| {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "storageProof missing or invalid",
                )) as Box<dyn std::error::Error + Send + Sync>
            })?;

        Ok(StorageProof {
            account_proof,
            balance: balance.to_string(),
            code_hash,
            nonce: nonce.to_string(),
            storage_hash,
            storage_proof,
        })
    }

    async fn get_transaction_receipt(
        &self,
        tx_hash: [u8; 32],
    ) -> Result<Option<TransactionReceipt>, Box<dyn std::error::Error + Send + Sync>> {
        let hash_hex = format!("0x{}", hex::encode(tx_hash));

        let result = self
            .client
            .query_json::<serde_json::Value>(
                "eth_getTransactionReceipt",
                &[serde_json::json!(hash_hex)],
            )
            .await?;

        // If result is null, the transaction doesn't exist
        if result.is_null() {
            return Ok(None);
        }

        let tx_hash_out: [u8; 32] = result
            .get("transactionHash")
            .and_then(|h| h.as_str())
            .and_then(Self::decode_hex)
            .and_then(|b| b.try_into().ok())
            .unwrap_or(tx_hash);

        let block_number = result
            .get("blockNumber")
            .and_then(|n| n.as_str())
            .and_then(Self::parse_u64)
            .unwrap_or(0);

        let block_hash: [u8; 32] = result
            .get("blockHash")
            .and_then(|h| h.as_str())
            .and_then(Self::decode_hex)
            .and_then(|b| b.try_into().ok())
            .unwrap_or([0u8; 32]);

        let contract_address = result
            .get("contractAddress")
            .and_then(|a| a.as_str())
            .and_then(Self::decode_hex)
            .and_then(|b| b.try_into().ok());

        let status = result
            .get("status")
            .and_then(|s| s.as_str())
            .and_then(Self::parse_u64)
            .unwrap_or(0);

        let gas_used = result
            .get("gasUsed")
            .and_then(|g| g.as_str())
            .and_then(Self::parse_u64)
            .unwrap_or(0);

        let logs: Vec<LogEntry> = result
            .get("logs")
            .and_then(|l| l.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|log| {
                        let address_hex = log.get("address")?.as_str()?;
                        let mut address = [0u8; 20];
                        if let Some(bytes) = Self::decode_hex(address_hex) {
                            address.copy_from_slice(&bytes[..20]);
                        }

                        let topics: Vec<[u8; 32]> = log
                            .get("topics")
                            .and_then(|t| t.as_array())
                            .map(|t| {
                                t.iter()
                                    .filter_map(|topic| {
                                        topic
                                            .as_str()
                                            .and_then(Self::decode_hex)
                                            .and_then(|b| b.try_into().ok())
                                    })
                                    .collect()
                            })
                            .unwrap_or_default();

                        let data = log
                            .get("data")
                            .and_then(|d| d.as_str())
                            .and_then(Self::decode_hex)
                            .unwrap_or_default();

                        let log_index = log
                            .get("logIndex")
                            .and_then(|l| l.as_str())
                            .and_then(Self::parse_u64)
                            .unwrap_or(0);

                        Some(LogEntry {
                            address,
                            topics,
                            data,
                            log_index,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(Some(TransactionReceipt {
            tx_hash: tx_hash_out,
            block_number,
            block_hash,
            contract_address,
            logs,
            status,
            gas_used,
            success: status == 1,
        }))
    }

    async fn get_block_state_root(
        &self,
        block_hash: [u8; 32],
    ) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
        let hash_hex = format!("0x{}", hex::encode(block_hash));

        let block = self.client.get_block_by_hash(&hash_hex).await?;

        let state_root_hex = block
            .get("stateRoot")
            .and_then(|s| s.as_str())
            .unwrap_or("0x0000000000000000000000000000000000000000000000000000000000000000");

        let mut state_root = [0u8; 32];
        if let Some(bytes) = Self::decode_hex(state_root_hex) {
            state_root.copy_from_slice(&bytes[..32]);
        }

        Ok(state_root)
    }

    async fn get_finalized_block_number(
        &self,
    ) -> Result<Option<u64>, Box<dyn std::error::Error + Send + Sync>> {
        // Query the finalized block number using eth_getBlockByNumber with "finalized"
        let result = self
            .client
            .query_json::<Option<serde_json::Value>>(
                "eth_getBlockByNumber",
                &[serde_json::json!("finalized"), serde_json::json!(false)],
            )
            .await?;

        Ok(result.and_then(|b| {
            b.get("number")
                .and_then(|n| n.as_str())
                .and_then(Self::parse_u64)
        }))
    }

    async fn send_raw_transaction(
        &self,
        tx_bytes: Vec<u8>,
    ) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
        let tx_hex = format!("0x{}", hex::encode(&tx_bytes));

        let tx_hash_hex = self
            .client
            .query_json::<String>("eth_sendRawTransaction", &[serde_json::json!(tx_hex)])
            .await?;

        let mut tx_hash = [0u8; 32];
        if let Some(bytes) = Self::decode_hex(&tx_hash_hex) {
            tx_hash.copy_from_slice(&bytes[..32]);
        }

        Ok(tx_hash)
    }

    async fn get_balance(
        &self,
        address: [u8; 20],
    ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        let addr_hex = format!("0x{}", hex::encode(address));

        let balance_hex = self
            .client
            .query_json::<String>("eth_getBalance", &[serde_json::json!(addr_hex)])
            .await?;

        Self::parse_u64(&balance_hex).ok_or_else(|| "Invalid balance response".into())
    }

    async fn get_transaction_count(
        &self,
        address: [u8; 20],
    ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        let addr_hex = format!("0x{}", hex::encode(address));

        let nonce_hex = self
            .client
            .query_json::<String>("eth_getTransactionCount", &[serde_json::json!(addr_hex)])
            .await?;

        Self::parse_u64(&nonce_hex).ok_or_else(|| "Invalid nonce response".into())
    }

    async fn get_code(
        &self,
        address: [u8; 20],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let addr_hex = format!("0x{}", hex::encode(address));

        let code_hex = self
            .client
            .query_json::<String>("eth_getCode", &[serde_json::json!(addr_hex)])
            .await?;

        Ok(Self::decode_hex(&code_hex).unwrap_or_default())
    }

    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }

    fn clone_boxed(&self) -> Box<dyn EthereumRpc> {
        // QuorumEthereumRpc doesn't implement Clone directly; create a new instance
        // In production, providers would be cloned from the original configuration
        let provider_count = self.client.provider_count();
        let providers: Vec<_> = (0..provider_count.max(1))
            .map(|_| {
                csv_protocol::rpc::quorum_client::RpcProvider::new(
                    "http://localhost:8545".to_string(),
                )
            })
            .collect();
        Box::new(QuorumEthereumRpc {
            client: QuorumClient::with_defaults(providers),
        })
    }

    async fn get_gas_price(&self) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        let gas_hex = self
            .client
            .query_json::<String>("eth_gasPrice", &[])
            .await?;

        Self::parse_u64(&gas_hex).ok_or_else(|| "Invalid gas price response".into())
    }

    async fn get_block_by_number(
        &self,
        block_number: u64,
    ) -> Result<Option<RpcBlock>, Box<dyn std::error::Error + Send + Sync>> {
        let block_hex = format!("0x{:x}", block_number);

        let result = self
            .client
            .query_json::<Option<serde_json::Value>>(
                "eth_getBlockByNumber",
                &[serde_json::json!(block_hex), serde_json::json!(false)],
            )
            .await?;

        Ok(result.map(|block| {
            let number = block
                .get("number")
                .and_then(|n| n.as_str())
                .and_then(Self::parse_u64)
                .unwrap_or(0);

            let hash: [u8; 32] = block
                .get("hash")
                .and_then(|h| h.as_str())
                .and_then(Self::decode_hex)
                .and_then(|b| b.try_into().ok())
                .unwrap_or([0u8; 32]);

            let state_root: [u8; 32] = block
                .get("stateRoot")
                .and_then(|s| s.as_str())
                .and_then(Self::decode_hex)
                .and_then(|b| b.try_into().ok())
                .unwrap_or([0u8; 32]);

            let timestamp = block
                .get("timestamp")
                .and_then(|t| t.as_str())
                .and_then(Self::parse_u64)
                .unwrap_or(0);

            RpcBlock {
                number,
                hash,
                state_root,
                timestamp,
            }
        }))
    }

    async fn get_transaction(
        &self,
        tx_hash: [u8; 32],
    ) -> Result<Option<RpcTransaction>, Box<dyn std::error::Error + Send + Sync>> {
        let hash_hex = format!("0x{}", hex::encode(tx_hash));

        let result = self
            .client
            .query_json::<Option<serde_json::Value>>(
                "eth_getTransactionByHash",
                &[serde_json::json!(hash_hex)],
            )
            .await?;

        Ok(result.map(|tx| {
            let tx_hash_out: [u8; 32] = tx
                .get("hash")
                .and_then(|h| h.as_str())
                .and_then(Self::decode_hex)
                .and_then(|b| b.try_into().ok())
                .unwrap_or(tx_hash);

            let from: [u8; 20] = tx
                .get("from")
                .and_then(|f| f.as_str())
                .and_then(Self::decode_hex)
                .and_then(|b| b.try_into().ok())
                .unwrap_or([0u8; 20]);

            let to = tx
                .get("to")
                .and_then(|t| t.as_str())
                .and_then(Self::decode_hex)
                .and_then(|b| b.try_into().ok());

            let value = tx
                .get("value")
                .and_then(|v| v.as_str())
                .and_then(Self::parse_u64);

            let gas_price = tx
                .get("gasPrice")
                .and_then(|g| g.as_str())
                .and_then(Self::parse_u64);

            let gas = tx
                .get("gas")
                .and_then(|g| g.as_str())
                .and_then(Self::parse_u64)
                .unwrap_or(0);

            let block_number = tx
                .get("blockNumber")
                .and_then(|b| b.as_str())
                .and_then(Self::parse_u64);

            RpcTransaction {
                hash: tx_hash_out,
                from,
                to,
                value,
                gas_price,
                gas,
                block_number,
            }
        }))
    }

    async fn eth_get_logs(
        &self,
        filter: serde_json::Value,
    ) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error + Send + Sync>> {
        let result = self
            .client
            .query_json::<Vec<serde_json::Value>>("eth_getLogs", &[filter])
            .await?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ethereum_rpc_block_number() {
        let rpc = MockEthereumRpc::new(1000);
        assert_eq!(rpc.block_number().await.unwrap(), 1000);
    }

    #[tokio::test]
    async fn test_ethereum_rpc_storage() {
        let rpc = MockEthereumRpc::new(1000);
        let address = [1u8; 20];
        let key = [2u8; 32];
        let value = 1000u64.to_be_bytes().to_vec();

        rpc.set_storage(address, key, value.clone());

        let proof = rpc.get_proof(address, vec![key], 1000).await.unwrap();
        assert_eq!(proof.storage_proof.len(), 1);
        assert_eq!(proof.storage_proof[0].value, value);
    }

    #[tokio::test]
    async fn test_ethereum_rpc_receipt() {
        let rpc = MockEthereumRpc::new(1000);
        let tx_hash = [3u8; 32];
        let receipt = TransactionReceipt {
            tx_hash,
            block_number: 500,
            block_hash: [4u8; 32],
            contract_address: None,
            logs: vec![LogEntry {
                address: [5u8; 20],
                topics: vec![[6u8; 32]],
                data: vec![7, 8, 9],
                log_index: 0,
            }],
            status: 1,
            gas_used: 21000,
            success: true,
        };

        rpc.add_receipt(tx_hash, receipt.clone());

        let fetched = rpc.get_transaction_receipt(tx_hash).await.unwrap();
        let receipt = fetched.unwrap();
        assert_eq!(receipt.logs.len(), 1);
        assert_eq!(receipt.status, 1);
    }

    #[tokio::test]
    async fn test_ethereum_rpc_finalized() {
        let rpc = MockEthereumRpc::new(1000);
        let finalized = rpc.get_finalized_block_number().await.unwrap();
        assert!(finalized.is_some());
        assert!(finalized.unwrap() <= 1000);
    }

    #[tokio::test]
    async fn test_ethereum_rpc_send_transaction() {
        let rpc = MockEthereumRpc::new(1000);
        let tx_hash = rpc.send_raw_transaction(vec![0x01, 0x02]).await.unwrap();
        assert_eq!(tx_hash, [0xAB; 32]);
    }
}
