//! Real Ethereum RPC implementation using Alloy with reqwest HTTP transport
//!
//! Only compiled when the `rpc` feature is enabled.
//! Implements the `EthereumRpc` trait using Alloy's JSON-RPC client.

#[cfg(feature = "rpc")]
mod real_rpc_impl {
    use alloy::{
        consensus::TxEnvelope,
        eips::eip2718::Encodable2718,
        primitives::{Address, TxKind, U256},
        signers::local::PrivateKeySigner,
    };
    use async_trait::async_trait;

    use serde_json::json;

    use crate::rpc::{
        EthereumRpc, LogEntry, RpcBlock, RpcTransaction, SingleStorageProof, StorageProof,
        TransactionReceipt,
    };
    use crate::seal_contract::CsvSealAbi;
    use crate::types::EthereumSealPoint;

    /// Error type for Alloy-based RPC operations
    #[derive(Debug, thiserror::Error)]
    pub enum AlloyRpcError {
        #[error("RPC error: {0}")]
        Rpc(String),
        #[error("Invalid RPC URL: {0}")]
        InvalidUrl(String),
    }

    /// Real Ethereum RPC client backed by Alloy's HTTP transport
    pub struct EthereumNode {
        client: reqwest::Client,
        rpc_url: String,
        csv_seal_address: Address,
        signer: Option<PrivateKeySigner>,
        chain_id: Option<u64>,
    }

    impl EthereumNode {
        /// Create a new RPC client connecting to the given URL
        pub async fn new(rpc_url: &str, csv_seal_address: [u8; 20]) -> Result<Self, AlloyRpcError> {
            let client = reqwest::Client::new();

            // Try to get chain_id
            let chain_id = Self::get_chain_id_impl(&client, rpc_url).await?;

            Ok(Self {
                client,
                rpc_url: rpc_url.to_string(),
                csv_seal_address: Address::from(csv_seal_address),
                signer: None,
                chain_id: Some(chain_id),
            })
        }

        async fn get_chain_id_impl(
            client: &reqwest::Client,
            rpc_url: &str,
        ) -> Result<u64, AlloyRpcError> {
            let req = json!({
                "jsonrpc": "2.0",
                "method": "eth_chainId",
                "params": [],
                "id": 0
            });

            let response = client
                .post(rpc_url)
                .json(&req)
                .send()
                .await
                .map_err(|e| AlloyRpcError::Rpc(e.to_string()))?;

            let body: serde_json::Value = response
                .json::<serde_json::Value>()
                .await
                .map_err(|e| AlloyRpcError::Rpc(e.to_string()))?;

            let hex_str = body
                .get("result")
                .and_then(|v| v.as_str())
                .ok_or_else(|| AlloyRpcError::Rpc("Invalid chainId response".to_string()))?;

            let hex_str = hex_str.trim_start_matches("0x");
            u64::from_str_radix(hex_str, 16)
                .map_err(|e| AlloyRpcError::Rpc(format!("Failed to parse chainId: {}", e)))
        }

        /// Get the CSVSeal contract address
        pub fn csv_seal_address(&self) -> [u8; 20] {
            (*self.csv_seal_address).0
        }

        /// Get a reference to the configured signer, if any
        pub fn signer(&self) -> Option<&PrivateKeySigner> {
            self.signer.as_ref()
        }

        /// Get the compressed public key (33 bytes) for the configured signer
        pub fn public_key(&self) -> Option<[u8; 33]> {
            use secp256k1::{Secp256k1, SecretKey, PublicKey};
            
            self.signer.as_ref().map(|s| {
                // Get the secret key bytes from the signer
                let secret_key_bytes = s.credential().to_bytes();
                let secret_key = SecretKey::from_slice(&secret_key_bytes)
                    .expect("valid 32-byte secret key");
                
                let secp = Secp256k1::new();
                let public_key = PublicKey::from_secret_key(&secp, &secret_key);
                
                // serialize() returns 33 bytes (compressed format)
                let pk_bytes = public_key.serialize();
                let mut compressed = [0u8; 33];
                compressed.copy_from_slice(&pk_bytes);
                compressed
            })
        }

        /// Set the signer private key for transaction signing
        pub fn with_signer(mut self, private_key_hex: &str) -> Result<Self, AlloyRpcError> {
            let bytes = hex::decode(private_key_hex.trim_start_matches("0x"))
                .map_err(|e| AlloyRpcError::Rpc(format!("Invalid private key hex: {}", e)))?;
            if bytes.len() != 32 {
                return Err(AlloyRpcError::Rpc(
                    "Private key must be 32 bytes".to_string(),
                ));
            }
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&bytes);
            let signer = PrivateKeySigner::from_slice(&key_bytes)
                .map_err(|e| AlloyRpcError::Rpc(format!("Invalid private key: {}", e)))?;
            self.signer = Some(signer);
            Ok(self)
        }

        /// Make a JSON-RPC call to the Ethereum node
        async fn rpc_call(
            &self,
            method: &str,
            params: serde_json::Value,
        ) -> Result<serde_json::Value, AlloyRpcError> {
            let req = json!({
                "jsonrpc": "2.0",
                "method": method,
                "params": params,
                "id": 1
            });

            let response = self
                .client
                .post(&self.rpc_url)
                .json(&req)
                .send()
                .await
                .map_err(|e| AlloyRpcError::Rpc(e.to_string()))?;

            let status = response.status();
            let body: serde_json::Value = response
                .json::<serde_json::Value>()
                .await
                .map_err(|e| AlloyRpcError::Rpc(e.to_string()))?;

            if !status.is_success() {
                return Err(AlloyRpcError::Rpc(format!(
                    "HTTP error {}: {}",
                    status, body
                )));
            }

            if let Some(error) = body.get("error") {
                return Err(AlloyRpcError::Rpc(format!("RPC error: {:?}", error)));
            }

            body.get("result")
                .cloned()
                .ok_or_else(|| AlloyRpcError::Rpc("Missing result in RPC response".to_string()))
        }

        async fn block_number_raw(&self) -> Result<u64, AlloyRpcError> {
            let hex_str = self
                .rpc_call("eth_blockNumber", json!([]))
                .await?
                .as_str()
                .ok_or_else(|| AlloyRpcError::Rpc("Invalid block number response".to_string()))?
                .to_string();
            parse_hex_u64(&hex_str)
        }

        async fn get_block_by_tag(
            &self,
            tag: &str,
        ) -> Result<Option<serde_json::Value>, AlloyRpcError> {
            let result = self
                .rpc_call("eth_getBlockByNumber", json!([tag, false]))
                .await?;
            if result.is_null() {
                return Ok(None);
            }
            Ok(Some(result))
        }

        async fn get_block_by_hash_raw(
            &self,
            hash: &str,
        ) -> Result<Option<serde_json::Value>, AlloyRpcError> {
            let result = self
                .rpc_call("eth_getBlockByHash", json!([hash, false]))
                .await?;
            if result.is_null() {
                return Ok(None);
            }
            Ok(Some(result))
        }

        async fn get_proof_raw(
            &self,
            address: &str,
            keys: Vec<&str>,
            block_tag: &str,
        ) -> Result<serde_json::Value, AlloyRpcError> {
            self.rpc_call("eth_getProof", json!([address, keys, block_tag]))
                .await
        }

        async fn get_tx_receipt_raw(
            &self,
            tx_hash: &str,
        ) -> Result<Option<serde_json::Value>, AlloyRpcError> {
            let result = self
                .rpc_call("eth_getTransactionReceipt", json!([tx_hash]))
                .await?;
            if result.is_null() {
                return Ok(None);
            }
            Ok(Some(result))
        }

        async fn send_raw_tx_raw(&self, tx_data: &str) -> Result<String, AlloyRpcError> {
            let val = self
                .rpc_call("eth_sendRawTransaction", json!([tx_data]))
                .await?;
            val.as_str()
                .ok_or_else(|| AlloyRpcError::Rpc("Invalid tx hash response".to_string()))
                .map(|s| s.to_string())
        }
    }

    fn parse_hex_u64(s: &str) -> Result<u64, AlloyRpcError> {
        let s = s.trim_start_matches("0x");
        u64::from_str_radix(s, 16)
            .map_err(|e| AlloyRpcError::Rpc(format!("Failed to parse hex: {}", e)))
    }

    fn parse_hex_bytes(s: &str) -> Vec<u8> {
        let s = s.trim_start_matches("0x");
        if s.is_empty() {
            return Vec::new();
        }
        (0..s.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
            .collect()
    }

    fn parse_hex_bytes32(s: &str) -> Result<[u8; 32], String> {
        let s = s.trim_start_matches("0x");
        let bytes = hex::decode(s).map_err(|e| format!("Invalid hex: {}", e))?;
        bytes
            .try_into()
            .map_err(|v: Vec<u8>| format!("must be 32 bytes, got {}", v.len()))
    }

    fn parse_hex_bytes20(s: &str) -> Result<[u8; 20], String> {
        let s = s.trim_start_matches("0x");
        let bytes = hex::decode(s).map_err(|e| format!("Invalid hex: {}", e))?;
        bytes
            .try_into()
            .map_err(|v: Vec<u8>| format!("must be 20 bytes, got {}", v.len()))
    }

    #[async_trait]
    impl EthereumRpc for EthereumNode {
        fn has_signer(&self) -> bool {
            self.signer.is_some()
        }

        async fn block_number(&self) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
            self.block_number_raw().await.map_err(|e| e.into())
        }

        async fn get_block_hash(
            &self,
            block_number: u64,
        ) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
            let tag = format!("0x{:x}", block_number);
            let block = self
                .get_block_by_tag(&tag)
                .await?
                .ok_or_else(|| format!("Block {} not found", block_number))?;

            let hash_str = block["hash"].as_str().ok_or("Missing block hash")?;
            parse_hex_bytes32(hash_str).map_err(|e| e.into())
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
            let block_tag = format!("0x{:x}", block_number);

            let proof = self
                .get_proof_raw(
                    &addr_hex,
                    keys_hex.iter().map(|s| s.as_str()).collect(),
                    &block_tag,
                )
                .await?;

            let account_proof_arr = proof["accountProof"]
                .as_array()
                .ok_or("Missing accountProof field")?;
            let account_proof: Vec<Vec<u8>> = account_proof_arr
                .iter()
                .filter_map(|v| v.as_str().map(parse_hex_bytes))
                .collect();

            let storage_proof_arr = proof["storageProof"]
                .as_array()
                .ok_or("Missing storageProof field")?;
            let storage_proof: Vec<SingleStorageProof> = storage_proof_arr
                .iter()
                .filter_map(|sp| {
                    let key_str = sp["key"].as_str()?;
                    let key = parse_hex_bytes32(key_str).ok()?;
                    let value_str = sp["value"].as_str()?;
                    let value = parse_hex_bytes(value_str);
                    let proof_nodes_arr = sp["proof"].as_array()?;
                    let proof_nodes: Vec<Vec<u8>> = proof_nodes_arr
                        .iter()
                        .filter_map(|v| v.as_str().map(parse_hex_bytes))
                        .collect();
                    Some(SingleStorageProof {
                        key,
                        value,
                        proof: proof_nodes,
                    })
                })
                .collect();

            let code_hash_str = proof["codeHash"].as_str().ok_or("Missing codeHash")?;
            let code_hash = parse_hex_bytes32(code_hash_str).map_err(|e| e.to_string())?;
            let storage_hash_str = proof["storageHash"].as_str().ok_or("Missing storageHash")?;
            let storage_hash = parse_hex_bytes32(storage_hash_str).map_err(|e| e.to_string())?;

            let balance = proof["balance"]
                .as_str()
                .ok_or("Missing balance field")?
                .to_string();
            let nonce = proof["nonce"]
                .as_str()
                .ok_or("Missing nonce field")?
                .to_string();

            Ok(StorageProof {
                account_proof,
                balance,
                code_hash,
                nonce,
                storage_hash,
                storage_proof,
            })
        }

        async fn get_transaction_receipt(
            &self,
            tx_hash: [u8; 32],
        ) -> Result<Option<TransactionReceipt>, Box<dyn std::error::Error + Send + Sync>> {
            let hash_hex = format!("0x{}", hex::encode(tx_hash));
            let receipt = match self.get_tx_receipt_raw(&hash_hex).await? {
                Some(r) => r,
                None => return Ok(None),
            };

            let logs_arr = receipt["logs"].as_array().ok_or("Missing logs field")?;

            let logs: Vec<LogEntry> = logs_arr
                .iter()
                .filter_map(|log| {
                    let address = log["address"]
                        .as_str()
                        .and_then(|s| parse_hex_bytes20(s).ok())?;
                    let topics_arr = log["topics"].as_array()?;
                    let topics: Vec<[u8; 32]> = topics_arr
                        .iter()
                        .filter_map(|v| v.as_str().and_then(|s| parse_hex_bytes32(s).ok()))
                        .collect();
                    let data_str = log["data"].as_str()?;
                    let data = parse_hex_bytes(data_str);
                    let log_index_str = log["logIndex"].as_str()?;
                    let log_index = parse_hex_u64(log_index_str).ok()?;
                    Some(LogEntry {
                        address,
                        topics,
                        data,
                        log_index,
                    })
                })
                .collect();

            let contract_addr = receipt["contractAddress"]
                .as_str()
                .filter(|s| !s.is_empty() && *s != "null")
                .and_then(|s| parse_hex_bytes20(s).ok());

            let status_str = receipt["status"]
                .as_str()
                .ok_or("Missing status field")?;
            let status = parse_hex_u64(status_str)
                .map_err(|e| format!("Invalid status: {}", e))?;

            let block_number_str = receipt["blockNumber"]
                .as_str()
                .ok_or("Missing blockNumber field")?;
            let block_number = parse_hex_u64(block_number_str)
                .map_err(|e| format!("Invalid blockNumber: {}", e))?;

            let block_hash = receipt["blockHash"]
                .as_str()
                .ok_or("Missing blockHash field")?;
            let block_hash = parse_hex_bytes32(block_hash).map_err(|e| e.to_string())?;

            let gas_used_str = receipt["gasUsed"]
                .as_str()
                .ok_or("Missing gasUsed field")?;
            let gas_used = parse_hex_u64(gas_used_str)
                .map_err(|e| format!("Invalid gasUsed: {}", e))?;

            let success = status == 1;

            Ok(Some(TransactionReceipt {
                tx_hash,
                block_number,
                block_hash,
                contract_address: contract_addr,
                logs,
                status,
                gas_used,
                success,
            }))
        }

        fn clone_boxed(&self) -> Box<dyn EthereumRpc> {
            Box::new(EthereumNode {
                client: self.client.clone(),
                rpc_url: self.rpc_url.clone(),
                csv_seal_address: self.csv_seal_address,
                signer: self.signer.clone(),
                chain_id: self.chain_id,
            })
        }

        async fn get_gas_price(&self) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
            let result = self.rpc_call("eth_gasPrice", json!([])).await?;
            let hex_str = result.as_str().ok_or("Invalid gas price response")?;
            parse_hex_u64(hex_str).map_err(|e| e.into())
        }

        async fn get_block_by_number(
            &self,
            block_number: u64,
        ) -> Result<Option<RpcBlock>, Box<dyn std::error::Error + Send + Sync>> {
            let tag = format!("0x{:x}", block_number);
            let result = self
                .rpc_call("eth_getBlockByNumber", json!([tag, false]))
                .await?;
            if result.is_null() {
                return Ok(None);
            }
            let hash_str = result["hash"].as_str().ok_or("Missing block hash")?;
            let hash = parse_hex_bytes32(hash_str).map_err(|e| e.to_string())?;
            let state_root_str = result["stateRoot"].as_str().ok_or("Missing stateRoot")?;
            let state_root = parse_hex_bytes32(state_root_str).map_err(|e| e.to_string())?;
            let timestamp_str = result["timestamp"].as_str().ok_or("Missing timestamp")?;
            let timestamp =
                parse_hex_u64(timestamp_str).map_err(|e| format!("Invalid timestamp: {}", e))?;

            Ok(Some(RpcBlock {
                number: block_number,
                hash,
                state_root,
                timestamp,
            }))
        }

        async fn get_transaction(
            &self,
            tx_hash: [u8; 32],
        ) -> Result<Option<RpcTransaction>, Box<dyn std::error::Error + Send + Sync>> {
            let hash_hex = format!("0x{}", hex::encode(tx_hash));
            let result = self
                .rpc_call("eth_getTransactionByHash", json!([hash_hex]))
                .await?;
            if result.is_null() {
                return Ok(None);
            }

            let from_str = result["from"].as_str().ok_or("Missing from address")?;
            let from =
                parse_hex_bytes20(from_str).map_err(|e| format!("Invalid from address: {}", e))?;
            let to = result["to"]
                .as_str()
                .filter(|s| !s.is_empty() && *s != "null")
                .and_then(|s| parse_hex_bytes20(s).ok());
            let value = result["value"].as_str().and_then(|s| parse_hex_u64(s).ok());
            let gas_price = result["gasPrice"]
                .as_str()
                .and_then(|s| parse_hex_u64(s).ok());
            let gas_str = result["gas"].as_str().ok_or("Missing gas field")?;
            let gas = parse_hex_u64(gas_str).map_err(|e| format!("Invalid gas: {}", e))?;
            let block_number = result["blockNumber"]
                .as_str()
                .and_then(|s| parse_hex_u64(s).ok());

            Ok(Some(RpcTransaction {
                hash: tx_hash,
                from,
                to,
                value,
                gas_price,
                gas,
                block_number,
            }))
        }

        async fn get_block_state_root(
            &self,
            block_hash: [u8; 32],
        ) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
            let hash_hex = format!("0x{}", hex::encode(block_hash));
            let block = self
                .get_block_by_hash_raw(&hash_hex)
                .await?
                .ok_or_else(|| format!("Block {:?} not found", block_hash))?;

            let state_root_str = block["stateRoot"].as_str().ok_or("Missing stateRoot")?;
            parse_hex_bytes32(state_root_str).map_err(|e| e.into())
        }

        async fn get_finalized_block_number(
            &self,
        ) -> Result<Option<u64>, Box<dyn std::error::Error + Send + Sync>> {
            let block = self.get_block_by_tag("finalized").await?;
            match block {
                Some(b) => {
                    let num_str = b["number"].as_str().ok_or("Missing block number")?;
                    let num = parse_hex_u64(num_str)
                        .map_err(|e| format!("Invalid block number: {}", e))?;
                    Ok(Some(num))
                }
                None => Ok(None),
            }
        }

        async fn send_raw_transaction(
            &self,
            tx_bytes: Vec<u8>,
        ) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
            let tx_hex = format!("0x{}", hex::encode(&tx_bytes));
            let hash_str = self.send_raw_tx_raw(&tx_hex).await?;
            parse_hex_bytes32(&hash_str).map_err(|e| e.into())
        }

        async fn get_balance(
            &self,
            address: [u8; 20],
        ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
            let addr_hex = format!("0x{}", hex::encode(address));
            let result = self
                .rpc_call("eth_getBalance", json!([addr_hex, "latest"]))
                .await?;
            let hex_str = result.as_str().ok_or("Invalid balance response")?;
            let balance = parse_hex_u64(hex_str)?;
            Ok(balance)
        }

        async fn get_transaction_count(
            &self,
            address: [u8; 20],
        ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
            let addr_hex = format!("0x{}", hex::encode(address));
            let result = self
                .rpc_call("eth_getTransactionCount", json!([addr_hex, "latest"]))
                .await?;
            let hex_str = result
                .as_str()
                .ok_or("Invalid transaction count response")?;
            let count = parse_hex_u64(hex_str)?;
            Ok(count)
        }

        async fn get_transaction_count_pending(
            &self,
            address: [u8; 20],
        ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
            let addr_hex = format!("0x{}", hex::encode(address));
            let result = self
                .rpc_call("eth_getTransactionCount", json!([addr_hex, "pending"]))
                .await?;
            let hex_str = result
                .as_str()
                .ok_or("Invalid transaction count response")?;
            let count = parse_hex_u64(hex_str)?;
            Ok(count)
        }

        async fn get_code(
            &self,
            address: [u8; 20],
        ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
            let addr_hex = format!("0x{}", hex::encode(address));
            let result = self
                .rpc_call("eth_getCode", json!([addr_hex, "latest"]))
                .await?;
            let hex_str = result.as_str().ok_or("Invalid code response")?;
            Ok(parse_hex_bytes(hex_str))
        }

        async fn eth_call(
            &self,
            call: serde_json::Value,
            block: &str,
        ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
            let result = self
                .rpc_call("eth_call", json!([call, block]))
                .await?;
            let hex_str = result.as_str().ok_or("Invalid eth_call response")?;
            Ok(parse_hex_bytes(hex_str))
        }

        async fn eth_get_logs(
            &self,
            filter: serde_json::Value,
        ) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error + Send + Sync>> {
            let result = self
                .rpc_call("eth_getLogs", json!([filter]))
                .await?;
            result
                .as_array()
                .cloned()
                .ok_or("Invalid eth_getLogs response".into())
        }

        fn as_any(&self) -> Option<&dyn std::any::Any> {
            Some(self)
        }
    }

    /// Wait for a transaction receipt with polling and timeout
    pub async fn wait_for_transaction_receipt(
        rpc: &EthereumNode,
        tx_hash: [u8; 32],
        timeout_secs: u64,
    ) -> Result<TransactionReceipt, Box<dyn std::error::Error + Send + Sync>> {
        let start = std::time::Instant::now();
        let poll_interval = std::time::Duration::from_secs(2);

        println!("[Ethereum] Waiting for transaction receipt (timeout: {}s)...", timeout_secs);

        loop {
            if let Some(receipt) = rpc.get_transaction_receipt(tx_hash).await? {
                println!("[Ethereum] Receipt received:");
                println!("[Ethereum]   Status: {}", if receipt.success { "SUCCESS" } else { "FAILED" });
                println!("[Ethereum]   Block number: {}", receipt.block_number);
                println!("[Ethereum]   Gas used: {}", receipt.gas_used);
                println!("[Ethereum]   Logs count: {}", receipt.logs.len());
                if !receipt.success {
                    println!("[Ethereum]   Transaction reverted - this explains why there are no logs");
                }
                return Ok(receipt);
            }

            // Check timeout
            if start.elapsed() > std::time::Duration::from_secs(timeout_secs) {
                return Err(format!("Transaction receipt not found after {} seconds", timeout_secs).into());
            }

            // Wait before next poll
            tokio::time::sleep(poll_interval).await;
        }
    }

    /// Publishes a Sanad-creation transaction: builds calldata -> signs -> broadcasts -> returns tx hash.
    ///
    /// This calls the canonical `create_seal(commitment, sanad_id)` entrypoint, which
    /// anchors the commitment and sets `sanadStates[sanad_id] = Created`. The on-chain
    /// state is keyed by the canonical `sanad_id` so that the state reader
    /// (`sanadStates(sanad_id)`) observes the entry — see BTC-XFER / SANAD-KEY.
    pub async fn publish(
        rpc: &EthereumNode,
        seal: &EthereumSealPoint,
        commitment: [u8; 32],
        sanad_id: [u8; 32],
    ) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
        let signer = rpc
            .signer
            .as_ref()
            .ok_or("No signer configured - call with_signer() first")?;

        let chain_id = rpc.chain_id.ok_or("Chain ID not available")?;

        println!("[Ethereum] Building transaction for create_seal...");
        println!("[Ethereum]   Seal ID: 0x{}", hex::encode(seal.seal_id));
        println!("[Ethereum]   Sanad ID (state key): 0x{}", hex::encode(sanad_id));
        println!("[Ethereum]   Commitment: 0x{}", hex::encode(commitment));
        println!("[Ethereum]   Chain ID: {}", chain_id);

        // Step 1: Build the calldata for create_seal(commitment, sanad_id).
        // The on-chain state must be keyed by the canonical sanad_id (not the
        // commitment, and not the seal_id which encodes contract_address +
        // slot_index + nonce), so the state reader can find the entry.
        let calldata = CsvSealAbi::encode_create_seal(commitment, sanad_id);

        println!("[Ethereum]   Calldata length: {} bytes", calldata.len());
        println!("[Ethereum]   Function selector: 0x{}", hex::encode(&calldata[..4]));

        // Step 2: Get current nonce using "pending" to account for transactions in mempool
        let signer_addr = format!("0x{}", hex::encode(signer.address()));
        println!("[Ethereum]   Signer address: {}", signer_addr);
        let nonce_str = rpc
            .rpc_call("eth_getTransactionCount", json!([signer_addr, "pending"]))
            .await?;
        let nonce_str = nonce_str.as_str().ok_or("Invalid nonce response")?;
        let nonce = u64::from_str_radix(nonce_str.trim_start_matches("0x"), 16)
            .map_err(|e| format!("Failed to parse nonce: {}", e))?;
        println!("[Ethereum]   Nonce: {}", nonce);

        // Step 3: Get gas prices
        let gas_prices = rpc.rpc_call("eth_gasPrice", json!([])).await?;
        let max_fee_str = gas_prices.as_str().ok_or("Invalid gas price response")?;
        let base_fee = u128::from_str_radix(max_fee_str.trim_start_matches("0x"), 16)
            .map_err(|e| format!("Failed to parse gas price: {}", e))?;
        let max_fee_per_gas = base_fee.saturating_mul(15) / 10; // 150% of base
        let max_priority_fee_per_gas = (base_fee / 10).max(1_000_000_000); // At least 1 gwei
        println!("[Ethereum]   Base gas price: {} wei", base_fee);
        println!("[Ethereum]   Max fee per gas: {} wei", max_fee_per_gas);

        // Step 4: Broadcast with retry logic for "replacement transaction underpriced" error
        println!("[Ethereum]   Contract address: 0x{}", hex::encode(rpc.csv_seal_address));
        println!("[Ethereum]   Gas limit: 300,000");
        println!("[Ethereum] Broadcasting transaction...");
        
        let mut current_max_fee = max_fee_per_gas;
        let mut retry_count = 0;
        let max_retries = 3;

        loop {
            // Build and sign transaction with current gas price
            let tx = alloy::consensus::TxEip1559 {
                chain_id,
                nonce,
                max_fee_per_gas: current_max_fee,
                max_priority_fee_per_gas,
                gas_limit: 300_000,
                to: TxKind::Call(rpc.csv_seal_address),
                value: U256::ZERO,
                input: alloy::primitives::Bytes::from(calldata.clone()),
                access_list: Default::default(),
            };

            use alloy::consensus::SignableTransaction;
            use alloy::signers::SignerSync;

            let sig_hash = tx.signature_hash();
            let signature = signer
                .sign_hash_sync(&sig_hash)
                .map_err(|e| format!("Failed to sign transaction: {}", e))?;
            let signed_tx = tx.into_signed(signature);
            let tx_envelope = TxEnvelope::Eip1559(signed_tx);
            let tx_bytes = tx_envelope.encoded_2718();

            let tx_hex = format!("0x{}", hex::encode(&tx_bytes));
            match rpc.send_raw_tx_raw(&tx_hex).await {
                Ok(hash_str) => {
                    println!("[Ethereum] Transaction hash: 0x{}", hash_str.trim_start_matches("0x"));
                    let bytes = hex::decode(hash_str.trim_start_matches("0x"))
                        .map_err(|e| format!("Invalid hex response: {}", e))?;
                    if bytes.len() != 32 {
                        return Err(format!("Expected 32-byte hash, got {} bytes", bytes.len()).into());
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    return Ok(arr);
                }
                Err(e) => {
                    let error_str = e.to_string();
                    if error_str.contains("replacement transaction underpriced") 
                        || error_str.contains("underpriced") {
                        retry_count += 1;
                        if retry_count >= max_retries {
                            return Err(format!(
                                "Failed to send transaction after {} retries: {}",
                                max_retries, e
                            ).into());
                        }
                        
                        // Bump gas price by 20% and retry
                        current_max_fee = current_max_fee.saturating_mul(12) / 10;
                        println!("[Ethereum]   Retry {}/{}: Bumping gas price to {} wei", 
                            retry_count, max_retries, current_max_fee);
                        continue;
                    } else {
                        return Err(format!("Failed to send transaction: {}", e).into());
                    }
                }
            }
        }
    }

    /// Legacy: Build and send a raw transaction that calls `lock_sanad` on the CSVSeal contract.
   /// Expects pre-signed transaction bytes. For signing + sending, use `publish()`.
    pub async fn publish_seal_consumption(
        rpc: &dyn EthereumRpc,
        _seal: &EthereumSealPoint,
        commitment: [u8; 32],
        sanad_id: [u8; 32],
    ) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
        let calldata = CsvSealAbi::encode_create_seal(commitment, sanad_id);
        rpc.send_raw_transaction(calldata).await
    }

    /// Verify that a transaction receipt contains a valid `SanadCreated` event
    /// (emitted by `create_seal`) for the given `sanad_id`/`commitment`.
    ///
    /// `create_seal` emits `SanadCreated(sanadId, commitment, owner, ts)` (both
    /// `sanadId` and `commitment` indexed) plus the legacy `SealUsed(sanadId, commitment)`.
    /// We accept either as proof the creation landed under the canonical key.
    pub fn verify_seal_creation_in_receipt(
        receipt: &TransactionReceipt,
        sanad_id: [u8; 32],
        commitment: [u8; 32],
        csv_seal_address: [u8; 20],
    ) -> bool {
        let sanad_created_sig = CsvSealAbi::sanad_created_event_signature();
        let seal_used_sig = CsvSealAbi::seal_used_event_signature();

        println!("[Ethereum] Verifying create_seal events in receipt...");
        println!("[Ethereum]   Expected sanad_id: 0x{}", hex::encode(sanad_id));
        println!("[Ethereum]   Expected commitment: 0x{}", hex::encode(commitment));

        for log in receipt.logs.iter() {
            if log.address != csv_seal_address {
                continue;
            }

            // Canonical: SanadCreated(sanadId indexed, commitment indexed, ...)
            if log.topics.len() >= 3
                && log.topics[0] == sanad_created_sig
                && log.topics[1] == sanad_id
                && log.topics[2] == commitment
            {
                println!("[Ethereum]   -> SanadCreated event verified!");
                return true;
            }

            // Legacy: SealUsed(sanadId indexed, commitment in data)
            if log.topics.len() >= 2
                && log.topics[0] == seal_used_sig
                && log.topics[1] == sanad_id
                && log.data.len() >= 32
                && log.data[..32] == commitment
            {
                println!("[Ethereum]   -> SealUsed (legacy) event verified!");
                return true;
            }
        }

        println!("[Ethereum]   No matching SanadCreated/SealUsed event found");
        false
    }

    /// Verify that a transaction receipt contains a valid `CrossChainLock` or `SealUsed` event.
    /// The CrossChainLock event signature is: event CrossChainLock(bytes32 indexed sanadId, bytes32 indexed commitment, ...)
    /// - topics[0]: event signature
    /// - topics[1]: indexed sanadId (seal_id)
    /// - topics[2]: indexed commitment
    /// - data: other fields (destinationChain, destinationOwner, etc.)
    pub fn verify_seal_consumption_in_receipt(
        receipt: &TransactionReceipt,
        seal_id: [u8; 32],
        commitment: [u8; 32],
        csv_seal_address: [u8; 20],
    ) -> bool {
        let sanad_locked_sig = CsvSealAbi::sanad_locked_event_signature();
        let cross_chain_sig = CsvSealAbi::cross_chain_lock_event_signature();
        let seal_used_sig = CsvSealAbi::seal_used_event_signature();

        println!("[Ethereum] Verifying events in receipt...");
        println!("[Ethereum]   Expected seal_id: 0x{}", hex::encode(seal_id));
        println!("[Ethereum]   Expected commitment: 0x{}", hex::encode(commitment));
        println!("[Ethereum]   Expected SanadLocked sig: 0x{}", hex::encode(sanad_locked_sig));
        println!("[Ethereum]   Expected CrossChainLock sig: 0x{}", hex::encode(cross_chain_sig));
        println!("[Ethereum]   Expected SealUsed sig: 0x{}", hex::encode(seal_used_sig));
        println!("[Ethereum]   Logs in receipt: {}", receipt.logs.len());

        for (i, log) in receipt.logs.iter().enumerate() {
            println!("[Ethereum]   Log #{}:", i);
            println!("[Ethereum]     Address: 0x{}", hex::encode(log.address));
            println!("[Ethereum]     Topics: {} topics", log.topics.len());
            for (j, topic) in log.topics.iter().enumerate() {
                println!("[Ethereum]       Topic {}: 0x{}", j, hex::encode(topic));
            }
            println!("[Ethereum]     Data length: {} bytes", log.data.len());
            if !log.data.is_empty() {
                println!("[Ethereum]     Data (first 64 bytes): 0x{}", hex::encode(&log.data[..log.data.len().min(64)]));
            }

            if log.address != csv_seal_address {
                println!("[Ethereum]     -> Address mismatch, skipping");
                continue;
            }

            // The deployed contract emits canonical SanadLocked and legacy CrossChainLock
            // with identical indexed fields.
            if log.topics.len() >= 3
                && (log.topics[0] == sanad_locked_sig || log.topics[0] == cross_chain_sig)
            {
                println!("[Ethereum]     -> Sanad lock event signature matches");
                // topics[1] = indexed sanadId, topics[2] = indexed commitment
                if log.topics[1] == seal_id && log.topics[2] == commitment {
                    println!("[Ethereum]     -> Sanad lock event verified!");
                    return true;
                }
                println!("[Ethereum]     -> Sanad lock event: seal_id or commitment mismatch");
            }

            // Also check for SealUsed event (emitted by markSealUsed and lockSanad)
            if log.topics.len() >= 2 && log.topics[0] == seal_used_sig {
                println!("[Ethereum]     -> SealUsed event signature matches");
                if log.topics[1] == seal_id && log.data.len() >= 32 {
                    let mut event_commitment = [0u8; 32];
                    event_commitment.copy_from_slice(&log.data[..32]);
                    if event_commitment == commitment {
                        println!("[Ethereum]     -> SealUsed event verified!");
                        return true;
                    }
                    println!("[Ethereum]     -> SealUsed event: commitment mismatch");
                }
                println!("[Ethereum]     -> SealUsed event: seal_id mismatch or data too short");
            }
        }

        println!("[Ethereum]   No matching events found");
        false
    }
}

#[cfg(feature = "rpc")]
pub use real_rpc_impl::{
    AlloyRpcError, EthereumNode, publish, publish_seal_consumption,
    verify_seal_consumption_in_receipt, verify_seal_creation_in_receipt,
    wait_for_transaction_receipt,
};

#[cfg(all(test, feature = "rpc"))]
mod receipt_tests {
    use super::verify_seal_consumption_in_receipt;
    use crate::rpc::{LogEntry, TransactionReceipt};
    use crate::seal_contract::CsvSealAbi;

    fn receipt(topic: [u8; 32], sanad_id: [u8; 32], commitment: [u8; 32]) -> TransactionReceipt {
        TransactionReceipt {
            tx_hash: [1u8; 32],
            block_number: 11_122_645,
            block_hash: [2u8; 32],
            contract_address: None,
            logs: vec![LogEntry {
                address: [3u8; 20],
                topics: vec![topic, sanad_id, commitment, [0u8; 32]],
                data: vec![0u8; 160],
                log_index: 0,
            }],
            status: 1,
            gas_used: 204_096,
            success: true,
        }
    }

    #[test]
    fn accepts_deployed_sanad_locked_event() {
        let sanad_id = [4u8; 32];
        let commitment = [5u8; 32];
        let receipt = receipt(
            CsvSealAbi::sanad_locked_event_signature(),
            sanad_id,
            commitment,
        );

        assert!(verify_seal_consumption_in_receipt(
            &receipt,
            sanad_id,
            commitment,
            [3u8; 20],
        ));
    }

    #[test]
    fn rejects_deployed_sanad_locked_event_with_wrong_commitment() {
        let sanad_id = [4u8; 32];
        let receipt = receipt(
            CsvSealAbi::sanad_locked_event_signature(),
            sanad_id,
            [5u8; 32],
        );

        assert!(!verify_seal_consumption_in_receipt(
            &receipt,
            sanad_id,
            [6u8; 32],
            [3u8; 20],
        ));
    }
}
