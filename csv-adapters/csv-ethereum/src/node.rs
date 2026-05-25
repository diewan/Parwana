//! Real Ethereum RPC implementation using Alloy with reqwest HTTP transport
//!
//! Only compiled when the `rpc` feature is enabled.
//! Implements the `EthereumRpc` trait using Alloy's JSON-RPC client.

#[cfg(feature = "rpc")]
mod real_rpc_impl {
    use alloy::{
        consensus::TxEnvelope,
        eips::eip2718::Encodable2718,
        primitives::{Address, TxKind, U256, keccak256},
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
        bytes.try_into().map_err(|v: Vec<u8>| format!("must be 32 bytes, got {}", v.len()))
    }

    fn parse_hex_bytes20(s: &str) -> Result<[u8; 20], String> {
        let s = s.trim_start_matches("0x");
        let bytes = hex::decode(s).map_err(|e| format!("Invalid hex: {}", e))?;
        bytes.try_into().map_err(|v: Vec<u8>| format!("must be 20 bytes, got {}", v.len()))
    }

    #[async_trait]
    impl EthereumRpc for EthereumNode {
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

            let account_proof: Vec<Vec<u8>> = proof["accountProof"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(parse_hex_bytes))
                        .collect()
                })
                .unwrap_or_default();

            let storage_proof: Vec<SingleStorageProof> = proof["storageProof"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|sp| {
                            let key_str = sp["key"].as_str()?;
                            let key = parse_hex_bytes32(key_str).ok()?;
                            let value = sp["value"]
                                .as_str()
                                .map(parse_hex_bytes)
                                .unwrap_or_default();
                            let proof_nodes: Vec<Vec<u8>> = sp["proof"]
                                .as_array()
                                .map(|p| {
                                    p.iter()
                                        .filter_map(|v| v.as_str().map(parse_hex_bytes))
                                        .collect()
                                })
                                .unwrap_or_default();
                            Some(SingleStorageProof {
                                key,
                                value,
                                proof: proof_nodes,
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();

            let code_hash_str = proof["codeHash"].as_str().ok_or("Missing codeHash")?;
            let code_hash = parse_hex_bytes32(code_hash_str).map_err(|e| e.to_string())?;
            let storage_hash_str = proof["storageHash"].as_str().ok_or("Missing storageHash")?;
            let storage_hash = parse_hex_bytes32(storage_hash_str).map_err(|e| e.to_string())?;
            
            Ok(StorageProof {
                account_proof,
                balance: proof["balance"].as_str().unwrap_or("0").to_string(),
                code_hash,
                nonce: proof["nonce"].as_str().unwrap_or("0").to_string(),
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

            let logs: Vec<LogEntry> = receipt["logs"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|log| {
                            let address = log["address"].as_str()
                                .and_then(|s| parse_hex_bytes20(s).ok())?;
                            let topics: Vec<[u8; 32]> = log["topics"]
                                .as_array()
                                .map(|t| {
                                    t.iter()
                                        .filter_map(|v| {
                                            v.as_str()
                                                .and_then(|s| parse_hex_bytes32(s).ok())
                                        })
                                        .collect()
                                })
                                .unwrap_or_default();
                            let data = log["data"]
                                .as_str()
                                .map(parse_hex_bytes)
                                .unwrap_or_default();
                            let log_index = log["logIndex"]
                                .as_str()
                                .and_then(|s| parse_hex_u64(s).ok())
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

            let contract_addr = receipt["contractAddress"]
                .as_str()
                .filter(|s| !s.is_empty() && *s != "null")
                .and_then(|s| parse_hex_bytes20(s).ok());

            let status = receipt["status"]
                .as_str()
                .and_then(|s| parse_hex_u64(s).ok())
                .unwrap_or(1);

            let block_number = receipt["blockNumber"]
                .as_str()
                .and_then(|s| parse_hex_u64(s).ok())
                .unwrap_or(0);

            let block_hash = receipt["blockHash"]
                .as_str()
                .and_then(|s| parse_hex_bytes32(s).ok())
                .unwrap_or_default();

            let gas_used = receipt["gasUsed"]
                .as_str()
                .and_then(|s| parse_hex_u64(s).ok())
                .unwrap_or(0);

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
            
            Ok(Some(RpcBlock {
                number: block_number,
                hash,
                state_root,
                timestamp: parse_hex_u64(result["timestamp"].as_str().unwrap_or("0x0"))
                    .unwrap_or(0),
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

            let from = parse_hex_bytes20(result["from"].as_str().unwrap_or("0x0"))
                .map_err(|e| format!("Invalid from address: {}", e))?;
            let to = result["to"]
                .as_str()
                .filter(|s| !s.is_empty() && *s != "null")
                .and_then(|s| parse_hex_bytes20(s).ok());
            let value = result["value"].as_str().and_then(|s| parse_hex_u64(s).ok());
            let gas_price = result["gasPrice"]
                .as_str()
                .and_then(|s| parse_hex_u64(s).ok());
            let gas = parse_hex_u64(result["gas"].as_str().unwrap_or("0x0")).unwrap_or(0);
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
                    let num = b["number"]
                        .as_str()
                        .and_then(|s| parse_hex_u64(s).ok())
                        .unwrap_or(0);
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

        fn as_any(&self) -> Option<&dyn std::any::Any> {
            Some(self)
        }
    }

    /// Publishes a seal consumption transaction: builds calldata -> signs -> broadcasts -> returns tx hash.
    pub async fn publish(
        rpc: &EthereumNode,
        seal: &EthereumSealPoint,
        commitment: [u8; 32],
    ) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
        let signer = rpc
            .signer
            .as_ref()
            .ok_or("No signer configured - call with_signer() first")?;

        let chain_id = rpc.chain_id.ok_or("Chain ID not available")?;

        // Step 1: Build the calldata
        let calldata = CsvSealAbi::encode_mark_seal_used(seal.seal_id, commitment);

        // Step 2: Get current nonce
        let signer_addr = format!("0x{}", hex::encode(signer.address()));
        let nonce_str = rpc
            .rpc_call("eth_getTransactionCount", json!([signer_addr, "latest"]))
            .await?;
        let nonce_str = nonce_str.as_str().ok_or("Invalid nonce response")?;
        let nonce = u64::from_str_radix(nonce_str.trim_start_matches("0x"), 16)
            .map_err(|e| format!("Failed to parse nonce: {}", e))?;

        // Step 3: Get gas prices
        let gas_prices = rpc.rpc_call("eth_gasPrice", json!([])).await?;
        let max_fee_str = gas_prices.as_str().ok_or("Invalid gas price response")?;
        let base_fee = u128::from_str_radix(max_fee_str.trim_start_matches("0x"), 16)
            .map_err(|e| format!("Failed to parse gas price: {}", e))?;
        let max_fee_per_gas = base_fee.saturating_mul(15) / 10; // 150% of base
        let max_priority_fee_per_gas = (base_fee / 10).max(1_000_000_000); // At least 1 gwei

        // Step 4: Build the typed EIP-1559 transaction (pre-signing RLP without signature)
        let _tx_hash = keccak256(&calldata);

        // Build and sign EIP-1559 tx using alloy
        let tx = alloy::consensus::TxEip1559 {
            chain_id,
            nonce,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            gas_limit: 100_000, // Reasonable default for a simple contract call
            to: TxKind::Call(rpc.csv_seal_address),
            value: U256::ZERO,
            input: alloy::primitives::Bytes::from(calldata.clone()),
            access_list: Default::default(),
        };

        // Sign the transaction using SignableTransaction trait + SignerSync
        use alloy::consensus::SignableTransaction;
        use alloy::signers::SignerSync;

        // Calculate the signature hash
        let sig_hash = tx.signature_hash();

        // Sign using the sync signer
        let signature = signer
            .sign_hash_sync(&sig_hash)
            .map_err(|e| format!("Failed to sign transaction: {}", e))?;

        // Convert to signed transaction
        let signed_tx = tx.into_signed(signature);

        // Build the signed transaction envelope and encode using EIP-2718
        let tx_envelope = TxEnvelope::Eip1559(signed_tx);
        let tx_bytes = tx_envelope.encoded_2718();

        // Step 5: Broadcast
        let tx_hex = format!("0x{}", hex::encode(&tx_bytes));
        rpc.send_raw_tx_raw(&tx_hex)
            .await
            .map(|h| {
                let bytes = hex::decode(h.trim_start_matches("0x")).unwrap_or_default();
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes[..32.min(bytes.len())]);
                arr
            })
            .map_err(|e| e.into())
    }

    /// Legacy: Build and send a raw transaction that calls `markSealUsed` on the CSVSeal contract.
    /// Expects pre-signed transaction bytes. For signing + sending, use `publish()`.
    pub async fn publish_seal_consumption(
        rpc: &dyn EthereumRpc,
        seal: &EthereumSealPoint,
        commitment: [u8; 32],
    ) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
        let calldata = CsvSealAbi::encode_mark_seal_used(seal.seal_id, commitment);
        rpc.send_raw_transaction(calldata).await
    }

    /// Verify that a transaction receipt contains a valid `SealUsed` event.
    pub fn verify_seal_consumption_in_receipt(
        receipt: &TransactionReceipt,
        seal_id: [u8; 32],
        commitment: [u8; 32],
        csv_seal_address: [u8; 20],
    ) -> bool {
        let expected_sig = CsvSealAbi::seal_used_event_signature();

        for log in &receipt.logs {
            if log.address != csv_seal_address {
                continue;
            }
            if log.topics.is_empty() || log.topics[0] != expected_sig {
                continue;
            }
            if log.data.len() < 64 {
                continue;
            }

            let mut event_seal_id = [0u8; 32];
            event_seal_id.copy_from_slice(&log.data[..32]);

            let mut event_commitment = [0u8; 32];
            event_commitment.copy_from_slice(&log.data[32..64]);

            if event_seal_id == seal_id && event_commitment == commitment {
                return true;
            }
        }

        false
    }
}

#[cfg(feature = "rpc")]
pub use real_rpc_impl::{
    AlloyRpcError, EthereumNode, publish, publish_seal_consumption,
    verify_seal_consumption_in_receipt,
};
