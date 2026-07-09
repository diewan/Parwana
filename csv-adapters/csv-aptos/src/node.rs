//! Real Aptos RPC client using REST API
//!
//! Implements the Aptos RPC subtraits using Aptos's official REST API.
//! Only compiled when the `rpc` feature is enabled and not targeting wasm32.

#[cfg(all(feature = "rpc", not(target_arch = "wasm32")))]
use std::time::{Duration, Instant};

#[cfg(all(feature = "rpc", not(target_arch = "wasm32")))]
use reqwest::Client;

#[cfg(all(feature = "rpc", not(target_arch = "wasm32")))]
use serde_json::Value;

use crate::address_utils::format_address;
use crate::rpc::{
    AptosAccountReader, AptosBlockInfo, AptosCheckpointVerifier, AptosEvent, AptosEventReader,
    AptosLedgerInfo, AptosLedgerReader, AptosModulePublisher, AptosResource, AptosRpc,
    AptosSignerIdentity, AptosTransaction, AptosTransactionReader, AptosTransactionSubmitter,
    BoxFuture,
};

#[cfg(all(feature = "rpc", not(target_arch = "wasm32")))]
type RpcResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Real Aptos RPC client using REST API
#[cfg(all(feature = "rpc", not(target_arch = "wasm32")))]
pub struct AptosNode {
    client: Client,
    rpc_url: String,
    signer_address: Option<[u8; 32]>,
}

#[cfg(all(feature = "rpc", not(target_arch = "wasm32")))]
impl AptosNode {
    /// Create a new Aptos RPC client
    pub fn new(rpc_url: &str) -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(20))
                .build()
                .unwrap_or_else(|_| Client::new()),
            rpc_url: rpc_url.trim_end_matches('/').to_string(),
            signer_address: None,
        }
    }

    /// Create a new Aptos RPC client with a configured signer address
    pub fn with_signer_address(rpc_url: &str, signer_address: [u8; 32]) -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(20))
                .build()
                .unwrap_or_else(|_| Client::new()),
            rpc_url: rpc_url.trim_end_matches('/').to_string(),
            signer_address: Some(signer_address),
        }
    }

    /// Make a GET request to the Aptos REST API
    async fn get(&self, path: &str) -> RpcResult<Value> {
        // Avoid /v1 duplication if the URL already contains it
        let base = if self.rpc_url.ends_with("/v1") {
            &self.rpc_url
        } else {
            &format!("{}/v1", self.rpc_url)
        };
        let url = format!("{}{}", base, path);
        log::debug!("AptosNode: GET request to {}", url);
        let response = self.client.get(&url).send().await?;
        log::debug!("AptosNode: GET response status: {}", response.status());
        let json: Value = response.json().await?;
        Ok(json)
    }

    /// Make a POST request to the Aptos REST API
    async fn post(&self, path: &str, body: &Value) -> RpcResult<Value> {
        // Avoid /v1 duplication if the URL already contains it
        let base = if self.rpc_url.ends_with("/v1") {
            &self.rpc_url
        } else {
            &format!("{}/v1", self.rpc_url)
        };
        let url = format!("{}{}", base, path);
        let response: Value = self
            .client
            .post(&url)
            .json(body)
            .send()
            .await?
            .json()
            .await?;
        Ok(response)
    }

    fn missing_field(field: &str) -> Box<dyn std::error::Error + Send + Sync> {
        format!(
            "Malformed Aptos RPC response: missing or invalid `{}`",
            field
        )
        .into()
    }

    fn required_field<'a>(value: &'a Value, field: &str) -> RpcResult<&'a Value> {
        value.get(field).ok_or_else(|| Self::missing_field(field))
    }

    fn required_str<'a>(value: &'a Value, field: &str) -> RpcResult<&'a str> {
        Self::required_field(value, field)?
            .as_str()
            .ok_or_else(|| Self::missing_field(field))
    }

    /// Parse hex string to 32-byte array.
    fn parse_hex_bytes(field: &str, hex_str: &str) -> RpcResult<[u8; 32]> {
        let hex = hex_str.trim_start_matches("0x");
        let bytes = hex::decode(hex).map_err(|e| {
            format!(
                "Malformed Aptos RPC response: invalid `{}` hex: {}",
                field, e
            )
        })?;
        let result = bytes.try_into().map_err(|bytes: Vec<u8>| {
            format!(
                "Malformed Aptos RPC response: `{}` must be 32 bytes, got {}",
                field,
                bytes.len()
            )
        })?;
        Ok(result)
    }

    fn required_hex_bytes(value: &Value, field: &str) -> RpcResult<[u8; 32]> {
        Self::parse_hex_bytes(field, Self::required_str(value, field)?)
    }

    fn optional_hex_bytes(value: &Value, field: &str) -> RpcResult<Option<[u8; 32]>> {
        match value.get(field).and_then(Value::as_str) {
            Some(hex) => Self::parse_hex_bytes(field, hex).map(Some),
            None => Ok(None),
        }
    }

    /// Parse u64 from string (Aptos returns numbers as strings)
    fn parse_u64(value: &Value, field: &str) -> RpcResult<u64> {
        if let Some(number) = value.as_u64() {
            return Ok(number);
        }

        let string = value.as_str().ok_or_else(|| Self::missing_field(field))?;
        string.parse::<u64>().map_err(|e| {
            format!(
                "Malformed Aptos RPC response: invalid `{}` integer: {}",
                field, e
            )
            .into()
        })
    }

    fn required_u64(value: &Value, field: &str) -> RpcResult<u64> {
        Self::parse_u64(Self::required_field(value, field)?, field)
    }

    /// Parse a transaction from API response
    fn parse_transaction(result: &Value) -> RpcResult<AptosTransaction> {
        let hash = Self::required_hex_bytes(result, "hash")?;

        // version is optional in some API responses (pending transactions)
        let version = if let Some(v) = result.get("version") {
            Self::parse_u64(v, "version")?
        } else {
            0
        };

        // success is optional in some API responses (pending transactions)
        let success = if let Some(s) = result.get("success") {
            s.as_bool().unwrap_or(false)
        } else {
            false
        };

        let vm_status = if let Some(v) = result.get("vm_status") {
            v.as_str().unwrap_or("unknown").to_string()
        } else {
            "unknown".to_string()
        };

        // epoch and round are optional in some API responses
        let epoch = if let Some(e) = result.get("epoch") {
            Self::parse_u64(e, "epoch").unwrap_or(0)
        } else {
            0
        };
        let round = if let Some(r) = result.get("round") {
            Self::parse_u64(r, "round").unwrap_or(0)
        } else {
            0
        };

        let gas_used = if let Some(g) = result.get("gas_used") {
            Self::parse_u64(g, "gas_used")?
        } else {
            0
        };

        // cumulative_gas_used is optional
        let cumulative_gas_used = if let Some(c) = result.get("cumulative_gas_used") {
            Self::parse_u64(c, "cumulative_gas_used").unwrap_or(0)
        } else {
            0
        };

        // Parse state hashes - these are optional for pending transactions
        let state_change_hash = if let Some(s) = result.get("state_change_hash") {
            Self::required_hex_bytes(result, "state_change_hash")?
        } else {
            [0u8; 32]
        };
        let event_root_hash = if let Some(e) = result.get("event_root_hash") {
            Self::required_hex_bytes(result, "event_root_hash")?
        } else {
            [0u8; 32]
        };
        let state_checkpoint_hash = Self::optional_hex_bytes(result, "state_checkpoint_hash")?;

        // Parse events - optional for pending transactions
        let events = if let Some(e) = result.get("events") {
            e.as_array()
                .ok_or_else(|| Self::missing_field("events"))?
                .iter()
                .map(Self::parse_event)
                .collect::<RpcResult<Vec<_>>>()?
        } else {
            vec![]
        };

        // Parse payload - optional for pending transactions
        let payload = if let Some(p) = result.get("payload") {
            serde_json::to_vec(p)?
        } else {
            vec![]
        };

        Ok(AptosTransaction {
            version,
            hash,
            state_change_hash,
            event_root_hash,
            state_checkpoint_hash,
            epoch,
            round,
            events,
            payload,
            success,
            vm_status,
            gas_used,
            cumulative_gas_used,
        })
    }

    /// Parse an event from API response
    fn parse_event(value: &Value) -> RpcResult<AptosEvent> {
        let guid = Self::required_field(value, "guid")?;
        let event_sequence_number = Self::parse_u64(
            Self::required_field(guid, "creation_number")?,
            "guid.creation_number",
        )?;
        // guid.id.creation_num is optional in some API responses
        let key = guid
            .get("id")
            .and_then(|v| v.get("creation_num"))
            .and_then(Value::as_str)
            .unwrap_or(&event_sequence_number.to_string())
            .to_string();
        let data = if let Some(d) = value.get("data") {
            serde_json::to_vec(d)?
        } else {
            vec![]
        };
        let transaction_version = if let Some(v) = value.get("version") {
            Self::parse_u64(v, "version").unwrap_or(0)
        } else {
            0
        };

        Ok(AptosEvent {
            event_sequence_number,
            key,
            data,
            transaction_version,
        })
    }
}

#[cfg(all(feature = "rpc", not(target_arch = "wasm32")))]
impl AptosLedgerReader for AptosNode {
    fn get_ledger_info(
        &self,
    ) -> BoxFuture<'_, Result<AptosLedgerInfo, Box<dyn std::error::Error + Send + Sync>>> {
        Box::pin(async move {
            let result = self.get("/").await?;
            Ok(AptosLedgerInfo {
                chain_id: Self::required_u64(&result, "chain_id")?,
                epoch: Self::required_u64(&result, "epoch")?,
                ledger_version: Self::required_u64(&result, "ledger_version")?,
                oldest_ledger_version: Self::required_u64(&result, "oldest_ledger_version")?,
                ledger_timestamp: Self::required_u64(&result, "ledger_timestamp")?,
                oldest_transaction_timestamp: Self::parse_u64(
                    result
                        .get("oldest_transaction_timestamp")
                        .unwrap_or(&Value::Number(0.into())),
                    "oldest_transaction_timestamp",
                )
                .unwrap_or(0),
                epoch_start_timestamp: Self::parse_u64(
                    result
                        .get("epoch_start_timestamp")
                        .unwrap_or(&Value::Number(0.into())),
                    "epoch_start_timestamp",
                )
                .unwrap_or(0),
            })
        })
    }

    fn get_latest_version(
        &self,
    ) -> BoxFuture<'_, Result<u64, Box<dyn std::error::Error + Send + Sync>>> {
        Box::pin(async move {
            let ledger = self.get_ledger_info().await?;
            Ok(ledger.ledger_version)
        })
    }
}

#[cfg(all(feature = "rpc", not(target_arch = "wasm32")))]
impl AptosAccountReader for AptosNode {
    fn get_account_sequence_number(
        &self,
        address: [u8; 32],
    ) -> BoxFuture<'_, Result<u64, Box<dyn std::error::Error + Send + Sync>>> {
        Box::pin(async move {
            let addr_str = format_address(address);
            let result = self.get(&format!("/accounts/{}", addr_str)).await?;
            Self::required_u64(&result, "sequence_number")
        })
    }

    fn get_resource(
        &self,
        address: [u8; 32],
        resource_type: &str,
        _position: Option<u64>,
    ) -> BoxFuture<'_, Result<Option<AptosResource>, Box<dyn std::error::Error + Send + Sync>>>
    {
        let resource_type = resource_type.to_string();
        Box::pin(async move {
            let addr_str = format_address(address);

            // For CoinStore resources, use the dedicated /balance endpoint
            // This is more efficient than /resources which returns all account resources
            // Endpoint format: /accounts/{address}/balance/{coin_type}
            if resource_type.contains("CoinStore") && resource_type.contains("AptosCoin") {
                // Extract coin type from CoinStore<T> format
                // e.g., "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>" -> "0x1::aptos_coin::AptosCoin"
                let coin_type = resource_type
                    .strip_prefix("0x1::coin::CoinStore<")
                    .and_then(|s| s.strip_suffix(">"))
                    .ok_or_else(|| {
                        format!("Invalid CoinStore resource type format: {}", resource_type)
                    })?;

                let result = self
                    .get(&format!("/accounts/{}/balance/{}", addr_str, coin_type))
                    .await?;

                // Check if the endpoint returned an error (account not initialized)
                if result.get("error_code").is_some() {
                    // Account doesn't have CoinStore initialized, return zero balance
                    let mut bcs_data = vec![0u8; 8];
                    bcs_data.copy_from_slice(&0u64.to_le_bytes());
                    return Ok(Some(AptosResource { data: bcs_data }));
                }

                if result.is_null() {
                    return Ok(None);
                }

                // /balance endpoint can return either:
                // 1. A direct number: 1000000000
                // 2. An object: { balance: "1000000000" }
                let balance = if result.is_number() {
                    result
                        .as_u64()
                        .ok_or_else(|| format!("Failed to parse balance as number: {:?}", result))?
                } else {
                    let balance_str =
                        result
                            .get("balance")
                            .and_then(|v| v.as_str())
                            .ok_or_else(|| {
                                format!("Failed to extract balance from response: {:?}", result)
                            })?;
                    balance_str
                        .parse::<u64>()
                        .map_err(|e| format!("Failed to parse balance '{}': {}", balance_str, e))?
                };

                // Construct BCS data: coin.value (u64, 8 bytes little-endian) at offset 0
                let mut bcs_data = vec![0u8; 8];
                bcs_data.copy_from_slice(&balance.to_le_bytes());
                return Ok(Some(AptosResource { data: bcs_data }));
            }

            // For non-CoinStore resources, fall back to /resources endpoint
            let result = self
                .get(&format!("/accounts/{}/resources", addr_str))
                .await?;

            if result.is_null() {
                return Ok(None);
            }

            // The response is an array of resources
            let resources = result
                .as_array()
                .ok_or_else(|| format!("Expected array of resources, got: {:?}", result))?;

            // Find the resource matching the requested type
            for resource in resources {
                let res_type = resource.get("type").and_then(|v| v.as_str());
                if res_type != Some(&resource_type) {
                    continue;
                }

                let data = Self::required_field(resource, "data")?;
                let data_bytes = serde_json::to_vec(data)?;
                return Ok(Some(AptosResource { data: data_bytes }));
            }

            // Resource not found
            Ok(None)
        })
    }
}

#[cfg(all(feature = "rpc", not(target_arch = "wasm32")))]
impl AptosTransactionReader for AptosNode {
    fn get_transaction(
        &self,
        version: u64,
    ) -> BoxFuture<'_, Result<Option<AptosTransaction>, Box<dyn std::error::Error + Send + Sync>>>
    {
        Box::pin(async move {
            let result = self.get(&format!("/transactions/{}", version)).await?;
            if result.get("hash").is_none() {
                return Ok(None);
            }
            Ok(Some(Self::parse_transaction(&result)?))
        })
    }

    fn get_transactions(
        &self,
        start_version: u64,
        limit: u32,
    ) -> BoxFuture<'_, Result<Vec<AptosTransaction>, Box<dyn std::error::Error + Send + Sync>>>
    {
        Box::pin(async move {
            let result = self
                .get(&format!(
                    "/transactions?start={}&limit={}",
                    start_version, limit
                ))
                .await?;

            let txs = result
                .as_array()
                .ok_or_else(|| Self::missing_field("transactions"))?
                .iter()
                .map(Self::parse_transaction)
                .collect::<RpcResult<Vec<_>>>()?;
            Ok(txs)
        })
    }

    fn wait_for_transaction(
        &self,
        tx_hash: [u8; 32],
    ) -> BoxFuture<'_, Result<AptosTransaction, Box<dyn std::error::Error + Send + Sync>>> {
        Box::pin(async move {
            let hash_hex = format!("0x{}", hex::encode(tx_hash));
            let start = Instant::now();
            let poll_interval = Duration::from_millis(500); // Poll more frequently (500ms)
            let timeout = Duration::from_secs(20); // 20 second timeout as requested by user

            loop {
                if start.elapsed() > timeout {
                    return Err(format!(
                        "Timeout waiting for transaction confirmation after {} seconds. Hash: {}",
                        timeout.as_secs(),
                        hash_hex
                    )
                    .into());
                }

                log::debug!("Querying transaction by hash: {}", hash_hex);

                // Try the transactions_by_hash endpoint first
                let result = self
                    .get(&format!("/transactions/by_hash/{}", hash_hex))
                    .await;

                match result {
                    Ok(result) => {
                        log::debug!(
                            "Transaction query response: {}",
                            serde_json::to_string(&result).unwrap_or_else(|_| "failed".to_string())
                        );

                        // Check if transaction is found
                        if result.get("hash").is_some() {
                            // Try to parse the transaction
                            match Self::parse_transaction(&result) {
                                Ok(tx) => {
                                    log::debug!(
                                        "Transaction parsed - success: {}, vm_status: {}",
                                        tx.success,
                                        tx.vm_status
                                    );
                                    // Transaction confirmed
                                    if tx.success {
                                        log::debug!(
                                            "Transaction confirmed successfully: {}",
                                            hash_hex
                                        );
                                        return Ok(tx);
                                    }
                                    // Pending states: "unknown" (pre-execution) or "pending" (being processed)
                                    if tx.vm_status == "unknown" || tx.vm_status == "pending" {
                                        log::debug!(
                                            "Transaction still pending (vm_status={}), continuing to wait",
                                            tx.vm_status
                                        );
                                    } else {
                                        return Err(format!(
                                            "Transaction failed: {}",
                                            tx.vm_status
                                        )
                                        .into());
                                    }
                                }
                                Err(e) => {
                                    // If parsing fails due to missing required fields, transaction might still be pending
                                    let error_str = e.to_string();
                                    log::warn!("Transaction parsing failed: {}", error_str);
                                    if error_str.contains("missing")
                                        || error_str.contains("invalid")
                                    {
                                        // Transaction is still pending, continue waiting
                                        log::debug!(
                                            "Transaction still pending ({}), continuing to wait",
                                            error_str
                                        );
                                    } else {
                                        // Other parsing error, return it
                                        return Err(e);
                                    }
                                }
                            }
                        } else {
                            // Transaction not found yet - check if it's a 404 or other error
                            if let Some(error_code) = result.get("error_code") {
                                log::debug!("Transaction lookup returned error: {:?}", error_code);
                            } else {
                                log::debug!("Transaction not found in response");
                            }
                        }
                    }
                    Err(e) => {
                        log::warn!("Failed to query transaction by hash, error: {:?}", e);
                    }
                }

                tokio::time::sleep(poll_interval).await;
            }
        })
    }

    fn get_block_by_version(
        &self,
        version: u64,
    ) -> BoxFuture<'_, Result<Option<AptosBlockInfo>, Box<dyn std::error::Error + Send + Sync>>>
    {
        Box::pin(async move {
            let tx = self.get_transaction(version).await?;
            if let Some(tx) = tx {
                let block_hash = tx.state_checkpoint_hash.ok_or_else(|| {
                    Self::missing_field("state_checkpoint_hash for block derivation")
                })?;
                Ok(Some(AptosBlockInfo {
                    version: tx.version,
                    block_hash,
                    epoch: tx.epoch,
                    round: tx.round,
                    timestamp_usecs: 0,
                }))
            } else {
                Ok(None)
            }
        })
    }

    fn get_transaction_by_version(
        &self,
        version: u64,
    ) -> BoxFuture<'_, Result<Option<AptosTransaction>, Box<dyn std::error::Error + Send + Sync>>>
    {
        Box::pin(async move { self.get_transaction(version).await })
    }

    fn get_transaction_by_hash<'a>(
        &'a self,
        hash: &'a str,
    ) -> BoxFuture<'a, Result<Option<AptosTransaction>, Box<dyn std::error::Error + Send + Sync>>>
    {
        Box::pin(async move {
            let hash_hex = if hash.starts_with("0x") {
                hash.to_string()
            } else {
                format!("0x{}", hash)
            };
            let result = self
                .get(&format!("/transactions/by_hash/{}", hash_hex))
                .await?;
            if result.get("hash").is_none() {
                return Ok(None);
            }
            Ok(Some(Self::parse_transaction(&result)?))
        })
    }
}

#[cfg(all(feature = "rpc", not(target_arch = "wasm32")))]
impl AptosEventReader for AptosNode {
    fn get_events(
        &self,
        event_handle: String,
        _position: String,
        limit: u32,
    ) -> BoxFuture<'_, Result<Vec<AptosEvent>, Box<dyn std::error::Error + Send + Sync>>> {
        Box::pin(async move {
            let result = self
                .get(&format!("/events?handle={}&limit={}", event_handle, limit))
                .await?;
            let events = result
                .as_array()
                .ok_or_else(|| Self::missing_field("events"))?
                .iter()
                .map(Self::parse_event)
                .collect::<RpcResult<Vec<_>>>()?;
            Ok(events)
        })
    }

    fn get_events_by_account(
        &self,
        account: [u8; 32],
        start: u64,
        limit: u32,
    ) -> BoxFuture<'_, Result<Vec<AptosEvent>, Box<dyn std::error::Error + Send + Sync>>> {
        Box::pin(async move {
            let addr_str = format_address(account);
            let result = self
                .get(&format!(
                    "/accounts/{}/events?start={}&limit={}",
                    addr_str, start, limit
                ))
                .await?;

            let events = result
                .as_array()
                .ok_or_else(|| Self::missing_field("events"))?
                .iter()
                .map(Self::parse_event)
                .collect::<RpcResult<Vec<_>>>()?;
            Ok(events)
        })
    }
}

#[cfg(all(feature = "rpc", not(target_arch = "wasm32")))]
impl AptosSignerIdentity for AptosNode {
    fn sender_address(
        &self,
    ) -> BoxFuture<'_, Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>>> {
        Box::pin(async move {
            if let Some(addr) = self.signer_address {
                Ok(addr)
            } else {
                Err(
                    "CapabilityUnavailable: sender_address requires a configured signer. \
                 Use AptosNode::with_signer_address() to configure the signer address."
                        .into(),
                )
            }
        })
    }
}

#[cfg(all(feature = "rpc", not(target_arch = "wasm32")))]
impl AptosTransactionSubmitter for AptosNode {
    fn submit_transaction(
        &self,
        _tx_bytes: Vec<u8>,
    ) -> BoxFuture<'_, Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>>> {
        Box::pin(async move {
            Err("CapabilityUnavailable: BCS-encoded transaction submission not yet implemented.                  Use submit_signed_transaction() with JSON format, or                  implement BCS encoding with proper transaction structure.".into())
        })
    }

    fn submit_signed_transaction(
        &self,
        signed_tx_json: serde_json::Value,
    ) -> BoxFuture<'_, Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>>> {
        Box::pin(async move {
            log::debug!("AptosNode: Submitting transaction to /transactions endpoint");
            log::debug!(
                "AptosNode: Transaction payload: {}",
                serde_json::to_string_pretty(&signed_tx_json)
                    .unwrap_or_else(|_| "failed to serialize".to_string())
            );
            let result = self.post("/transactions", &signed_tx_json).await?;
            log::debug!(
                "AptosNode: Received response: {}",
                serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|_| "failed to serialize".to_string())
            );
            if let Some(hash_hex) = result.get("hash").and_then(|h| h.as_str()) {
                log::debug!(
                    "AptosNode: Transaction submitted successfully, hash: {}",
                    hash_hex
                );
                Ok(Self::parse_hex_bytes("hash", hash_hex)?)
            } else if let Some(error) = result.get("error_code") {
                log::error!(
                    "AptosNode: Transaction submission failed: {} - {:?}",
                    error,
                    result.get("message")
                );
                Err(format!(
                    "Aptos transaction submission failed: {} - {:?}",
                    error,
                    result.get("message")
                )
                .into())
            } else {
                log::error!("AptosNode: Unexpected response: {:?}", result);
                Err(format!("Unexpected Aptos response: {:?}", result).into())
            }
        })
    }
}

#[cfg(all(feature = "rpc", not(target_arch = "wasm32")))]
impl AptosModulePublisher for AptosNode {
    fn publish_module(
        &self,
        _tx_bytes: Vec<u8>,
    ) -> BoxFuture<'_, Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>>> {
        Box::pin(async move {
            Err("CapabilityUnavailable: Module publishing not yet implemented.                  Use submit_signed_transaction() with a properly constructed                  module publish transaction including bytecode and signature.".into())
        })
    }
}

#[cfg(all(feature = "rpc", not(target_arch = "wasm32")))]
impl AptosCheckpointVerifier for AptosNode {
    fn verify_checkpoint(
        &self,
        sequence_number: u64,
    ) -> BoxFuture<'_, Result<bool, Box<dyn std::error::Error + Send + Sync>>> {
        Box::pin(async move {
            Err(format!(
                "CapabilityUnavailable: Aptos checkpoint signature verification is not implemented for sequence {}",
                sequence_number
            )
            .into())
        })
    }
}

#[cfg(all(feature = "rpc", not(target_arch = "wasm32")))]
impl AptosRpc for AptosNode {
    fn clone_boxed(&self) -> Box<dyn AptosRpc> {
        Box::new(AptosNode {
            client: Client::new(),
            rpc_url: self.rpc_url.clone(),
            signer_address: self.signer_address,
        })
    }
}

#[cfg(all(test, feature = "rpc", not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use serde_json::json;

    fn hex32(byte: u8) -> String {
        format!("0x{}", hex::encode([byte; 32]))
    }

    #[test]
    fn parse_hex_bytes_rejects_short_values() {
        let err = AptosNode::parse_hex_bytes("hash", "0x1234").unwrap_err();
        assert!(err.to_string().contains("must be 32 bytes"));
    }

    #[test]
    fn parse_u64_accepts_aptos_string_numbers() {
        let value = json!("42");
        assert_eq!(AptosNode::parse_u64(&value, "version").unwrap(), 42);
    }

    #[test]
    fn parse_transaction_rejects_missing_cryptographic_fields() {
        let tx = json!({
            "hash": hex32(1),
            "version": "1",
            "success": true,
            "vm_status": "Executed",
            "epoch": "1",
            "round": "1",
            "gas_used": "1",
            "cumulative_gas_used": "1",
            "event_root_hash": hex32(3),
            "state_change_hash": "0x1234", // too short (should be 32 bytes)
            "events": [],
            "payload": {}
        });

        let err = AptosNode::parse_transaction(&tx).unwrap_err();
        assert!(err.to_string().contains("must be 32 bytes"));
    }

    #[test]
    fn parse_transaction_rejects_truncated_hashes() {
        let tx = json!({
            "hash": "0x1234",
            "version": "1",
            "success": true,
            "vm_status": "Executed",
            "epoch": "1",
            "round": "1",
            "gas_used": "1",
            "cumulative_gas_used": "1",
            "state_change_hash": hex32(2),
            "event_root_hash": hex32(3),
            "events": [],
            "payload": {}
        });

        let err = AptosNode::parse_transaction(&tx).unwrap_err();
        assert!(err.to_string().contains("hash"));
    }
}
