//! Real Aptos RPC client using REST API
//!
//! Implements the AptosRpc trait using Aptos's official REST API.
//! Only compiled when the `rpc` feature is enabled.

use std::time::{Duration, Instant};

use reqwest::Client;
use serde_json::Value;

use crate::address_utils::format_address;
use crate::rpc::{
    AptosBlockInfo, AptosEvent, AptosLedgerInfo, AptosResource, AptosRpc, AptosTransaction,
    BoxFuture,
};

type RpcResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Real Aptos RPC client using REST API
pub struct AptosNode {
    client: Client,
    rpc_url: String,
}

impl AptosNode {
    /// Create a new Aptos RPC client
    pub fn new(rpc_url: &str) -> Self {
        Self {
            client: Client::new(),
            rpc_url: rpc_url.trim_end_matches('/').to_string(),
        }
    }

    /// Make a GET request to the Aptos REST API
    async fn get(&self, path: &str) -> RpcResult<Value> {
        let url = format!("{}/v1{}", self.rpc_url, path);
        let response: Value = self.client.get(&url).send().await?.json().await?;
        Ok(response)
    }

    /// Make a POST request to the Aptos REST API
    async fn post(&self, path: &str, body: &Value) -> RpcResult<Value> {
        let url = format!("{}/v1{}", self.rpc_url, path);
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

    fn required_bool(value: &Value, field: &str) -> RpcResult<bool> {
        Self::required_field(value, field)?
            .as_bool()
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
        let version = Self::required_u64(result, "version")?;
        let success = Self::required_bool(result, "success")?;
        let vm_status = Self::required_str(result, "vm_status")?.to_string();
        let epoch = Self::required_u64(result, "epoch")?;
        let round = Self::required_u64(result, "round")?;
        let gas_used = Self::required_u64(result, "gas_used")?;
        let cumulative_gas_used = Self::required_u64(result, "cumulative_gas_used")?;

        // Parse state hashes
        let state_change_hash = Self::required_hex_bytes(result, "state_change_hash")?;
        let event_root_hash = Self::required_hex_bytes(result, "event_root_hash")?;
        let state_checkpoint_hash = Self::optional_hex_bytes(result, "state_checkpoint_hash")?;

        // Parse events
        let events = Self::required_field(result, "events")?
            .as_array()
            .ok_or_else(|| Self::missing_field("events"))?
            .iter()
            .map(Self::parse_event)
            .collect::<RpcResult<Vec<_>>>()?;

        // Parse payload
        let payload = serde_json::to_vec(Self::required_field(result, "payload")?)?;

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
        let key = Self::required_field(guid, "id")?
            .get("creation_num")
            .and_then(Value::as_str)
            .ok_or_else(|| Self::missing_field("guid.id.creation_num"))?
            .to_string();
        let data = serde_json::to_vec(Self::required_field(value, "data")?)?;
        let transaction_version = Self::required_u64(value, "version")?;

        Ok(AptosEvent {
            event_sequence_number,
            key,
            data,
            transaction_version,
        })
    }
}

impl AptosRpc for AptosNode {
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
                oldest_transaction_timestamp: Self::required_u64(
                    &result,
                    "oldest_transaction_timestamp",
                )?,
                epoch_start_timestamp: Self::required_u64(&result, "epoch_start_timestamp")?,
            })
        })
    }

    fn sender_address(
        &self,
    ) -> BoxFuture<'_, Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>>> {
        Box::pin(async move {
            Err("CapabilityUnavailable: sender_address requires a configured signer.                  Use AptosNode with an external key management system or                  configure a signer address explicitly.".into())
        })
    }

    fn get_account_sequence_number(
        &self,
        address: [u8; 32],
    ) -> BoxFuture<'_, Result<u64, Box<dyn std::error::Error + Send + Sync>>> {
        Box::pin(async move {
            let addr_str = format_address(address);
            let result = self.get(&format!("/accounts/{}", addr_str)).await?;
            Ok(Self::required_u64(&result, "sequence_number")?)
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
            let result = self
                .get(&format!(
                    "/accounts/{}/resource/{}",
                    addr_str, resource_type
                ))
                .await?;

            if result.is_null() || result.get("type").is_none() {
                return Ok(None);
            }

            let data_bytes = serde_json::to_vec(Self::required_field(&result, "data")?)?;
            Ok(Some(AptosResource { data: data_bytes }))
        })
    }

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
            let result = self.post("/transactions", &signed_tx_json).await?;
            if let Some(hash_hex) = result.get("hash").and_then(|h| h.as_str()) {
                Ok(Self::parse_hex_bytes("hash", hash_hex)?)
            } else if let Some(error) = result.get("error_code") {
                Err(format!(
                    "Aptos transaction submission failed: {} - {:?}",
                    error,
                    result.get("message")
                )
                .into())
            } else {
                Err(format!("Unexpected Aptos response: {:?}", result).into())
            }
        })
    }

    fn wait_for_transaction(
        &self,
        tx_hash: [u8; 32],
    ) -> BoxFuture<'_, Result<AptosTransaction, Box<dyn std::error::Error + Send + Sync>>> {
        Box::pin(async move {
            let hash_hex = format!("0x{}", hex::encode(tx_hash));
            let timeout = Duration::from_secs(60);
            let start = Instant::now();
            let poll_interval = Duration::from_secs(2);

            loop {
                if start.elapsed() > timeout {
                    return Err("Timeout waiting for transaction confirmation".into());
                }

                if let Ok(result) = self
                    .get(&format!("/transactions/by_hash/{}", hash_hex))
                    .await
                {
                    if result.get("hash").is_some() {
                        let tx = Self::parse_transaction(&result)?;
                        if tx.success {
                            return Ok(tx);
                        } else {
                            return Err(format!("Transaction failed: {}", tx.vm_status).into());
                        }
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

    fn get_latest_version(
        &self,
    ) -> BoxFuture<'_, Result<u64, Box<dyn std::error::Error + Send + Sync>>> {
        Box::pin(async move {
            let ledger = self.get_ledger_info().await?;
            Ok(ledger.ledger_version)
        })
    }

    fn get_transaction_by_version(
        &self,
        version: u64,
    ) -> BoxFuture<'_, Result<Option<AptosTransaction>, Box<dyn std::error::Error + Send + Sync>>>
    {
        Box::pin(async move { self.get_transaction(version).await })
    }

    fn publish_module(
        &self,
        _tx_bytes: Vec<u8>,
    ) -> BoxFuture<'_, Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>>> {
        Box::pin(async move {
            Err("CapabilityUnavailable: Module publishing not yet implemented.                  Use submit_signed_transaction() with a properly constructed                  module publish transaction including bytecode and signature.".into())
        })
    }

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

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn clone_boxed(&self) -> Box<dyn AptosRpc> {
        Box::new(AptosNode::new(&self.rpc_url))
    }
}

#[cfg(test)]
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
            "events": [],
            "payload": {}
        });

        let err = AptosNode::parse_transaction(&tx).unwrap_err();
        assert!(err.to_string().contains("state_change_hash"));
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
