//! Real Sui RPC client using JSON-RPC over HTTP
//!
//! Implements the SuiRpc trait using Sui's official JSON-RPC API.
//! Only compiled when the `rpc` feature is enabled.

use async_trait::async_trait;
use base64::Engine;
use reqwest::Client;
use serde_json::{Value, json};
use std::time::{Duration, Instant};

use crate::rpc::{
    SuiCheckpoint, SuiEvent, SuiExecutionStatus, SuiLedgerInfo, SuiObject, SuiObjectChange, SuiRpc,
    SuiTransactionBlock, SuiTransactionEffects,
};

/// Real Sui RPC client using JSON-RPC
pub struct SuiNode {
    client: Client,
    rpc_url: String,
}

impl SuiNode {
    /// Create a new Sui RPC client
    pub fn new(rpc_url: &str) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_else(|e| panic!("Failed to build HTTP client: {}", e));
        Self {
            client,
            rpc_url: rpc_url.to_string(),
        }
    }

    /// Call a Sui JSON-RPC method
    async fn rpc_call(
        &self,
        method: &str,
        params: Value,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        let payload = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });

        let response: Value = self
            .client
            .post(&self.rpc_url)
            .json(&payload)
            .send()
            .await?
            .json()
            .await?;

        if let Some(error) = response.get("error") {
            return Err(format!("RPC error: {}", error).into());
        }

        Ok(response.get("result").cloned().unwrap_or(Value::Null))
    }

    /// Parse object ID from Sui response format
    fn parse_object_id_static(
        id_str: &str,
    ) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
        let bytes = hex::decode(id_str.trim_start_matches("0x"))?;
        let mut result = [0u8; 32];
        result.copy_from_slice(&bytes);
        Ok(result)
    }

    /// Parse digest from Sui response format
    fn parse_digest_static(
        digest_str: &str,
    ) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
        let bytes = hex::decode(digest_str)?;
        let mut result = [0u8; 32];
        result.copy_from_slice(&bytes[..32.min(bytes.len())]);
        Ok(result)
    }
}

#[async_trait]
impl SuiRpc for SuiNode {
    async fn get_object(
        &self,
        object_id: [u8; 32],
    ) -> Result<Option<SuiObject>, Box<dyn std::error::Error + Send + Sync>> {
        let id_hex = format!("0x{}", hex::encode(object_id));
        let result = self
            .rpc_call(
                "sui_getObject",
                json!([
                    id_hex,
                    { "showContent": true, "showBcs": true, "showOwner": true }
                ]),
            )
            .await?;

        if result.get("data").is_none() || result["data"].is_null() {
            return Ok(None);
        }

        let data = &result["data"];
        let object_id = Self::parse_object_id_static(data["objectId"].as_str().unwrap_or(""))?;
        let version = data["version"].as_str().unwrap_or("0").parse()?;
        let digest = Self::parse_digest_static(data["digest"].as_str().unwrap_or(""))?;

        Ok(Some(SuiObject {
            object_id,
            version,
            digest,
            owner: data["owner"].to_string().into_bytes(),
            object_type: data["type"].as_str().unwrap_or("").to_string(),
            has_public_transfer: data["hasPublicTransfer"].as_bool().unwrap_or(false),
            bcs_data: data["bcs"].as_str().and_then(|s| hex::decode(s).ok()),
        }))
    }

    async fn get_transaction_block(
        &self,
        digest: [u8; 32],
    ) -> Result<Option<SuiTransactionBlock>, Box<dyn std::error::Error + Send + Sync>> {
        let digest_hex = format!("0x{}", hex::encode(digest));
        let result = self
            .rpc_call(
                "sui_getTransactionBlock",
                json!([
                    digest_hex,
                    { "showInput": true, "showEffects": true, "showEvents": true }
                ]),
            )
            .await?;

        if result.is_null() {
            return Ok(None);
        }

        let effects = &result["effects"];
        let status_str = effects["status"]["status"].as_str().unwrap_or("failure");
        let status = if status_str == "success" {
            SuiExecutionStatus::Success
        } else {
            SuiExecutionStatus::Failure {
                error: effects["status"]["error"]
                    .as_str()
                    .unwrap_or("")
                    .to_string(),
            }
        };

        let checkpoint = result["checkpoint"].as_u64();
        let digest = Self::parse_digest_static(digest_hex.trim_start_matches("0x"))?;

        // Parse modified objects from effects
        let modified_objects: Vec<SuiObjectChange> = effects["modifiedObjects"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|obj| {
                        let id_str = obj["objectId"].as_str()?;
                        let object_id = Self::parse_object_id_static(id_str).ok()?;
                        let change_type = match obj["type"].as_str() {
                            Some(s) => s.to_string(),
                            None => return None,
                        };
                        Some(SuiObjectChange {
                            object_id,
                            change_type,
                        })
                    })
                    .collect()
            })
            .ok_or_else(|| Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "modifiedObjects missing",
            )) as Box<dyn std::error::Error + Send + Sync>)?;

        Ok(Some(SuiTransactionBlock {
            digest,
            checkpoint,
            effects: SuiTransactionEffects {
                status,
                gas_used: effects["gasUsed"].as_u64().ok_or_else(|| Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "gasUsed missing",
                )) as Box<dyn std::error::Error + Send + Sync>)?,
                modified_objects,
            },
        }))
    }

    async fn get_transaction_events(
        &self,
        digest: [u8; 32],
    ) -> Result<Vec<SuiEvent>, Box<dyn std::error::Error + Send + Sync>> {
        let digest_hex = format!("0x{}", hex::encode(digest));
        let result = self
            .rpc_call(
                "sui_getTransactionBlock",
                json!([
                    digest_hex,
                    { "showInput": false, "showEffects": false, "showEvents": true }
                ]),
            )
            .await?;

        let events = result["events"]
            .as_array()
            .ok_or_else(|| Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "events missing",
            )) as Box<dyn std::error::Error + Send + Sync>)?
            .iter()
            .enumerate()
            .map(|(index, event)| {
                let data = event
                    .get("bcs")
                    .and_then(|value| value.as_str())
                    .and_then(|bcs| {
                        base64::engine::general_purpose::STANDARD.decode(bcs).ok()
                    })
                    .or_else(|| {
                        event.get("parsedJson")
                            .and_then(|json| serde_json::to_vec(json).ok())
                    })
                    .ok_or_else(|| Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Failed to decode event data",
                    )) as Box<dyn std::error::Error + Send + Sync>)?;

                let id = event
                    .get("id")
                    .map(|id| id.to_string())
                    .ok_or_else(|| Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "id missing",
                    )) as Box<dyn std::error::Error + Send + Sync>)?;

                let type_field = event
                    .get("type")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "type missing",
                    )) as Box<dyn std::error::Error + Send + Sync>)?
                    .to_string();

                Ok(SuiEvent {
                    id,
                    transaction_digest: digest,
                    event_sequence_number: index as u64,
                    type_field,
                    data,
                })
            })
            .collect::<Result<Vec<_>, Box<dyn std::error::Error + Send + Sync>>>()?;

        Ok(events)
    }

    async fn get_checkpoint(
        &self,
        sequence_number: u64,
    ) -> Result<Option<SuiCheckpoint>, Box<dyn std::error::Error + Send + Sync>> {
        let result = self
            .rpc_call(
                "sui_getCheckpoint",
                json!([
                    sequence_number.to_string(),
                    { "showBcs": true, "showTransactions": false }
                ]),
            )
            .await?;

        if result.is_null() {
            return Ok(None);
        }

        let digest = Self::parse_digest_static(result["digest"].as_str().unwrap_or(""))?;

        Ok(Some(SuiCheckpoint {
            sequence_number,
            digest,
            epoch: result["epoch"].as_str().unwrap_or("0").parse()?,
            network_total_transactions: result["networkTotalTransactions"]
                .as_str()
                .unwrap_or("0")
                .parse()?,
            certified: result["certified"].as_bool().unwrap_or(false),
        }))
    }

    async fn get_latest_checkpoint_sequence_number(
        &self,
    ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        let result = self
            .rpc_call("sui_getLatestCheckpointSequenceNumber", json!([]))
            .await?;
        Ok(result.as_str().unwrap_or("0").parse()?)
    }

    async fn sender_address(&self) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
        // This method requires a configured signer with a known address
        // The SuiNode does not store signing keys - they must be provided externally
        Err(
            "CapabilityUnavailable: sender_address requires a configured signer. \
             Use SuiNode with an external key management system or \
             configure a signer address explicitly."
                .into(),
        )
    }

    async fn get_gas_objects(
        &self,
        owner: [u8; 32],
    ) -> Result<Vec<SuiObject>, Box<dyn std::error::Error + Send + Sync>> {
        let owner_hex = format!("0x{}", hex::encode(owner));
        let result = self
            .rpc_call(
                "suix_getBalance",
                json!([
                    owner_hex,
                    "0x2::sui::SUI" // coin type
                ]),
            )
            .await?;

        // suix_getBalance returns: { totalBalance: string, coinType: string }
        let total_balance = result
            .get("totalBalance")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or_else(|| {
                format!(
                    "Failed to parse totalBalance from suix_getBalance response: {:?}",
                    result
                )
            })?;

        // Construct a single SUI coin object with the total balance
        let mut bcs_data = vec![0u8; 40];
        bcs_data[32..40].copy_from_slice(&total_balance.to_le_bytes());

        Ok(vec![SuiObject {
            object_id: [0u8; 32], // Placeholder object ID
            version: 1,
            digest: [0u8; 32],
            owner: owner.to_vec(),
            object_type: "0x2::coin::Coin<0x2::sui::SUI>".to_string(),
            has_public_transfer: true,
            bcs_data: Some(bcs_data),
        }])
    }

    async fn execute_signed_transaction(
        &self,
        tx_bytes: Vec<u8>,
        signature: Vec<u8>,
        public_key: Vec<u8>,
    ) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
        // Call sui_executeTransactionBlock with signed transaction
        // https://docs.sui.io/sui-jsonrpc#suix_executeTransactionBlock
        let tx_b64 = base64::engine::general_purpose::STANDARD.encode(&tx_bytes);
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&signature);
        let pk_b64 = base64::engine::general_purpose::STANDARD.encode(&public_key);

        let result = self
            .rpc_call(
                "sui_executeTransactionBlock",
                json!([
                    tx_b64,
                    [sig_b64],
                    [pk_b64],
                    {
                        "showInput": true,
                        "showEffects": true,
                        "showEvents": true
                    }
                ]),
            )
            .await?;

        // Parse the response to get the transaction digest
        if let Some(digest) = result.get("digest").and_then(|d| d.as_str()) {
            Self::parse_digest_static(digest.trim_start_matches("0x"))
        } else {
            Err(format!("Failed to execute transaction: {:?}", result.get("error")).into())
        }
    }

    async fn wait_for_transaction(
        &self,
        digest: [u8; 32],
        timeout_ms: u64,
    ) -> Result<Option<SuiTransactionBlock>, Box<dyn std::error::Error + Send + Sync>> {
        let start = Instant::now();
        let poll_interval = Duration::from_millis(2000);

        loop {
            if start.elapsed() > Duration::from_millis(timeout_ms) {
                return Err("Timeout waiting for transaction confirmation".into());
            }

            if let Some(block) = self.get_transaction_block(digest).await? {
                if matches!(block.effects.status, SuiExecutionStatus::Success) {
                    return Ok(Some(block));
                }
            }

            tokio::time::sleep(poll_interval).await;
        }
    }

    async fn get_ledger_info(
        &self,
    ) -> Result<SuiLedgerInfo, Box<dyn std::error::Error + Send + Sync>> {
        let latest_checkpoint = self.get_latest_checkpoint_sequence_number().await?;
        let checkpoint = self.get_checkpoint(latest_checkpoint).await?;

        Ok(SuiLedgerInfo {
            latest_version: checkpoint
                .as_ref()
                .map(|c| c.network_total_transactions)
                .unwrap_or(0),
            latest_epoch: checkpoint.map(|c| c.epoch).unwrap_or(0),
        })
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn clone_boxed(&self) -> Box<dyn SuiRpc> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_else(|e| panic!("Failed to build HTTP client: {}", e));
        Box::new(SuiNode {
            client,
            rpc_url: self.rpc_url.clone(),
        })
    }
}
