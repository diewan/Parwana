//! Aptos RPC trait and test implementation

use std::future::Future;
use std::pin::Pin;

pub(crate) type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Aptos ledger read capability.
pub trait AptosLedgerReader: Send + Sync + 'static {
    fn get_ledger_info(
        &self,
    ) -> BoxFuture<'_, Result<AptosLedgerInfo, Box<dyn std::error::Error + Send + Sync>>>;

    fn get_latest_version(
        &self,
    ) -> BoxFuture<'_, Result<u64, Box<dyn std::error::Error + Send + Sync>>>;
}

/// Aptos account/resource read capability.
pub trait AptosAccountReader: Send + Sync + 'static {
    fn get_account_sequence_number(
        &self,
        address: [u8; 32],
    ) -> BoxFuture<'_, Result<u64, Box<dyn std::error::Error + Send + Sync>>>;

    fn get_resource(
        &self,
        address: [u8; 32],
        resource_type: &str,
        position: Option<u64>,
    ) -> BoxFuture<'_, Result<Option<AptosResource>, Box<dyn std::error::Error + Send + Sync>>>;
}

/// Aptos transaction read capability.
pub trait AptosTransactionReader: Send + Sync + 'static {
    fn get_transaction(
        &self,
        version: u64,
    ) -> BoxFuture<'_, Result<Option<AptosTransaction>, Box<dyn std::error::Error + Send + Sync>>>;

    fn get_transactions(
        &self,
        start_version: u64,
        limit: u32,
    ) -> BoxFuture<'_, Result<Vec<AptosTransaction>, Box<dyn std::error::Error + Send + Sync>>>;

    fn wait_for_transaction(
        &self,
        tx_hash: [u8; 32],
    ) -> BoxFuture<'_, Result<AptosTransaction, Box<dyn std::error::Error + Send + Sync>>>;

    fn get_block_by_version(
        &self,
        version: u64,
    ) -> BoxFuture<'_, Result<Option<AptosBlockInfo>, Box<dyn std::error::Error + Send + Sync>>>;

    fn get_transaction_by_version(
        &self,
        version: u64,
    ) -> BoxFuture<'_, Result<Option<AptosTransaction>, Box<dyn std::error::Error + Send + Sync>>>;

    fn get_transaction_by_hash<'a>(
        &'a self,
        hash: &'a str,
    ) -> BoxFuture<'a, Result<Option<AptosTransaction>, Box<dyn std::error::Error + Send + Sync>>>;
}

/// Aptos event read capability.
pub trait AptosEventReader: Send + Sync + 'static {
    fn get_events(
        &self,
        event_handle: String,
        position: String,
        limit: u32,
    ) -> BoxFuture<'_, Result<Vec<AptosEvent>, Box<dyn std::error::Error + Send + Sync>>>;

    fn get_events_by_account(
        &self,
        account: [u8; 32],
        start: u64,
        limit: u32,
    ) -> BoxFuture<'_, Result<Vec<AptosEvent>, Box<dyn std::error::Error + Send + Sync>>>;
}

/// Aptos signer identity capability.
pub trait AptosSignerIdentity: Send + Sync + 'static {
    /// Get the sender's account address.
    fn sender_address(
        &self,
    ) -> BoxFuture<'_, Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>>>;
}

/// Aptos transaction submission capability.
pub trait AptosTransactionSubmitter: Send + Sync + 'static {
    fn submit_transaction(
        &self,
        tx_bytes: Vec<u8>,
    ) -> BoxFuture<'_, Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>>>;

    /// Submit a signed transaction as JSON to the Aptos REST API.
    fn submit_signed_transaction(
        &self,
        signed_tx_json: serde_json::Value,
    ) -> BoxFuture<'_, Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>>>;
}

/// Read-only Move view-function capability.
pub trait AptosViewReader: Send + Sync + 'static {
    fn call_view<'a>(
        &'a self,
        function: &'a str,
        arguments: Vec<serde_json::Value>,
    ) -> BoxFuture<'a, Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>>>;
}

/// Aptos module publishing capability.
pub trait AptosModulePublisher: Send + Sync + 'static {
    fn publish_module(
        &self,
        tx_bytes: Vec<u8>,
    ) -> BoxFuture<'_, Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>>>;
}

/// Aptos checkpoint verification capability.
pub trait AptosCheckpointVerifier: Send + Sync + 'static {
    fn verify_checkpoint(
        &self,
        sequence_number: u64,
    ) -> BoxFuture<'_, Result<bool, Box<dyn std::error::Error + Send + Sync>>>;
}

/// Composite Aptos RPC trait combining multiple capabilities.
///
/// This trait combines the most commonly used subtraits for convenience
/// in situations where multiple capabilities are needed (e.g., seal_protocol).
/// For new code, prefer depending on the narrowest possible trait bound
/// to enforce least privilege:
/// - AptosLedgerReader for ledger info
/// - AptosAccountReader for account resources
/// - AptosTransactionReader for transaction queries
/// - AptosEventReader for event queries
/// - AptosSignerIdentity for signer operations
/// - AptosTransactionSubmitter for transaction submission
/// - AptosModulePublisher for module publishing
/// - AptosCheckpointVerifier for checkpoint verification
pub trait AptosRpc:
    AptosLedgerReader
    + AptosAccountReader
    + AptosTransactionReader
    + AptosEventReader
    + AptosSignerIdentity
    + AptosTransactionSubmitter
    + AptosViewReader
    + AptosModulePublisher
    + AptosCheckpointVerifier
    + Send
    + Sync
    + 'static
{
    /// Clone the RPC client for creating new boxed instances
    fn clone_boxed(&self) -> Box<dyn AptosRpc>;
}

// Blanket impls removed to enforce least privilege.
// Callers must now explicitly depend on the specific subtraits they need.
// This prevents accidental access to privileged operations (e.g., module publishing).

/// Aptos ledger info
#[derive(Clone, Debug, serde::Serialize)]
pub struct AptosLedgerInfo {
    pub chain_id: u64,
    pub epoch: u64,
    pub ledger_version: u64,
    pub oldest_ledger_version: u64,
    pub ledger_timestamp: u64,
    pub oldest_transaction_timestamp: u64,
    pub epoch_start_timestamp: u64,
}

/// Aptos resource
#[derive(Clone, Debug)]
pub struct AptosResource {
    pub data: Vec<u8>,
}

impl AptosResource {
    /// Parse coin balance from BCS-encoded CoinStore resource data
    ///
    /// Aptos CoinStore<T> has the following BCS structure:
    /// - coin: Coin<T> { value: u64 }
    /// - frozen: bool
    /// - deposit_events: EventHandle
    /// - withdraw_events: EventHandle
    ///
    /// The BCS layout for CoinStore<0x1::aptos_coin::AptosCoin>:
    /// - coin.value: u64 (8 bytes, little-endian) at offset 0
    pub fn parse_coin_balance(&self) -> Option<u64> {
        if self.data.len() < 8 {
            return None;
        }

        let value_bytes = &self.data[0..8];
        let balance = u64::from_le_bytes([
            value_bytes[0],
            value_bytes[1],
            value_bytes[2],
            value_bytes[3],
            value_bytes[4],
            value_bytes[5],
            value_bytes[6],
            value_bytes[7],
        ]);

        Some(balance)
    }

    /// Parse a u64 field from JSON-encoded resource data
    ///
    /// This is used when the resource data is in JSON format (from REST API)
    /// rather than BCS format. The field_name should be the key in the JSON object.
    pub fn parse_u64_field(&self, field_name: &str) -> Result<u64, String> {
        // Try to parse as JSON first
        if let Ok(json_value) = serde_json::from_slice::<serde_json::Value>(&self.data) {
            if let Some(value) = json_value.get(field_name) {
                if let Some(num) = value.as_u64() {
                    return Ok(num);
                }
                if let Some(str) = value.as_str() {
                    return str
                        .parse::<u64>()
                        .map_err(|e| format!("Failed to parse {} as u64: {}", field_name, e));
                }
            }
            return Err(format!("Field '{}' not found in JSON data", field_name));
        }

        // Fallback to BCS parsing (first 8 bytes as little-endian u64)
        if self.data.len() < 8 {
            return Err("Data too short for u64 field".to_string());
        }

        let value_bytes = &self.data[0..8];
        Ok(u64::from_le_bytes([
            value_bytes[0],
            value_bytes[1],
            value_bytes[2],
            value_bytes[3],
            value_bytes[4],
            value_bytes[5],
            value_bytes[6],
            value_bytes[7],
        ]))
    }
}

/// Aptos transaction
#[derive(Clone, Debug)]
pub struct AptosTransaction {
    pub version: u64,
    pub hash: [u8; 32],
    pub state_change_hash: [u8; 32],
    pub event_root_hash: [u8; 32],
    pub state_checkpoint_hash: Option<[u8; 32]>,
    pub epoch: u64,
    pub round: u64,
    pub events: Vec<AptosEvent>,
    pub payload: Vec<u8>,
    pub success: bool,
    pub vm_status: String,
    pub gas_used: u64,
    pub cumulative_gas_used: u64,
}

/// Aptos event
#[derive(Clone, Debug)]
pub struct AptosEvent {
    pub event_sequence_number: u64,
    pub key: String,
    pub data: Vec<u8>,
    pub transaction_version: u64,
}

/// Aptos block info
#[derive(Clone, Debug)]
pub struct AptosBlockInfo {
    pub version: u64,
    pub block_hash: [u8; 32],
    pub epoch: u64,
    pub round: u64,
    pub timestamp_usecs: u64,
}

/// Mock Aptos RPC for testing
pub struct MockAptosRpc {
    pub latest_version: u64,
    pub chain_id: u64,
    pub test_address: [u8; 32],
    pub tx_counter: std::sync::atomic::AtomicU64,
    pub stale_submissions_remaining: std::sync::atomic::AtomicU64,
    pub resources: std::sync::Mutex<std::collections::HashMap<([u8; 32], String), AptosResource>>,
    pub transactions: std::sync::Mutex<std::collections::HashMap<u64, AptosTransaction>>,
    pub events: std::sync::Mutex<std::collections::HashMap<String, Vec<AptosEvent>>>,
    pub blocks: std::sync::Mutex<std::collections::HashMap<u64, AptosBlockInfo>>,
    pub sent_transactions: std::sync::Mutex<Vec<Vec<u8>>>,
    pub next_tx_events: std::sync::Mutex<Vec<AptosEvent>>,
    pub view_results: std::sync::Mutex<std::collections::HashMap<String, serde_json::Value>>,
}

impl MockAptosRpc {
    pub fn new(latest_version: u64) -> Self {
        Self {
            latest_version,
            chain_id: 1,
            test_address: [0x42; 32],
            tx_counter: std::sync::atomic::AtomicU64::new(0),
            stale_submissions_remaining: std::sync::atomic::AtomicU64::new(0),
            resources: std::sync::Mutex::new(std::collections::HashMap::new()),
            transactions: std::sync::Mutex::new(std::collections::HashMap::new()),
            events: std::sync::Mutex::new(std::collections::HashMap::new()),
            sent_transactions: std::sync::Mutex::new(Vec::new()),
            blocks: std::sync::Mutex::new(std::collections::HashMap::new()),
            next_tx_events: std::sync::Mutex::new(Vec::new()),
            view_results: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    pub fn set_view_result(&self, function: &str, result: serde_json::Value) {
        self.view_results
            .lock()
            .expect("mutex not poisoned")
            .insert(function.to_string(), result);
    }

    pub fn reject_next_submissions_as_stale(&self, count: u64) {
        self.stale_submissions_remaining
            .store(count, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn with_chain_id(latest_version: u64, chain_id: u64) -> Self {
        Self {
            latest_version,
            chain_id,
            ..Self::new(latest_version)
        }
    }

    pub fn set_resource(&self, address: [u8; 32], resource_type: &str, resource: AptosResource) {
        self.resources
            .lock()
            .expect("mutex not poisoned")
            .insert((address, resource_type.to_string()), resource);
    }

    pub fn add_transaction(&self, version: u64, tx: AptosTransaction) {
        self.transactions
            .lock()
            .expect("mutex not poisoned")
            .insert(version, tx);
    }

    pub fn add_event(&self, handle: &str, event: AptosEvent) {
        self.events
            .lock()
            .expect("mutex not poisoned")
            .entry(handle.to_string())
            .or_default()
            .push(event);
    }

    pub fn add_events(&self, handle: &str, events: Vec<AptosEvent>) {
        self.events
            .lock()
            .expect("mutex not poisoned")
            .entry(handle.to_string())
            .or_default()
            .extend(events);
    }

    pub fn set_block(&self, version: u64, block: AptosBlockInfo) {
        self.blocks
            .lock()
            .expect("mutex not poisoned")
            .insert(version, block);
    }
}

// Implement specific subtraits for MockAptosRpc
impl AptosLedgerReader for MockAptosRpc {
    fn get_ledger_info(
        &self,
    ) -> BoxFuture<'_, Result<AptosLedgerInfo, Box<dyn std::error::Error + Send + Sync>>> {
        Box::pin(async {
            Ok(AptosLedgerInfo {
                chain_id: self.chain_id,
                epoch: 1,
                ledger_version: self.latest_version,
                oldest_ledger_version: 0,
                ledger_timestamp: 0,
                oldest_transaction_timestamp: 0,
                epoch_start_timestamp: 0,
            })
        })
    }

    fn get_latest_version(
        &self,
    ) -> BoxFuture<'_, Result<u64, Box<dyn std::error::Error + Send + Sync>>> {
        Box::pin(async { Ok(self.latest_version) })
    }
}

impl AptosAccountReader for MockAptosRpc {
    fn get_account_sequence_number(
        &self,
        _address: [u8; 32],
    ) -> BoxFuture<'_, Result<u64, Box<dyn std::error::Error + Send + Sync>>> {
        Box::pin(async { Ok(0) })
    }

    fn get_resource(
        &self,
        address: [u8; 32],
        resource_type: &str,
        _position: Option<u64>,
    ) -> BoxFuture<'_, Result<Option<AptosResource>, Box<dyn std::error::Error + Send + Sync>>>
    {
        let resource_type_owned = resource_type.to_string();
        let key = (address, resource_type_owned);
        let result = self
            .resources
            .lock()
            .expect("mutex not poisoned")
            .get(&key)
            .cloned();
        Box::pin(async move { Ok(result) })
    }
}

impl AptosTransactionReader for MockAptosRpc {
    fn get_transaction(
        &self,
        version: u64,
    ) -> BoxFuture<'_, Result<Option<AptosTransaction>, Box<dyn std::error::Error + Send + Sync>>>
    {
        let result = self
            .transactions
            .lock()
            .expect("mutex not poisoned")
            .get(&version)
            .cloned();
        Box::pin(async move { Ok(result) })
    }

    fn get_transactions(
        &self,
        _start_version: u64,
        _limit: u32,
    ) -> BoxFuture<'_, Result<Vec<AptosTransaction>, Box<dyn std::error::Error + Send + Sync>>>
    {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn wait_for_transaction(
        &self,
        _tx_hash: [u8; 32],
    ) -> BoxFuture<'_, Result<AptosTransaction, Box<dyn std::error::Error + Send + Sync>>> {
        Box::pin(async move {
            Ok(AptosTransaction {
                version: self.latest_version,
                hash: _tx_hash,
                state_change_hash: [0u8; 32],
                event_root_hash: [0u8; 32],
                state_checkpoint_hash: None,
                epoch: 1,
                round: 0,
                events: vec![],
                payload: vec![],
                success: true,
                vm_status: "Executed".to_string(),
                gas_used: 100,
                cumulative_gas_used: 100,
            })
        })
    }

    fn get_block_by_version(
        &self,
        version: u64,
    ) -> BoxFuture<'_, Result<Option<AptosBlockInfo>, Box<dyn std::error::Error + Send + Sync>>>
    {
        let result = self
            .blocks
            .lock()
            .expect("mutex not poisoned")
            .get(&version)
            .cloned();
        Box::pin(async move { Ok(result) })
    }

    fn get_transaction_by_version(
        &self,
        version: u64,
    ) -> BoxFuture<'_, Result<Option<AptosTransaction>, Box<dyn std::error::Error + Send + Sync>>>
    {
        let result = self
            .transactions
            .lock()
            .expect("mutex not poisoned")
            .get(&version)
            .cloned();
        Box::pin(async move { Ok(result) })
    }

    fn get_transaction_by_hash(
        &self,
        _hash: &str,
    ) -> BoxFuture<'_, Result<Option<AptosTransaction>, Box<dyn std::error::Error + Send + Sync>>>
    {
        Box::pin(async move { Ok(None) })
    }
}

impl AptosEventReader for MockAptosRpc {
    fn get_events(
        &self,
        event_handle: String,
        _position: String,
        limit: u32,
    ) -> BoxFuture<'_, Result<Vec<AptosEvent>, Box<dyn std::error::Error + Send + Sync>>> {
        Box::pin(async move {
            Ok(self
                .events
                .lock()
                .expect("mutex not poisoned")
                .get(&event_handle)
                .cloned()
                .ok_or_else(|| {
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("Event handle {} not found", event_handle),
                    )) as Box<dyn std::error::Error + Send + Sync>
                })?
                .into_iter()
                .take(limit as usize)
                .collect())
        })
    }

    fn get_events_by_account(
        &self,
        _account: [u8; 32],
        start: u64,
        limit: u32,
    ) -> BoxFuture<'_, Result<Vec<AptosEvent>, Box<dyn std::error::Error + Send + Sync>>> {
        Box::pin(async move {
            let events = self.events.lock().expect("mutex not poisoned");
            Ok(events
                .values()
                .flatten()
                .skip(start as usize)
                .take(limit as usize)
                .cloned()
                .collect())
        })
    }
}

impl AptosSignerIdentity for MockAptosRpc {
    fn sender_address(
        &self,
    ) -> BoxFuture<'_, Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>>> {
        Box::pin(async { Ok(self.test_address) })
    }
}

impl AptosTransactionSubmitter for MockAptosRpc {
    fn submit_transaction(
        &self,
        tx_bytes: Vec<u8>,
    ) -> BoxFuture<'_, Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>>> {
        Box::pin(async move {
            self.sent_transactions
                .lock()
                .expect("mutex not poisoned")
                .push(tx_bytes);
            Ok([0xAB; 32])
        })
    }

    fn submit_signed_transaction(
        &self,
        signed_tx_json: serde_json::Value,
    ) -> BoxFuture<'_, Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>>> {
        Box::pin(async move {
            if self
                .stale_submissions_remaining
                .fetch_update(
                    std::sync::atomic::Ordering::SeqCst,
                    std::sync::atomic::Ordering::SeqCst,
                    |remaining| remaining.checked_sub(1),
                )
                .is_ok()
            {
                return Err("Invalid transaction: SEQUENCE_NUMBER_TOO_OLD".into());
            }
            let tx_bytes = serde_json::to_vec(&signed_tx_json).map_err(|e| {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Failed to serialize transaction: {}", e),
                )) as Box<dyn std::error::Error + Send + Sync>
            })?;
            self.sent_transactions
                .lock()
                .expect("mutex not poisoned")
                .push(tx_bytes);

            if let Some(payload) = signed_tx_json.get("payload")
                && payload
                    .get("function")
                    .and_then(|value| value.as_str())
                    .is_some_and(|function| function.ends_with("::consume_seal"))
            {
                if let Some(args) = payload.get("arguments").and_then(|a| a.as_array()) {
                    if !args.is_empty() {
                        let commit_str = args[0].as_str().ok_or_else(|| {
                            Box::new(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "Commitment argument is not a string",
                            ))
                                as Box<dyn std::error::Error + Send + Sync>
                        })?;
                        let commitment = if let Some(hex) = commit_str.strip_prefix("0x") {
                            hex::decode(hex).map_err(|e| {
                                Box::new(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    format!("Failed to decode hex commitment: {}", e),
                                ))
                                    as Box<dyn std::error::Error + Send + Sync>
                            })?
                        } else {
                            hex::decode(commit_str).map_err(|e| {
                                Box::new(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    format!("Failed to decode hex commitment: {}", e),
                                ))
                                    as Box<dyn std::error::Error + Send + Sync>
                            })?
                        };

                        if commitment.len() != 32 {
                            return Err(Box::new(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                format!("Commitment must be 32 bytes, got {}", commitment.len()),
                            ))
                                as Box<dyn std::error::Error + Send + Sync>);
                        }

                        let mut event_data = vec![0u8; 96];
                        event_data[31] = 0x01;
                        event_data[32..64].copy_from_slice(&self.test_address);
                        event_data[64..96].copy_from_slice(&commitment);

                        let mut events = self.next_tx_events.lock().expect("mutex not poisoned");
                        events.push(AptosEvent {
                            data: event_data,
                            event_sequence_number: 0,
                            key: "CSV::AnchorEvent".to_string(),
                            transaction_version: self.latest_version,
                        });
                    }
                }
            }

            let counter = self
                .tx_counter
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut hash = [0u8; 32];
            hash[..4].copy_from_slice(b"test");
            hash[4..12].copy_from_slice(&counter.to_le_bytes());
            Ok(hash)
        })
    }
}

impl AptosModulePublisher for MockAptosRpc {
    fn publish_module(
        &self,
        tx_bytes: Vec<u8>,
    ) -> BoxFuture<'_, Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>>> {
        Box::pin(async move {
            self.sent_transactions
                .lock()
                .expect("mutex not poisoned")
                .push(tx_bytes);
            Ok([0xAB; 32])
        })
    }
}

impl AptosViewReader for MockAptosRpc {
    fn call_view<'a>(
        &'a self,
        function: &'a str,
        _arguments: Vec<serde_json::Value>,
    ) -> BoxFuture<'a, Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>>> {
        Box::pin(async move {
            self.view_results
                .lock()
                .expect("mutex not poisoned")
                .get(function)
                .cloned()
                .ok_or_else(|| format!("No mock Aptos view result for {function}").into())
        })
    }
}

impl AptosCheckpointVerifier for MockAptosRpc {
    fn verify_checkpoint(
        &self,
        _sequence_number: u64,
    ) -> BoxFuture<'_, Result<bool, Box<dyn std::error::Error + Send + Sync>>> {
        Box::pin(async { Ok(true) })
    }
}

impl AptosRpc for MockAptosRpc {
    fn clone_boxed(&self) -> Box<dyn AptosRpc> {
        let tx_count = self.tx_counter.load(std::sync::atomic::Ordering::SeqCst);
        Box::new(MockAptosRpc {
            latest_version: self.latest_version,
            chain_id: self.chain_id,
            test_address: self.test_address,
            tx_counter: std::sync::atomic::AtomicU64::new(tx_count),
            stale_submissions_remaining: std::sync::atomic::AtomicU64::new(
                self.stale_submissions_remaining
                    .load(std::sync::atomic::Ordering::SeqCst),
            ),
            resources: std::sync::Mutex::new(
                self.resources.lock().expect("mutex not poisoned").clone(),
            ),
            transactions: std::sync::Mutex::new(
                self.transactions
                    .lock()
                    .expect("mutex not poisoned")
                    .clone(),
            ),
            events: std::sync::Mutex::new(self.events.lock().expect("mutex not poisoned").clone()),
            blocks: std::sync::Mutex::new(self.blocks.lock().expect("mutex not poisoned").clone()),
            sent_transactions: std::sync::Mutex::new(
                self.sent_transactions
                    .lock()
                    .expect("mutex not poisoned")
                    .clone(),
            ),
            next_tx_events: std::sync::Mutex::new(
                self.next_tx_events
                    .lock()
                    .expect("mutex not poisoned")
                    .clone(),
            ),
            view_results: std::sync::Mutex::new(
                self.view_results
                    .lock()
                    .expect("mutex not poisoned")
                    .clone(),
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ledger_info() {
        let rpc = MockAptosRpc::new(1000);
        let info = AptosLedgerReader::get_ledger_info(&rpc).await.unwrap();
        assert_eq!(info.chain_id, 1);
        assert_eq!(info.ledger_version, 1000);
    }

    #[tokio::test]
    async fn test_resource() {
        let rpc = MockAptosRpc::new(1000);
        let address = [1u8; 32];
        let resource = AptosResource {
            data: vec![0xAB, 0xCD],
        };
        rpc.set_resource(address, "CSV::Seal", resource.clone());

        let fetched = AptosAccountReader::get_resource(&rpc, address, "CSV::Seal", None)
            .await
            .unwrap();
        assert_eq!(fetched.unwrap().data, vec![0xAB, 0xCD]);
    }

    #[tokio::test]
    async fn test_transaction() {
        let rpc = MockAptosRpc::new(1000);
        let tx = AptosTransaction {
            version: 500,
            hash: [1u8; 32],
            state_change_hash: [2u8; 32],
            event_root_hash: [3u8; 32],
            state_checkpoint_hash: None,
            epoch: 1,
            round: 0,
            events: vec![],
            payload: vec![0x01, 0x02],
            success: true,
            vm_status: "Executed".to_string(),
            gas_used: 100,
            cumulative_gas_used: 100,
        };
        rpc.add_transaction(500, tx.clone());

        let fetched = AptosTransactionReader::get_transaction(&rpc, 500)
            .await
            .unwrap();
        assert_eq!(fetched.unwrap().version, 500);
    }

    #[tokio::test]
    async fn test_events() {
        let rpc = MockAptosRpc::new(1000);
        let event = AptosEvent {
            event_sequence_number: 1,
            key: "CSV::Seal".to_string(),
            data: vec![0xAB, 0xCD],
            transaction_version: 500,
        };
        rpc.add_event("CSV::Seal", event.clone());

        let fetched =
            AptosEventReader::get_events(&rpc, "CSV::Seal".to_string(), "0".to_string(), 10)
                .await
                .unwrap();
        assert_eq!(fetched.len(), 1);
    }

    #[tokio::test]
    async fn test_submit_transaction() {
        let rpc = MockAptosRpc::new(1000);
        let tx_hash = AptosTransactionSubmitter::submit_transaction(&rpc, vec![0x01, 0x02])
            .await
            .unwrap();
        assert_eq!(tx_hash, [0xAB; 32]);
    }

    #[tokio::test]
    async fn test_wait_for_transaction() {
        let rpc = MockAptosRpc::new(1000);
        let tx_hash = [1u8; 32];
        let tx = AptosTransactionReader::wait_for_transaction(&rpc, tx_hash)
            .await
            .unwrap();
        assert_eq!(tx.version, 1000);
        assert!(tx.success);
    }
}
