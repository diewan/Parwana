//! Sui RPC trait and test implementation

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;

/// Trait for Sui RPC operations
#[async_trait]
pub trait SuiRpc: Send + Sync + 'static {
    /// Get object by ID
    async fn get_object(
        &self,
        object_id: [u8; 32],
    ) -> Result<Option<SuiObject>, Box<dyn std::error::Error + Send + Sync>>;

    /// Get transaction block by digest
    async fn get_transaction_block(
        &self,
        digest: [u8; 32],
    ) -> Result<Option<SuiTransactionBlock>, Box<dyn std::error::Error + Send + Sync>>;

    /// Get transaction events by digest
    async fn get_transaction_events(
        &self,
        digest: [u8; 32],
    ) -> Result<Vec<SuiEvent>, Box<dyn std::error::Error + Send + Sync>>;

    /// Get checkpoint by sequence number
    async fn get_checkpoint(
        &self,
        sequence_number: u64,
    ) -> Result<Option<SuiCheckpoint>, Box<dyn std::error::Error + Send + Sync>>;

    /// Get latest checkpoint sequence number
    async fn get_latest_checkpoint_sequence_number(
        &self,
    ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>>;

    /// Get the sender's address
    async fn sender_address(&self) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>>;

    /// Get gas objects owned by the sender
    async fn get_gas_objects(
        &self,
        owner: [u8; 32],
    ) -> Result<Vec<SuiObject>, Box<dyn std::error::Error + Send + Sync>>;

    /// Execute a signed MoveCall transaction and return the transaction digest
    ///
    /// # Arguments
    /// * `tx_bytes` - BCS-serialized TransactionData
    /// * `signature` - Ed25519 signature (64 bytes)
    /// * `public_key` - Signer's public key (32 bytes)
    async fn execute_signed_transaction(
        &self,
        tx_bytes: Vec<u8>,
        signature: Vec<u8>,
        public_key: Vec<u8>,
    ) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>>;

    /// Wait for transaction confirmation
    async fn wait_for_transaction(
        &self,
        digest: [u8; 32],
        timeout_ms: u64,
    ) -> Result<Option<SuiTransactionBlock>, Box<dyn std::error::Error + Send + Sync>>;

    /// Get ledger info
    async fn get_ledger_info(
        &self,
    ) -> Result<SuiLedgerInfo, Box<dyn std::error::Error + Send + Sync>>;

    /// Clone the RPC client for creating new boxed instances
    fn clone_boxed(&self) -> Box<dyn SuiRpc>;

    /// Downcast to Any for feature-gated real implementations
    fn as_any(&self) -> &dyn std::any::Any
    where
        Self: Sized,
    {
        self
    }
}

/// Sui object representation
#[derive(Clone, Debug)]
pub struct SuiObject {
    pub object_id: [u8; 32],
    pub version: u64,
    pub digest: [u8; 32],
    pub owner: Vec<u8>,
    pub object_type: String,
    pub has_public_transfer: bool,
    /// BCS-encoded object content for parsing balances and other data
    pub bcs_data: Option<Vec<u8>>,
}

impl SuiObject {
    /// Create a new SuiObject with the given properties
    pub fn new(
        object_id: [u8; 32],
        version: u64,
        owner: Vec<u8>,
        object_type: String,
        has_public_transfer: bool,
    ) -> Self {
        Self {
            object_id,
            version,
            digest: [0u8; 32],
            owner,
            object_type,
            has_public_transfer,
            bcs_data: None,
        }
    }

    /// Set the BCS data for this object
    pub fn with_bcs_data(mut self, bcs_data: Vec<u8>) -> Self {
        self.bcs_data = Some(bcs_data);
        self
    }

    /// Parse balance from BCS data for Coin objects
    /// SUI Coin BCS format: id (32 bytes) + value (u64, 8 bytes little-endian)
    pub fn parse_coin_balance(&self) -> Option<u64> {
        let bcs_data = self.bcs_data.as_ref()?;

        // Coin<T> has struct layout: { id: UID, value: u64 }
        // UID is 32 bytes, u64 is 8 bytes little-endian
        // Minimum size: 32 + 8 = 40 bytes
        if bcs_data.len() < 40 {
            return None;
        }

        // Parse u64 from last 8 bytes (little-endian)
        let value_bytes = &bcs_data[32..40];
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
}

/// Sui object change type
#[derive(Clone, Debug)]
pub struct SuiObjectChange {
    pub object_id: [u8; 32],
    pub change_type: String,
}

/// Sui execution status
#[derive(Clone, Debug, PartialEq)]
pub enum SuiExecutionStatus {
    Success,
    Failure { error: String },
}

/// Sui transaction effects
#[derive(Clone, Debug)]
pub struct SuiTransactionEffects {
    pub status: SuiExecutionStatus,
    pub gas_used: u64,
    pub modified_objects: Vec<SuiObjectChange>,
}

/// Sui transaction block
#[derive(Clone, Debug)]
pub struct SuiTransactionBlock {
    pub digest: [u8; 32],
    pub checkpoint: Option<u64>,
    pub effects: SuiTransactionEffects,
}

/// Sui event
#[derive(Clone, Debug)]
pub struct SuiEvent {
    pub id: String,
    pub transaction_digest: [u8; 32],
    pub event_sequence_number: u64,
    pub type_field: String,
    pub data: Vec<u8>,
}

/// Sui checkpoint
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SuiCheckpoint {
    pub sequence_number: u64,
    pub digest: [u8; 32],
    pub epoch: u64,
    pub network_total_transactions: u64,
    pub certified: bool,
}

/// Sui ledger info
#[derive(Clone, Debug)]
pub struct SuiLedgerInfo {
    pub latest_version: u64,
    pub latest_epoch: u64,
}

/// Mock Sui RPC for testing
///
/// This implementation is only compiled in test builds to prevent
/// accidental use in production environments.
pub struct MockSuiRpc {
    objects: Mutex<HashMap<[u8; 32], SuiObject>>,
    transactions: Mutex<HashMap<[u8; 32], SuiTransactionBlock>>,
    checkpoints: Mutex<HashMap<u64, SuiCheckpoint>>,
    latest_checkpoint: u64,
    test_address: [u8; 32],
    tx_counter: std::sync::atomic::AtomicU64,
}

impl MockSuiRpc {
    pub fn new(latest_checkpoint: u64) -> Self {
        Self {
            objects: Mutex::new(HashMap::new()),
            transactions: Mutex::new(HashMap::new()),
            checkpoints: Mutex::new(HashMap::new()),
            latest_checkpoint,
            test_address: [0x42; 32],
            tx_counter: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn new_with_address(latest_checkpoint: u64, address: [u8; 32]) -> Self {
        Self {
            objects: Mutex::new(HashMap::new()),
            transactions: Mutex::new(HashMap::new()),
            checkpoints: Mutex::new(HashMap::new()),
            latest_checkpoint,
            test_address: address,
            tx_counter: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn add_object(&self, object: SuiObject) {
        self.objects
            .lock()
            .unwrap()
            .insert(object.object_id, object);
    }

    pub fn add_transaction(&self, tx: SuiTransactionBlock) {
        self.transactions.lock().unwrap().insert(tx.digest, tx);
    }

    pub fn add_checkpoint(&self, checkpoint: SuiCheckpoint) {
        self.checkpoints
            .lock()
            .unwrap()
            .insert(checkpoint.sequence_number, checkpoint);
    }
}

#[async_trait]
impl SuiRpc for MockSuiRpc {
    async fn get_object(
        &self,
        object_id: [u8; 32],
    ) -> Result<Option<SuiObject>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.objects.lock().unwrap().get(&object_id).cloned())
    }

    async fn get_transaction_block(
        &self,
        digest: [u8; 32],
    ) -> Result<Option<SuiTransactionBlock>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.transactions.lock().unwrap().get(&digest).cloned())
    }

    async fn get_transaction_events(
        &self,
        _digest: [u8; 32],
    ) -> Result<Vec<SuiEvent>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Vec::new())
    }

    async fn get_checkpoint(
        &self,
        sequence_number: u64,
    ) -> Result<Option<SuiCheckpoint>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self
            .checkpoints
            .lock()
            .unwrap()
            .get(&sequence_number)
            .cloned())
    }

    async fn get_latest_checkpoint_sequence_number(
        &self,
    ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.latest_checkpoint)
    }

    async fn sender_address(&self) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.test_address)
    }

    async fn get_gas_objects(
        &self,
        _owner: [u8; 32],
    ) -> Result<Vec<SuiObject>, Box<dyn std::error::Error + Send + Sync>> {
        // Return test gas objects
        Ok(vec![SuiObject {
            object_id: [0x01; 32],
            version: 1,
            digest: [0x01; 32],
            owner: self.test_address.to_vec(),
            object_type: "0x2::coin::Coin<0x2::sui::SUI>".to_string(),
            has_public_transfer: true,
            bcs_data: None,
        }])
    }

    async fn execute_signed_transaction(
        &self,
        _tx_bytes: Vec<u8>,
        _signature: Vec<u8>,
        _public_key: Vec<u8>,
    ) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
        // Test: return a deterministic digest with incrementing counter
        let counter = self
            .tx_counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut digest = [0u8; 32];
        digest[..4].copy_from_slice(b"test");
        digest[4..12].copy_from_slice(&counter.to_le_bytes());
        Ok(digest)
    }

    async fn wait_for_transaction(
        &self,
        _digest: [u8; 32],
        _timeout_ms: u64,
    ) -> Result<Option<SuiTransactionBlock>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(None)
    }

    async fn get_ledger_info(
        &self,
    ) -> Result<SuiLedgerInfo, Box<dyn std::error::Error + Send + Sync>> {
        Ok(SuiLedgerInfo {
            latest_version: self.latest_checkpoint,
            latest_epoch: 1,
        })
    }

    fn clone_boxed(&self) -> Box<dyn SuiRpc> {
        Box::new(MockSuiRpc {
            objects: std::sync::Mutex::new(self.objects.lock().unwrap().clone()),
            transactions: std::sync::Mutex::new(self.transactions.lock().unwrap().clone()),
            checkpoints: std::sync::Mutex::new(self.checkpoints.lock().unwrap().clone()),
            latest_checkpoint: self.latest_checkpoint,
            test_address: self.test_address,
            tx_counter: std::sync::atomic::AtomicU64::new(
                self.tx_counter.load(std::sync::atomic::Ordering::SeqCst),
            ),
        })
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_object() {
        let rpc = MockSuiRpc::new(1000);
        let obj = SuiObject {
            object_id: [1u8; 32],
            version: 1,
            digest: [1u8; 32],
            owner: vec![2, 3],
            object_type: "CSV::Seal".to_string(),
            has_public_transfer: false,
            bcs_data: None,
        };
        rpc.add_object(obj.clone());

        let fetched = rpc.get_object([1u8; 32]).await.unwrap();
        assert_eq!(fetched.unwrap().version, 1);
    }

    #[tokio::test]
    async fn test_checkpoint() {
        let rpc = MockSuiRpc::new(1000);
        let cp = SuiCheckpoint {
            sequence_number: 500,
            digest: [1u8; 32],
            epoch: 1,
            network_total_transactions: 50000,
            certified: true,
        };
        rpc.add_checkpoint(cp.clone());

        let fetched = rpc.get_checkpoint(500).await.unwrap();
        assert!(fetched.unwrap().certified);
    }
}
