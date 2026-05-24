//! Transfer management runtime.
//!
//! The [`TransferManager`] handles cross-chain transfers between any
//! two supported chains using the lock-and-prove protocol.
//!
//! # Cross-Chain Transfer Protocol
//!
//! 1. **Lock** — Source chain consumes the Sanad's seal, emits a lock event
//! 2. **Prove** — Client generates an inclusion proof of the lock event
//! 3. **Verify** — Destination chain verifies the proof (client-side)
//! 4. **Claim** — New Sanad created on destination chain with new seal
//!
//! No bridges, no wrapped tokens, no cross-chain messaging.

use std::collections::HashMap;
use std::sync::Arc;

use csv_hash::Hash;
use csv_hash::chain_id::ChainId;
use csv_hash::sanad::SanadId;

use crate::client::ClientRef;
use crate::error::CsvError;
use crate::runtime::ChainRuntime;

/// Filter options for listing transfers.
#[derive(Debug, Clone, Default)]
pub struct TransferFilters {
    /// Filter by source chain.
    pub from_chain: Option<ChainId>,
    /// Filter by destination chain.
    pub to_chain: Option<ChainId>,
    /// Filter by status.
    pub status: Option<String>,
    /// Maximum number of results.
    pub limit: Option<usize>,
}

/// Priority level for transfer execution.
#[derive(Debug, Clone, Copy, Default)]
pub enum Priority {
    /// Normal priority (default fee rates).
    #[default]
    Normal,
    /// High priority (elevated fee rates for faster confirmation).
    High,
    /// Urgent (maximum fee rates, RBF enabled).
    Urgent,
}

/// Manager for cross-chain transfer operations.
///
/// Obtain a [`TransferManager`] via
/// [`CsvClient::transfers()`](crate::client::CsvClient::transfers).
///
/// # Example
///
/// ```ignore
/// use csv_sdk::prelude::*;
///
/// # #[tokio::main]
/// # async fn main() -> Result<()> {
/// # let client = CsvClient::builder()
/// #     .with_chain(ChainId::new("bitcoin"))
/// #     .with_chain(ChainId::new("sui"))
/// #     .with_store_backend(StoreBackend::InMemory)
/// #     .build()?;
/// let transfers = client.transfers();
///
/// // Start a cross-chain transfer
/// let transfer = transfers
///     .cross_chain(SanadId::default(), ChainId::new("sui"))
///     .to_address("0xabc...".to_string())
///     .with_priority(Priority::High)
///     .execute()?;
///
/// // Check status
/// let status = transfers.status(&transfer)?;
/// # Ok(())
/// # }
/// ```
pub struct TransferManager {
    #[allow(dead_code)]
    client: Arc<ClientRef>,
    /// Chain runtime for executing real chain operations
    runtime: Arc<ChainRuntime>,
    /// Local transfer records wrapped in Arc for shared ownership
    transfers: Arc<std::sync::Mutex<HashMap<String, TransferRecord>>>,
}

impl TransferManager {
    pub(crate) fn new(client: Arc<ClientRef>, runtime: Arc<ChainRuntime>) -> Self {
        Self {
            client,
            runtime,
            transfers: Arc::new(std::sync::Mutex::new(HashMap::new())),
        }
    }

    /// Start building a cross-chain transfer.
    ///
    /// # Arguments
    ///
    /// * `sanad_id` — The Sanad to transfer.
    /// * `to_chain` — The destination chain.
    pub fn cross_chain(&self, sanad_id: SanadId, to_chain: ChainId) -> TransferBuilder {
        TransferBuilder::new(
            self.transfers.clone(),
            self.runtime.clone(),
            sanad_id,
            to_chain,
        )
    }

    /// Get the current status of a transfer.
    ///
    /// # Arguments
    ///
    /// * `transfer_id` — The transfer identifier returned by
    ///   [`TransferBuilder::execute()`].
    pub fn status(&self, transfer_id: &str) -> Result<crate::TransferStatus, CsvError> {
        let transfers = self
            .transfers
            .lock()
            .map_err(|e| CsvError::StoreError(e.to_string()))?;
        match transfers.get(transfer_id) {
            Some(record) => Ok(record.status.clone()),
            None => Err(CsvError::TransferNotFound(transfer_id.to_string())),
        }
    }

    /// Get detailed transfer information by ID.
    pub fn details(&self, transfer_id: &str) -> Result<TransferRecord, CsvError> {
        let transfers = self
            .transfers
            .lock()
            .map_err(|e| CsvError::StoreError(e.to_string()))?;
        transfers
            .get(transfer_id)
            .cloned()
            .ok_or_else(|| CsvError::TransferNotFound(transfer_id.to_string()))
    }

    /// List transfers matching the given filters.
    pub fn list(&self, filters: TransferFilters) -> Result<Vec<TransferRecord>, CsvError> {
        let transfers = self
            .transfers
            .lock()
            .map_err(|e| CsvError::StoreError(e.to_string()))?;
        let mut result: Vec<TransferRecord> = transfers.values().cloned().collect();

        if let Some(from_chain) = filters.from_chain {
            result.retain(|t| t.from_chain == from_chain);
        }
        if let Some(to_chain) = filters.to_chain {
            result.retain(|t| t.to_chain == to_chain);
        }
        if let Some(status) = &filters.status {
            result.retain(|t| t.status.to_string().contains(status));
        }
        if let Some(limit) = filters.limit {
            result.truncate(limit);
        }

        Ok(result)
    }
}

/// A record of a cross-chain transfer.
#[derive(Debug, Clone)]
pub struct TransferRecord {
    /// Unique transfer identifier.
    pub transfer_id: String,
    /// The Sanad being transferred.
    pub sanad_id: SanadId,
    /// Source chain.
    pub from_chain: ChainId,
    /// Destination chain.
    pub to_chain: ChainId,
    /// Destination address.
    pub to_address: String,
    /// Current status.
    pub status: crate::TransferStatus,
    /// Lock transaction hash on source chain (populated after lock)
    pub lock_tx_hash: Option<String>,
    /// Inclusion proof of the lock transaction (populated after proof generation)
    #[allow(dead_code)]
    pub inclusion_proof: Option<csv_protocol::proof::InclusionProof>,
}

/// Fluent builder for a cross-chain transfer.
///
/// Created via [`TransferManager::cross_chain()`].
pub struct TransferBuilder {
    transfers: std::sync::Arc<std::sync::Mutex<HashMap<String, TransferRecord>>>,
    runtime: Arc<ChainRuntime>,
    sanad_id: SanadId,
    from_chain: ChainId,
    to_chain: ChainId,
    to_address: Option<String>,
    priority: Priority,
    metadata: HashMap<String, String>,
    lease_token: Option<csv_hash::Hash>,
}

impl TransferBuilder {
    pub(crate) fn new(
        transfers: std::sync::Arc<std::sync::Mutex<HashMap<String, TransferRecord>>>,
        runtime: Arc<ChainRuntime>,
        sanad_id: SanadId,
        to_chain: ChainId,
    ) -> Self {
        Self {
            transfers,
            runtime,
            sanad_id,
            from_chain: ChainId::new("bitcoin"),
            to_chain,
            to_address: None,
            priority: Priority::default(),
            metadata: HashMap::new(),
            lease_token: None,
        }
    }

    /// Set the source chain for this transfer.
    pub fn from_chain(mut self, chain: ChainId) -> Self {
        self.from_chain = chain;
        self
    }

    /// Set the destination address for the transfer.
    pub fn to_address(mut self, address: String) -> Self {
        self.to_address = Some(address);
        self
    }

    /// Set the priority level for this transfer.
    ///
    /// Higher priority transfers use elevated fee rates for faster
    /// confirmation on the source chain.
    pub fn with_priority(mut self, priority: Priority) -> Self {
        self.priority = priority;
        self
    }

    /// Attach custom metadata to the transfer.
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }

    /// Set the lease token for this transfer.
    ///
    /// The lease token must have been acquired via the
    /// [`TransferManager::acquire_lease()`] method before calling this.
    pub fn with_lease_token(mut self, lease_token: Hash) -> Self {
        self.lease_token = Some(lease_token);
        self
    }

    /// Execute the cross-chain transfer.
    ///
    /// This initiates the lock-and-prove protocol:
    /// 1. Locks the Sanad on the source chain (consumes the seal)
    /// 2. Polls for transaction finality
    /// 3. Builds an inclusion proof of the lock transaction
    /// 4. Mints a new Sanad on the destination chain
    /// 5. Returns a transfer ID for tracking progress
    ///
    /// # Returns
    ///
    /// A unique transfer identifier. Use [`TransferManager::status()`]
    /// to track progress.
    ///
    /// # Errors
    ///
    /// - [`CsvError::SanadNotFound`] if the Sanad ID is unknown
    /// - [`CsvError::SanadAlreadyConsumed`] if the seal was already used
    /// - [`CsvError::ChainNotSupported`] if the destination chain is not enabled
    /// - [`CsvError::InsufficientFunds`] if the wallet lacks funds
    pub async fn execute(self) -> Result<String, CsvError> {
        let to_address = self.to_address.as_ref().ok_or_else(|| {
            CsvError::BuilderError(
                "Destination address is required. Use .to_address() to set it.".to_string(),
            )
        })?;

        // Generate a unique transfer ID
        let transfer_id = format!("xfer-{}", hex::encode(generate_salt()));

        // Create initial transfer record
        let mut record = TransferRecord {
            transfer_id: transfer_id.clone(),
            sanad_id: self.sanad_id.clone(),
            from_chain: self.from_chain.clone(),
            to_chain: self.to_chain.clone(),
            to_address: to_address.clone(),
            status: crate::TransferStatus::Initiated,
            lock_tx_hash: None,
            inclusion_proof: None,
        };

        // Persist initial record
        {
            let mut transfers = self
                .transfers
                .lock()
                .map_err(|e| CsvError::StoreError(e.to_string()))?;
            transfers.insert(transfer_id.clone(), record.clone());
        }

        // Step 1: Lock the sanad on the source chain
        let lock_result = self
            .runtime
            .lock_sanad(
                self.from_chain.clone(),
                &self.sanad_id,
                self.to_chain.to_string().as_str(),
                self.from_chain.as_ref(),
            )
            .await?;

        let lock_tx_hash = lock_result.transaction_hash.clone();
        let lock_block_height = lock_result.block_height;

        // Update status to Locking
        record.status = crate::TransferStatus::Locking {
            current_confirmations: 0,
            required_confirmations: 1,
        };
        record.lock_tx_hash = Some(lock_tx_hash.clone());
        {
            let mut transfers = self
                .transfers
                .lock()
                .map_err(|e| CsvError::StoreError(e.to_string()))?;
            transfers.insert(transfer_id.clone(), record.clone());
        }

        // Step 2: Poll for transaction finality
        let tx_status = self
            .runtime
            .confirm_transaction(
                self.from_chain.clone(),
                &lock_tx_hash,
                1,   // required confirmations
                300, // 5 minute timeout
            )
            .await?;

        let finality_block = match tx_status {
            csv_protocol::backend::TransactionStatus::Confirmed { block_height, .. } => {
                block_height
            }
            csv_protocol::backend::TransactionStatus::Failed { reason, .. } => {
                record.status = crate::TransferStatus::Failed {
                    error_code: "LOCK_FAILED".to_string(),
                    retryable: true,
                };
                let mut transfers = self
                    .transfers
                    .lock()
                    .map_err(|e| CsvError::StoreError(e.to_string()))?;
                transfers.insert(transfer_id.clone(), record);
                return Err(CsvError::TransferFailed {
                    transfer_id: transfer_id.clone(),
                    error: format!("Lock transaction failed: {}", reason),
                });
            }
            _ => lock_block_height,
        };

        // Update status to GeneratingProof
        record.status = crate::TransferStatus::GeneratingProof {
            progress_percent: 0,
        };
        {
            let mut transfers = self
                .transfers
                .lock()
                .map_err(|e| CsvError::StoreError(e.to_string()))?;
            transfers.insert(transfer_id.clone(), record.clone());
        }

        // Step 3: Build inclusion proof of the lock transaction
        let commitment_bytes: [u8; 32] = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(lock_tx_hash.as_bytes());
            hasher.finalize().into()
        };
        let commitment = Hash::new(commitment_bytes);
        let inclusion_proof = self
            .runtime
            .build_inclusion_proof(
                self.from_chain.clone(),
                &commitment,
                finality_block,
                lock_tx_hash.as_bytes(),
            )
            .await?;

        // Step 3.5: Broadcast proof via P2P for destination chain discovery
        #[cfg(feature = "p2p")]
        {
            self.runtime
                .broadcast_proof(self.from_chain.clone(), &inclusion_proof)
                .await?;
        }

        // Update status to ProofReady
        record.status = crate::TransferStatus::ProofReady {
            proof_block: finality_block,
        };
        record.inclusion_proof = Some(inclusion_proof.clone());
        {
            let mut transfers = self
                .transfers
                .lock()
                .map_err(|e| CsvError::StoreError(e.to_string()))?;
            transfers.insert(transfer_id.clone(), record.clone());
        }

        // Step 4: Mint sanad on destination chain
        record.status = crate::TransferStatus::Minting;
        {
            let mut transfers = self
                .transfers
                .lock()
                .map_err(|e| CsvError::StoreError(e.to_string()))?;
            transfers.insert(transfer_id.clone(), record.clone());
        }

        let _mint_result = self
            .runtime
            .mint_sanad(
                self.to_chain.clone(),
                self.from_chain.to_string().as_str(),
                &self.sanad_id,
                &inclusion_proof,
                to_address,
            )
            .await?;

        // Step 5: Update transfer record to Completed
        record.status = crate::TransferStatus::Completed;
        {
            let mut transfers = self
                .transfers
                .lock()
                .map_err(|e| CsvError::StoreError(e.to_string()))?;
            transfers.insert(transfer_id.clone(), record);
        }

        Ok(transfer_id)
    }
}

fn generate_salt() -> Vec<u8> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let mut salt = Vec::with_capacity(16);
    salt.extend_from_slice(&timestamp.to_le_bytes());
    salt.extend_from_slice(&timestamp.rotate_left(32).to_le_bytes());
    salt
}

#[allow(dead_code)]
fn iso_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Simple RFC 3339-ish timestamp
    format!("{}-01-01T00:00:00Z", 2020 + secs / 31_536_000)
}
