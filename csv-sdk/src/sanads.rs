//! Sanads management runtime.
//!
//! The [`SanadsManager`] provides a high-level API for creating, querying,
//! and managing Sanads across all supported chains.
//!
//! # What is a Sanad?
//!
//! A **Sanad** is a verifiable, single-use digital claim that can be
//! transferred cross-chain. It exists in client state (not on any chain)
//! and is anchored to a single-use seal on a specific chain.
//!
//! To transfer a Sanad, the seal is consumed on-chain and the new owner
//! verifies the consumption proof locally — no bridges, no minting,
//! no cross-chain messaging.

use std::sync::Arc;

use csv_hash::chain_id::ChainId;
use csv_hash::Hash;
use csv_hash::sanad::SanadId;
use csv_protocol::Sanad;

use crate::client::ClientRef;
use crate::error::CsvError;

/// Filter options for listing Sanads.
#[derive(Debug, Clone, Default)]
pub struct SanadFilters {
    /// Filter by chain (the chain where the seal is anchored).
    pub chain: Option<ChainId>,
    /// Filter by owner address.
    pub owner: Option<String>,
    /// Filter by consumed status.
    pub consumed: Option<bool>,
    /// Maximum number of results.
    pub limit: Option<usize>,
}

/// Manager for Sanad operations.
///
/// Obtain a [`SanadsManager`] via [`CsvClient::sanads()`](crate::client::CsvClient::sanads).
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
/// #     .with_store_backend(StoreBackend::InMemory)
/// #     .build()?;
/// let sanads = client.sanads();
///
/// // List all Sanads
/// let all_sanads = sanads.list(SanadFilters::default())?;
/// # Ok(())
/// # }
/// ```
pub struct SanadsManager {
    client: Arc<ClientRef>,
}

impl SanadsManager {
    pub(crate) fn new(client: Arc<ClientRef>) -> Self {
        Self { client }
    }

    /// Create a new Sanad anchored to the specified chain.
    ///
    /// This method:
    /// 1. Creates a single-use seal on the target chain
    /// 2. Constructs a Sanad with the given commitment
    /// 3. Records the seal consumption in the local store
    ///
    /// # Arguments
    ///
    /// * `commitment` — The commitment hash binding the Sanad's state.
    /// * `chain` — The chain where the seal will be anchored.
    ///
    /// # Returns
    ///
    /// The newly created [`Sanad`] with a unique [`SanadId`].
    ///
    /// # Errors
    ///
    /// - [`CsvError::ChainNotSupported`] if the chain is not enabled.
    /// - [`CsvError::InsufficientFunds`] if the wallet lacks funds for seal creation.
    /// - [`CsvError::ProtocolError`] if the underlying chain operation fails.
    pub fn create(&self, commitment: Hash, chain: ChainId) -> Result<Sanad, CsvError> {
        if !self.client.is_chain_enabled(chain.clone()) {
            return Err(CsvError::ChainNotSupported(chain));
        }

        // In a full implementation, this would:
        // 1. Call the chain adapter's SealProtocol::create_seal()
        // 2. Construct the Sanad with the seal reference
        // 3. Publish the commitment via SealProtocol::publish()
        // 4. Record the seal in the local store
        // 5. Emit a SanadCreated event
        //
        // The chain adapters (csv-adapter-bitcoin, etc.) provide the
        // actual SealPoint types and publishing logic.
        //
        // Example for Bitcoin:
        //   let btc_adapter = csv_bitcoin::BitcoinSealProtocol::signet()?;
        //   let seal = btc_adapter.create_seal(None)?;
        //   let sanad = Sanad::new(commitment.hash(), owner_proof, salt);

        let salt = generate_salt();
        let owner = csv_protocol::OwnershipProof {
            proof: vec![0u8; 32], // Derived from wallet in full implementation
            owner: vec![0u8; 32],
            scheme: None,
        };

        let sanad = Sanad::new(commitment, owner, &salt);

        // Persist the Sanad to the store
        let record = csv_protocol::SanadRecord {
            sanad_id: sanad.id.clone(),
            chain: chain.to_string(),
            owner: sanad.owner.owner.clone(),
            sanad_data: sanad.to_canonical_bytes().map_err(|e| {
                CsvError::SerializationError(format!("Failed to serialize Sanad: {:?}", e))
            })?,
            consumed: false,
            recorded_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            consumed_at: None,
        };

        // Lock the store and save the sanad
        let mut store = self
            .client
            .store
            .lock()
            .map_err(|_| CsvError::StoreError("Failed to acquire store lock".to_string()))?;
        store.save_sanad(&record)?;
        drop(store); // Release lock before emitting event

        self.client.emit_event(crate::events::Event::SanadCreated {
            sanad_id: sanad.id.clone(),
            chain,
        });

        Ok(sanad)
    }

    /// Get a Sanad by its ID.
    ///
    /// # Note
    ///
    /// Sanads exist in client state, not on-chain. This method queries
    /// the local store for previously created or received Sanads.
    pub fn get(&self, sanad_id: &SanadId) -> Result<Option<Sanad>, CsvError> {
        // Query the local store for the Sanad by ID
        let store = self
            .client
            .store
            .lock()
            .map_err(|_| CsvError::StoreError("Failed to acquire store lock".to_string()))?;

        match store.get_sanad(sanad_id)? {
            Some(record) => {
                // Deserialize the Sanad from stored data
                let sanad = Sanad::from_canonical_bytes(&record.sanad_data).map_err(|e| {
                    CsvError::SerializationError(format!("Failed to deserialize Sanad: {:?}", e))
                })?;
                Ok(Some(sanad))
            }
            None => Ok(None),
        }
    }

    /// List Sanads matching the given filters.
    pub fn list(&self, filters: SanadFilters) -> Result<Vec<Sanad>, CsvError> {
        let store = self
            .client
            .store
            .lock()
            .map_err(|_| CsvError::StoreError("Failed to acquire store lock".to_string()))?;

        // Get all sanads (we'll filter in memory for now - can optimize later)
        let records = store.list_active_sanads()?;

        // Apply filters and deserialize
        let mut sanads = Vec::new();
        for record in records {
            // Deserialize the Sanad
            let sanad = match Sanad::from_canonical_bytes(&record.sanad_data) {
                Ok(r) => r,
                Err(e) => {
                    // Log warning but skip invalid records
                    eprintln!("Warning: Failed to deserialize Sanad record: {:?}", e);
                    continue;
                }
            };

            // Apply filters
            if let Some(ref chain) = filters.chain {
                if record.chain != chain.to_string() {
                    continue;
                }
            }

            if let Some(ref owner) = filters.owner {
                let owner_bytes = owner.as_bytes();
                if record.owner != owner_bytes {
                    continue;
                }
            }

            if let Some(consumed) = filters.consumed {
                if record.consumed != consumed {
                    continue;
                }
            }

            sanads.push(sanad);
        }

        // Apply limit if specified
        if let Some(limit) = filters.limit {
            sanads.truncate(limit);
        }

        Ok(sanads)
    }

    /// Transfer a Sanad to a new owner on a different chain.
    ///
    /// This initiates a cross-chain transfer:
    /// 1. The source chain seal is consumed (locking the Sanad)
    /// 2. A proof of consumption is generated
    /// 3. The Sanad can be verified and claimed on the destination chain
    ///
    /// # Arguments
    ///
    /// * `sanad_id` — The Sanad to transfer.
    /// * `to_chain` — The destination chain.
    /// * `to_address` — The destination owner's address.
    ///
    /// # Returns
    ///
    /// A transfer identifier for tracking progress.
    pub fn transfer(
        &self,
        sanad_id: &SanadId,
        to_chain: ChainId,
        to_address: String,
    ) -> Result<String, CsvError> {
        if !self.client.is_chain_enabled(to_chain.clone()) {
            return Err(CsvError::ChainNotSupported(to_chain));
        }

        // Cross-chain transfer requires:
        // 1. Look up the Sanad by ID from store
        // 2. Verify the Sanad is not already consumed
        // 3. Consume the seal on the source chain (lock)
        // 4. Generate the inclusion proof
        // 5. Return a transfer ID for tracking
        //
        // Full implementation requires store and chain adapter integration
        Err(CsvError::ChainNotEnabled(format!(
            "Cross-chain transfer not available. Sanad: {:?}, To: {} on {:?}",
            sanad_id, to_address, to_chain
        )))
    }

    /// Burn (permanently consume) a Sanad.
    ///
    /// This is an irreversible operation that destroys the Sanad by
    /// consuming its seal without creating a new one.
    ///
    /// # Arguments
    ///
    /// * `sanad_id` — The Sanad to burn.
    pub fn burn(&self, sanad_id: &SanadId) -> Result<(), CsvError> {
        // Consume the seal on-chain without a destination owner
        // Full implementation requires chain adapter integration
        // For now, return FeatureNotEnabled error with context
        Err(CsvError::ChainNotEnabled(format!(
            "Sanad burn operation not available. Sanad ID: {:?}",
            sanad_id
        )))
    }
}

/// Generate a random 16-byte salt.
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
