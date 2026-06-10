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
//!
//! # Wallet Integration
//!
//! Creating a Sanad requires:
//! 1. A [`SanadPayloadDescriptor`] binding content metadata to the Sanad ID
//! 2. A signed [`OwnershipProof`] from the wallet
//!
//! Use [`SanadsManager::create`] which accepts both the descriptor and owner proof.
//!
//! ## Example: Creating a Sanad with Real Wallet
//!
//! ```ignore
//! use csv_sdk::prelude::*;
//! use csv_protocol::{SanadPayloadDescriptor, OwnershipProof};
//! use csv_keys::memory::SecretKey;
//!
//! // 1. Create a payload descriptor
//! let descriptor = SanadPayloadDescriptor::new(
//!     "csv.sanad.content.v1",
//!     schema_hash,
//!     1, // CBOR codec
//!     payload_hash,
//!     None, // no content root
//!     disclosure_policy_hash,
//!     proof_policy_hash,
//! );
//!
//! // 2. Sign the descriptor hash with the wallet
//! let owner_proof = wallet.sign_descriptor(&descriptor)?;
//!
//! // 3. Create the Sanad
//! let sanad = sanads.create(
//!     &descriptor,
//!     commitment,
//!     owner_proof,
//!     salt,
//!     chain,
//! )?;
//! ```

use std::sync::Arc;

use crate::local_store::SanadRecord;
use csv_hash::Hash;
use csv_hash::chain_id::ChainId;
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
    /// This is the **only** method for creating Sanads. It requires:
    /// 1. A [`SanadPayloadDescriptor`] binding content metadata to the Sanad ID
    /// 2. A signed [`OwnershipProof`] from the wallet
    /// 3. A commitment hash binding the Sanad's state
    /// 4. Salt bytes for uniqueness in ID derivation
    ///
    /// ## Workflow
    ///
    /// 1. Create a [`SanadPayloadDescriptor`] with schema, payload hash, and content roots
    /// 2. Sign the descriptor hash with the wallet's secret key
    /// 3. Create the seal on the target chain (via chain adapter)
    /// 4. Construct the Sanad with the descriptor, commitment, and ownership proof
    /// 5. Persist to local store and emit event
    ///
    /// # Arguments
    ///
    /// * `descriptor` — The payload descriptor binding content metadata to the Sanad
    /// * `commitment` — The commitment hash binding the Sanad's state
    /// * `owner` — The ownership proof (wallet signature over descriptor hash)
    /// * `salt` — Salt bytes for uniqueness in ID derivation
    /// * `chain` — The chain where the seal will be anchored
    ///
    /// # Returns
    ///
    /// The newly created [`Sanad`] with a unique [`SanadId`] that binds:
    /// - The descriptor hash (content metadata)
    /// - The commitment hash (state binding)
    /// - The salt (uniqueness)
    ///
    /// # Errors
    ///
    /// - [`CsvError::ChainNotSupported`] if the chain is not enabled.
    /// - [`CsvError::InvalidInput`] if the ownership proof is malformed.
    /// - [`CsvError::SerializationError`] if the Sanad cannot be serialized.
    pub fn create(
        &self,
        descriptor: &csv_protocol::SanadPayloadDescriptor,
        commitment: Hash,
        owner: csv_protocol::OwnershipProof,
        salt: &[u8],
        chain: ChainId,
    ) -> Result<Sanad, CsvError> {
        if !self.client.is_chain_enabled(chain.clone()) {
            return Err(CsvError::ChainNotSupported(chain.clone()));
        }

        // Validate ownership proof structure
        if owner.owner.is_empty() {
            return Err(CsvError::InvalidInput(
                "Ownership proof owner field is empty".to_string(),
            ));
        }
        if owner.proof.is_empty() {
            return Err(CsvError::InvalidInput(
                "Ownership proof signature bytes are empty".to_string(),
            ));
        }

        let sanad = Sanad::new(descriptor, commitment, owner, salt);

        // Persist the Sanad to the store
        let record = SanadRecord {
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
            if let Some(ref chain) = filters.chain
                && record.chain != chain.to_string()
            {
                continue;
            }

            if let Some(ref owner) = filters.owner
                && record.owner != owner.as_bytes()
            {
                continue;
            }

            if let Some(consumed) = filters.consumed
                && record.consumed != consumed
            {
                continue;
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
